"""
AI Memory Firewall - Core Firewall Evaluation Engine
=====================================================
Orchestrates the multi-stage inspection pipeline:
  1. Apply active tenant FirewallRules (regex, keyword, custom patterns)
  2. Apply built-in PII detection & redaction
  3. Apply built-in Prompt Injection detection
  4. Calculate composite risk score
  5. Determine final decision (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT)
  6. Measure evaluation latency
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.engine.injection import InjectionDetector, InjectionMatch
from src.engine.pii import PIIDetector, PIIMatch


# ---------------------------------------------------------------------------
# Decision constants (mirrors RuleAction enum values)
# ---------------------------------------------------------------------------
DECISION_ALLOW      = "ALLOW"
DECISION_REDACT     = "REDACT"
DECISION_BLOCK      = "BLOCK"
DECISION_QUARANTINE = "QUARANTINE"
DECISION_AUDIT      = "AUDIT"

# Risk score threshold above which QUARANTINE is forced regardless of rule action
QUARANTINE_RISK_THRESHOLD = 0.90
# Risk score threshold above which BLOCK is forced
BLOCK_RISK_THRESHOLD = 0.75


@dataclass
class RuleViolation:
    """Represents a single rule match / violation detail."""
    rule_id: Optional[str]        # Database UUID of the matched FirewallRule (None = built-in)
    rule_name: str                # Human-readable rule name
    rule_type: str                # e.g., "PII_DETECTION", "PROMPT_INJECTION", "REGEX_PATTERN"
    action: str                   # Action the rule prescribes
    severity: str                 # LOW / MEDIUM / HIGH / CRITICAL
    matched_text: str             # Exact text that triggered the rule
    risk_contribution: float      # Score contribution from this rule


@dataclass
class EvaluationResult:
    """
    The complete result of a firewall evaluation pass on a piece of text.

    Attributes:
        decision:         Final action to take (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT)
        original_text:    The input text as-received.
        sanitized_text:   The text after all redactions have been applied.
        risk_score:       Composite risk score from 0.0 (safe) to 1.0 (critical).
        violations:       List of all rule/pattern matches found.
        pii_matches:      Detailed PII entities detected.
        injection_matches: Detailed injection signals detected.
        latency_ms:       Total evaluation time in milliseconds.
        is_clean:         True if decision is ALLOW with no violations.
    """
    decision: str
    original_text: str
    sanitized_text: str
    risk_score: float
    violations: List[RuleViolation] = field(default_factory=list)
    pii_matches: List[PIIMatch] = field(default_factory=list)
    injection_matches: List[InjectionMatch] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def is_clean(self) -> bool:
        """True only when the decision is ALLOW with no violations detected."""
        return self.decision == DECISION_ALLOW and len(self.violations) == 0

    @property
    def detected_entity_types(self) -> List[str]:
        """Returns a deduplicated list of detected entity type names."""
        types = set()
        for p in self.pii_matches:
            types.add(p.pii_type.value)
        for i in self.injection_matches:
            types.add(i.category.value)
        return sorted(types)


class FirewallEvaluator:
    """
    The core evaluation engine for the AI Memory Firewall.

    Stages:
      1. Apply custom database-backed rules (ordered by priority_order ASC).
      2. Apply built-in PII detector.
      3. Apply built-in Prompt Injection detector.
      4. Aggregate risk score and determine final decision.

    Usage:
        evaluator = FirewallEvaluator()

        # Run against a piece of text with no custom rules (built-in only)
        result = evaluator.evaluate(text="My SSN is 123-45-6789")
        print(result.decision)        # "REDACT"
        print(result.sanitized_text)  # "My SSN is [REDACTED_SSN]"
        print(result.risk_score)      # 0.9

        # Run with custom database rules (plain dicts)
        rules = [
            {
                "id": "rule-uuid-1",
                "name": "Block competitor mentions",
                "rule_type": "KEYWORD_FILTER",
                "pattern_payload": "competitor_name",
                "action": "BLOCK",
                "severity": "HIGH",
                "priority_order": 5,
            }
        ]
        result = evaluator.evaluate("Visit competitor_name for a better deal", db_rules=rules)
    """

    def __init__(self) -> None:
        self._pii_detector = PIIDetector()
        self._injection_detector = InjectionDetector()

    def evaluate(
        self,
        text: str,
        db_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> EvaluationResult:
        """
        Run the full inspection pipeline on a piece of text.

        Args:
            text:     The raw text to evaluate (prompt, memory content, etc.).
            db_rules: List of active FirewallRule dicts fetched from the database,
                      ordered by priority_order ASC.
                      Each dict must have keys: id, name, rule_type, pattern_payload,
                      action, severity, priority_order.

        Returns:
            EvaluationResult with decision, sanitized text, risk score, and violation details.
        """
        start_time = time.perf_counter()

        violations: List[RuleViolation] = []
        sanitized = text
        risk_score = 0.0

        # ── Stage 1: Custom database-backed rules ────────────────────────
        if db_rules:
            for rule in db_rules:
                matched = self._apply_db_rule(rule, sanitized)
                if matched:
                    violations.append(matched)
                    # Apply redaction inline if rule prescribes REDACT
                    if rule.get("action") == DECISION_REDACT:
                        sanitized = self._redact_pattern(
                            rule["pattern_payload"],
                            rule["rule_type"],
                            sanitized,
                            rule.get("name", "custom_rule"),
                        )

        # ── Stage 2: Built-in PII detection ─────────────────────────────
        pii_matches, sanitized = self._pii_detector.scan(sanitized)
        for pii in pii_matches:
            violations.append(
                RuleViolation(
                    rule_id=None,
                    rule_name=f"Built-in PII Detector [{pii.pii_type.value}]",
                    rule_type="PII_DETECTION",
                    action=DECISION_REDACT,
                    severity=self._weight_to_severity(pii.risk_weight),
                    matched_text=pii.original,
                    risk_contribution=pii.risk_weight,
                )
            )

        # ── Stage 3: Built-in Prompt Injection detection ─────────────────
        injection_matches = self._injection_detector.scan(sanitized)
        for inj in injection_matches:
            violations.append(
                RuleViolation(
                    rule_id=None,
                    rule_name=inj.rule_name,
                    rule_type="PROMPT_INJECTION",
                    action=DECISION_QUARANTINE,
                    severity=self._weight_to_severity(inj.risk_weight),
                    matched_text=inj.matched_phrase,
                    risk_contribution=inj.risk_weight,
                )
            )

        # ── Stage 4: Composite risk score ────────────────────────────────
        if violations:
            # Weighted combination: max signal drives the score heavily,
            # additional violations push it slightly higher.
            individual_weights = [v.risk_contribution for v in violations]
            max_weight = max(individual_weights)
            # Each extra violation adds a diminishing increment.
            extras = sum(individual_weights) - max_weight
            # Cap extras at 0.5 contribution
            risk_score = min(1.0, max_weight + (extras * 0.05))

        # ── Stage 5: Final decision ───────────────────────────────────────
        decision = self._determine_decision(violations, risk_score)

        latency_ms = (time.perf_counter() - start_time) * 1000

        return EvaluationResult(
            decision=decision,
            original_text=text,
            sanitized_text=sanitized,
            risk_score=round(risk_score, 4),
            violations=violations,
            pii_matches=pii_matches,
            injection_matches=injection_matches,
            latency_ms=round(latency_ms, 3),
        )

    # ── Private helpers ──────────────────────────────────────────────────

    def _apply_db_rule(
        self, rule: Dict[str, Any], text: str
    ) -> Optional[RuleViolation]:
        """Apply a single database-backed rule. Returns a RuleViolation or None."""
        rule_type = rule.get("rule_type", "REGEX_PATTERN")
        payload = rule.get("pattern_payload", "")
        action = rule.get("action", DECISION_AUDIT)
        severity = rule.get("severity", "MEDIUM")

        matched_text = ""

        if rule_type == "REGEX_PATTERN":
            try:
                m = re.search(payload, text, re.IGNORECASE)
                if m:
                    matched_text = m.group()
            except re.error:
                return None  # Invalid regex — skip silently

        elif rule_type == "KEYWORD_FILTER":
            # payload is a comma-separated list of keywords
            keywords = [k.strip().lower() for k in payload.split(",") if k.strip()]
            lower_text = text.lower()
            for kw in keywords:
                if kw in lower_text:
                    matched_text = kw
                    break

        elif rule_type in ("PII_DETECTION", "PROMPT_INJECTION"):
            # These are handled by built-in detectors in Stages 2 & 3.
            return None

        if not matched_text:
            return None

        return RuleViolation(
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("name", "Custom Rule"),
            rule_type=rule_type,
            action=action,
            severity=severity,
            matched_text=matched_text,
            risk_contribution=self._severity_to_weight(severity),
        )

    def _redact_pattern(
        self, payload: str, rule_type: str, text: str, rule_name: str
    ) -> str:
        """Apply redaction for REDACT-action rules."""
        if rule_type == "REGEX_PATTERN":
            try:
                return re.sub(payload, f"[REDACTED_{rule_name.upper().replace(' ', '_')}]", text, flags=re.IGNORECASE)
            except re.error:
                return text
        elif rule_type == "KEYWORD_FILTER":
            keywords = [k.strip() for k in payload.split(",") if k.strip()]
            for kw in keywords:
                text = re.sub(re.escape(kw), "[REDACTED]", text, flags=re.IGNORECASE)
            return text
        return text

    def _determine_decision(
        self, violations: List[RuleViolation], risk_score: float
    ) -> str:
        """Determine the highest-priority action from all violations and risk score."""
        if not violations:
            return DECISION_ALLOW

        # Risk score thresholds override individual rule actions
        if risk_score >= QUARANTINE_RISK_THRESHOLD:
            return DECISION_QUARANTINE
        if risk_score >= BLOCK_RISK_THRESHOLD:
            return DECISION_BLOCK

        # Otherwise, pick the most severe action from rule violations
        action_priority = {
            DECISION_QUARANTINE: 5,
            DECISION_BLOCK: 4,
            DECISION_REDACT: 3,
            DECISION_AUDIT: 2,
            DECISION_ALLOW: 1,
        }
        actions = [v.action for v in violations]
        return max(actions, key=lambda a: action_priority.get(a, 0))

    @staticmethod
    def _weight_to_severity(weight: float) -> str:
        if weight >= 0.90:
            return "CRITICAL"
        if weight >= 0.70:
            return "HIGH"
        if weight >= 0.50:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _severity_to_weight(severity: str) -> float:
        return {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25,
        }.get(severity.upper(), 0.50)
