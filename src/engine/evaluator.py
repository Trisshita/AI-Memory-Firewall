"""
AI Memory Firewall - Core Firewall Evaluation Engine
=====================================================
Orchestrates the multi-stage inspection pipeline:
  1.   Apply active tenant FirewallRules (regex, keyword, custom patterns)
  1.5. Apply NLP Sensitivity Classifier (spaCy + Presidio + regex fusion) [Week 3]
  2.   Apply built-in PII detection & redaction
  3.   Apply built-in Prompt Injection detection
  4.   Calculate composite risk score
  4.5. Apply PolicyEngine evaluation (RBAC & Policy constraints) [Week 4]
  5.   Determine final decision (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT)
  5.5. Apply DataRedactor strategy-aware masking [Week 5]
  6.   Measure evaluation latency
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.engine.classifier import ClassificationResult, SensitivityClassifier
from src.engine.injection import InjectionDetector, InjectionMatch
from src.engine.pii import PIIDetector, PIIMatch
from src.engine.policy_engine import (
    PolicyEngine,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
)
from src.engine.redactor import DataRedactor, RedactionResult  # Week 5


# ---------------------------------------------------------------------------
# Decision constants (mirrors RuleAction enum values)
# ---------------------------------------------------------------------------
DECISION_ALLOW      = "ALLOW"
DECISION_REDACT     = "REDACT"
DECISION_BLOCK      = "BLOCK"
DECISION_QUARANTINE = "QUARANTINE"
DECISION_AUDIT      = "AUDIT"
DECISION_ASK_USER   = "ASK_USER"

# Risk score threshold above which QUARANTINE is forced regardless of rule action
QUARANTINE_RISK_THRESHOLD = 0.90
# Risk score threshold above which BLOCK is forced
BLOCK_RISK_THRESHOLD = 0.80
# Minimum risk score required before a REDACT decision is issued.
# Below this threshold low-confidence NLP detections (LOCATION, DATE, CARDINAL)
# are treated as AUDIT/ALLOW to avoid false positives on clean text.
REDACT_RISK_THRESHOLD = 0.40


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
        decision:          Final action to take (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT)
        original_text:     The input text as-received.
        sanitized_text:    The text after all redactions have been applied.
        risk_score:        Composite risk score from 0.0 (safe) to 1.0 (critical).
        violations:        List of all rule/pattern matches found.
        pii_matches:       Detailed PII entities detected.
        injection_matches: Detailed injection signals detected.
        classifier_result: SensitivityClassifier output (Week 3).
        policy_result:     PolicyEngine output (Week 4).
        redaction_result:  DataRedactor output with strategy-aware masking (Week 5).
        latency_ms:        Total evaluation time in milliseconds.
        is_clean:          True if decision is ALLOW with no violations.
    """
    decision: str
    original_text: str
    sanitized_text: str
    risk_score: float
    violations: List[RuleViolation] = field(default_factory=list)
    pii_matches: List[PIIMatch] = field(default_factory=list)
    injection_matches: List[InjectionMatch] = field(default_factory=list)
    classifier_result: Optional[ClassificationResult] = None  # Week 3
    policy_result: Optional[PolicyEvaluationResult] = None      # Week 4
    redaction_result: Optional[RedactionResult] = None           # Week 5
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
        if self.classifier_result:
            for e in self.classifier_result.entity_types:
                types.add(e)
        return sorted(types)


class FirewallEvaluator:
    """
    The core evaluation engine for the AI Memory Firewall.

    Stages:
      1. Apply custom database-backed rules (ordered by priority_order ASC).
      1.5 Apply NLP Sensitivity Classifier (spaCy + Presidio + regex fusion) [Week 3]
      2. Apply built-in PII detector.
      3. Apply built-in Prompt Injection detector.
      4. Aggregate risk score.
      4.5 Apply PolicyEngine evaluation (RBAC & Policy constraints) [Week 4]
      5. Determine final decision (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT).
    """

    def __init__(self) -> None:
        self._pii_detector = PIIDetector()
        self._injection_detector = InjectionDetector()
        self._classifier = SensitivityClassifier()  # Week 3: NLP classifier
        self._policy_engine = PolicyEngine()        # Week 4: Policy engine
        self._redactor = DataRedactor()             # Week 5: Data redactor

    def evaluate(
        self,
        text: str,
        db_rules: Optional[List[Dict[str, Any]]] = None,
        db_policies: Optional[List[Dict[str, Any]]] = None,
        user_role: str = "user",
        tenant_id: Optional[str] = None,
    ) -> EvaluationResult:
        """
        Run the full inspection pipeline on a piece of text.

        Args:
            text:        The raw text to evaluate (prompt, memory content, etc.).
            db_rules:    List of active FirewallRule dicts fetched from the database.
            db_policies: List of active SecurityPolicy dicts fetched from the database.
            user_role:   Role of the user submitting the memory ('admin', 'user', 'agent').
            tenant_id:   Optional tenant ID for tenant-scoped policy evaluation.

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
                    if rule.get("action") == DECISION_REDACT:
                        sanitized = self._redact_pattern(
                            rule["pattern_payload"],
                            rule["rule_type"],
                            sanitized,
                            rule.get("name", "custom_rule"),
                        )

        # ── Stage 1.5: NLP Sensitivity Classifier ──────────────────────
        classifier_result = self._classifier.classify(sanitized)
        for entity in classifier_result.entities:
            # Low-confidence generic NLP tags (LOCATION, DATE, CARDINAL, generic ORG)
            # with risk_weight < 0.50 are benign contextual signals, not security violations.
            if entity.risk_weight >= 0.50:
                violations.append(
                    RuleViolation(
                        rule_id=None,
                        rule_name=(
                            f"Classifier [{entity.entity_type}] "
                            f"via {entity.source}"
                        ),
                        rule_type="SENSITIVITY_CLASSIFIER",
                        action=DECISION_REDACT,
                        severity=self._weight_to_severity(entity.risk_weight),
                        matched_text=entity.original_text,
                        risk_contribution=entity.risk_weight,
                    )
                )
        sanitized = classifier_result.sanitized_text

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
            individual_weights = [v.risk_contribution for v in violations]
            max_weight = max(individual_weights)
            extras = sum(individual_weights) - max_weight
            risk_score = min(1.0, max_weight + (extras * 0.05))

        # ── Stage 4.5: Policy Engine Evaluation ─────────────────────────
        detected_types = list(
            set(
                [p.pii_type.value for p in pii_matches]
                + [i.category.value for i in injection_matches]
                + classifier_result.entity_types
            )
        )
        policy_ctx = PolicyEvaluationContext(
            user_role=user_role,
            tenant_id=tenant_id,
            memory_text=text,
            requested_action="evaluate",
            risk_score=risk_score,
            detected_entities=detected_types,
        )
        policy_result = self._policy_engine.evaluate_policies(
            context=policy_ctx,
            policies=db_policies,
        )

        for pol_viol in policy_result.violations:
            violations.append(
                RuleViolation(
                    rule_id=pol_viol.policy_id,
                    rule_name=f"Policy [{pol_viol.policy_name}]",
                    rule_type="SECURITY_POLICY",
                    action=pol_viol.action,
                    severity=self._weight_to_severity(pol_viol.risk_score),
                    matched_text=pol_viol.reason,
                    risk_contribution=pol_viol.risk_score,
                )
            )

        # ── Stage 5: Final decision ───────────────────────────────────────
        decision = self._determine_decision(violations, risk_score)

        # If policy_result decision has higher severity and policy violations occurred, enforce it
        if policy_result and policy_result.violations and policy_result.decision:
            pol_action = policy_result.decision
            action_priority = {
                DECISION_QUARANTINE: 6,
                DECISION_BLOCK: 5,
                DECISION_ASK_USER: 4,
                DECISION_REDACT: 3,
                DECISION_AUDIT: 2,
                DECISION_ALLOW: 1,
            }
            if action_priority.get(pol_action, 0) > action_priority.get(decision, 0):
                decision = pol_action

        # ── Stage 5.5: DataRedactor strategy-aware masking ────────────────
        # Run the redactor whenever sensitive entities were detected so that
        # the sanitized_text carries proper strategy-masked values instead of
        # raw [REDACTED_X] placeholders from the classifier.
        redaction_result: Optional[RedactionResult] = None
        if classifier_result and classifier_result.entities:
            redaction_result = self._redactor.redact(
                text=text,
                entities=classifier_result.entities,
            )
            # Use the strategy-aware sanitized text as the canonical output
            sanitized = redaction_result.redacted_text

        latency_ms = (time.perf_counter() - start_time) * 1000

        return EvaluationResult(
            decision=decision,
            original_text=text,
            sanitized_text=sanitized,
            risk_score=round(risk_score, 4),
            violations=violations,
            pii_matches=pii_matches,
            injection_matches=injection_matches,
            classifier_result=classifier_result,
            policy_result=policy_result,
            redaction_result=redaction_result,
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

        # Pick the most severe action from rule violations
        action_priority = {
            DECISION_QUARANTINE: 6,
            DECISION_BLOCK: 5,
            DECISION_ASK_USER: 4,
            DECISION_REDACT: 3,
            DECISION_AUDIT: 2,
            DECISION_ALLOW: 1,
        }
        best_action = max(violations, key=lambda v: action_priority.get(v.action, 0)).action

        # Gate REDACT decisions: if the composite risk score is below the minimum
        # redaction threshold, low-confidence NLP entities (LOCATION, DATE, CARDINAL)
        # should not cause clean text to be redacted. Demote to ALLOW in that case.
        if best_action == DECISION_REDACT and risk_score < REDACT_RISK_THRESHOLD:
            return DECISION_ALLOW

        return best_action

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
