"""
AI Memory Firewall - Policy Evaluation Engine
================================================
Rule-based evaluation engine for Role-Based Access Control (RBAC) policies,
risk score thresholds, blocked entities, and security policy enforcement across AI memory streams.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID


@dataclass
class PolicyEvaluationContext:
    """
    Contextual information supplied for evaluating security policies.

    Attributes:
        user_role: Role of the subject making the request ('admin', 'user', 'agent', etc.).
        tenant_id: UUID or string ID of the tenant owning the memory context.
        memory_text: Raw or sanitized input text stream to inspect.
        requested_action: Action being attempted ('read', 'write', 'export', 'delete', etc.).
        risk_score: Composite risk score computed by NLP/evaluator engine (0.0 to 1.0).
        detected_entities: List of entity types detected in text (e.g. ['SSN', 'AWS_KEY']).
        metadata: Optional auxiliary parameters (e.g. token_count, IP address).
    """

    user_role: str = "user"
    tenant_id: Optional[str] = None
    memory_text: str = ""
    requested_action: str = "write"
    risk_score: float = 0.0
    detected_entities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyViolationDetail:
    """Represents a specific constraint or rule breach inside a policy."""

    policy_id: Optional[str]
    policy_name: str
    target_role: str
    action: str
    reason: str
    risk_score: float


@dataclass
class PolicyEvaluationResult:
    """
    Result of evaluating all applicable security policies against a request context.

    Attributes:
        decision: Final decision ('ALLOW', 'REDACT', 'BLOCK', 'QUARANTINE', 'AUDIT').
        is_allowed: True if decision is 'ALLOW' or 'AUDIT' or 'REDACT' (non-blocking).
        matched_policy_id: UUID string of primary driving policy.
        matched_policy_name: Human-readable name of primary driving policy.
        violations: Detailed list of triggered policy violations.
        latency_ms: Execution duration in milliseconds.
    """

    decision: str
    is_allowed: bool
    matched_policy_id: Optional[str] = None
    matched_policy_name: Optional[str] = None
    violations: List[PolicyViolationDetail] = field(default_factory=list)
    latency_ms: float = 0.0


class PolicyEngine:
    """
    Core Policy Evaluation Engine.

    Evaluates active policies in order of priority (`priority_order` ASC), enforcing:
      1. Role-Based Access Control (RBAC) role scoping (`target_role`).
      2. Max risk score thresholds (`max_risk_threshold`).
      3. Blocked entity types (e.g. API keys, SSNs, Injection signals).
      4. Keyword & Regex filtering in policy `rules_config`.
      5. Length / token limits.
      6. System default fallbacks.
    """

    # Action precedence hierarchy
    ACTION_PRIORITY = {
        "QUARANTINE": 5,
        "BLOCK": 4,
        "REDACT": 3,
        "AUDIT": 2,
        "ALLOW": 1,
    }

    def evaluate_policies(
        self,
        context: PolicyEvaluationContext,
        policies: Optional[List[Dict[str, Any]]] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate security policies against the provided request context.

        Args:
            context: Context details (user_role, risk_score, detected_entities, etc.)
            policies: List of policy dictionaries fetched from database/memory.
                      If None or empty, applies system default evaluation rules.

        Returns:
            PolicyEvaluationResult with final decision, violations, and latency.
        """
        start_time = time.perf_counter()

        violations: List[PolicyViolationDetail] = []

        if not policies:
            policies = self._get_system_default_policies()

        # Filter active policies and sort by priority_order ASC
        active_policies = [
            p for p in policies if p.get("is_active", True) is True
        ]
        active_policies.sort(key=lambda p: p.get("priority_order", 50))

        driving_policy_id: Optional[str] = None
        driving_policy_name: Optional[str] = None

        for pol in active_policies:
            target_role = str(pol.get("target_role", "*")).lower()
            current_role = context.user_role.lower()

            # ── 1. Role matching (RBAC) ───────────────────────────────────────
            if target_role not in ("*", current_role):
                continue  # Policy does not apply to this user role

            # ── 2. Check tenant scoping ───────────────────────────────────────
            pol_tenant_id = pol.get("tenant_id")
            if pol_tenant_id and context.tenant_id:
                if str(pol_tenant_id) != str(context.tenant_id):
                    continue

            action = str(pol.get("action", "REDACT")).upper()
            pol_id = str(pol.get("id", "")) if pol.get("id") else None
            pol_name = str(pol.get("name", "Unnamed Policy"))
            max_threshold = float(pol.get("max_risk_threshold", 0.75))
            rules_config = pol.get("rules_config") or {}

            trig_reasons: List[str] = []

            # ── 3. Risk Threshold Check ───────────────────────────────────────
            if context.risk_score > max_threshold:
                trig_reasons.append(
                    f"Risk score {context.risk_score:.2f} exceeds policy threshold {max_threshold:.2f}"
                )

            # ── 4. Blocked Entity Types Check ─────────────────────────────────
            blocked_entities = rules_config.get("blocked_entities", [])
            if blocked_entities:
                blocked_set = {e.upper() for e in blocked_entities}
                matched_blocked = [
                    e for e in context.detected_entities if e.upper() in blocked_set
                ]
                if matched_blocked:
                    trig_reasons.append(
                        f"Detected prohibited entity types: {', '.join(matched_blocked)}"
                    )

            # ── 5. Prohibited Keywords Check ─────────────────────────────────
            prohibited_keywords = rules_config.get("prohibited_keywords", [])
            if prohibited_keywords and context.memory_text:
                lower_text = context.memory_text.lower()
                matched_kw = [
                    kw for kw in prohibited_keywords if kw.lower() in lower_text
                ]
                if matched_kw:
                    trig_reasons.append(
                        f"Found prohibited keywords: {', '.join(matched_kw)}"
                    )

            # ── 6. Prohibited Regex Patterns Check ─────────────────────────────
            prohibited_regexes = rules_config.get("prohibited_regexes", [])
            if prohibited_regexes and context.memory_text:
                for pat in prohibited_regexes:
                    try:
                        if re.search(pat, context.memory_text, re.IGNORECASE):
                            trig_reasons.append(
                                f"Matched prohibited pattern '{pat}'"
                            )
                            break
                    except re.error:
                        pass

            # ── 7. Max Text Length Check ──────────────────────────────────────
            max_length = rules_config.get("max_text_length")
            if max_length and len(context.memory_text) > int(max_length):
                trig_reasons.append(
                    f"Text length ({len(context.memory_text)}) exceeds limit ({max_length})"
                )

            # ── 8. Allowed Roles Check ────────────────────────────────────────
            allowed_roles = rules_config.get("allowed_roles")
            if allowed_roles:
                allowed_set = {r.lower() for r in allowed_roles}
                if current_role not in allowed_set:
                    trig_reasons.append(
                        f"Role '{current_role}' is not in allowed roles: {list(allowed_set)}"
                    )

            # If any rule condition triggered, record violation
            if trig_reasons:
                for reason in trig_reasons:
                    violations.append(
                        PolicyViolationDetail(
                            policy_id=pol_id,
                            policy_name=pol_name,
                            target_role=target_role,
                            action=action,
                            reason=reason,
                            risk_score=context.risk_score,
                        )
                    )
                if not driving_policy_name:
                    driving_policy_id = pol_id
                    driving_policy_name = pol_name

        # Determine final decision based on highest action priority among violations
        if violations:
            final_action = max(
                (v.action for v in violations),
                key=lambda a: self.ACTION_PRIORITY.get(a, 0),
            )
        else:
            final_action = "ALLOW"

        is_allowed = final_action not in ("BLOCK", "QUARANTINE")

        latency_ms = (time.perf_counter() - start_time) * 1000

        return PolicyEvaluationResult(
            decision=final_action,
            is_allowed=is_allowed,
            matched_policy_id=driving_policy_id,
            matched_policy_name=driving_policy_name,
            violations=violations,
            latency_ms=round(latency_ms, 3),
        )

    def _get_system_default_policies(self) -> List[Dict[str, Any]]:
        """Provides default fallback system policies when no tenant policies exist."""
        return [
            {
                "id": "def-admin-001",
                "name": "Default Admin Policy",
                "target_role": "admin",
                "action": "ALLOW",
                "priority_order": 10,
                "is_active": True,
                "is_default": True,
                "max_risk_threshold": 0.95,
                "rules_config": {},
            },
            {
                "id": "def-agent-002",
                "name": "Default Agent Exfiltration Policy",
                "target_role": "agent",
                "action": "BLOCK",
                "priority_order": 15,
                "is_active": True,
                "is_default": True,
                "max_risk_threshold": 0.50,
                "rules_config": {
                    "blocked_entities": [
                        "AWS_KEY",
                        "API_KEY",
                        "PRIVATE_KEY",
                        "PROMPT_INJECTION",
                    ]
                },
            },

            {
                "id": "def-user-003",
                "name": "Default User PII Policy",
                "target_role": "user",
                "action": "REDACT",
                "priority_order": 50,
                "is_active": True,
                "is_default": True,
                "max_risk_threshold": 0.70,
                "rules_config": {},
            },
            {
                "id": "def-global-004",
                "name": "Strict Quarantine Policy",
                "target_role": "*",
                "action": "QUARANTINE",
                "priority_order": 20,
                "is_active": True,
                "is_default": True,
                "max_risk_threshold": 0.92,   # Only trigger on truly critical multi-entity content
                "rules_config": {
                    "blocked_entities": ["PROMPT_INJECTION"]
                },
            },
        ]
