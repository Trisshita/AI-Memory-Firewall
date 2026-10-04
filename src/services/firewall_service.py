"""
AI Memory Firewall - Firewall Service
======================================
Orchestrates the full firewall pipeline:
  1. Load active tenant FirewallRules from the database.
  2. Delegate to FirewallEvaluator for multi-stage inspection.
  3. Persist a sanitized MemoryRecord (quarantining if needed).
  4. Write an immutable SecurityAuditEvent to the audit log.
  5. Append a chain entry to the global SHA-256 hash chain (Week 6).
     High-risk events (risk_score >= 0.8) also auto-raise a SecurityAlert.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from src.engine.audit_logger import AuditLogger  # Week 6
from src.engine.evaluator import EvaluationResult, FirewallEvaluator
from src.models.agent import AgentSession, Tenant
from src.models.audit import AuditEventType, SecurityAuditEvent, ViolationStatus  # Week 6
from src.models.memory import MemoryRecord, MemoryType, SensitivityLevel
from src.models.policy import FirewallRule, RuleAction

_evaluator = FirewallEvaluator()
_audit_logger = AuditLogger()  # Week 6: Global hash-chain logger


def _sha256(text: str) -> str:
    """Compute a SHA-256 hex digest of the given text."""
    return hashlib.sha256(text.encode("utf-8")).digest().hex()


def _map_decision_to_violation_status(decision: str) -> ViolationStatus:
    """Map evaluator decision string to ViolationStatus enum value."""
    return {
        "ALLOW": ViolationStatus.FALSE_POSITIVE,
        "REDACT": ViolationStatus.MITIGATED,
        "BLOCK": ViolationStatus.BLOCKED,
        "QUARANTINE": ViolationStatus.DETECTED,
        "AUDIT": ViolationStatus.FLAGGED_FOR_REVIEW,
    }.get(decision, ViolationStatus.DETECTED)


def load_active_rules(db: Session, tenant_id: UUID) -> List[Dict[str, Any]]:
    """
    Fetch all active FirewallRules for a tenant, ordered by priority_order ASC.

    Args:
        db:        SQLAlchemy synchronous session.
        tenant_id: UUID of the target tenant.

    Returns:
        List of rule dicts compatible with FirewallEvaluator.evaluate(db_rules=...).
    """
    rules: List[FirewallRule] = (
        db.query(FirewallRule)
        .filter(
            FirewallRule.tenant_id == tenant_id,
            FirewallRule.is_active.is_(True),
        )
        .order_by(FirewallRule.priority_order.asc())
        .all()
    )
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "rule_type": r.rule_type.value if hasattr(r.rule_type, "value") else r.rule_type,
            "pattern_payload": r.pattern_payload,
            "action": r.action.value if hasattr(r.action, "value") else r.action,
            "severity": r.severity,
            "priority_order": r.priority_order,
        }
        for r in rules
    ]


def inspect_text(
    db: Session,
    tenant_id: UUID,
    text: str,
    session_id: Optional[UUID] = None,
) -> EvaluationResult:
    """
    Run a pure inspection pass on text without persisting anything to the database.

    Useful for real-time prompt screening before any memory operation.

    Args:
        db:         SQLAlchemy synchronous session.
        tenant_id:  UUID of the tenant whose rules to apply.
        text:       Raw text to inspect.
        session_id: Optional context session UUID (not used for storage here).

    Returns:
        EvaluationResult with decision, sanitized text, violations, and risk score.
    """
    db_rules = load_active_rules(db, tenant_id)
    return _evaluator.evaluate(text, db_rules=db_rules)


def store_memory(
    db: Session,
    tenant_id: UUID,
    session_id: UUID,
    text: str,
    memory_type: str = "SHORT_TERM",
    sensitivity_tier: str = "INTERNAL",
    metadata: Optional[Dict[str, Any]] = None,
    client_ip: Optional[str] = None,
) -> tuple[MemoryRecord, EvaluationResult]:
    """
    Inspect text through the full firewall pipeline and persist a MemoryRecord + AuditEvent.

    Decision outcomes:
      - ALLOW / REDACT / AUDIT  → Save the sanitized memory normally.
      - QUARANTINE / BLOCK      → Save the memory record flagged as quarantined
                                  so the agent cannot recall it.

    Args:
        db:               SQLAlchemy synchronous session.
        tenant_id:        UUID of the owning tenant.
        session_id:       UUID of the owning agent session.
        text:             Raw text to store.
        memory_type:      Functional memory category (SHORT_TERM, EPISODIC, etc.).
        sensitivity_tier: Classification tier (INTERNAL, CONFIDENTIAL, etc.).
        metadata:         Optional dict of extra metadata for the memory record.
        client_ip:        IP address of the originating request (for audit trail).

    Returns:
        Tuple of (MemoryRecord, EvaluationResult).
    """
    db_rules = load_active_rules(db, tenant_id)
    result: EvaluationResult = _evaluator.evaluate(text, db_rules=db_rules)

    # Determine quarantine status
    is_quarantined = result.decision in ("QUARANTINE", "BLOCK")
    quarantine_reason: Optional[str] = None
    if is_quarantined and result.violations:
        quarantine_reason = "; ".join(
            f"{v.rule_type}: {v.rule_name}" for v in result.violations[:3]
        )

    # Map type / tier strings to enum values safely
    try:
        mem_type = MemoryType(memory_type)
    except ValueError:
        mem_type = MemoryType.SHORT_TERM

    try:
        sens_tier = SensitivityLevel(sensitivity_tier)
    except ValueError:
        sens_tier = SensitivityLevel.INTERNAL

    # Build and persist the MemoryRecord
    memory = MemoryRecord(
        session_id=session_id,
        memory_type=mem_type,
        sensitivity_tier=sens_tier,
        raw_content=text[:5000],           # Truncate to DB column limit
        sanitized_content=result.sanitized_text[:5000],
        content_hash=_sha256(text),
        is_quarantined=is_quarantined,
        quarantine_reason=quarantine_reason,
        metadata_json=metadata,
    )
    db.add(memory)
    db.flush()   # Assigns memory.id without committing yet

    # Build audit payload
    detected_entities: Dict[str, Any] = {
        "pii_types": [p.pii_type.value for p in result.pii_matches],
        "injection_categories": [i.category.value for i in result.injection_matches],
        "violation_count": len(result.violations),
    }

    # Determine which rule_id to attribute (first matching custom rule, if any)
    rule_id: Optional[UUID] = None
    for v in result.violations:
        if v.rule_id:
            try:
                rule_id = UUID(v.rule_id)
                break
            except (ValueError, AttributeError):
                pass

    # Write the immutable SecurityAuditEvent
    audit = SecurityAuditEvent(
        tenant_id=tenant_id,
        session_id=session_id,
        rule_id=rule_id,
        action_taken=result.decision,
        violation_status=_map_decision_to_violation_status(result.decision),
        risk_score=result.risk_score,
        original_snippet=text[:500] if text else None,
        sanitized_snippet=result.sanitized_text[:500] if result.sanitized_text else None,
        detected_entities=detected_entities,
        latency_ms=result.latency_ms,
        client_ip=client_ip,
    )
    db.add(audit)
    db.flush()  # Get audit.id before chain entry

    # ── Week 6: Append to global hash chain ──────────────────────────────────
    # Determine severity for chain entry based on risk score
    if result.risk_score >= 0.90:
        chain_severity = "CRITICAL"
    elif result.risk_score >= 0.80:
        chain_severity = "HIGH"
    elif result.risk_score >= 0.50:
        chain_severity = "MEDIUM"
    elif result.risk_score > 0.0:
        chain_severity = "LOW"
    else:
        chain_severity = "INFO"

    chain_payload: Dict[str, Any] = {
        "decision": result.decision,
        "risk_score": result.risk_score,
        "violation_count": len(result.violations),
        "latency_ms": result.latency_ms,
        "detected_entities": detected_entities,
        "session_id": str(session_id),
    }
    if client_ip:
        chain_payload["client_ip"] = client_ip

    _audit_logger.log_event(
        db=db,
        action="memory.store",
        event_type=AuditEventType.FIREWALL_EVAL.value,
        severity=chain_severity,
        tenant_id=str(tenant_id),
        actor=client_ip or "unknown",
        resource=str(session_id),
        payload=chain_payload,
        event_id=str(audit.id),
        raise_alert_if_high_risk=True,  # auto-alert when risk_score >= 0.8
    )

    db.commit()
    db.refresh(memory)

    return memory, result


def get_session_memories(
    db: Session,
    session_id: UUID,
    include_quarantined: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> List[MemoryRecord]:
    """
    Retrieve memory records for an agent session.

    Args:
        db:                  SQLAlchemy synchronous session.
        session_id:          UUID of the target agent session.
        include_quarantined: If False (default), quarantined memories are excluded
                             so agents cannot recall dangerous content.
        limit:               Maximum records to return (default 100).
        offset:              Pagination offset.

    Returns:
        List of MemoryRecord instances.
    """
    q = db.query(MemoryRecord).filter(MemoryRecord.session_id == session_id)
    if not include_quarantined:
        q = q.filter(MemoryRecord.is_quarantined.is_(False))
    return q.order_by(MemoryRecord.created_at.desc()).offset(offset).limit(limit).all()


def create_firewall_rule(
    db: Session,
    tenant_id: UUID,
    name: str,
    rule_type: str,
    pattern_payload: str,
    action: str = "AUDIT",
    severity: str = "MEDIUM",
    priority_order: int = 100,
    description: Optional[str] = None,
    is_active: bool = True,
    rule_config: Optional[Dict[str, Any]] = None,
) -> FirewallRule:
    """Create and persist a new custom FirewallRule for a tenant."""
    from src.models.policy import RuleAction, RuleType  # avoid circular imports
    try:
        rt = RuleType(rule_type)
    except ValueError:
        rt = RuleType.KEYWORD_FILTER

    try:
        ra = RuleAction(action)
    except ValueError:
        ra = RuleAction.AUDIT

    rule = FirewallRule(
        tenant_id=tenant_id,
        name=name,
        description=description,
        rule_type=rt,
        pattern_payload=pattern_payload,
        action=ra,
        severity=severity,
        priority_order=priority_order,
        is_active=is_active,
        rule_config=rule_config,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def get_audit_events(
    db: Session,
    tenant_id: UUID,
    limit: int = 50,
    offset: int = 0,
    min_risk_score: Optional[float] = None,
) -> List[SecurityAuditEvent]:
    """
    Retrieve security audit events for a tenant.

    Args:
        db:            SQLAlchemy synchronous session.
        tenant_id:     UUID of the target tenant.
        limit:         Maximum events to return.
        offset:        Pagination offset.
        min_risk_score: If provided, only return events at or above this risk score.

    Returns:
        List of SecurityAuditEvent instances, newest first.
    """
    q = db.query(SecurityAuditEvent).filter(SecurityAuditEvent.tenant_id == tenant_id)
    if min_risk_score is not None:
        q = q.filter(SecurityAuditEvent.risk_score >= min_risk_score)
    return q.order_by(SecurityAuditEvent.created_at.desc()).offset(offset).limit(limit).all()
