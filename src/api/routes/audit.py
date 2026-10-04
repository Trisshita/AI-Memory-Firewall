"""
AI Memory Firewall - Audit API Routes (Week 6)
===============================================
Provides tamper-proof audit trail and hash-chain verification endpoints.

Tiered access model:
  - Any authenticated user (Bearer JWT or API key):
      GET  /api/v1/audit/events           — legacy event log (existing)
      GET  /api/v1/audit/logs             — hash-chain entries (Week 6)
      GET  /api/v1/audit/verify           — chain integrity verification (Week 6)
      GET  /api/v1/audit/alerts           — security alerts (own tenant only)
  - Admin role required:
      PUT  /api/v1/audit/alerts/{id}/resolve  — resolve a security alert
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.api.deps import require_admin, require_user
from src.engine.audit_logger import AuditLogger, ChainVerificationResult
from src.schemas.audit import (
    AuditLogEntryResponse,
    AuditLogListResponse,
    AuditSummaryResponse,
    ChainVerificationResponse,
    ResolveAlertResponse,
    SecurityAlertListResponse,
    SecurityAlertResponse,
)
from src.schemas.policy import AuditEventListResponse, AuditEventResponse
from src.services import audit_service, firewall_service

router = APIRouter(prefix="/audit", tags=["Audit"])
_audit_logger = AuditLogger()


@router.get(
    "/summary",
    response_model=AuditSummaryResponse,
    summary="Get Aggregated System Dashboard Summary",
    description="Returns aggregate counts of events, blocked threats, active alerts, memories, and hash chain status.",
)
def get_audit_summary(
    tenant_id: Optional[UUID] = Query(default=None, description="Optional tenant ID filter."),
    db: Session = Depends(get_sync_db),
) -> AuditSummaryResponse:
    from src.models.audit import AuditLogEntry, SecurityAlert, SecurityAuditEvent
    from src.models.decision import DecisionStatus, UserDecision
    from src.models.memory import MemoryRecord

    ev_q = db.query(SecurityAuditEvent)
    if tenant_id:
        ev_q = ev_q.filter(SecurityAuditEvent.tenant_id == tenant_id)
    total_events = ev_q.count()
    total_blocked = ev_q.filter(SecurityAuditEvent.action_taken.in_(["BLOCK", "QUARANTINE"])).count()

    mem_q = db.query(MemoryRecord)
    total_memories = mem_q.count()
    quarantined_memories = mem_q.filter(MemoryRecord.is_quarantined.is_(True)).count()

    alt_q = db.query(SecurityAlert).filter(SecurityAlert.is_resolved.is_(False))
    if tenant_id:
        alt_q = alt_q.filter(SecurityAlert.tenant_id == tenant_id)
    active_alerts = alt_q.count()

    chain_length = db.query(AuditLogEntry).count()

    dec_q = db.query(UserDecision).filter(UserDecision.status == DecisionStatus.PENDING)
    if tenant_id:
        dec_q = dec_q.filter(UserDecision.tenant_id == tenant_id)
    pending_decisions = dec_q.count()

    # Quick verify
    verification = _audit_logger.verify_chain(db)

    return AuditSummaryResponse(
        total_events=total_events,
        total_blocked=total_blocked,
        total_memories=total_memories,
        quarantined_memories=quarantined_memories,
        active_alerts=active_alerts,
        chain_length=chain_length,
        pending_decisions=pending_decisions,
        is_chain_valid=verification.is_valid,
    )


# ─── Existing endpoint (Weeks 1-5) ───────────────────────────────────────────

@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="Query Security Audit Events",
    description=(
        "Returns the immutable security audit trail for a tenant. "
        "Each event records a firewall evaluation: action taken, risk score, violation details, "
        "and latency. Supports filtering by minimum risk score for high-priority incident review."
    ),
)
def get_audit_events(
    tenant_id: UUID = Query(..., description="UUID of the tenant whose audit events to retrieve."),
    min_risk_score: Optional[float] = Query(
        default=None,
        ge=0.0,
        le=1.0,
        description="Filter: only return events with risk_score >= this value.",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
    _current_user=Depends(require_user),
) -> AuditEventListResponse:
    """Retrieve security audit events for a tenant."""
    events = firewall_service.get_audit_events(
        db=db,
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
        min_risk_score=min_risk_score,
    )

    return AuditEventListResponse(
        tenant_id=tenant_id,
        total=len(events),
        events=[AuditEventResponse.model_validate(e) for e in events],
    )


# ─── Week 6: Hash-chain log ───────────────────────────────────────────────────

@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Query Tamper-Proof Hash-Chain Audit Log",
    description=(
        "Returns entries from the global SHA-256 hash chain. "
        "Each entry is cryptographically linked to the previous one. "
        "Supports filtering by tenant, event_type, severity, and date range. "
        "Results are newest-first. Use GET /audit/verify to confirm chain integrity."
    ),
)
def get_audit_logs(
    tenant_id: Optional[UUID] = Query(
        default=None,
        description="Filter entries to this tenant only. Omit to see all (admin-level view).",
    ),
    event_type: Optional[str] = Query(
        default=None,
        description="Filter by event type: FIREWALL_EVAL | AUTH_EVENT | POLICY_CHANGE | SECURITY_ALERT | SYSTEM",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: INFO | LOW | MEDIUM | HIGH | CRITICAL",
    ),
    from_dt: Optional[datetime] = Query(
        default=None,
        description="Return entries created on or after this ISO-8601 datetime.",
    ),
    to_dt: Optional[datetime] = Query(
        default=None,
        description="Return entries created on or before this ISO-8601 datetime.",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
    _current_user=Depends(require_user),
) -> AuditLogListResponse:
    """Retrieve entries from the global tamper-proof hash chain."""
    entries = audit_service.get_chain_entries(
        db=db,
        limit=limit,
        offset=offset,
        tenant_id=tenant_id,
        event_type=event_type,
        severity=severity,
        from_dt=from_dt,
        to_dt=to_dt,
    )
    chain_length = audit_service.get_chain_length(db)

    return AuditLogListResponse(
        total=len(entries),
        chain_length=chain_length,
        entries=[AuditLogEntryResponse.model_validate(e) for e in entries],
    )


# ─── Week 6: Chain verification ───────────────────────────────────────────────

@router.get(
    "/verify",
    response_model=ChainVerificationResponse,
    summary="Verify Hash-Chain Integrity",
    description=(
        "Runs a full integrity scan of the global SHA-256 audit hash chain. "
        "Re-computes every entry_hash from stored content + previous_hash. "
        "Returns is_valid=true only if every hash matches. "
        "Any mismatch indicates retroactive tampering. "
        "A CRITICAL alert is automatically raised if tampering is detected."
    ),
)
def verify_audit_chain(
    raise_alert: bool = Query(
        default=True,
        description="If true, auto-raise a CHAIN_TAMPER CRITICAL alert when tampering is detected.",
    ),
    db: Session = Depends(get_sync_db),
    _current_user=Depends(require_user),
) -> ChainVerificationResponse:
    """Run full SHA-256 hash-chain integrity verification."""
    result: ChainVerificationResult = _audit_logger.verify_chain(
        db=db,
        raise_alert_on_tamper=raise_alert,
    )

    if result.is_valid:
        message = (
            f"Chain integrity confirmed. All {result.total_entries} "
            f"entr{'y' if result.total_entries == 1 else 'ies'} verified successfully."
        )
    else:
        message = (
            f"TAMPER DETECTED: {len(result.broken_entries)} "
            f"entr{'y' if len(result.broken_entries) == 1 else 'ies'} failed hash verification. "
            f"First broken at sequence #{result.first_broken_sequence}."
        )

    return ChainVerificationResponse(
        is_valid=result.is_valid,
        total_entries=result.total_entries,
        first_broken_sequence=result.first_broken_sequence,
        broken_entries=result.broken_entries,
        verification_time_ms=result.verification_time_ms,
        message=message,
    )


# ─── Week 6: Security alerts ──────────────────────────────────────────────────

@router.get(
    "/alerts",
    response_model=SecurityAlertListResponse,
    summary="List Security Alerts",
    description=(
        "Returns auto-generated security alerts for anomalous events. "
        "Authenticated users see alerts for their tenant. "
        "Supports filtering by resolution status, severity, and alert type."
    ),
)
def get_security_alerts(
    tenant_id: Optional[UUID] = Query(
        default=None,
        description="Filter to this tenant's alerts. Admins may omit to see all.",
    ),
    is_resolved: Optional[bool] = Query(
        default=None,
        description="Filter: true = resolved only, false = unresolved only, omit = all.",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: LOW | MEDIUM | HIGH | CRITICAL",
    ),
    alert_type: Optional[str] = Query(
        default=None,
        description="Filter by alert type: CHAIN_TAMPER | HIGH_RISK_EVENT | AUTH_ANOMALY | POLICY_VIOLATION",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
    _current_user=Depends(require_user),
) -> SecurityAlertListResponse:
    """Retrieve security alerts with optional filtering."""
    alerts = audit_service.get_alerts(
        db=db,
        limit=limit,
        offset=offset,
        tenant_id=tenant_id,
        is_resolved=is_resolved,
        severity=severity,
        alert_type=alert_type,
    )
    unresolved = audit_service.count_unresolved_alerts(db=db, tenant_id=tenant_id)

    return SecurityAlertListResponse(
        total=len(alerts),
        unresolved_count=unresolved,
        alerts=[SecurityAlertResponse.model_validate(a) for a in alerts],
    )


@router.put(
    "/alerts/{alert_id}/resolve",
    response_model=ResolveAlertResponse,
    summary="Resolve a Security Alert",
    description=(
        "Mark a security alert as resolved (admin only). "
        "Sets is_resolved=true and records resolved_at timestamp. "
        "Resolved alerts are excluded from the default unresolved alert view."
    ),
)
def resolve_security_alert(
    alert_id: UUID = Path(..., description="UUID of the security alert to resolve."),
    db: Session = Depends(get_sync_db),
    _current_admin=Depends(require_admin),
) -> ResolveAlertResponse:
    """Resolve a security alert (admin only)."""
    alert = audit_service.resolve_alert(db=db, alert_id=alert_id)

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )

    return ResolveAlertResponse(
        id=alert.id,
        is_resolved=alert.is_resolved,
        resolved_at=alert.resolved_at,
        message=f"Alert '{alert_id}' has been resolved successfully.",
    )

