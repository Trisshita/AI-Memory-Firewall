"""
AI Memory Firewall - Audit Service (Week 6)
===========================================
Database query orchestration for the tamper-proof hash-chain audit log
and security alert management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from src.models.audit import AuditLogEntry, SecurityAlert


def get_chain_entries(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    tenant_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    from_dt: Optional[datetime] = None,
    to_dt: Optional[datetime] = None,
) -> List[AuditLogEntry]:
    """
    Retrieve global chain entries with optional filtering.

    Args:
        db:         SQLAlchemy synchronous session.
        limit:      Maximum entries to return (default 50, max 500).
        offset:     Pagination offset.
        tenant_id:  If provided, filter to entries from this tenant only.
        event_type: If provided, filter by event_type string.
        severity:   If provided, filter by severity string.
        from_dt:    If provided, return only entries created >= from_dt.
        to_dt:      If provided, return only entries created <= to_dt.

    Returns:
        List of AuditLogEntry instances, newest first.
    """
    q = db.query(AuditLogEntry)

    if tenant_id is not None:
        q = q.filter(AuditLogEntry.tenant_id == tenant_id)
    if event_type:
        q = q.filter(AuditLogEntry.event_type == event_type)
    if severity:
        q = q.filter(AuditLogEntry.severity == severity)
    if from_dt:
        q = q.filter(AuditLogEntry.created_at >= from_dt)
    if to_dt:
        q = q.filter(AuditLogEntry.created_at <= to_dt)

    return (
        q.order_by(AuditLogEntry.sequence_number.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_chain_length(db: Session) -> int:
    """Return the total count of entries in the global chain."""
    return db.query(AuditLogEntry).count()


def get_alerts(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    tenant_id: Optional[UUID] = None,
    is_resolved: Optional[bool] = None,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> List[SecurityAlert]:
    """
    Retrieve security alerts with optional filtering.

    Tiered access note:
      - Authenticated users: can query their own tenant's alerts.
      - Admins: can query all alerts (pass tenant_id=None to see all).

    Args:
        db:          SQLAlchemy synchronous session.
        limit:       Maximum alerts to return.
        offset:      Pagination offset.
        tenant_id:   Filter to this tenant's alerts.
        is_resolved: If provided, filter by resolution status.
        severity:    If provided, filter by severity string.
        alert_type:  If provided, filter by alert_type string.

    Returns:
        List of SecurityAlert instances, newest first.
    """
    q = db.query(SecurityAlert)

    if tenant_id is not None:
        q = q.filter(SecurityAlert.tenant_id == tenant_id)
    if is_resolved is not None:
        q = q.filter(SecurityAlert.is_resolved == is_resolved)
    if severity:
        q = q.filter(SecurityAlert.severity == severity)
    if alert_type:
        q = q.filter(SecurityAlert.alert_type == alert_type)

    return (
        q.order_by(SecurityAlert.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def count_unresolved_alerts(
    db: Session,
    tenant_id: Optional[UUID] = None,
) -> int:
    """Count unresolved alerts, optionally scoped to a tenant."""
    q = db.query(SecurityAlert).filter(SecurityAlert.is_resolved.is_(False))
    if tenant_id is not None:
        q = q.filter(SecurityAlert.tenant_id == tenant_id)
    return q.count()


def resolve_alert(
    db: Session,
    alert_id: UUID,
) -> Optional[SecurityAlert]:
    """
    Mark a security alert as resolved.

    Args:
        db:       SQLAlchemy synchronous session.
        alert_id: UUID of the alert to resolve.

    Returns:
        The updated SecurityAlert, or None if not found.
    """
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        return None

    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert
