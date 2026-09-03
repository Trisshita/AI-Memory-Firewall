"""
AI Memory Firewall - Security Audit Events Route
================================================
GET /api/v1/audit/events — Query the immutable security audit log
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.schemas.policy import AuditEventListResponse, AuditEventResponse
from src.services import firewall_service

router = APIRouter(prefix="/audit", tags=["Audit"])


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
