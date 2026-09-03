"""
AI Memory Firewall - Firewall Rules Management Routes
=====================================================
POST /api/v1/rules           — Create a new custom firewall rule
GET  /api/v1/rules/{tenant_id} — List all rules for a tenant
"""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.schemas.policy import (
    CreateRuleRequest,
    FirewallRuleListResponse,
    FirewallRuleResponse,
)
from src.services import firewall_service

router = APIRouter(prefix="/rules", tags=["Rules"])


@router.post(
    "",
    response_model=FirewallRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Firewall Rule",
    description=(
        "Creates a new custom security rule for a tenant. "
        "Rules are evaluated in priority order (lower number first) against incoming memory content. "
        "Supported rule types: REGEX_PATTERN, KEYWORD_FILTER, PII_DETECTION, PROMPT_INJECTION, "
        "DATA_EXFILTRATION, SEMANTIC_SIMILARITY."
    ),
)
def create_rule(
    payload: CreateRuleRequest,
    db: Session = Depends(get_sync_db),
) -> FirewallRuleResponse:
    """Create a custom firewall rule for a tenant."""
    rule = firewall_service.create_firewall_rule(
        db=db,
        tenant_id=payload.tenant_id,
        name=payload.name,
        rule_type=payload.rule_type,
        pattern_payload=payload.pattern_payload,
        action=payload.action,
        severity=payload.severity,
        priority_order=payload.priority_order,
        description=payload.description,
        is_active=payload.is_active,
        rule_config=payload.rule_config,
    )
    return FirewallRuleResponse.model_validate(rule)


@router.get(
    "/{tenant_id}",
    response_model=FirewallRuleListResponse,
    summary="List Tenant Firewall Rules",
    description="Returns all firewall rules configured for the specified tenant, ordered by priority.",
)
def list_rules(
    tenant_id: UUID,
    active_only: bool = Query(default=False, description="If true, returns only active rules."),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
) -> FirewallRuleListResponse:
    """List firewall rules for a tenant."""
    from src.models.policy import FirewallRule

    q = db.query(FirewallRule).filter(FirewallRule.tenant_id == tenant_id)
    if active_only:
        q = q.filter(FirewallRule.is_active.is_(True))
    rules = q.order_by(FirewallRule.priority_order.asc()).offset(offset).limit(limit).all()

    return FirewallRuleListResponse(
        tenant_id=tenant_id,
        total=len(rules),
        rules=[FirewallRuleResponse.model_validate(r) for r in rules],
    )
