"""
AI Memory Firewall - Admin Policy Management Endpoints
======================================================
API routes for CRUD operations on SecurityPolicy entities, default policy seeding,
and direct policy engine evaluation testing. Mounted at /api/v1/admin/policies.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.api.deps import require_admin
from src.engine.policy_engine import PolicyEngine, PolicyEvaluationContext
from src.models.policy import RuleAction
from src.schemas.policy import (
    CreatePolicyRequest,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    PolicyListResponse,
    PolicyResponse,
    UpdatePolicyRequest,
)
from src.services import policy_service

router = APIRouter(prefix="/admin/policies", tags=["Admin Policies"], dependencies=[Depends(require_admin)])


@router.get(
    "",
    response_model=PolicyListResponse,
    summary="List Security Policies",
    description="Returns list of configured security policies with optional filtering by tenant or role.",
)
def list_policies(
    tenant_id: Optional[UUID] = Query(default=None, description="Filter by tenant ID."),
    target_role: Optional[str] = Query(default=None, description="Filter by target user role."),
    active_only: bool = Query(default=False, description="Returns active policies only if true."),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
) -> PolicyListResponse:
    policies = policy_service.list_security_policies(
        db=db,
        tenant_id=tenant_id,
        target_role=target_role,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    return PolicyListResponse(
        total=len(policies),
        policies=[PolicyResponse.model_validate(p) for p in policies],
    )


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Security Policy",
    description="Creates a new security policy rule governing RBAC and risk limits.",
)
def create_policy(
    payload: CreatePolicyRequest,
    db: Session = Depends(get_sync_db),
) -> PolicyResponse:
    try:
        action_enum = RuleAction(payload.action.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{payload.action}'. Must be one of ALLOW, REDACT, BLOCK, QUARANTINE, AUDIT.",
        )

    policy = policy_service.create_security_policy(
        db=db,
        name=payload.name,
        description=payload.description,
        target_role=payload.target_role,
        action=action_enum,
        priority_order=payload.priority_order,
        max_risk_threshold=payload.max_risk_threshold,
        tenant_id=payload.tenant_id,
        is_active=payload.is_active,
        rules_config=payload.rules_config,
    )
    return PolicyResponse.model_validate(policy)


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Get Policy Details",
    description="Retrieves a specific security policy by UUID.",
)
def get_policy(
    policy_id: UUID,
    db: Session = Depends(get_sync_db),
) -> PolicyResponse:
    policy = policy_service.get_security_policy(db=db, policy_id=policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy with ID '{policy_id}' not found.",
        )
    return PolicyResponse.model_validate(policy)


@router.put(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Update Security Policy",
    description="Modifies parameters of an existing security policy.",
)
def update_policy(
    policy_id: UUID,
    payload: UpdatePolicyRequest,
    db: Session = Depends(get_sync_db),
) -> PolicyResponse:
    update_data = payload.model_dump(exclude_unset=True)
    if "action" in update_data and update_data["action"]:
        try:
            update_data["action"] = RuleAction(update_data["action"].upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action '{update_data['action']}'. Must be one of ALLOW, REDACT, BLOCK, QUARANTINE, AUDIT.",
            )

    policy = policy_service.update_security_policy(db=db, policy_id=policy_id, **update_data)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy with ID '{policy_id}' not found.",
        )
    return PolicyResponse.model_validate(policy)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Security Policy",
    description="Deletes a security policy by UUID.",
)
def delete_policy(
    policy_id: UUID,
    db: Session = Depends(get_sync_db),
) -> None:
    deleted = policy_service.delete_security_policy(db=db, policy_id=policy_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy with ID '{policy_id}' not found.",
        )


@router.post(
    "/seed",
    response_model=PolicyListResponse,
    summary="Seed Default Policies",
    description="Populates out-of-the-box system default security policies.",
)
def seed_policies(
    db: Session = Depends(get_sync_db),
) -> PolicyListResponse:
    policies = policy_service.seed_default_policies(db=db)
    return PolicyListResponse(
        total=len(policies),
        policies=[PolicyResponse.model_validate(p) for p in policies],
    )


@router.post(
    "/evaluate",
    response_model=PolicyEvaluationResponse,
    summary="Evaluate Policies against Context",
    description="Runs the PolicyEngine against active database policies for testing/simulation.",
)
def evaluate_policies(
    payload: PolicyEvaluationRequest,
    db: Session = Depends(get_sync_db),
) -> PolicyEvaluationResponse:
    # Load policies from DB
    db_policies = policy_service.list_security_policies(
        db=db, tenant_id=payload.tenant_id, active_only=True
    )
    policy_dicts = [
        {
            "id": str(p.id),
            "name": p.name,
            "target_role": p.target_role,
            "action": p.action.value,
            "priority_order": p.priority_order,
            "is_active": p.is_active,
            "is_default": p.is_default,
            "max_risk_threshold": p.max_risk_threshold,
            "rules_config": p.rules_config or {},
            "tenant_id": str(p.tenant_id) if p.tenant_id else None,
        }
        for p in db_policies
    ]

    ctx = PolicyEvaluationContext(
        user_role=payload.user_role,
        tenant_id=str(payload.tenant_id) if payload.tenant_id else None,
        memory_text=payload.memory_text,
        requested_action=payload.requested_action,
        risk_score=payload.risk_score,
        detected_entities=payload.detected_entities,
    )

    engine = PolicyEngine()
    result = engine.evaluate_policies(context=ctx, policies=policy_dicts if policy_dicts else None)

    return PolicyEvaluationResponse(
        decision=result.decision,
        is_allowed=result.is_allowed,
        matched_policy_id=result.matched_policy_id,
        matched_policy_name=result.matched_policy_name,
        violations_count=len(result.violations),
        violations=[
            {
                "policy_id": v.policy_id,
                "policy_name": v.policy_name,
                "target_role": v.target_role,
                "action": v.action,
                "reason": v.reason,
                "risk_score": v.risk_score,
            }
            for v in result.violations
        ],
        latency_ms=result.latency_ms,
    )
