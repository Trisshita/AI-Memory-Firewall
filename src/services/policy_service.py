"""
AI Memory Firewall - Policy Service
===================================
Database operations and business logic for managing SecurityPolicy entities
and seeding default RBAC and data protection policies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from src.models.policy import RuleAction, SecurityPolicy


def create_security_policy(
    db: Session,
    name: str,
    target_role: str = "*",
    action: RuleAction = RuleAction.REDACT,
    priority_order: int = 50,
    max_risk_threshold: float = 0.75,
    description: Optional[str] = None,
    tenant_id: Optional[UUID] = None,
    is_active: bool = True,
    is_default: bool = False,
    rules_config: Optional[Dict[str, Any]] = None,
) -> SecurityPolicy:
    """Create a new SecurityPolicy entity."""
    policy = SecurityPolicy(
        tenant_id=tenant_id,
        name=name,
        description=description,
        target_role=target_role.lower(),
        action=action,
        priority_order=priority_order,
        is_active=is_active,
        is_default=is_default,
        max_risk_threshold=max_risk_threshold,
        rules_config=rules_config or {},
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def get_security_policy(db: Session, policy_id: UUID) -> Optional[SecurityPolicy]:
    """Fetch a SecurityPolicy by its primary key ID."""
    return db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()


def list_security_policies(
    db: Session,
    tenant_id: Optional[UUID] = None,
    target_role: Optional[str] = None,
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> List[SecurityPolicy]:
    """Retrieve security policies with optional tenant, role, and active status filters."""
    query = db.query(SecurityPolicy)
    if tenant_id:
        # Include tenant-specific OR global policies (where tenant_id is NULL)
        query = query.filter(
            (SecurityPolicy.tenant_id == tenant_id) | (SecurityPolicy.tenant_id.is_(None))
        )
    if target_role:
        query = query.filter(
            (SecurityPolicy.target_role == target_role.lower()) | (SecurityPolicy.target_role == "*")
        )
    if active_only:
        query = query.filter(SecurityPolicy.is_active.is_(True))

    return query.order_by(SecurityPolicy.priority_order.asc()).offset(offset).limit(limit).all()


def update_security_policy(
    db: Session,
    policy_id: UUID,
    **kwargs: Any,
) -> Optional[SecurityPolicy]:
    """Update fields of an existing SecurityPolicy."""
    policy = get_security_policy(db, policy_id)
    if not policy:
        return None

    for key, value in kwargs.items():
        if value is not None and hasattr(policy, key):
            if key == "target_role" and isinstance(value, str):
                value = value.lower()
            setattr(policy, key, value)

    db.commit()
    db.refresh(policy)
    return policy


def delete_security_policy(db: Session, policy_id: UUID) -> bool:
    """Delete a SecurityPolicy by ID."""
    policy = get_security_policy(db, policy_id)
    if not policy:
        return False

    db.delete(policy)
    db.commit()
    return True


def seed_default_policies(db: Session) -> List[SecurityPolicy]:
    """
    Idempotent seeding of standard out-of-the-box system default policies.
    Returns list of seeded SecurityPolicy objects.
    """
    defaults = [
        {
            "name": "Default Admin Policy",
            "description": "High-trust administrative access policy with wide risk tolerance.",
            "target_role": "admin",
            "action": RuleAction.ALLOW,
            "priority_order": 10,
            "max_risk_threshold": 0.95,
            "is_default": True,
            "rules_config": {},
        },
        {
            "name": "Strict Quarantine Policy",
            "description": "Global quarantine policy for high-risk prompt injection threats.",
            "target_role": "*",
            "action": RuleAction.QUARANTINE,
            "priority_order": 20,
            "max_risk_threshold": 0.85,
            "is_default": True,
            "rules_config": {"blocked_entities": ["PROMPT_INJECTION"]},
        },
        {
            "name": "Default Agent Exfiltration Policy",
            "description": "Prevents AI agents from leaking API keys, private keys, or cloud credentials.",
            "target_role": "agent",
            "action": RuleAction.BLOCK,
            "priority_order": 15,
            "max_risk_threshold": 0.50,
            "is_default": True,
            "rules_config": {
                "blocked_entities": ["AWS_KEY", "API_KEY", "PRIVATE_KEY", "PROMPT_INJECTION"]
            },
        },

        {
            "name": "Default User PII Policy",
            "description": "Standard user policy redacting sensitive PII entities.",
            "target_role": "user",
            "action": RuleAction.REDACT,
            "priority_order": 50,
            "max_risk_threshold": 0.70,
            "is_default": True,
            "rules_config": {},
        },
        {
            "name": "Audit All Policy",
            "description": "Catch-all default audit logging policy for compliance monitoring.",
            "target_role": "*",
            "action": RuleAction.AUDIT,
            "priority_order": 100,
            "max_risk_threshold": 0.0,
            "is_default": True,
            "rules_config": {},
        },
    ]

    seeded: List[SecurityPolicy] = []
    for data in defaults:
        existing = (
            db.query(SecurityPolicy)
            .filter(
                SecurityPolicy.name == data["name"],
                SecurityPolicy.is_default.is_(True),
            )
            .first()
        )
        if not existing:
            pol = create_security_policy(
                db=db,
                name=data["name"],
                description=data["description"],
                target_role=data["target_role"],
                action=data["action"],
                priority_order=data["priority_order"],
                max_risk_threshold=data["max_risk_threshold"],
                is_default=True,
                rules_config=data["rules_config"],
            )
            seeded.append(pol)
        else:
            seeded.append(existing)

    return seeded
