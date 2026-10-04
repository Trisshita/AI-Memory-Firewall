"""
AI Memory Firewall - Policy & Rule Models
=========================================
Models defining security policies, inspection rules, and mitigation actions.
"""

from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING, List, Optional
import uuid
from sqlalchemy import Boolean, Enum as SQLEnum, Float, ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import Tenant
    from src.models.audit import SecurityAuditEvent


class RuleAction(str, Enum):
    """Action to take when a firewall rule matches."""
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    AUDIT = "AUDIT"
    ASK_USER = "ASK_USER"


class RuleType(str, Enum):
    """Category of the inspection rule."""
    REGEX_PATTERN = "REGEX_PATTERN"
    KEYWORD_FILTER = "KEYWORD_FILTER"
    PII_DETECTION = "PII_DETECTION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"


class FirewallRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Represents a rule evaluated against incoming and stored AI memory streams."""

    __tablename__ = "firewall_rules"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_type: Mapped[RuleType] = mapped_column(
        SQLEnum(RuleType, name="rule_type_enum"),
        nullable=False,
        index=True,
    )
    pattern_payload: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[RuleAction] = mapped_column(
        SQLEnum(RuleAction, name="rule_action_enum"),
        default=RuleAction.BLOCK,
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(50), default="MEDIUM", nullable=False)
    priority_order: Mapped[int] = mapped_column(Integer, default=100, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    rule_config: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="firewall_rules")
    audit_events: Mapped[List[SecurityAuditEvent]] = relationship(
        "SecurityAuditEvent", back_populates="rule"
    )

    def __repr__(self) -> str:
        return f"<FirewallRule(id={self.id}, name='{self.name}', type={self.rule_type}, action={self.action})>"


class SecurityPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Represents a security policy defining RBAC target roles, risk score thresholds,
    and inspection conditions for AI memory evaluation.
    """

    __tablename__ = "security_policies"

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_role: Mapped[str] = mapped_column(String(50), default="*", nullable=False, index=True)
    action: Mapped[RuleAction] = mapped_column(
        SQLEnum(RuleAction, name="rule_action_enum"),
        default=RuleAction.REDACT,
        nullable=False,
        index=True,
    )
    priority_order: Mapped[int] = mapped_column(Integer, default=50, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    max_risk_threshold: Mapped[float] = mapped_column(Float, default=0.75, nullable=False)
    rules_config: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    tenant: Mapped[Optional[Tenant]] = relationship("Tenant")

    def __repr__(self) -> str:
        return f"<SecurityPolicy(id={self.id}, name='{self.name}', role='{self.target_role}', action={self.action})>"
