"""
AI Memory Firewall - Audit & Security Event Models
==================================================
Models capturing security evaluations, policy violations, and mitigation audits.
"""

from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import Enum as SQLEnum, Float, ForeignKey, Index, JSON, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import AgentSession, Tenant
    from src.models.policy import FirewallRule


class ViolationStatus(str, Enum):
    """Lifecycle status of a detected security violation."""
    DETECTED = "DETECTED"
    MITIGATED = "MITIGATED"
    BLOCKED = "BLOCKED"
    FLAGGED_FOR_REVIEW = "FLAGGED_FOR_REVIEW"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class SecurityAuditEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Immutable audit trail of firewall evaluations and mitigation actions."""

    __tablename__ = "security_audit_events"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("agent_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("firewall_rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action_taken: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    violation_status: Mapped[ViolationStatus] = mapped_column(
        SQLEnum(ViolationStatus, name="violation_status_enum"),
        default=ViolationStatus.DETECTED,
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    original_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sanitized_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detected_entities: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="audit_events")
    session: Mapped[Optional[AgentSession]] = relationship("AgentSession", back_populates="audit_events")
    rule: Mapped[Optional[FirewallRule]] = relationship("FirewallRule", back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_tenant_action", "tenant_id", "action_taken"),
        Index("ix_audit_created_at_desc", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<SecurityAuditEvent(id={self.id}, action='{self.action_taken}', risk_score={self.risk_score})>"
