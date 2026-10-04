"""
AI Memory Firewall - User Decision & Consent Models (Week 8)
=============================================================
Models representing human-in-the-loop decisions, pending confirmation requests,
and session-level user preferences for sensitive data screening.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import AgentSession, Tenant
    from src.models.user import User


class DecisionStatus(str, Enum):
    """Lifecycle status of an ASK_USER pending confirmation request."""
    PENDING = "PENDING"
    RESOLVED = "RESOLVED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class DecisionChoice(str, Enum):
    """Choice options selected by the human user."""
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    REMEMBER_FOR_SESSION = "REMEMBER_FOR_SESSION"


class DecisionScope(str, Enum):
    """Scope over which the decision preference applies."""
    ONCE = "ONCE"
    SESSION = "SESSION"
    TENANT = "TENANT"


class UserDecision(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Represents an individual ASK_USER confirmation request and its resolution state.
    """

    __tablename__ = "user_decisions"

    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        nullable=False,
        index=True,
    )
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)  # Encrypted at rest (AES-256 Fernet)
    sanitized_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_reason: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    matched_text: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    status: Mapped[DecisionStatus] = mapped_column(
        SQLEnum(DecisionStatus, name="decision_status_enum"),
        default=DecisionStatus.PENDING,
        nullable=False,
        index=True,
    )
    selected_decision: Mapped[Optional[DecisionChoice]] = mapped_column(
        SQLEnum(DecisionChoice, name="decision_choice_enum"),
        nullable=True,
        index=True,
    )
    scope: Mapped[DecisionScope] = mapped_column(
        SQLEnum(DecisionScope, name="decision_scope_enum"),
        default=DecisionScope.ONCE,
        nullable=False,
    )

    model: Mapped[str] = mapped_column(String(100), default="gpt-4o-mini", nullable=False)
    system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    temperature: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    max_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    session: Mapped[AgentSession] = relationship("AgentSession")
    tenant: Mapped[Tenant] = relationship("Tenant")
    user: Mapped[Optional[User]] = relationship("User")

    __table_args__ = (
        Index("ix_user_decision_session_status", "session_id", "status"),
        Index("ix_user_decision_tenant_status", "tenant_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<UserDecision(id={self.id}, status={self.status}, "
            f"choice={self.selected_decision}, scope={self.scope})>"
        )
