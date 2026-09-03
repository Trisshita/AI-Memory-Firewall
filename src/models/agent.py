"""
AI Memory Firewall - Tenant & Agent Models
==========================================
Models representing tenants, isolated AI agents, and active agent sessions.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
import uuid
from sqlalchemy import Boolean, ForeignKey, Integer, JSON, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.audit import SecurityAuditEvent
    from src.models.memory import MemoryRecord
    from src.models.policy import FirewallRule


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Represents a customer, workspace, or organizational boundary for multi-tenant isolation."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_memory_limit_mb: Mapped[int] = mapped_column(Integer, default=1024, nullable=False)
    settings_json: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    sessions: Mapped[List[AgentSession]] = relationship(
        "AgentSession", back_populates="tenant", cascade="all, delete-orphan"
    )
    firewall_rules: Mapped[List[FirewallRule]] = relationship(
        "FirewallRule", back_populates="tenant", cascade="all, delete-orphan"
    )
    audit_events: Mapped[List[SecurityAuditEvent]] = relationship(
        "SecurityAuditEvent", back_populates="tenant", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Tenant(id={self.id}, name='{self.name}', slug='{self.slug}')>"


class AgentSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Represents an active or historical context session for a specific AI agent."""

    __tablename__ = "agent_sessions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE", nullable=False)
    context_metadata: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="sessions")
    memories: Mapped[List[MemoryRecord]] = relationship(
        "MemoryRecord", back_populates="session", cascade="all, delete-orphan"
    )
    audit_events: Mapped[List[SecurityAuditEvent]] = relationship(
        "SecurityAuditEvent", back_populates="session", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<AgentSession(id={self.id}, agent='{self.agent_name}', status='{self.status}')>"
