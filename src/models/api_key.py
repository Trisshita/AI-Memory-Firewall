"""
AI Memory Firewall - API Key Model
==================================
Domain model representing machine/agent API credentials for service-to-service authentication.
"""

from __future__ import annotations
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import Tenant
    from src.models.user import User


class APIKey(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """API key credential for programmatic access and external AI agent authentication."""

    __tablename__ = "api_keys"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Relationships
    user: Mapped[Optional[User]] = relationship("User", back_populates="api_keys")
    tenant: Mapped[Optional[Tenant]] = relationship("Tenant")

    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name='{self.name}', prefix='{self.key_prefix}', active={self.is_active})>"
