"""
AI Memory Firewall - User Model
===============================
Domain model representing human users, administrators, and agent service accounts.
"""

from __future__ import annotations
import enum
from typing import TYPE_CHECKING, List, Optional
import uuid
from sqlalchemy import Boolean, ForeignKey, String, Uuid
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import Tenant
    from src.models.api_key import APIKey


class UserRole(str, enum.Enum):
    """System access roles for RBAC authorization."""
    ADMIN = "admin"
    USER = "user"
    AGENT = "agent"


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """User account entity for authentication and RBAC authorization."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default=UserRole.USER.value, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    tenant: Mapped[Optional[Tenant]] = relationship("Tenant")
    api_keys: Mapped[List[APIKey]] = relationship(
        "APIKey", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}', is_active={self.is_active})>"
