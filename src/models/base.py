"""
AI Memory Firewall - Base Model Mixins & Common Types
=====================================================
Common SQLAlchemy 2.0 declarative mixins for timestamps, UUIDs, and serialization.
"""

from __future__ import annotations
from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column


class UUIDPrimaryKeyMixin:
    """Provides a UUID primary key column compatible with both PostgreSQL and SQLite."""

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        sort_order=-10,
    )


class TimestampMixin:
    """Provides automatic created_at and updated_at UTC timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
