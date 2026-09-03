"""
AI Memory Firewall - Memory Storage Models
==========================================
Models for storing inspected, sanitized, and classified AI memory units.
"""

from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import Boolean, Enum as SQLEnum, ForeignKey, Index, JSON, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from src.models.agent import AgentSession


class SensitivityLevel(str, Enum):
    """Data classification level for memory items."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL = "CRITICAL"


class MemoryType(str, Enum):
    """Functional role of the memory item in the AI architecture."""
    SHORT_TERM = "SHORT_TERM"
    LONG_TERM = "LONG_TERM"
    EPISODIC = "EPISODIC"
    SEMANTIC = "SEMANTIC"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    USER_CONTEXT = "USER_CONTEXT"


class MemoryRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Represents a piece of persistent memory stored for an AI agent session."""

    __tablename__ = "memory_records"

    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    memory_type: Mapped[MemoryType] = mapped_column(
        SQLEnum(MemoryType, name="memory_type_enum"),
        default=MemoryType.SHORT_TERM,
        nullable=False,
        index=True,
    )
    sensitivity_tier: Mapped[SensitivityLevel] = mapped_column(
        SQLEnum(SensitivityLevel, name="sensitivity_level_enum"),
        default=SensitivityLevel.INTERNAL,
        nullable=False,
        index=True,
    )
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    quarantine_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vector_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    session: Mapped[AgentSession] = relationship("AgentSession", back_populates="memories")

    __table_args__ = (
        Index("ix_memory_session_sensitivity", "session_id", "sensitivity_tier"),
    )

    def __repr__(self) -> str:
        return (
            f"<MemoryRecord(id={self.id}, type={self.memory_type}, "
            f"tier={self.sensitivity_tier}, quarantined={self.is_quarantined})>"
        )
