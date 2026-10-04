"""
AI Memory Firewall - Audit & Security Event Models
==================================================
Models capturing security evaluations, policy violations, and mitigation audits.
Includes the Week 6 tamper-proof global hash-chain (AuditLogEntry) and
security alert system (SecurityAlert).
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import (
    BigInteger,
    Boolean,
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
    from src.models.policy import FirewallRule


# ─── Enums ────────────────────────────────────────────────────────────────────

class ViolationStatus(str, Enum):
    """Lifecycle status of a detected security violation."""
    DETECTED = "DETECTED"
    MITIGATED = "MITIGATED"
    BLOCKED = "BLOCKED"
    FLAGGED_FOR_REVIEW = "FLAGGED_FOR_REVIEW"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AuditEventType(str, Enum):
    """Semantic category of an audit log chain entry."""
    FIREWALL_EVAL  = "FIREWALL_EVAL"
    AUTH_EVENT     = "AUTH_EVENT"
    POLICY_CHANGE  = "POLICY_CHANGE"
    SECURITY_ALERT = "SECURITY_ALERT"
    SYSTEM         = "SYSTEM"


class AlertType(str, Enum):
    """Category of a generated security alert."""
    CHAIN_TAMPER      = "CHAIN_TAMPER"
    HIGH_RISK_EVENT   = "HIGH_RISK_EVENT"
    AUTH_ANOMALY      = "AUTH_ANOMALY"
    RATE_LIMIT        = "RATE_LIMIT"
    POLICY_VIOLATION  = "POLICY_VIOLATION"


class AlertSeverity(str, Enum):
    """Severity level for security alerts."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ─── Legacy Audit Event (Weeks 1-5) ───────────────────────────────────────────

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


# ─── Week 6: Global Hash-Chain Audit Log ─────────────────────────────────────

class AuditLogEntry(Base, UUIDPrimaryKeyMixin):
    """
    A single node in the global tamper-proof SHA-256 hash chain.

    The chain is global (shared across all tenants) and append-only.
    Each entry seals its own content hash + the previous entry's hash,
    making retroactive modification detectable by re-computing the chain.

    Genesis entry uses previous_hash = '0' * 64.
    """

    __tablename__ = "audit_log_entries"

    # Global monotonic sequence (1-indexed, incremented atomically)
    sequence_number: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        unique=True,
        index=True,
    )

    # Tenant context (nullable so SYSTEM events are not tenant-bound)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Optional link to the originating SecurityAuditEvent
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("security_audit_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Event classification
    event_type: Mapped[str] = mapped_column(
        String(50),
        default=AuditEventType.FIREWALL_EVAL.value,
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default="INFO",
        nullable=False,
        index=True,
    )

    # Who/what triggered the event
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Arbitrary structured payload (risk score, decision, entity types, etc.)
    payload: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # ── Hash chain columns ───────────────────────────────────────────────────
    # SHA-256 hex of the previous entry's entry_hash  ('0'*64 for genesis)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 of this entry's canonical content + previous_hash
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    # Immutable creation timestamp (no updated_at — chain entries never change)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    tenant: Mapped[Optional[Tenant]] = relationship("Tenant")
    source_event: Mapped[Optional[SecurityAuditEvent]] = relationship("SecurityAuditEvent")
    alerts: Mapped[list["SecurityAlert"]] = relationship(
        "SecurityAlert", back_populates="related_entry", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_audit_chain_seq_asc", "sequence_number"),
        Index("ix_audit_chain_tenant", "tenant_id", "created_at"),
        Index("ix_audit_chain_event_type", "event_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLogEntry(seq={self.sequence_number}, "
            f"action='{self.action}', hash='{self.entry_hash[:12]}...')>"
        )


# ─── Week 6: Security Alerts ─────────────────────────────────────────────────

class SecurityAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A security alert auto-raised by AuditLogger when anomalous conditions are detected.

    Conditions:
      - risk_score >= 0.8 on a FIREWALL_EVAL event → HIGH_RISK_EVENT alert
      - Chain integrity verification fails         → CHAIN_TAMPER alert (CRITICAL)
      - Repeated auth failures (future)            → AUTH_ANOMALY alert
    """

    __tablename__ = "security_alerts"

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    alert_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default=AlertSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Link to the chain entry that triggered this alert
    related_entry_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("audit_log_entries.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    metadata_json: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    tenant: Mapped[Optional[Tenant]] = relationship("Tenant")
    related_entry: Mapped[Optional[AuditLogEntry]] = relationship(
        "AuditLogEntry", back_populates="alerts"
    )

    __table_args__ = (
        Index("ix_alerts_tenant_type", "tenant_id", "alert_type"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_unresolved", "is_resolved", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityAlert(id={self.id}, type='{self.alert_type}', "
            f"severity='{self.severity}', resolved={self.is_resolved})>"
        )

