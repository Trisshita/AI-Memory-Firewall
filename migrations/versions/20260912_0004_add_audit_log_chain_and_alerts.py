"""Add audit_log_entries (global hash chain) and security_alerts tables

Revision ID: 20260912_0004
Revises: 20260910_0003
Create Date: 2026-09-12 15:00:00.000000

Week 6: Tamper-proof global SHA-256 hash chain audit log and auto-generated
security alert system.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260912_0004"
down_revision: Union[str, None] = "20260910_0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── audit_log_entries ─────────────────────────────────────────────────────
    op.create_table(
        "audit_log_entries",
        sa.Column(
            "id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            primary_key=True,
        ),
        # Global monotonic sequence across all tenants
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        # Tenant context (nullable — SYSTEM events have no tenant)
        sa.Column(
            "tenant_id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("tenants.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Optional back-link to the SecurityAuditEvent that triggered this entry
        sa.Column(
            "event_id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("security_audit_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(50), server_default="FIREWALL_EVAL", nullable=False),
        sa.Column("severity", sa.String(20), server_default="INFO", nullable=False),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource", sa.String(255), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        # Hash-chain columns
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # Unique + regular indexes
    op.create_index("ix_audit_log_entries_id", "audit_log_entries", ["id"], unique=False)
    op.create_index(
        "ix_audit_log_entries_sequence_number",
        "audit_log_entries",
        ["sequence_number"],
        unique=True,
    )
    op.create_index(
        "ix_audit_log_entries_entry_hash",
        "audit_log_entries",
        ["entry_hash"],
        unique=True,
    )
    op.create_index("ix_audit_log_entries_tenant_id", "audit_log_entries", ["tenant_id"], unique=False)
    op.create_index("ix_audit_log_entries_event_id", "audit_log_entries", ["event_id"], unique=False)
    op.create_index("ix_audit_log_entries_event_type", "audit_log_entries", ["event_type"], unique=False)
    op.create_index("ix_audit_log_entries_severity", "audit_log_entries", ["severity"], unique=False)
    op.create_index("ix_audit_log_entries_created_at", "audit_log_entries", ["created_at"], unique=False)
    # Composite index for fast chain traversal
    op.create_index(
        "ix_audit_chain_seq_asc",
        "audit_log_entries",
        ["sequence_number"],
        unique=False,
    )
    op.create_index(
        "ix_audit_chain_tenant",
        "audit_log_entries",
        ["tenant_id", "created_at"],
        unique=False,
    )

    # ── security_alerts ───────────────────────────────────────────────────────
    op.create_table(
        "security_alerts",
        sa.Column(
            "id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            primary_key=True,
        ),
        sa.Column(
            "tenant_id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), server_default="MEDIUM", nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "related_entry_id",
            sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("audit_log_entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_resolved", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_index("ix_security_alerts_id", "security_alerts", ["id"], unique=False)
    op.create_index("ix_security_alerts_tenant_id", "security_alerts", ["tenant_id"], unique=False)
    op.create_index("ix_security_alerts_alert_type", "security_alerts", ["alert_type"], unique=False)
    op.create_index("ix_security_alerts_severity", "security_alerts", ["severity"], unique=False)
    op.create_index("ix_security_alerts_is_resolved", "security_alerts", ["is_resolved"], unique=False)
    op.create_index("ix_security_alerts_related_entry_id", "security_alerts", ["related_entry_id"], unique=False)
    op.create_index(
        "ix_alerts_tenant_type",
        "security_alerts",
        ["tenant_id", "alert_type"],
        unique=False,
    )
    op.create_index(
        "ix_alerts_unresolved",
        "security_alerts",
        ["is_resolved", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    # Drop alerts first (has FK to audit_log_entries)
    op.drop_index("ix_alerts_unresolved", table_name="security_alerts")
    op.drop_index("ix_alerts_tenant_type", table_name="security_alerts")
    op.drop_index("ix_security_alerts_related_entry_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_is_resolved", table_name="security_alerts")
    op.drop_index("ix_security_alerts_severity", table_name="security_alerts")
    op.drop_index("ix_security_alerts_alert_type", table_name="security_alerts")
    op.drop_index("ix_security_alerts_tenant_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_id", table_name="security_alerts")
    op.drop_table("security_alerts")

    op.drop_index("ix_audit_chain_tenant", table_name="audit_log_entries")
    op.drop_index("ix_audit_chain_seq_asc", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_created_at", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_severity", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_event_type", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_event_id", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_tenant_id", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_entry_hash", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_sequence_number", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_id", table_name="audit_log_entries")
    op.drop_table("audit_log_entries")
