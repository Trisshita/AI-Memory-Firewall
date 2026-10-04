"""Add user_decisions table for Week 8 ASK_USER confirmation flow

Revision ID: 20260916_0005
Revises: 20260912_0004
Create Date: 2026-09-16 14:00:00.000000

Week 8: Human-in-the-loop (HITL) ASK_USER confirmation flow, user decision persistence,
and session-level memory preferences.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260916_0005"
down_revision: Union[str, None] = "20260912_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enums ─────────────────────────────────────────────────────────────────
    decision_status_enum = postgresql.ENUM(
        "PENDING", "RESOLVED", "EXPIRED", "CANCELLED",
        name="decision_status_enum",
        create_type=True,
    )
    decision_status_enum.create(op.get_bind(), checkfirst=True)

    decision_choice_enum = postgresql.ENUM(
        "ALLOW", "REDACT", "BLOCK", "REMEMBER_FOR_SESSION",
        name="decision_choice_enum",
        create_type=True,
    )
    decision_choice_enum.create(op.get_bind(), checkfirst=True)

    decision_scope_enum = postgresql.ENUM(
        "ONCE", "SESSION", "TENANT",
        name="decision_scope_enum",
        create_type=True,
    )
    decision_scope_enum.create(op.get_bind(), checkfirst=True)

    # ── user_decisions table ──────────────────────────────────────────────────
    op.create_table(
        "user_decisions",
        sa.Column("id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), primary_key=True),
        sa.Column("session_id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), nullable=False),
        sa.Column("tenant_id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), nullable=False),
        sa.Column("user_id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), nullable=True),
        sa.Column("message_id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), nullable=False),
        sa.Column("original_prompt", sa.Text(), nullable=False),
        sa.Column("sanitized_prompt", sa.Text(), nullable=False),
        sa.Column("trigger_reason", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=True),
        sa.Column("matched_text", sa.String(length=500), nullable=True),
        sa.Column("status", sa.Enum("PENDING", "RESOLVED", "EXPIRED", "CANCELLED", name="decision_status_enum"), nullable=False, server_default="PENDING"),
        sa.Column("selected_decision", sa.Enum("ALLOW", "REDACT", "BLOCK", "REMEMBER_FOR_SESSION", name="decision_choice_enum"), nullable=True),
        sa.Column("scope", sa.Enum("ONCE", "SESSION", "TENANT", name="decision_scope_enum"), nullable=False, server_default="ONCE"),
        sa.Column("model", sa.String(length=100), server_default="gpt-4o-mini", nullable=False),
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("temperature", sa.Float(), server_default="0.7", nullable=False),
        sa.Column("max_tokens", sa.Integer(), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )

    op.create_index("ix_user_decisions_id", "user_decisions", ["id"], unique=False)
    op.create_index("ix_user_decisions_session_id", "user_decisions", ["session_id"], unique=False)
    op.create_index("ix_user_decisions_tenant_id", "user_decisions", ["tenant_id"], unique=False)
    op.create_index("ix_user_decisions_user_id", "user_decisions", ["user_id"], unique=False)
    op.create_index("ix_user_decisions_message_id", "user_decisions", ["message_id"], unique=False)
    op.create_index("ix_user_decisions_status", "user_decisions", ["status"], unique=False)
    op.create_index("ix_user_decisions_entity_type", "user_decisions", ["entity_type"], unique=False)
    op.create_index("ix_user_decision_session_status", "user_decisions", ["session_id", "status"], unique=False)
    op.create_index("ix_user_decision_tenant_status", "user_decisions", ["tenant_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_user_decision_tenant_status", table_name="user_decisions")
    op.drop_index("ix_user_decision_session_status", table_name="user_decisions")
    op.drop_index("ix_user_decisions_entity_type", table_name="user_decisions")
    op.drop_index("ix_user_decisions_status", table_name="user_decisions")
    op.drop_index("ix_user_decisions_message_id", table_name="user_decisions")
    op.drop_index("ix_user_decisions_user_id", table_name="user_decisions")
    op.drop_index("ix_user_decisions_tenant_id", table_name="user_decisions")
    op.drop_index("ix_user_decisions_session_id", table_name="user_decisions")
    op.drop_index("ix_user_decisions_id", table_name="user_decisions")
    op.drop_table("user_decisions")

    sa.Enum(name="decision_scope_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="decision_choice_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="decision_status_enum").drop(op.get_bind(), checkfirst=True)
