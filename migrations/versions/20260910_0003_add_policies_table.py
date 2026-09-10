"""Add security_policies table for rule-based policy evaluation engine

Revision ID: 20260910_0003
Revises: 20260909_0002
Create Date: 2026-09-10 13:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260910_0003"
down_revision: Union[str, None] = "20260909_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    rule_action_enum = postgresql.ENUM(
        "ALLOW", "REDACT", "BLOCK", "QUARANTINE", "AUDIT", name="rule_action_enum", create_type=False
    )

    op.create_table(
        "security_policies",
        sa.Column("id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), primary_key=True),
        sa.Column("tenant_id", sa.Uuid().with_variant(postgresql.UUID(as_uuid=True), "postgresql"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target_role", sa.String(length=50), server_default="*", nullable=False),
        sa.Column("action", rule_action_enum, nullable=False),
        sa.Column("priority_order", sa.Integer(), server_default="50", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("is_default", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("max_risk_threshold", sa.Float(), server_default="0.75", nullable=False),
        sa.Column("rules_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_security_policies_id", "security_policies", ["id"], unique=False)
    op.create_index("ix_security_policies_tenant_id", "security_policies", ["tenant_id"], unique=False)
    op.create_index("ix_security_policies_name", "security_policies", ["name"], unique=False)
    op.create_index("ix_security_policies_target_role", "security_policies", ["target_role"], unique=False)
    op.create_index("ix_security_policies_action", "security_policies", ["action"], unique=False)
    op.create_index("ix_security_policies_priority_order", "security_policies", ["priority_order"], unique=False)
    op.create_index("ix_security_policies_is_active", "security_policies", ["is_active"], unique=False)
    op.create_index("ix_security_policies_is_default", "security_policies", ["is_default"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_security_policies_is_default", table_name="security_policies")
    op.drop_index("ix_security_policies_is_active", table_name="security_policies")
    op.drop_index("ix_security_policies_priority_order", table_name="security_policies")
    op.drop_index("ix_security_policies_action", table_name="security_policies")
    op.drop_index("ix_security_policies_target_role", table_name="security_policies")
    op.drop_index("ix_security_policies_name", table_name="security_policies")
    op.drop_index("ix_security_policies_tenant_id", table_name="security_policies")
    op.drop_index("ix_security_policies_id", table_name="security_policies")
    op.drop_table("security_policies")
