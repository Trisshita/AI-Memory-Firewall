"""Initial AI Memory Firewall schema

Revision ID: 20260902_0001
Revises: None
Create Date: 2026-09-02 20:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '20260902_0001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── 1. Tenants Table ─────────────────────────────────────────
    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('api_key_hash', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('max_memory_limit_mb', sa.Integer(), server_default=sa.text('1024'), nullable=False),
        sa.Column('settings_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_tenants_id', 'tenants', ['id'], unique=False)
    op.create_index('ix_tenants_name', 'tenants', ['name'], unique=False)
    op.create_index('ix_tenants_slug', 'tenants', ['slug'], unique=True)

    # ─── 2. Agent Sessions Table ──────────────────────────────────
    op.create_table(
        'agent_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_name', sa.String(length=255), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='ACTIVE', nullable=False),
        sa.Column('context_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_agent_sessions_id', 'agent_sessions', ['id'], unique=False)
    op.create_index('ix_agent_sessions_tenant_id', 'agent_sessions', ['tenant_id'], unique=False)
    op.create_index('ix_agent_sessions_agent_name', 'agent_sessions', ['agent_name'], unique=False)
    op.create_index('ix_agent_sessions_session_token', 'agent_sessions', ['session_token'], unique=True)

    # ─── 3. Memory Records Table ──────────────────────────────────
    memory_type_enum = postgresql.ENUM('SHORT_TERM', 'LONG_TERM', 'EPISODIC', 'SEMANTIC', 'SYSTEM_PROMPT', 'USER_CONTEXT', name='memory_type_enum', create_type=True)
    sensitivity_level_enum = postgresql.ENUM('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'CRITICAL', name='sensitivity_level_enum', create_type=True)
    
    op.create_table(
        'memory_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('agent_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('memory_type', memory_type_enum, nullable=False),
        sa.Column('sensitivity_tier', sensitivity_level_enum, nullable=False),
        sa.Column('raw_content', sa.Text(), nullable=False),
        sa.Column('sanitized_content', sa.Text(), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('is_quarantined', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('quarantine_reason', sa.String(length=255), nullable=True),
        sa.Column('vector_id', sa.String(length=128), nullable=True),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_memory_records_id', 'memory_records', ['id'], unique=False)
    op.create_index('ix_memory_records_session_id', 'memory_records', ['session_id'], unique=False)
    op.create_index('ix_memory_records_memory_type', 'memory_records', ['memory_type'], unique=False)
    op.create_index('ix_memory_records_sensitivity_tier', 'memory_records', ['sensitivity_tier'], unique=False)
    op.create_index('ix_memory_records_content_hash', 'memory_records', ['content_hash'], unique=False)
    op.create_index('ix_memory_records_is_quarantined', 'memory_records', ['is_quarantined'], unique=False)
    op.create_index('ix_memory_records_vector_id', 'memory_records', ['vector_id'], unique=False)
    op.create_index('ix_memory_session_sensitivity', 'memory_records', ['session_id', 'sensitivity_tier'], unique=False)

    # ─── 4. Firewall Rules Table ──────────────────────────────────
    rule_type_enum = postgresql.ENUM('REGEX_PATTERN', 'KEYWORD_FILTER', 'PII_DETECTION', 'PROMPT_INJECTION', 'DATA_EXFILTRATION', 'SEMANTIC_SIMILARITY', name='rule_type_enum', create_type=True)
    rule_action_enum = postgresql.ENUM('ALLOW', 'REDACT', 'BLOCK', 'QUARANTINE', 'AUDIT', name='rule_action_enum', create_type=True)

    op.create_table(
        'firewall_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('rule_type', rule_type_enum, nullable=False),
        sa.Column('pattern_payload', sa.Text(), nullable=False),
        sa.Column('action', rule_action_enum, nullable=False),
        sa.Column('severity', sa.String(length=50), server_default='MEDIUM', nullable=False),
        sa.Column('priority_order', sa.Integer(), server_default=sa.text('100'), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('rule_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_firewall_rules_id', 'firewall_rules', ['id'], unique=False)
    op.create_index('ix_firewall_rules_tenant_id', 'firewall_rules', ['tenant_id'], unique=False)
    op.create_index('ix_firewall_rules_name', 'firewall_rules', ['name'], unique=False)
    op.create_index('ix_firewall_rules_rule_type', 'firewall_rules', ['rule_type'], unique=False)
    op.create_index('ix_firewall_rules_action', 'firewall_rules', ['action'], unique=False)
    op.create_index('ix_firewall_rules_priority_order', 'firewall_rules', ['priority_order'], unique=False)
    op.create_index('ix_firewall_rules_is_active', 'firewall_rules', ['is_active'], unique=False)

    # ─── 5. Security Audit Events Table ───────────────────────────
    violation_status_enum = postgresql.ENUM('DETECTED', 'MITIGATED', 'BLOCKED', 'FLAGGED_FOR_REVIEW', 'FALSE_POSITIVE', name='violation_status_enum', create_type=True)

    op.create_table(
        'security_audit_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('agent_sessions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('firewall_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_taken', sa.String(length=50), nullable=False),
        sa.Column('violation_status', violation_status_enum, nullable=False),
        sa.Column('risk_score', sa.Float(), server_default=sa.text('0.0'), nullable=False),
        sa.Column('original_snippet', sa.Text(), nullable=True),
        sa.Column('sanitized_snippet', sa.Text(), nullable=True),
        sa.Column('detected_entities', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('client_ip', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_security_audit_events_id', 'security_audit_events', ['id'], unique=False)
    op.create_index('ix_security_audit_events_tenant_id', 'security_audit_events', ['tenant_id'], unique=False)
    op.create_index('ix_security_audit_events_session_id', 'security_audit_events', ['session_id'], unique=False)
    op.create_index('ix_security_audit_events_rule_id', 'security_audit_events', ['rule_id'], unique=False)
    op.create_index('ix_security_audit_events_action_taken', 'security_audit_events', ['action_taken'], unique=False)
    op.create_index('ix_security_audit_events_violation_status', 'security_audit_events', ['violation_status'], unique=False)
    op.create_index('ix_audit_tenant_action', 'security_audit_events', ['tenant_id', 'action_taken'], unique=False)
    op.create_index('ix_audit_created_at_desc', 'security_audit_events', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_table('security_audit_events')
    op.execute('DROP TYPE IF EXISTS violation_status_enum')
    op.drop_table('firewall_rules')
    op.execute('DROP TYPE IF EXISTS rule_action_enum')
    op.execute('DROP TYPE IF EXISTS rule_type_enum')
    op.drop_table('memory_records')
    op.execute('DROP TYPE IF EXISTS sensitivity_level_enum')
    op.execute('DROP TYPE IF EXISTS memory_type_enum')
    op.drop_table('agent_sessions')
    op.drop_table('tenants')
