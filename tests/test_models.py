"""
Tests for SQLAlchemy Domain Models
==================================
"""

import uuid

from src.models import (
    AgentSession,
    FirewallRule,
    MemoryRecord,
    MemoryType,
    RuleAction,
    RuleType,
    SecurityAuditEvent,
    SensitivityLevel,
    Tenant,
    ViolationStatus,
)


def test_create_tenant_and_session(db_session):
    """Verify tenant creation with active agent session."""
    tenant = Tenant(
        name="Acme AI Security",
        slug=f"acme-ai-{uuid.uuid4().hex[:8]}",
        api_key_hash="hash_abc123xyz",
        max_memory_limit_mb=2048,
    )
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    assert tenant.id is not None
    assert tenant.is_active is True

    session = AgentSession(
        tenant_id=tenant.id,
        agent_name="SupportBot-v2",
        session_token=f"sess_{uuid.uuid4().hex}",
        status="ACTIVE",
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    assert session.id is not None
    assert session.tenant.name == "Acme AI Security"


def test_create_memory_record(db_session):
    """Verify memory record creation and classification."""
    tenant = Tenant(
        name="FinanceCorp",
        slug=f"finance-{uuid.uuid4().hex[:8]}",
        api_key_hash="hash_finance123",
    )
    db_session.add(tenant)
    db_session.commit()

    session = AgentSession(
        tenant_id=tenant.id,
        agent_name="AnalystAgent",
        session_token=f"sess_{uuid.uuid4().hex}",
    )
    db_session.add(session)
    db_session.commit()

    memory = MemoryRecord(
        session_id=session.id,
        memory_type=MemoryType.EPISODIC,
        sensitivity_tier=SensitivityLevel.RESTRICTED,
        raw_content="User credit card was 4532-XXXX-XXXX-8901",
        sanitized_content="User credit card was [REDACTED_CC]",
        content_hash="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        is_quarantined=False,
    )
    db_session.add(memory)
    db_session.commit()
    db_session.refresh(memory)

    assert memory.id is not None
    assert memory.sensitivity_tier == SensitivityLevel.RESTRICTED
    assert memory.memory_type == MemoryType.EPISODIC
    assert memory.session.agent_name == "AnalystAgent"


def test_create_firewall_rule_and_audit(db_session):
    """Verify firewall rule configuration and security audit logging."""
    tenant = Tenant(
        name="HealthTech",
        slug=f"health-{uuid.uuid4().hex[:8]}",
        api_key_hash="hash_health123",
    )
    db_session.add(tenant)
    db_session.commit()

    rule = FirewallRule(
        tenant_id=tenant.id,
        name="PII SSN Detector",
        rule_type=RuleType.PII_DETECTION,
        pattern_payload=r"\b\d{3}-\d{2}-\d{4}\b",
        action=RuleAction.REDACT,
        severity="HIGH",
        priority_order=10,
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    assert rule.id is not None
    assert rule.action == RuleAction.REDACT

    audit = SecurityAuditEvent(
        tenant_id=tenant.id,
        rule_id=rule.id,
        action_taken="REDACT",
        violation_status=ViolationStatus.MITIGATED,
        risk_score=0.85,
        original_snippet="SSN: 000-12-3456",
        sanitized_snippet="SSN: [REDACTED_SSN]",
    )
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.id is not None
    assert audit.violation_status == ViolationStatus.MITIGATED
    assert audit.risk_score == 0.85


def test_create_user_and_api_key(db_session):
    """Verify User and APIKey model creation and relationships."""
    from src.models import APIKey, User, UserRole

    tenant = Tenant(
        name="SecurityHub",
        slug=f"sechub-{uuid.uuid4().hex[:8]}",
        api_key_hash="hash_sec123",
    )
    db_session.add(tenant)
    db_session.commit()

    user = User(
        email=f"operator-{uuid.uuid4().hex[:6]}@example.com",
        hashed_password="$2b$12$somehashedpasswordstringforuser",
        role=UserRole.ADMIN.value,
        tenant_id=tenant.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.id is not None
    assert user.role == "admin"
    assert user.tenant.name == "SecurityHub"

    api_key = APIKey(
        name="Production Agent Key",
        key_prefix="amf_live_1234",
        key_hash="some_sha256_hash_value_here",
        user_id=user.id,
        tenant_id=tenant.id,
        is_active=True,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)

    assert api_key.id is not None
    assert api_key.user.email == user.email
    assert api_key.tenant.name == "SecurityHub"
    assert len(user.api_keys) == 1

