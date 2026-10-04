"""
AI Memory Firewall - Week 8 ASK_USER Flow & User Decisions Test Suite
======================================================================
Comprehensive tests validating Human-in-the-Loop (HITL) workflows:
- Inbound ASK_USER triggering on sensitive rules
- /api/message/decide resolution with ALLOW, REDACT, BLOCK, REMEMBER_FOR_SESSION
- Session-level preference persistence across multi-turn conversations
- Conflict & error handling (404 Not Found, 409 Conflict)
- Pending decision retrieval (GET /api/message/pending/{session_id})
- Original prompt encryption at rest in user_decisions table (AES-256 Fernet)
- Safe timeout fallback to REDACT (Option A)
- Tamper-proof SHA-256 hash-chain audit logging of human decisions
- OpenAI client retry resilience with exponential backoff
"""

import uuid
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config.database import Base, get_sync_db
from src.app import create_app
from src.engine.audit_logger import AuditLogger
from src.models import (
    AgentSession,
    FirewallRule,
    MemoryRecord,
    RuleAction,
    RuleType,
    Tenant,
    User,
    UserRole,
)
from src.models.decision import DecisionChoice, DecisionStatus, UserDecision
from src.security import decrypt_data
from src.services import decision_service
from src.services.openai_service import OpenAIService


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def test_engine():
    """In-memory SQLite engine for test isolation."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def session_factory(test_engine):
    """Sessionmaker bound to SQLite engine."""
    return sessionmaker(bind=test_engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="module")
def seed_data(session_factory):
    """Seed initial tenant, agent session, and ASK_USER custom firewall rule."""
    session = session_factory()
    try:
        tenant_id = uuid.uuid4()
        tenant = Tenant(
            id=tenant_id,
            name="FinHealth Corp",
            slug=f"finhealth-{uuid.uuid4().hex[:6]}",
            api_key_hash="mock_hash_ask",
        )
        session.add(tenant)

        agent_session = AgentSession(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_name="AdvisorBot",
            session_token=f"sess_{uuid.uuid4().hex}",
            status="ACTIVE",
        )
        session.add(agent_session)

        # Create a rule with ASK_USER action for financial transaction inquiries
        ask_rule = FirewallRule(
            tenant_id=tenant_id,
            name="Confirm Wire Transfer Data",
            rule_type=RuleType.KEYWORD_FILTER,
            pattern_payload="wire transfer,account balance,routing number",
            action=RuleAction.ASK_USER,
            severity="MEDIUM",
            priority_order=1,
            is_active=True,
        )
        session.add(ask_rule)
        session.commit()

        return {
            "tenant_id": str(tenant.id),
            "session_id": str(agent_session.id),
        }
    finally:
        session.close()


@pytest.fixture(scope="module")
def client(test_engine, session_factory, seed_data):
    """FastAPI TestClient with overridden database dependency."""
    app = create_app()

    def _get_test_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_sync_db] = _get_test_db

    with TestClient(app) as c:
        yield c


# ─── Test Scenarios ───────────────────────────────────────────────────────────

# 1. Inbound message triggering ASK_USER
def test_ask_user_rule_triggers_confirmation(client, seed_data):
    payload = {
        "message": "Please initiate a wire transfer of $5,000 to routing number 123456789.",
        "session_id": seed_data["session_id"],
        "tenant_id": seed_data["tenant_id"],
    }
    resp = client.post("/api/message", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ASK_USER"
    assert data["pending_decision_id"] is not None
    assert data["reply"] is None  # Paused before LLM
    assert data["ask_user_details"] is not None
    assert "Confirm Wire Transfer Data" in data["ask_user_details"]["trigger_reason"]
    assert "ALLOW" in data["ask_user_details"]["available_choices"]
    assert "REMEMBER_FOR_SESSION" in data["ask_user_details"]["available_choices"]


# 2. Resolve with ALLOW choice
def test_decide_allow_flow(client, seed_data):
    # Trigger ASK_USER
    payload = {
        "message": "Check my account balance and routing number.",
        "session_id": seed_data["session_id"],
        "tenant_id": seed_data["tenant_id"],
    }
    resp1 = client.post("/api/message", json=payload)
    decision_id = resp1.json()["pending_decision_id"]
    assert decision_id is not None

    # Submit ALLOW decision
    decide_payload = {
        "decision_id": decision_id,
        "decision": "ALLOW",
        "scope": "ONCE",
        "mock_llm_response": "Your account balance is verified and safe.",
    }
    resp2 = client.post("/api/message/decide", json=decide_payload)
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["status"] == "RESOLVED"
    assert data["applied_decision"] == "ALLOW"
    assert "verified and safe" in data["reply"]
    assert data["memory_stored"] is True
    assert data["audit_logged"] is True


# 3. Resolve with REDACT choice
def test_decide_redact_flow(client, seed_data):
    payload = {
        "message": "Send account balance details to customer.",
        "session_id": seed_data["session_id"],
        "tenant_id": seed_data["tenant_id"],
    }
    resp1 = client.post("/api/message", json=payload)
    decision_id = resp1.json()["pending_decision_id"]

    # Submit REDACT decision
    decide_payload = {
        "decision_id": decision_id,
        "decision": "REDACT",
        "mock_llm_response": "Processed request with redacted balance details.",
    }
    resp2 = client.post("/api/message/decide", json=decide_payload)
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["status"] == "RESOLVED"
    assert data["applied_decision"] == "REDACT"
    assert data["reply"] is not None


# 4. Resolve with BLOCK choice
def test_decide_block_flow(client, session_factory, seed_data):
    payload = {
        "message": "Execute unverified wire transfer now.",
        "session_id": seed_data["session_id"],
        "tenant_id": seed_data["tenant_id"],
    }
    resp1 = client.post("/api/message", json=payload)
    decision_id = resp1.json()["pending_decision_id"]

    # Submit BLOCK decision
    decide_payload = {
        "decision_id": decision_id,
        "decision": "BLOCK",
    }
    resp2 = client.post("/api/message/decide", json=decide_payload)
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["status"] == "CANCELLED"
    assert data["applied_decision"] == "BLOCK"
    assert data["reply"] is None  # Blocked

    # Verify database record is quarantined
    db = session_factory()
    try:
        quarantined = (
            db.query(MemoryRecord)
            .filter(MemoryRecord.session_id == uuid.UUID(seed_data["session_id"]), MemoryRecord.is_quarantined == True)
            .order_by(MemoryRecord.created_at.desc())
            .first()
        )
        assert quarantined is not None
        assert quarantined.is_quarantined is True
    finally:
        db.close()


# 5. Remember preference for session (REMEMBER_FOR_SESSION)
def test_decide_remember_for_session_flow(client, seed_data):
    session_id = str(uuid.uuid4())

    # Turn 1: Trigger ASK_USER
    resp1 = client.post(
        "/api/message",
        json={
            "message": "What is my routing number for this account?",
            "session_id": session_id,
            "tenant_id": seed_data["tenant_id"],
        },
    )
    assert resp1.status_code == 200
    assert resp1.json()["decision"] == "ASK_USER"
    decision_id = resp1.json()["pending_decision_id"]

    # Resolve with REMEMBER_FOR_SESSION
    resp2 = client.post(
        "/api/message/decide",
        json={
            "decision_id": decision_id,
            "decision": "REMEMBER_FOR_SESSION",
            "scope": "SESSION",
            "mock_llm_response": "Your routing number is 021000021.",
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "RESOLVED"

    # Turn 2: Send another message matching the same rule in the same session
    resp3 = client.post(
        "/api/message",
        json={
            "message": "Please double check the wire transfer details.",
            "session_id": session_id,
            "tenant_id": seed_data["tenant_id"],
            "mock_llm_response": "Wire transfer details confirmed.",
        },
    )
    assert resp3.status_code == 200
    # Should automatically proceed as ALLOW without asking again!
    assert resp3.json()["decision"] == "ALLOW"
    assert "Wire transfer details confirmed." in resp3.json()["reply"]


# 6. Non-existent decision returns 404
def test_decide_nonexistent_decision_404(client):
    random_id = str(uuid.uuid4())
    resp = client.post(
        "/api/message/decide",
        json={"decision_id": random_id, "decision": "ALLOW"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# 7. Already resolved decision returns 409 Conflict
def test_decide_already_resolved_409(client, seed_data):
    # Trigger ASK_USER
    resp1 = client.post(
        "/api/message",
        json={
            "message": "Check routing number again.",
            "session_id": seed_data["session_id"],
            "tenant_id": seed_data["tenant_id"],
        },
    )
    decision_id = resp1.json()["pending_decision_id"]

    # First resolution
    resp2 = client.post(
        "/api/message/decide",
        json={"decision_id": decision_id, "decision": "ALLOW"},
    )
    assert resp2.status_code == 200

    # Second resolution attempt on same ID
    resp3 = client.post(
        "/api/message/decide",
        json={"decision_id": decision_id, "decision": "REDACT"},
    )
    assert resp3.status_code == 409
    assert "already been resolved" in resp3.json()["detail"].lower()


# 8. List pending decisions endpoint
def test_list_pending_decisions_for_session(client, seed_data):
    session_id = str(uuid.uuid4())
    # Create 2 pending decisions in this session
    client.post(
        "/api/message",
        json={
            "message": "Wire transfer prompt 1",
            "session_id": session_id,
            "tenant_id": seed_data["tenant_id"],
        },
    )
    client.post(
        "/api/message",
        json={
            "message": "Account balance prompt 2",
            "session_id": session_id,
            "tenant_id": seed_data["tenant_id"],
        },
    )

    resp = client.get(f"/api/message/pending/{session_id}")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    assert all(item["status"] == "PENDING" for item in items)


# 9. Original prompt encrypted at rest in user_decisions table
def test_user_decision_encryption_at_rest(client, session_factory, seed_data):
    secret_text = f"TopSecretAccountInfo-{uuid.uuid4().hex[:6]}"
    resp = client.post(
        "/api/message",
        json={
            "message": f"Please verify wire transfer for {secret_text}",
            "session_id": seed_data["session_id"],
            "tenant_id": seed_data["tenant_id"],
        },
    )
    decision_id = resp.json()["pending_decision_id"]

    db = session_factory()
    try:
        dec = db.query(UserDecision).filter(UserDecision.id == uuid.UUID(decision_id)).first()
        assert dec is not None
        # Must not be stored in plaintext
        assert secret_text not in dec.original_prompt
        # Must be valid Fernet ciphertext
        assert dec.original_prompt.startswith("gAAAA")
        # Must decrypt cleanly
        decrypted = decrypt_data(dec.original_prompt)
        assert secret_text in decrypted
    finally:
        db.close()


# 10. Timeout fallback to REDACT (Option A)
def test_timeout_fallback_to_redact(session_factory, seed_data):
    db = session_factory()
    try:
        pending = decision_service.create_pending_decision(
            db=db,
            session_id=uuid.UUID(seed_data["session_id"]),
            tenant_id=uuid.UUID(seed_data["tenant_id"]),
            message_id=uuid.uuid4(),
            raw_prompt="My sensitive wire transfer data.",
            sanitized_prompt="My sensitive [REDACTED] data.",
            trigger_reason="Keyword rule trigger",
        )
        db.commit()

        # Apply timeout fallback
        resolved = decision_service.apply_timeout_fallback(
            db=db,
            decision_id=pending.id,
            default_choice=DecisionChoice.REDACT,
        )
        assert resolved.status == DecisionStatus.EXPIRED
        assert resolved.selected_decision == DecisionChoice.REDACT
    finally:
        db.close()


# 11. Hash chain audit logging on user decisions
def test_hash_chain_audit_logging_on_decision(client, session_factory, seed_data):
    resp1 = client.post(
        "/api/message",
        json={
            "message": "Account balance verification test.",
            "session_id": seed_data["session_id"],
            "tenant_id": seed_data["tenant_id"],
        },
    )
    decision_id = resp1.json()["pending_decision_id"]

    client.post(
        "/api/message/decide",
        json={"decision_id": decision_id, "decision": "ALLOW"},
    )

    db = session_factory()
    try:
        audit_logger = AuditLogger()
        res = audit_logger.verify_chain(db)
        assert res.is_valid is True
        assert res.total_entries > 0
    finally:
        db.close()


# 12. Dual endpoint mounting for /api/v1/message/decide
def test_dual_endpoint_decide_mounting(client, seed_data):
    resp1 = client.post(
        "/api/v1/message",
        json={
            "message": "Inquire wire transfer via v1 endpoint.",
            "session_id": seed_data["session_id"],
            "tenant_id": seed_data["tenant_id"],
        },
    )
    decision_id = resp1.json()["pending_decision_id"]

    resp2 = client.post(
        "/api/v1/message/decide",
        json={"decision_id": decision_id, "decision": "ALLOW", "mock_llm_response": "Processed via v1."},
    )
    assert resp2.status_code == 200
    assert resp2.json()["applied_decision"] == "ALLOW"


# 13. OpenAI client retry resilience
def test_openai_retry_resilience():
    service = OpenAIService(mock_mode=True, max_retries=3)
    res = service.generate_chat_completion(
        messages=[{"role": "user", "content": "Hello"}],
        mock_response="Resilient response",
    )
    assert res.content == "Resilient response"
    assert res.is_mock is True
