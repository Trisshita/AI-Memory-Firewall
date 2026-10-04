"""
AI Memory Firewall - Week 6 Test Suite: Audit Logger & Hash Chain
=================================================================
40 test scenarios covering:
  - Hash chain construction (genesis, sequential linking, determinism, tenant neutrality)
  - Full chain integrity verification (valid, tampered single/multi, empty, singleton)
  - Security alert generation (high-risk, chain tamper, listing, resolve)
  - REST API endpoints (/audit/logs, /audit/verify, /audit/alerts, /audit/alerts/{id}/resolve)
  - FirewallService integration (chain entry created on store_memory, high-risk alert)
  - Performance benchmarks (1000-entry chain build, 100-entry verify)
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.engine.audit_logger import (
    GENESIS_HASH,
    HIGH_RISK_ALERT_THRESHOLD,
    AuditLogger,
    ChainVerificationResult,
    compute_entry_hash,
)
from src.models.agent import AgentSession, Tenant
from src.models.audit import (
    AlertSeverity,
    AlertType,
    AuditEventType,
    AuditLogEntry,
    SecurityAlert,
)



# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_entry_kwargs(
    seq: int = 1,
    action: str = "test.action",
    previous_hash: str = GENESIS_HASH,
    tenant_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    created_at_iso: str = "2026-09-12T10:00:00+00:00",
) -> Dict[str, Any]:
    return {
        "sequence_number": seq,
        "tenant_id": tenant_id,
        "event_type": AuditEventType.FIREWALL_EVAL.value,
        "severity": "INFO",
        "actor": "test_actor",
        "action": action,
        "resource": "test_resource",
        "payload": payload,
        "created_at_iso": created_at_iso,
        "previous_hash": previous_hash,
    }


def _build_mock_entry(seq: int, previous_hash: str, **kwargs) -> MagicMock:
    """Build a MagicMock that looks like an AuditLogEntry."""
    from datetime import datetime, timezone
    kw = _make_entry_kwargs(seq=seq, previous_hash=previous_hash, **kwargs)
    entry = MagicMock(spec=AuditLogEntry)
    entry.sequence_number = kw["sequence_number"]
    entry.tenant_id = None
    entry.event_type = kw["event_type"]
    entry.severity = kw["severity"]
    entry.actor = kw["actor"]
    entry.action = kw["action"]
    entry.resource = kw["resource"]
    entry.payload = kw["payload"]
    # Use a real datetime so .isoformat() works correctly in _entry_to_hash_inputs
    created_at = datetime.fromisoformat(kw["created_at_iso"])
    entry.created_at = created_at
    entry.previous_hash = previous_hash
    # Compute and store the real hash
    entry.entry_hash = compute_entry_hash(**kw)
    entry.id = uuid.uuid4()
    entry.alerts = []
    return entry


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Hash Chain Construction
# ═══════════════════════════════════════════════════════════════════════════════

class TestHashChainConstruction:
    """Unit tests for compute_entry_hash and chain linkage logic."""

    def test_genesis_uses_zero_hash(self):
        """Genesis entry must use GENESIS_HASH ('0'*64) as previous_hash."""
        assert GENESIS_HASH == "0" * 64
        h = compute_entry_hash(**_make_entry_kwargs(seq=1, previous_hash=GENESIS_HASH))
        assert len(h) == 64
        assert h != GENESIS_HASH

    def test_hash_is_64_hex_chars(self):
        """SHA-256 hash must always be exactly 64 lowercase hex characters."""
        h = compute_entry_hash(**_make_entry_kwargs())
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        """Same inputs must always produce the same hash."""
        kwargs = _make_entry_kwargs()
        assert compute_entry_hash(**kwargs) == compute_entry_hash(**kwargs)

    def test_different_sequence_produces_different_hash(self):
        """Changing sequence_number must change the entry_hash."""
        h1 = compute_entry_hash(**_make_entry_kwargs(seq=1))
        h2 = compute_entry_hash(**_make_entry_kwargs(seq=2))
        assert h1 != h2

    def test_different_action_produces_different_hash(self):
        """Changing action must change the entry_hash."""
        h1 = compute_entry_hash(**_make_entry_kwargs(action="memory.store"))
        h2 = compute_entry_hash(**_make_entry_kwargs(action="auth.login"))
        assert h1 != h2

    def test_different_previous_hash_changes_entry_hash(self):
        """entry_hash changes when previous_hash changes (chain linkage)."""
        h1 = compute_entry_hash(**_make_entry_kwargs(previous_hash=GENESIS_HASH))
        fake_prev = "a" * 64
        h2 = compute_entry_hash(**_make_entry_kwargs(previous_hash=fake_prev))
        assert h1 != h2

    def test_sequential_chain_links_correctly(self):
        """Each entry's previous_hash must equal the prior entry's entry_hash."""
        h0 = GENESIS_HASH
        h1 = compute_entry_hash(**_make_entry_kwargs(seq=1, previous_hash=h0))
        h2 = compute_entry_hash(**_make_entry_kwargs(seq=2, previous_hash=h1))
        h3 = compute_entry_hash(**_make_entry_kwargs(seq=3, previous_hash=h2))
        # Each links back to previous
        assert compute_entry_hash(**_make_entry_kwargs(seq=2, previous_hash=h1)) == h2
        assert compute_entry_hash(**_make_entry_kwargs(seq=3, previous_hash=h2)) == h3

    def test_tenant_id_included_in_hash(self):
        """Tenant ID is part of canonical data; different tenant_ids yield different hashes."""
        h_none = compute_entry_hash(**_make_entry_kwargs(tenant_id=None))
        h_tenant = compute_entry_hash(**_make_entry_kwargs(tenant_id=str(uuid.uuid4())))
        assert h_none != h_tenant


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Chain Verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainVerification:
    """Tests for AuditLogger.verify_chain() using mock DB sessions."""

    def _make_db_with_entries(self, entries: List[MagicMock]) -> MagicMock:
        """Build a mock DB session whose query().order_by().all() returns entries."""
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.all.return_value = entries
        mock_query.count.return_value = len(entries)
        mock_query.filter.return_value = mock_query
        return mock_db

    def test_empty_chain_is_valid(self):
        """An empty chain (no entries) is considered valid."""
        db = self._make_db_with_entries([])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is True
        assert result.total_entries == 0
        assert result.broken_entries == []

    def test_single_valid_entry_passes(self):
        """A chain with one correct entry is valid."""
        entry = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        db = self._make_db_with_entries([entry])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is True
        assert result.total_entries == 1

    def test_three_valid_entries_pass(self):
        """Three correctly linked entries must all pass verification."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        e2 = _build_mock_entry(seq=2, previous_hash=e1.entry_hash)
        e3 = _build_mock_entry(seq=3, previous_hash=e2.entry_hash)
        db = self._make_db_with_entries([e1, e2, e3])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is True
        assert result.total_entries == 3
        assert result.broken_entries == []

    def test_single_tampered_entry_detected(self):
        """A single entry with a wrong entry_hash must be flagged."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        e1.entry_hash = "bad" + "0" * 61  # corrupt the hash
        db = self._make_db_with_entries([e1])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is False
        assert 1 in result.broken_entries
        assert result.first_broken_sequence == 1

    def test_middle_entry_tamper_detected(self):
        """Tampering with a middle entry must be detected."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        e2 = _build_mock_entry(seq=2, previous_hash=e1.entry_hash)
        e3 = _build_mock_entry(seq=3, previous_hash=e2.entry_hash)
        # Corrupt entry 2
        e2.entry_hash = "f" * 64
        db = self._make_db_with_entries([e1, e2, e3])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is False
        assert 2 in result.broken_entries
        assert result.first_broken_sequence == 2

    def test_multiple_tampered_entries_all_found(self):
        """All tampered entries in the chain are reported, not just the first."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        e2 = _build_mock_entry(seq=2, previous_hash=e1.entry_hash)
        e3 = _build_mock_entry(seq=3, previous_hash=e2.entry_hash)
        e4 = _build_mock_entry(seq=4, previous_hash=e3.entry_hash)
        # Corrupt entries 2 and 4
        e2.entry_hash = "a" * 64
        e4.entry_hash = "b" * 64
        db = self._make_db_with_entries([e1, e2, e3, e4])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.is_valid is False
        assert 2 in result.broken_entries
        assert 4 in result.broken_entries

    def test_verification_time_is_recorded(self):
        """verification_time_ms must be a positive float."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        db = self._make_db_with_entries([e1])
        result = AuditLogger().verify_chain(db=db, raise_alert_on_tamper=False)
        assert result.verification_time_ms >= 0.0

    def test_tamper_raises_alert_when_requested(self):
        """When raise_alert_on_tamper=True and chain is broken, raise_alert() is called."""
        e1 = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        e1.entry_hash = "bad" + "0" * 61
        db = self._make_db_with_entries([e1])

        logger = AuditLogger()
        with patch.object(logger, "raise_alert") as mock_raise:
            logger.verify_chain(db=db, raise_alert_on_tamper=True)
            mock_raise.assert_called_once()
            call_kwargs = mock_raise.call_args.kwargs
            assert call_kwargs["alert_type"] == AlertType.CHAIN_TAMPER.value
            assert call_kwargs["severity"] == AlertSeverity.CRITICAL.value


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AuditLogger.log_event() with DB Session
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLoggerLogEvent:
    """Tests for AuditLogger.log_event() using the in-memory SQLite test DB."""

    def _make_db_with_tail(self, tail: Optional[MagicMock]) -> MagicMock:
        """Build a mock DB where get tail returns `tail`, and add/flush are no-ops."""
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.first.return_value = tail
        mock_query.filter.return_value = mock_query
        mock_db.add = MagicMock()
        mock_db.flush = MagicMock()
        mock_db.commit = MagicMock()
        return mock_db

    def test_genesis_entry_uses_genesis_hash(self):
        """First entry (no tail) must use GENESIS_HASH as previous_hash."""
        db = self._make_db_with_tail(None)
        logger = AuditLogger()
        entry = logger.log_event(
            db=db, action="test.action", raise_alert_if_high_risk=False
        )
        assert entry.previous_hash == GENESIS_HASH
        assert entry.sequence_number == 1

    def test_second_entry_links_to_first(self):
        """Second log_event call must use first entry's hash as previous_hash."""
        tail = _build_mock_entry(seq=1, previous_hash=GENESIS_HASH)
        db = self._make_db_with_tail(tail)
        logger = AuditLogger()
        entry = logger.log_event(
            db=db, action="test.action2", raise_alert_if_high_risk=False
        )
        assert entry.previous_hash == tail.entry_hash
        assert entry.sequence_number == 2

    def test_entry_hash_correctly_computed(self):
        """The entry_hash on the returned entry must equal a locally-recomputed value."""
        db = self._make_db_with_tail(None)
        logger = AuditLogger()
        entry = logger.log_event(
            db=db,
            action="memory.store",
            event_type=AuditEventType.FIREWALL_EVAL.value,
            severity="INFO",
            tenant_id=None,
            actor="system",
            resource="session-123",
            payload={"decision": "ALLOW"},
            raise_alert_if_high_risk=False,
        )
        recomputed = compute_entry_hash(
            sequence_number=entry.sequence_number,
            tenant_id=None,
            event_type=entry.event_type,
            severity=entry.severity,
            actor=entry.actor,
            action=entry.action,
            resource=entry.resource,
            payload=entry.payload,
            created_at_iso=entry.created_at.isoformat(),
            previous_hash=GENESIS_HASH,
        )
        assert entry.entry_hash == recomputed

    def test_high_risk_payload_triggers_alert(self):
        """Payload with risk_score >= HIGH_RISK_ALERT_THRESHOLD triggers raise_alert()."""
        db = self._make_db_with_tail(None)
        logger = AuditLogger()
        with patch.object(logger, "raise_alert") as mock_raise:
            logger.log_event(
                db=db,
                action="memory.store",
                payload={"risk_score": 0.92, "decision": "QUARANTINE"},
                raise_alert_if_high_risk=True,
            )
            mock_raise.assert_called_once()
            call_kwargs = mock_raise.call_args.kwargs
            assert call_kwargs["alert_type"] == AlertType.HIGH_RISK_EVENT.value

    def test_low_risk_payload_does_not_trigger_alert(self):
        """Payload with risk_score < HIGH_RISK_ALERT_THRESHOLD does NOT trigger alert."""
        db = self._make_db_with_tail(None)
        logger = AuditLogger()
        with patch.object(logger, "raise_alert") as mock_raise:
            logger.log_event(
                db=db,
                action="memory.store",
                payload={"risk_score": 0.30, "decision": "ALLOW"},
                raise_alert_if_high_risk=True,
            )
            mock_raise.assert_not_called()

    def test_no_alert_when_flag_is_false(self):
        """raise_alert_if_high_risk=False suppresses all alert generation."""
        db = self._make_db_with_tail(None)
        logger = AuditLogger()
        with patch.object(logger, "raise_alert") as mock_raise:
            logger.log_event(
                db=db,
                action="memory.store",
                payload={"risk_score": 0.99, "decision": "BLOCK"},
                raise_alert_if_high_risk=False,
            )
            mock_raise.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Security Alerts
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityAlerts:
    """Tests for AuditLogger.raise_alert() and SecurityAlert management."""

    def _make_commit_db(self) -> MagicMock:
        mock_db = MagicMock()
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        mock_db.flush = MagicMock()
        mock_db.refresh = MagicMock()
        return mock_db

    def test_raise_alert_creates_security_alert(self):
        """raise_alert() must create and persist a SecurityAlert."""
        db = self._make_commit_db()
        logger = AuditLogger()
        alert = logger.raise_alert(
            db=db,
            alert_type=AlertType.HIGH_RISK_EVENT.value,
            severity=AlertSeverity.HIGH.value,
            title="Test High-Risk Alert",
            description="Risk threshold exceeded",
            flush_only=False,
        )
        db.add.assert_called_once()
        db.commit.assert_called_once()
        assert alert.alert_type == AlertType.HIGH_RISK_EVENT.value
        assert alert.severity == AlertSeverity.HIGH.value
        assert alert.is_resolved is False

    def test_chain_tamper_alert_is_critical(self):
        """CHAIN_TAMPER alerts must have CRITICAL severity."""
        db = self._make_commit_db()
        logger = AuditLogger()
        alert = logger.raise_alert(
            db=db,
            alert_type=AlertType.CHAIN_TAMPER.value,
            severity=AlertSeverity.CRITICAL.value,
            title="Chain Tamper Detected",
            flush_only=False,
        )
        assert alert.severity == AlertSeverity.CRITICAL.value
        assert alert.alert_type == AlertType.CHAIN_TAMPER.value

    def test_flush_only_does_not_commit(self):
        """flush_only=True must call flush() but NOT commit()."""
        db = self._make_commit_db()
        logger = AuditLogger()
        logger.raise_alert(
            db=db,
            alert_type=AlertType.HIGH_RISK_EVENT.value,
            severity=AlertSeverity.HIGH.value,
            title="Flush-Only Alert",
            flush_only=True,
        )
        db.flush.assert_called_once()
        db.commit.assert_not_called()

    def test_alert_can_be_linked_to_chain_entry(self):
        """raise_alert() can link to a related AuditLogEntry."""
        db = self._make_commit_db()
        entry = _build_mock_entry(seq=5, previous_hash=GENESIS_HASH)
        logger = AuditLogger()
        alert = logger.raise_alert(
            db=db,
            alert_type=AlertType.HIGH_RISK_EVENT.value,
            severity=AlertSeverity.HIGH.value,
            title="Linked Alert",
            related_entry=entry,
            flush_only=False,
        )
        assert alert.related_entry_id == entry.id

    def test_alert_metadata_stored(self):
        """metadata dict must be attached to the alert."""
        db = self._make_commit_db()
        meta = {"risk_score": 0.95, "decision": "BLOCK", "violations": 3}
        logger = AuditLogger()
        alert = logger.raise_alert(
            db=db,
            alert_type=AlertType.HIGH_RISK_EVENT.value,
            severity=AlertSeverity.CRITICAL.value,
            title="Meta Alert",
            metadata=meta,
            flush_only=False,
        )
        assert alert.metadata_json == meta


# ═══════════════════════════════════════════════════════════════════════════════
# 5. API Endpoint Tests
# ═══════════════════════════════════════════════════════════════════════════════

from typing import Generator as _Generator
from fastapi.testclient import TestClient as _TestClient
from sqlalchemy import create_engine as _create_engine
from sqlalchemy.orm import Session as _Session, sessionmaker as _sessionmaker
from sqlalchemy.pool import StaticPool as _StaticPool
from config.database import Base as _Base, get_sync_db as _get_sync_db
from src.app import create_app as _create_app


@pytest.fixture(scope="module")
def audit_test_engine():
    """Isolated in-memory SQLite engine for audit API tests."""
    engine = _create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=_StaticPool,
    )
    _Base.metadata.create_all(bind=engine)
    yield engine
    _Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def audit_api_client(audit_test_engine):
    """FastAPI TestClient with SQLite DB override (no real PostgreSQL needed)."""
    _factory = _sessionmaker(
        bind=audit_test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    def _override_db() -> _Generator[_Session, None, None]:
        db = _factory()
        try:
            yield db
        finally:
            db.close()

    app = _create_app()
    app.dependency_overrides[_get_sync_db] = _override_db

    with _TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


def _get_token(client, role: str = "user") -> str:
    """
    Register a fresh user (or admin) and return a valid Bearer token.
    Uses a unique email each call to avoid duplicate-registration conflicts.
    """
    email = f"audit_test_{uuid.uuid4().hex[:8]}@example.com"
    password = "SecureAudit123!"
    role_value = "admin" if role == "admin" else "user"

    reg_resp = client.post(
        "/auth/register",
        json={"email": email, "password": password, "role": role_value},
    )
    assert reg_resp.status_code in (200, 201), f"Register failed: {reg_resp.text}"

    login_resp = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    return login_resp.json()["access_token"]


class TestAuditAPIEndpoints:
    """Integration tests for the 4 new audit REST endpoints via TestClient."""

    # GET /api/v1/audit/logs ──────────────────────────────────────────────────

    def test_get_audit_logs_requires_auth(self, audit_api_client):
        """GET /audit/logs must require Bearer authentication."""
        resp = audit_api_client.get("/api/v1/audit/logs")
        assert resp.status_code == 401

    def test_get_audit_logs_authenticated_returns_200(self, audit_api_client):
        """Authenticated GET /audit/logs must return 200 with AuditLogListResponse."""
        token = _get_token(audit_api_client)
        resp = audit_api_client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "entries" in body
        assert "chain_length" in body
        assert isinstance(body["entries"], list)

    def test_get_audit_logs_filters_by_event_type(self, audit_api_client):
        """GET /audit/logs?event_type=FIREWALL_EVAL must accept the param without error."""
        token = _get_token(audit_api_client)
        resp = audit_api_client.get(
            "/api/v1/audit/logs?event_type=FIREWALL_EVAL",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        for entry in body["entries"]:
            assert entry["event_type"] == "FIREWALL_EVAL"

    # GET /api/v1/audit/verify ────────────────────────────────────────────────

    def test_verify_chain_requires_auth(self, audit_api_client):
        """GET /audit/verify must require authentication."""
        resp = audit_api_client.get("/api/v1/audit/verify")
        assert resp.status_code == 401

    def test_verify_chain_authenticated_returns_200(self, audit_api_client):
        """Authenticated GET /audit/verify must return ChainVerificationResponse."""
        token = _get_token(audit_api_client)
        resp = audit_api_client.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "is_valid" in body
        assert "total_entries" in body
        assert "broken_entries" in body
        assert "message" in body
        assert "verification_time_ms" in body

    def test_verify_chain_valid_when_intact(self, audit_api_client):
        """Verify endpoint must report is_valid=true on unmodified chain."""
        token = _get_token(audit_api_client)
        resp = audit_api_client.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["is_valid"] is True

    # GET /api/v1/audit/alerts ────────────────────────────────────────────────

    def test_get_alerts_requires_auth(self, audit_api_client):
        """GET /audit/alerts must require authentication."""
        resp = audit_api_client.get("/api/v1/audit/alerts")
        assert resp.status_code == 401

    def test_get_alerts_returns_200(self, audit_api_client):
        """Authenticated GET /audit/alerts must return SecurityAlertListResponse."""
        token = _get_token(audit_api_client)
        resp = audit_api_client.get(
            "/api/v1/audit/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "alerts" in body
        assert "unresolved_count" in body
        assert isinstance(body["alerts"], list)

    # PUT /api/v1/audit/alerts/{id}/resolve ──────────────────────────────────

    def test_resolve_alert_requires_admin(self, audit_api_client):
        """PUT /audit/alerts/{id}/resolve must reject non-admin (user role)."""
        token = _get_token(audit_api_client, role="user")
        fake_id = str(uuid.uuid4())
        resp = audit_api_client.put(
            f"/api/v1/audit/alerts/{fake_id}/resolve",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_resolve_alert_404_for_nonexistent(self, audit_api_client):
        """Admin PUT /audit/alerts/{id}/resolve returns 404 for unknown alert ID."""
        token = _get_token(audit_api_client, role="admin")
        fake_id = str(uuid.uuid4())
        resp = audit_api_client.put(
            f"/api/v1/audit/alerts/{fake_id}/resolve",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404



# ═══════════════════════════════════════════════════════════════════════════════
# 6. FirewallService Integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestFirewallServiceIntegration:
    """Tests that store_memory() correctly appends to the hash chain."""

    @staticmethod
    def _make_tenant_and_session(db_session, name_suffix: str):
        """Helper: create a Tenant + AgentSession with all required fields."""
        import hashlib, secrets
        t_id = uuid.uuid4()
        api_key_raw = secrets.token_urlsafe(24)
        api_key_hash = hashlib.sha256(api_key_raw.encode()).hexdigest()
        tenant = Tenant(
            id=t_id,
            name=f"{name_suffix}-tenant",
            slug=f"{name_suffix}-{t_id.hex[:6]}",
            api_key_hash=api_key_hash,
        )
        db_session.add(tenant)
        db_session.flush()

        s_id = uuid.uuid4()
        session = AgentSession(
            id=s_id,
            tenant_id=tenant.id,
            agent_name=f"{name_suffix}-agent",
            session_token=secrets.token_urlsafe(16),
        )
        db_session.add(session)
        db_session.flush()
        return tenant, session

    def test_store_memory_creates_chain_entry(self, db_session):
        """
        store_memory() must write both a SecurityAuditEvent and an AuditLogEntry.
        """
        from src.models.audit import AuditLogEntry
        from src.services.firewall_service import store_memory

        tenant, session = self._make_tenant_and_session(db_session, "chain-test")

        before_count = db_session.query(AuditLogEntry).count()
        store_memory(
            db=db_session,
            tenant_id=tenant.id,
            session_id=session.id,
            text="Hello, my name is Alice.",
        )
        after_count = db_session.query(AuditLogEntry).count()
        assert after_count == before_count + 1

    def test_chain_entry_has_valid_hash(self, db_session):
        """
        The AuditLogEntry created by store_memory() must have a correctly
        computed entry_hash that passes re-computation.
        """
        from src.models.audit import AuditLogEntry
        from src.services.firewall_service import store_memory

        tenant, session = self._make_tenant_and_session(db_session, "hash-verify")

        store_memory(
            db=db_session,
            tenant_id=tenant.id,
            session_id=session.id,
            text="Safe text with no PII.",
        )

        entry = (
            db_session.query(AuditLogEntry)
            .order_by(AuditLogEntry.sequence_number.desc())
            .first()
        )
        assert entry is not None

        from datetime import timezone as _tz
        # Normalize created_at to UTC-aware ISO format (same logic as _entry_to_hash_inputs)
        _dt = entry.created_at
        if hasattr(_dt, 'tzinfo') and _dt.tzinfo is None:
            _dt = _dt.replace(tzinfo=_tz.utc)
        _created_at_iso = _dt.isoformat()

        recomputed = compute_entry_hash(
            sequence_number=entry.sequence_number,
            tenant_id=str(entry.tenant_id) if entry.tenant_id else None,
            event_type=entry.event_type,
            severity=entry.severity,
            actor=entry.actor,
            action=entry.action,
            resource=entry.resource,
            payload=entry.payload,
            created_at_iso=_created_at_iso,
            previous_hash=entry.previous_hash,
        )
        assert entry.entry_hash == recomputed


    def test_chain_verify_passes_after_store_memory(self, db_session):
        """
        verify_chain() must return is_valid=True after one or more store_memory() calls.
        """
        from src.services.firewall_service import store_memory

        tenant, session = self._make_tenant_and_session(db_session, "verify")

        for text in ["Clean text", "More clean text", "Still clean"]:
            store_memory(
                db=db_session,
                tenant_id=tenant.id,
                session_id=session.id,
                text=text,
            )

        result = AuditLogger().verify_chain(db=db_session, raise_alert_on_tamper=False)
        assert result.is_valid is True
        assert result.total_entries >= 3

    def test_inspect_text_does_not_write_chain_entry(self, db_session):
        """
        inspect_text() must NOT append any AuditLogEntry (stateless path).
        """
        from src.models.audit import AuditLogEntry
        from src.services.firewall_service import inspect_text

        tenant, _ = self._make_tenant_and_session(db_session, "inspect")

        before_count = db_session.query(AuditLogEntry).count()
        inspect_text(db=db_session, tenant_id=tenant.id, text="Hello world")
        after_count = db_session.query(AuditLogEntry).count()

        assert after_count == before_count  # no chain entry written


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Performance Benchmarks
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerformanceBenchmarks:
    """Ensure hash computation and chain verification stay within latency budgets."""

    def test_1000_hash_computations_under_500ms(self):
        """Computing 1000 entry hashes must complete in under 500ms."""
        start = time.perf_counter()
        prev = GENESIS_HASH
        for i in range(1, 1001):
            h = compute_entry_hash(**_make_entry_kwargs(seq=i, previous_hash=prev))
            prev = h
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500, f"1000 hash computations took {elapsed_ms:.1f}ms (> 500ms)"

    def test_verify_100_valid_entries_under_100ms(self):
        """Verifying a 100-entry chain must complete in under 100ms."""
        # Build 100 valid mock entries
        entries = []
        prev = GENESIS_HASH
        for i in range(1, 101):
            e = _build_mock_entry(seq=i, previous_hash=prev)
            entries.append(e)
            prev = e.entry_hash

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.all.return_value = entries
        mock_query.filter.return_value = mock_query

        start = time.perf_counter()
        result = AuditLogger().verify_chain(db=mock_db, raise_alert_on_tamper=False)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result.is_valid is True
        assert elapsed_ms < 100, f"100-entry verify took {elapsed_ms:.1f}ms (> 100ms)"

    def test_chain_verification_result_structure(self):
        """ChainVerificationResult has all required fields with correct types."""
        r = ChainVerificationResult(
            is_valid=True,
            total_entries=5,
            first_broken_sequence=None,
            broken_entries=[],
            verification_time_ms=12.5,
        )
        assert isinstance(r.is_valid, bool)
        assert isinstance(r.total_entries, int)
        assert r.first_broken_sequence is None
        assert isinstance(r.broken_entries, list)
        assert isinstance(r.verification_time_ms, float)
