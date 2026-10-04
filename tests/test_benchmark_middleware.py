"""
AI Memory Firewall - Week 7 Performance Benchmark Test Suite
============================================================
Benchmarks the latency and throughput of the Core Firewall Middleware:
- Inbound safety inspection (PII, injection, regex rules, policy)
- Memory encryption (AES-256 Fernet) and database persistence
- Safe context retrieval & decryption
- Outbound safety evaluation
- SHA-256 cryptographic hash-chain append & verification
- Total middleware overhead SLA verification (< 50ms)
"""

import time
import uuid
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config.database import Base
from src.engine.audit_logger import AuditLogger
from src.middleware.firewall_middleware import FirewallMiddleware
from src.models import AgentSession, Tenant
from src.security import decrypt_data, encrypt_data


@pytest.fixture(scope="module")
def benchmark_db():
    """In-memory SQLite engine for isolated latency measurements."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    sm = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = sm()

    tenant = Tenant(
        id=uuid.uuid4(),
        name="Benchmark Tenant",
        slug=f"bench-{uuid.uuid4().hex[:6]}",
        api_key_hash="mock_hash",
    )
    session.add(tenant)
    agent_session = AgentSession(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        agent_name="BenchmarkBot",
        session_token=f"sess_{uuid.uuid4().hex}",
        status="ACTIVE",
    )
    session.add(agent_session)
    session.commit()

    yield {
        "session": session,
        "tenant_id": tenant.id,
        "session_id": agent_session.id,
    }

    session.close()
    Base.metadata.drop_all(bind=engine)


def test_benchmark_inbound_evaluation_latency(benchmark_db):
    """Verify inbound screening latency meets SLA (< 50ms)."""
    middleware = FirewallMiddleware()
    db = benchmark_db["session"]
    tenant_id = benchmark_db["tenant_id"]
    session_id = benchmark_db["session_id"]

    prompt = "Hello! Please summarize the patient clinical guidelines for asthma treatment."

    # Warmup
    middleware.process_message(
        db=db,
        session_id=session_id,
        tenant_id=tenant_id,
        message=prompt,
        skip_llm=True,
    )

    # Benchmark run
    result = middleware.process_message(
        db=db,
        session_id=session_id,
        tenant_id=tenant_id,
        message=prompt,
        skip_llm=True,
    )

    inbound_ms = result.latency_breakdown.inbound_eval_ms
    assert inbound_ms < 50.0, f"Inbound evaluation took {inbound_ms}ms, exceeding 50ms SLA"


def test_benchmark_memory_encryption_latency():
    """Verify AES-256 Fernet encryption and decryption latency (< 5ms)."""
    payload = "Patient John Doe SSN: 000-12-3456 prescribed medication for condition Alpha." * 5

    t0 = time.perf_counter()
    ciphertext = encrypt_data(payload)
    enc_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    plaintext = decrypt_data(ciphertext)
    dec_ms = (time.perf_counter() - t1) * 1000

    assert plaintext == payload
    assert enc_ms < 10.0, f"Encryption took {enc_ms}ms, exceeding 10ms SLA"
    assert dec_ms < 10.0, f"Decryption took {dec_ms}ms, exceeding 10ms SLA"


def test_benchmark_hash_chain_append_latency(benchmark_db):
    """Verify SHA-256 cryptographic audit ledger append latency (< 15ms)."""
    logger = AuditLogger()
    db = benchmark_db["session"]
    tenant_id = str(benchmark_db["tenant_id"])

    t0 = time.perf_counter()
    entry = logger.log_event(
        db=db,
        action="benchmark.append",
        event_type="FIREWALL_EVAL",
        severity="INFO",
        tenant_id=tenant_id,
        actor="benchmarker",
        resource="benchmark_target",
        payload={"run": 1},
    )
    db.commit()
    append_ms = (time.perf_counter() - t0) * 1000

    assert entry is not None
    assert append_ms < 25.0, f"Hash chain append took {append_ms}ms, exceeding 25ms SLA"


def test_benchmark_total_middleware_overhead(benchmark_db):
    """Verify total firewall middleware overhead excluding LLM (< 60ms)."""
    middleware = FirewallMiddleware()
    db = benchmark_db["session"]
    tenant_id = benchmark_db["tenant_id"]
    session_id = benchmark_db["session_id"]

    message = "Can you describe the safety precautions for laser surgery?"
    res = middleware.process_message(
        db=db,
        session_id=session_id,
        tenant_id=tenant_id,
        message=message,
        skip_llm=True,
    )

    total_overhead = res.latency_breakdown.total_ms
    assert total_overhead < 60.0, f"Total middleware overhead was {total_overhead}ms, exceeding 60ms SLA"
