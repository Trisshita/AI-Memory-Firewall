# Day 2: PostgreSQL Setup & Architecture Decisions

This document outlines the architectural decisions and configuration patterns established during the **Day 2: PostgreSQL Setup** phase.

---

## 1. Database Engine & Dialect Selection

### Decision: PostgreSQL as Primary Store with Connection Pooling
- **Driver (Async):** `asyncpg` for high-throughput, non-blocking asynchronous FastAPI endpoints.
- **Driver (Sync):** `psycopg2-binary` for Alembic migrations, database administrative CLI scripts, and synchronous worker operations.
- **Connection Pooling:** Configured with `pool_pre_ping=True`, `pool_size=10`, and `max_overflow=20` to guarantee resilience against dropped connections and sudden traffic surges.

### Why this choice was made:
- AI Memory Firewall evaluates high-frequency prompt streams and conversational memories. The asynchronous `asyncpg` driver provides native binary protocol serialization and minimal overhead under high concurrency.
- `psycopg2-binary` remains the industry gold standard for Alembic schema migrations and operational stability.

---

## 2. Dynamic Connection URL Resolution

### Decision: Pydantic-driven Environment Mapping (`config/settings.py`)
Application settings dynamically compute:
- `sync_database_url`: `postgresql+psycopg2://...`
- `async_database_url`: `postgresql+asyncpg://...`

### Why this choice was made:
- Eliminates hardcoded driver prefixes across multiple application modules.
- Supports single-variable override (`DATABASE_URL`) commonly supplied by modern cloud database providers (Neon, Supabase, AWS RDS, Railway).

---

## 3. Multi-Tenant Isolation Strategy

### Decision: Relational Foreign Key Segregation with UUID Primary Keys
All core tables (`agent_sessions`, `firewall_rules`, `security_audit_events`) enforce foreign key relationships linked to a root `Tenant` entity with `ON DELETE CASCADE`.

### Advantages:
- Prevents cross-tenant memory leakage at the database constraint level.
- Non-sequential UUIDv4 primary keys prevent enumeration attacks across agent sessions and security audit records.
