# Day 3: Python Dependencies & Alembic Migration Framework

This document outlines the decisions, configuration patterns, and dependency selections established during the **Day 3: Python Dependencies & Alembic** phase.

---

## 1. Dependency Manifest & Version Pinning

### Decision: Modernized `requirements.txt`
Dependencies were updated with explicit constraints across four main categories:
1. **Web Core:** `fastapi>=0.104.0`, `uvicorn[standard]>=0.24.0`
2. **Database & ORM:** `sqlalchemy>=2.0.23`, `alembic>=1.13.0`, `psycopg2-binary>=2.9.9`, `asyncpg>=0.29.0`, `greenlet>=3.0.0`
3. **Configuration:** `pydantic>=2.5.0`, `pydantic-settings>=2.1.0`, `python-dotenv>=1.0.0`
4. **Testing & QA:** `pytest>=7.4.0`, `pytest-asyncio>=0.21.0`, `httpx>=0.25.0`, `black>=23.11.0`, `flake8>=6.1.0`

---

## 2. Alembic Migration Strategy

### Decision: Environment-Aware Dynamic `migrations/env.py`
Instead of static connection strings inside `alembic.ini`, `migrations/env.py` programmatically imports `config.settings.sync_database_url` and binds `target_metadata = Base.metadata`.

### Benefits:
- Single source of truth for database credentials via `.env`.
- Supports automated offline SQL generation (`alembic upgrade base:head --sql`) for CI/CD security audits and production DBA reviews.
- Automatically captures all models registered under `src.models`.
