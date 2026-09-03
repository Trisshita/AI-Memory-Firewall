# AI Memory Firewall

A real-time security and guardrail layer for AI memory systems — preventing unauthorized data access, prompt injection attacks, and sensitive information leakage across AI agent sessions.

## Project Structure

```
AI memory Firewall/
├── src/                  # Application source code
│   ├── engine/           # Security Evaluation Engine (PII + Injection + Evaluator)
│   ├── models/           # SQLAlchemy 2.0 domain models & enums
│   ├── schemas/          # Pydantic request/response schemas
│   ├── services/         # Business logic & database orchestration
│   ├── api/              # FastAPI REST routers (/api/v1)
│   └── app.py            # FastAPI application factory
├── tests/                # Automated pytest suite & fixtures
├── migrations/           # Alembic database migrations & versions
├── config/               # Pydantic settings & database engines
├── docs/                 # Architectural decision records (ADRs)
├── scripts/              # Utility & maintenance scripts
├── alembic.ini           # Alembic migration configuration
├── main.py               # Application entry point
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variable template
└── .env                  # Local environment variables (not committed)
```

## Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL 15+ (or SQLite for local dev/testing)
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd "AI memory Firewall"
   ```

2. **Activate the virtual environment**
   ```bash
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Run automated tests**
   ```bash
   pytest -v
   ```

7. **Run the application**
   ```bash
   python main.py
   ```

## Development Roadmap

| Milestone | Task | Status |
|---|---|:---:|
| **Day 1** | Project Initialization & Scaffolding | ✅ Completed |
| **Day 2** | PostgreSQL Setup & Connection Architecture | ✅ Completed |
| **Day 3** | Python Dependencies & Alembic Migration Framework | ✅ Completed |
| **Day 4–5** | SQLAlchemy 2.0 Models & Database Schema | ✅ Completed |
| **Day 6–7** | Security Evaluation Engine, REST API & Week 1 Finalization | ✅ Completed |

## Documentation

- [Day 1: Architecture & Design Decisions](docs/day1.md)
- [Day 2: PostgreSQL Setup & Architecture](docs/day2.md)
- [Day 3: Dependencies & Migration Framework](docs/day3.md)
- [Day 4–5: SQLAlchemy Models & Database Schema](docs/day4-5.md)
- [Day 6–7: Security Evaluation Engine & REST API](docs/day6-7.md)

## API Endpoints (v1)

| Method | Endpoint | Description |
|:------:|:---------|:------------|
| `POST` | `/api/v1/firewall/inspect` | Real-time text inspection |
| `POST` | `/api/v1/memory/store` | Inspect & store memory record |
| `GET` | `/api/v1/memory/{session_id}` | Retrieve safe agent memories |
| `POST` | `/api/v1/rules` | Create custom firewall rule |
| `GET` | `/api/v1/rules/{tenant_id}` | List tenant firewall rules |
| `GET` | `/api/v1/audit/events` | Query security audit log |
| `GET` | `/health` | Service health check |
| `GET` | `/docs` | Interactive API documentation (Swagger) |
