# AI Memory Firewall

A real-time security and guardrail layer for AI memory systems — preventing unauthorized data access, prompt injection attacks, and sensitive information leakage across AI agent sessions.

## Project Structure

```
AI memory Firewall/
├── src/                  # Application source code
│   ├── engine/           # Security Engine (PII, Injection, Classifier, Policy, Redactor, Evaluator)
│   ├── models/           # SQLAlchemy 2.0 models (Tenant, Session, Memory, User, APIKey, Policy)
│   ├── schemas/          # Pydantic schemas (Firewall, Memory, Policy, Auth)
│   ├── services/         # Business logic & database orchestration (PolicyService, etc.)
│   ├── api/              # FastAPI REST routers (/api/v1, /auth, /policies)
│   ├── security.py       # Cryptography & Auth (AES-256 Fernet, bcrypt, JWT, API keys)
│   └── app.py            # FastAPI application factory
├── tests/                # Automated pytest suite (238 unit & integration tests)
├── migrations/           # Alembic database migrations & versions
├── config/               # Pydantic settings & database engines
├── docs/                 # Architectural documentation & weekly milestone summaries
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
   # Edit .env with your database credentials and secret keys
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

## API Endpoints Reference

### Authentication & Authorization
| Method | Endpoint | Auth | Description |
|:------:|:---------|:----:|:------------|
| `POST` | `/auth/register` | None | Register new user account |
| `POST` | `/auth/login` | None | Authenticate credentials, return JWT access + refresh pair |
| `POST` | `/auth/refresh` | None | Exchange refresh token for new access token |
| `GET`  | `/auth/me` | Bearer | Retrieve authenticated user profile |
| `POST` | `/auth/api-keys` | Bearer | Generate machine API key for AI agents |
| `GET`  | `/auth/api-keys` | Bearer | List user API keys |
| `DELETE`| `/auth/api-keys/{id}` | Bearer | Revoke/deactivate an API key |

### Firewall & Memory Operations (v1)
| Method | Endpoint | Description |
|:------:|:---------|:------------|
| `POST` | `/api/v1/firewall/inspect` | Real-time text inspection & PII redaction |
| `POST` | `/api/v1/memory/store` | Inspect & store memory record with quarantine check |
| `GET`  | `/api/v1/memory/{session_id}` | Retrieve safe agent memories |
| `POST` | `/api/v1/rules` | Create custom tenant firewall rule |
| `GET`  | `/api/v1/rules/{tenant_id}` | List tenant firewall rules |
| `GET`  | `/api/v1/audit/events` | Query security audit log |
| `GET`  | `/health` | Service health check |
| `GET`  | `/docs` | Interactive API documentation (Swagger) |

