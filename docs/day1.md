# AI Memory Firewall — Architecture & Design Decisions

This document outlines the architectural choices, component designs, and engineering trade-offs established during the **Day 1: Project Initialization** phase.

---

## 1. Project Folder Structure

### Decision: Modular `src/` Layout
```
AI memory Firewall/
├── src/              # Application source code
├── tests/            # Automated test suite
├── migrations/       # Alembic database migration scripts
├── config/           # Configuration files and schemas
├── docs/             # Technical and architecture documentation
├── scripts/          # Deployment and utility scripts
├── main.py           # Application runtime entrypoint
├── requirements.txt  # Project dependency manifest
├── .env.example      # Environment variable template
└── .gitignore        # Version control ignore rules
```

### Alternative Considered: Flat Root Structure
Putting all modules (e.g., `app.py`, `models.py`, `tests.py`) directly in the root directory.

### Why this choice was made:
- **Prevents Circular Imports & Namespace Clutter:** Grouping domain logic in [`src/`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src) isolates core application code from project configuration files and tooling scripts.
- **Packaging & Testing Best Practices:** The `src/` layout is standard across Python packaging ecosystems, ensuring test runners test against installed/properly referenced packages rather than accidental local directory shadowing.

---

## 2. Application Architecture Pattern

### Decision: Application Factory Pattern (`create_app()`)
The FastAPI instance is generated through a factory function defined in [`src/app.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/app.py), while [`main.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/main.py) serves as the executable entrypoint.

### Alternative Considered: Global Static App Instance
Instantiating `app = FastAPI()` at top-level in `main.py`.

### Why this choice was made:
- **Testability:** Test suites in [`tests/`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/tests) can instantiate isolated app instances with mock databases, mock memory storage, or test settings without triggering server startup side-effects.
- **Dynamic Configuration:** Enables spinning up the application with different configurations (development, staging, testing) without altering the global application module state.

---

## 3. Web Framework Selection

### Decision: FastAPI + Uvicorn
Configured in [`requirements.txt`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/requirements.txt).

### Alternatives Considered: Flask or Django

### Why this choice was made:
- **Asynchronous Throughput:** An AI Memory Firewall serves as a real-time security proxy inspecting incoming prompts and memory streams. FastAPI's native `async`/`await` architecture delivers high concurrency and low latency.
- **Data Validation & Typing:** FastAPI integrates Pydantic for request/response serialization and schema enforcement.
- **Automatic API Documentation:** Out-of-the-box Interactive OpenAPI (Swagger) and ReDoc interfaces accelerate API inspection and testing.
- **Lightweight Footprint:** Unlike Django, FastAPI does not impose a monolithic MVC structure or rigid ORM constraints.

---

## 4. Database & Migration Layer

### Decision: SQLAlchemy 2.0 + Alembic + PostgreSQL
Included `sqlalchemy>=2.0.0`, `alembic>=1.12.0`, and `psycopg2-binary>=2.9.9`.

### Alternatives Considered: Raw SQL / Django ORM / SQLite
- **SQLAlchemy 2.0:** Delivers modern type hints, async database session support, and SQL injection protection.
- **Alembic:** Provides deterministic, version-controlled schema migrations that are safe for CI/CD pipelines.
- **PostgreSQL:** Enterprise-grade relational database with ACID compliance, robust concurrency controls, and native support for JSONB / vector extensions (essential for AI memory and embedding guardrails).

---

## 5. Configuration & Secret Management

### Decision: 12-Factor Environment Variables (`.env` & `.env.example`)
Configured [`.env.example`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/.env.example) as a committed blueprint and `.env` for local credentials.

### Alternative Considered: Hardcoded Configurations
Hardcoding database strings or credentials directly inside Python configuration files.

### Why this choice was made:
- **Security:** Prevents accidental leakage of production credentials or secrets to public or shared Git repositories.
- **12-Factor App Compliance:** Allows seamless configuration transitions across development, testing, staging, and production environments without modifying codebase files.

---

## 6. Version Control Hygiene

### Decision: Comprehensive `.gitignore` before First Commit
Created a detailed [`.gitignore`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/.gitignore) covering virtual environments, credentials, build artifacts, OS files, and caches.

### Alternative Considered: Late Git Configuration
Initializing `.gitignore` after writing code.

### Why this choice was made:
- Committing virtual environments (thousands of library files) or `.env` files permanently pollutes Git commit history and is tedious to scrub retrospectively.

---

## 7. Environment Isolation

### Decision: Standard Python `venv`
Created a localized `venv/` directory using standard `python -m venv venv`.

### Alternative Considered: System-wide Python installation
- Isolates dependencies strictly to the project, preventing dependency version conflicts with other Python projects on the machine.

---

## Decision Summary Matrix

| Category | Selection | Alternative | Primary Advantage |
| :--- | :--- | :--- | :--- |
| **Directory Structure** | `src/` modular layout | Flat root folder | Prevents namespace conflicts & aids scaling |
| **App Architecture** | Factory (`create_app`) | Global `app` variable | Enables isolated testing and dynamic configs |
| **Web Framework** | FastAPI + Uvicorn | Flask / Django | Native asynchronous execution & Pydantic validation |
| **Database & Migrations** | SQLAlchemy 2.0 + Alembic | Raw SQL / No migrations | Type safety & trackable schema version control |
| **Secrets & Config** | `.env` + `.env.example` | Hardcoded values | 12-factor compliance & secret leak prevention |
| **Version Control** | Preemptive `.gitignore` | Late configuration | Clean repository history without binary clutter |
| **Environment** | Python `venv` | Global Python | Dependency isolation |
