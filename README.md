# 🛡️ AI Memory Firewall

**AI Memory Firewall** is an enterprise-grade, real-time zero-trust security and privacy guardrail layer for AI memory and agent systems. It prevents prompt injection attacks, unauthorized memory persistence, and sensitive information leakage (PII/PHI) across AI conversational sessions.

---

## 🚀 Key Features

* **Real-Time Inbound Inspection:** Heuristic and rule-based detection for prompt injection attacks (instruction overrides, jailbreaks, system extraction).
* **Automated PII & PHI Sanitization:** Deep-scan classification using Microsoft Presidio and regex for automatic masking/redaction of sensitive data (SSN, medical records, financial data).
* **Interactive Privacy Gate:** Empowers users with interactive prompt decisions (`ALLOW`, `REDACT`, `ASK_USER`, `BLOCK`, `QUARANTINE`).
* **Field-Level Encryption:** Quarantined and critical memory records are encrypted at rest using AES-256 (Fernet).
* **Tamper-Evident Audit Ledger:** Cryptographic SHA-256 hash-chained audit logging to guarantee immutable compliance records.
* **Unified Streamlit UI:** Complete web portal featuring a user chat assistant, interactive policy prompt modals, and an administrative security control center.

---

## 🛠️ Current Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **User Interface** | **Streamlit** (Custom-styled modern dashboard, interactive chat, admin monitor) |
| **Core Backend & API** | **Python 3.11+**, **FastAPI**, **Uvicorn** |
| **AI / LLM Integration** | **Google Gemini** (`gemini-2.5-flash`) via OpenAI-compatible API client with automated resilience |
| **NLP & Safety Engines** | **Microsoft Presidio** (`presidio-analyzer`, `presidio-anonymizer`), **SpaCy**, Custom Heuristic Policy Engine |
| **Database & ORM** | **SQLite (WAL Mode)** for zero-latency concurrent local access / **PostgreSQL** ready, **SQLAlchemy 2.0 ORM** |
| **Data Migrations** | **Alembic** (Version-controlled schema migrations) |
| **Cryptography & Auth** | **AES-256 (Fernet)**, **Bcrypt**, **PyJWT (JSON Web Tokens)**, SHA-256 Chain |
| **Validation & Config** | **Pydantic v2**, **pydantic-settings** |
| **Testing** | **Pytest**, **pytest-asyncio**, **HTTPX** |

---

## 📂 Project Structure

```
AI memory Firewall/
├── config/              # Application settings & SQLite WAL engine configuration
│   ├── database.py      # SQLAlchemy 2.0 engine, WAL pragmas, session factories
│   └── settings.py      # Pydantic v2 typed environment settings
├── migrations/          # Alembic schema versions & migrations
├── scripts/             # Maintenance and database seeding
│   ├── benchmark_middleware.py
│   └── seed_demo.py     # Default tenant, policies, and credentials seed
├── src/                 # Core firewall source code
│   ├── api/             # FastAPI routers & dependencies
│   ├── engine/          # Security evaluation, PII detection & prompt injection rules
│   ├── middleware/      # End-to-end FirewallMiddleware pipeline
│   ├── models/          # Declarative SQLAlchemy ORM models
│   ├── schemas/         # Pydantic request/response schemas
│   ├── services/        # Policy, decision, and LLM services
│   ├── app.py           # FastAPI application factory
│   └── security.py      # AES-256, Bcrypt, and JWT cryptographic utilities
├── tests/               # Automated unit and integration test suite
├── .streamlit/          # Streamlit UI configuration
├── alembic.ini          # Alembic configuration
├── firewall.db          # Active SQLite database (WAL enabled)
├── main.py              # Main application launcher (seeds DB & starts Streamlit)
├── requirements.txt     # Python dependencies
├── streamlit_app.py     # Streamlit Web Application
├── .env.example         # Environment variable template
└── README.md            # Project documentation
```

---

## ⚡ Getting Started

### 1. Prerequisites
* **Python 3.11+**
* **Git**

### 2. Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Trisshita/AI-Memory-Firewall.git
   cd "AI memory Firewall"
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to configure your API keys (e.g. `GEMINI_API_KEY`, `ENCRYPTION_KEY`, etc.).

---

## 🖥️ Running the Application

To seed default database credentials and start the Streamlit web interface:

```bash
python main.py
```

Open your browser at **`http://localhost:8501`** to access the AI Memory Firewall:
* **User Portal:** Interact with the AI assistant, test sensitive medical/PII prompts, and test prompt injection defenses.
* **Security Admin Center:** Log in with default admin credentials (`admin1@gmail.com` / `admin@123`) to view live inspection logs, registered users, and policy triggers.

---

## 🧪 Running Tests

Run the automated pytest test suite:
```bash
pytest -v
```
