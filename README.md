# AI Memory Firewall

A security layer for AI memory systems — preventing unauthorized data access, injection attacks, and information leakage across AI agent sessions.

## Project Structure

```
AI memory Firewall/
├── src/              # Application source code
├── tests/            # Unit and integration tests
├── migrations/       # Alembic database migrations
├── config/           # Configuration files
├── docs/             # Project documentation
├── scripts/          # Utility scripts
├── main.py           # Application entry point
├── requirements.txt  # Python dependencies
├── .env.example      # Environment variable template
└── .env              # Local environment variables (not committed)
```

## Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL 15+
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

5. **Run the application**
   ```bash
   python main.py
   ```

## Development Roadmap

| Day | Task |
|-----|------|
| Day 1 | Project Initialization ✅ |
| Day 2 | PostgreSQL Setup |
| Day 3 | Python Dependencies & Alembic |
| Day 4–5 | SQLAlchemy Models & Database Schema |
| Day 6–7 | Review & Finalization |
