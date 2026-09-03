# Day 6–7: Security Evaluation Engine & REST API Finalization

This document details the technical design decisions, architecture patterns, and component implementations built during the **Day 6–7: Security Evaluation Engine & REST API** phase, completing Week 1 of the AI Memory Firewall.

---

## 1. Security Evaluation Engine Architecture

### Decision: Three-Stage Multi-Layer Inspection Pipeline

The `FirewallEvaluator` in [`src/engine/evaluator.py`](../src/engine/evaluator.py) orchestrates a sequential inspection pipeline:

```
[Input Text]
      │
      ▼
Stage 1: Custom Database Rules (REGEX_PATTERN, KEYWORD_FILTER)
      │
      ▼
Stage 2: Built-in PII Detector (SSN, Email, Credit Card, API Keys, AWS Keys, etc.)
      │
      ▼
Stage 3: Built-in Prompt Injection Detector (Jailbreaks, Overrides, Delimiter Attacks, Exfiltration)
      │
      ▼
Risk Score Aggregator (max signal + diminishing extras, capped at 1.0)
      │
      ▼
Final Decision Engine (ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT)
```

### Why this approach:
- **Stage ordering**: Custom rules run first, allowing tenant-specific policy to supersede built-in defaults when needed.
- **Layered detection**: PII and injection detectors are independent modules; each produces typed match objects that feed into the composite risk score.
- **Non-blocking design**: Invalid regex rules are caught and silently skipped — the firewall never crashes on a malformed tenant rule.

---

## 2. PII Detection Engine (`src/engine/pii.py`)

### Supported PII Entity Categories

| Entity Type     | Description                                  | Risk Weight |
|:----------------|:---------------------------------------------|:-----------:|
| `PRIVATE_KEY`   | PEM RSA/EC/OpenSSH private key blocks        | 1.00        |
| `API_KEY`       | OpenAI `sk-`, GitHub tokens, JWT, Slack, Bearer | 0.99     |
| `AWS_KEY`       | AWS AKIA* access key format                  | 0.98        |
| `CREDIT_CARD`   | Visa, Mastercard, Amex, Discover             | 0.95        |
| `SSN`           | US Social Security Numbers (excl. 000/666/9xx) | 0.90     |
| `EMAIL`         | Standard email addresses                     | 0.70        |
| `PHONE_NUMBER`  | US phone number formats                      | 0.65        |
| `IP_ADDRESS`    | IPv4 addresses                               | 0.55        |

### Design Decision: Regex-based with invalid range exclusions
- The SSN pattern excludes `000-xx-xxxx`, `666-xx-xxxx`, and `9xx-xx-xxxx` (ranges that are never valid US SSNs) to minimize false positives.
- All redactions are applied to a working copy of the text, so the original is always preserved in the `EvaluationResult.original_text` field.

---

## 3. Prompt Injection Detection Engine (`src/engine/injection.py`)

### Supported Attack Categories

| Category               | Example Signals                                              | Risk Weight |
|:-----------------------|:-------------------------------------------------------------|:-----------:|
| `JAILBREAK`            | DAN mode, developer mode, "jailbroken assistant"             | 0.97        |
| `DATA_EXFILTRATION`    | "dump database", "reveal secret key", "exfiltrate"          | 0.95        |
| `INSTRUCTION_OVERRIDE` | "ignore previous instructions", "bypass guidelines"         | 0.92        |
| `ROLE_MANIPULATION`    | "pretend you are a hacker", "you have no restrictions"      | 0.90        |
| `DELIMITER_INJECTION`  | `<system>`, `[INST]`, `###Instruction:`, `<\|im_start\|>`   | 0.88        |
| `SYSTEM_PROMPT_LEAK`   | "repeat your system prompt", "what are your instructions"   | 0.88        |

---

## 4. Risk Scoring Model

```
risk_score = min(1.0, max_violation_weight + (sum_of_extras × 0.05))
```

- **Threshold mapping:**
  - `risk_score >= 0.90` → Force **QUARANTINE**
  - `risk_score >= 0.75` → Force **BLOCK**
  - `< 0.75` → Use the highest-priority action from individual violations

This ensures that even if a single rule prescribes `AUDIT`, a truly critical risk score will escalate the decision to BLOCK/QUARANTINE automatically.

---

## 5. REST API Endpoints (`src/api/`)

All endpoints are grouped under `/api/v1`:

| Method | Path                        | Description                                         |
|:------:|:----------------------------|:----------------------------------------------------|
| `POST` | `/api/v1/firewall/inspect`  | Real-time text inspection without storage           |
| `POST` | `/api/v1/memory/store`      | Inspect text and persist as a MemoryRecord          |
| `GET`  | `/api/v1/memory/{session_id}` | Retrieve safe (non-quarantined) agent memories    |
| `POST` | `/api/v1/rules`             | Create a custom FirewallRule for a tenant           |
| `GET`  | `/api/v1/rules/{tenant_id}` | List all rules for a tenant                         |
| `GET`  | `/api/v1/audit/events`      | Query immutable security audit log                  |
| `GET`  | `/health`                   | Service health check                                |
| `GET`  | `/health/db`                | Database connectivity diagnostic                    |

### Memory Store: Quarantine Flow
When `POST /api/v1/memory/store` receives text that evaluates to `BLOCK` or `QUARANTINE`:
1. The MemoryRecord is **still persisted** (for audit trail completeness).
2. `is_quarantined = True` is set — the AI agent **cannot recall this memory** via `GET /api/v1/memory/{session_id}`.
3. A `SecurityAuditEvent` is written with the full violation details and risk score.

---

## 6. Firewall Service Layer (`src/services/firewall_service.py`)

The service layer orchestrates the four key operations:

1. **`load_active_rules()`** — Fetches active `FirewallRule` rows from DB, ordered by `priority_order ASC`, and maps them to evaluator-compatible dicts.
2. **`inspect_text()`** — Pure evaluation (no writes). Used by `/api/v1/firewall/inspect`.
3. **`store_memory()`** — Full pipeline: evaluate → persist MemoryRecord → write SecurityAuditEvent.
4. **`get_session_memories()`** — Returns clean, un-quarantined memories for agent recall.

### SHA-256 Content Hashing
Every MemoryRecord stores a `content_hash` (SHA-256 hex of the original raw text) enabling:
- **Deduplication detection** across sessions.
- **Tamper evidence** — the hash of the stored raw content can be verified against the original.

---

## 7. Testing Strategy

### Test Coverage Summary

| Test File                 | Tests | What is Verified                                             |
|:--------------------------|:-----:|:-------------------------------------------------------------|
| `test_engine.py`          |  48   | PII detection, injection detection, evaluator pipeline       |
| `test_firewall_api.py`    |  25   | All `/api/v1` endpoints with SQLite DB override fixture      |
| `test_models.py`          |   3   | ORM model creation and relationships                         |
| `test_app.py`             |   2   | Health endpoints                                             |
| `test_settings.py`        |   2   | Pydantic settings loading                                    |
| **Total**                 | **80**| **100% pass, 0 failures**                                    |

### Key Testing Patterns Applied
- **FastAPI Dependency Override**: `app.dependency_overrides[get_sync_db]` redirects all endpoint DB calls to an in-memory SQLite instance — no running PostgreSQL is required for any test.
- **Module-scoped seeding**: A `Tenant` and `AgentSession` with stable UUIDs are created once per test module, making all endpoint tests hermetic and fast.
- **Transactional isolation**: Each test operates on a shared SQLite DB; the seeded data persists within the module scope without cross-test interference.

---

## Decision Summary

| Component           | Decision                        | Rationale                                                          |
|:--------------------|:--------------------------------|:-------------------------------------------------------------------|
| **Evaluation stages** | 3-stage sequential pipeline   | Composable, independently testable, extensible                     |
| **PII detection**   | Regex with risk weights         | Zero-dependency, deterministic, runs in microseconds               |
| **Injection detection** | Regex pattern registry      | Covers all known LLM attack surface categories                     |
| **Risk scoring**    | Max signal + diminishing extras | Single critical signal drives the decision; extras add nuance      |
| **Memory quarantine** | Store & flag (not discard)    | Preserves audit trail; agents can't recall but admins can review   |
| **Test isolation**  | FastAPI dependency override + SQLite | Tests run without PostgreSQL; fast, reliable, portable        |
