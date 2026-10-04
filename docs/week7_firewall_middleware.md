# Week 7 Comprehensive Guide: Core Firewall Middleware & OpenAI Integration

> **Audience**: AI Engineers, Security Architects & Backend Developers  
> **Goal**: Understand the complete unified firewall middleware, inbound/outbound safety gates, AES-256 Fernet memory encryption, context recall isolation, OpenAI integration, REST API routes, and performance benchmarks introduced in Week 7.

---

## 1. Executive Summary

In Weeks 1–6, the AI Memory Firewall implemented individual security modules:
- **Week 1**: Core rule evaluators, regex patterns, and foundational REST API.
- **Week 2**: Authentication (JWT, API keys) and AES-256 field-level encryption.
- **Week 3**: Sensitivity classification (spaCy NLP, Presidio, rule heuristics).
- **Week 4**: Policy engine with RBAC and contextual risk limits.
- **Week 5**: Data redactor with strategy-aware masking, hashing, and synthetic placeholders.
- **Week 6**: Tamper-proof SHA-256 hash-chain audit logging and automatic security alerting.

**Week 7 wires all these subsystems together into a single, high-performance middleware pipeline (`FirewallMiddleware`) and integrates directly with OpenAI's Chat Completions API.**

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         AI MEMORY FIREWALL (WEEK 7)                         │
 │                                                                             │
 │                     POST /api/message · POST /api/v1/message                │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                         ┌──────────────▼──────────────┐
                         │  1. Inbound Evaluation      │
                         │  • PII Detection (8 types)  │
                         │  • Injection Detection      │
                         │  • NLP Sensitivity Classify │
                         │  • Policy Engine / RBAC     │
                         │  • Strategy-Aware Redactor  │
                         └──────────────┬──────────────┘
                                        │
                        ┌───────────────┴───────────────┐
                        │ Risk >= 0.80 / Quarantine?   │
                        └───────┬───────────────┬───────┘
                                │ YES           │ NO
                                ▼               ▼
                 ┌───────────────────────┐ ┌───────────────────────────────────┐
                 │ 2. Short-Circuit Gate │ │ 3. Memory Encryption & Inbound    │
                 │ • Encrypt raw prompt  │ │ • Encrypt raw with AES-256 Fernet │
                 │ • Store quarantined   │ │ • Store sanitized text in DB      │
                 │ • Log hash-chain alert│ │ • Calculate SHA-256 content hash  │
                 │ • HALT (No LLM call)  │ └─────────────────┬─────────────────┘
                 └───────────────────────┘                   │
                                                             ▼
                                           ┌───────────────────────────────────┐
                                           │ 4. Context Synthesis              │
                                           │ • Recall safe history from DB     │
                                           │ • Isolate quarantined records     │
                                           │ • Format conversation payload     │
                                           └─────────────────┬─────────────────┘
                                                             │
                                                             ▼
                                           ┌───────────────────────────────────┐
                                           │ 5. OpenAI LLM Execution           │
                                           │ • Live Chat Completions or        │
                                           │ • Deterministic Mock Provider     │
                                           └─────────────────┬─────────────────┘
                                                             │
                                                             ▼
                                           ┌───────────────────────────────────┐
                                           │ 6. Outbound Evaluation            │
                                           │ • Screen LLM response for PII/leak│
                                           │ • Suppress if blocked / redact    │
                                           └─────────────────┬─────────────────┘
                                                             │
                                                             ▼
                                           ┌───────────────────────────────────┐
                                           │ 7. Outbound Storage & Audit Log   │
                                           │ • Encrypt & store assistant reply │
                                           │ • Seal turn in SHA-256 hash-chain │
                                           │ • Auto-raise alert if high risk   │
                                           └─────────────────┬─────────────────┘
                                                             │
                                                             ▼
                                                 [Structured JSON Response]
```

---

## 2. Core Middleware Architecture (`firewall_middleware.py`)

### 2.1. Inbound Evaluation Pipeline
Every incoming prompt is passed through `FirewallEvaluator.evaluate()`:
1. **Tenant Active Rules**: Priority-ordered regex, keyword, and custom filters.
2. **Sensitivity Classification**: Multilabel tagging (`SECRETS`, `PII`, `FINANCIAL`, `CONFIDENTIAL`).
3. **Prompt Injection & Jailbreak Detector**: 6 attack categories including `INSTRUCTION_OVERRIDE` and `JAILBREAK`.
4. **Policy Engine**: Validates role access, action permissions, and sensitivity tier constraints.
5. **Data Redactor**: Applies strategy-aware masking (e.g. `pa***@***.com`).

### 2.2. Short-Circuit Safety Gate
If an attacker sends malicious prompts (e.g., prompt injection or critical attack payloads), the firewall immediately:
- Flags decision as `BLOCK` or `QUARANTINE`.
- Encrypts the raw attack payload using **AES-256 Fernet**.
- Stores the record marked as `is_quarantined = True`.
- Logs the security incident to the tamper-proof **SHA-256 hash chain**.
- Auto-raises a **CRITICAL/HIGH** security alert.
- **Short-circuits execution**: The OpenAI API is **never invoked**, protecting LLM context, billing, and backend security.

### 2.3. Memory Encryption & Quarantine Isolation
- **Encryption at Rest**: `MemoryRecord.raw_content` stores authenticated AES-256 Fernet ciphertext (`gAAAA...`). Plaintext secrets never touch the database columns.
- **Context Isolation**: When retrieving past conversational context for multi-turn sessions (`_retrieve_safe_context`), queries strictly filter `is_quarantined == False`. Quarantined records can never be recalled into future LLM prompts.

---

## 3. OpenAI Integration (`openai_service.py`)

Located at `src/services/openai_service.py`.

### Features
- **Production Chat Completions**: Communicates with `https://api.openai.com/v1/chat/completions` using asynchronous or synchronous `httpx`.
- **Configurable Models**: Supports `gpt-4o-mini`, `gpt-4o`, `gpt-3.5-turbo`, custom system prompts, temperature, and max tokens.
- **Deterministic Mock Simulation**: When `OPENAI_API_KEY` is a placeholder, unset, or during test execution, the service generates realistic, context-aware synthetic responses without requiring network access or external API credits.
- **Explicit Mock Injection**: Supports `mock_llm_response` in the request schema for 100% deterministic end-to-end integration testing.

---

## 4. API Specification

### Endpoints
- `POST /api/message`
- `POST /api/v1/message`

### Request Payload (`MessageRequest`)

```json
{
  "message": "Hello, can you help summarize my medical record?",
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "model": "gpt-4o-mini",
  "system_prompt": "You are a professional clinical assistant.",
  "temperature": 0.7,
  "max_tokens": 500,
  "skip_llm": false,
  "mock_llm_response": null
}
```

### Response Payload (`MessageResponse`)

```json
{
  "message_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "decision": "ALLOW",
  "inbound_risk_score": 0.05,
  "outbound_risk_score": 0.0,
  "reply": "I would be happy to help summarize your medical record.",
  "sanitized_prompt": "Hello, can you help summarize my medical record?",
  "violations": [],
  "memory_stored": true,
  "memory_encrypted": true,
  "audit_logged": true,
  "latency_ms": {
    "inbound_eval_ms": 8.42,
    "memory_store_ms": 0.85,
    "llm_ms": 12.10,
    "outbound_eval_ms": 4.15,
    "audit_log_ms": 1.02,
    "total_ms": 26.54
  },
  "is_mock": true
}
```

---

## 5. Performance Benchmarks

All pipeline stages were benchmarked across 20 iterations using `scripts/benchmark_middleware.py`:

| Pipeline Stage | Average Latency | P95 Latency | SLA Target | Status |
|:---|:---|:---|:---|:---|
| **1. Inbound Evaluation (Full Pipeline)** | **8.69 ms** | 11.22 ms | < 50.0 ms | **PASS** |
| **2. AES-256 Memory Encryption** | **0.033 ms** | 0.022 ms | < 5.0 ms | **PASS** |
| **3. AES-256 Memory Decryption** | **0.017 ms** | 0.027 ms | < 5.0 ms | **PASS** |
| **4. SHA-256 Hash-Chain Append** | **0.91 ms** | 4.44 ms | < 20.0 ms | **PASS** |
| **5. Total Middleware Overhead (excl. LLM)** | **13.26 ms** | **23.11 ms** | < 60.0 ms | **PASS** |

---

## 6. Verification & Test Suite

Run the full E2E test suite and benchmarks:

```powershell
# Run 24 End-to-End test scenarios
.\venv\Scripts\pytest tests\test_e2e_middleware.py -v

# Run performance benchmark assertions
.\venv\Scripts\pytest tests\test_benchmark_middleware.py -v

# Execute standalone benchmark report
.\venv\Scripts\python scripts\benchmark_middleware.py

# Run complete repository test suite (310 tests)
.\venv\Scripts\pytest
```
