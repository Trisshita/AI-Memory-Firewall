# Week 6 Comprehensive Guide: Audit Logging & Hash Chain

> **Audience**: Security Engineers, AI Platform Developers & Compliance Teams  
> **Goal**: Understand the tamper-proof global audit log, SHA-256 hash chain algorithm, chain integrity verification, security alert system, and all new REST endpoints introduced in Week 6.

---

## 1. Executive Summary

Weeks 1–5 built a complete firewall pipeline: PII detection → NLP classification → policy enforcement → data redaction → persistent audit events. However, the `SecurityAuditEvent` table written by `store_memory()` was a flat, append-only log with **no cryptographic protection**. An attacker with database access could silently alter or delete historical records without any detection mechanism.

**Week 6 introduces a tamper-proof, globally-shared SHA-256 hash chain audit log.** Every firewall evaluation is cryptographically sealed into an append-only ledger. If any historical record is modified or deleted, the entire chain breaks — and the system auto-raises an automatic **CRITICAL** security alert.

Key properties:

- **Global chain** — all tenants share a single monotonic sequence (no per-tenant fragmentation)
- **Append-only** — entries can never be updated or deleted without detection
- **Self-verifying** — any client can call `GET /audit/verify` to cryptographically confirm the entire chain is intact
- **Tiered access** — read/verify is available to all authenticated users; only admins can resolve alerts
- **Stateless inspect** — `inspect_text()` remains fully stateless and writes nothing to the chain

---

## 2. Architecture Overview

```
                     ┌─────────────────────────────────────────────┐
                     │     AI Memory Firewall – store_memory()     │
                     └────────────────────┬────────────────────────┘
                                          │
            ┌─────────────────────────────▼──────────────────────────────┐
            │ Stage 1–5.5: FirewallEvaluator Pipeline (Weeks 1–5)        │
            │  • PII detection → NLP classify → Policy → Redact          │
            │  • Returns: EvaluationResult (decision, risk_score, ...)   │
            └────────────────────┬───────────────────────────────────────┘
                                 │
            ┌────────────────────▼───────────────────────────────────────┐
            │ Persist MemoryRecord  (quarantine if needed)                │
            └────────────────────┬───────────────────────────────────────┘
                                 │
            ┌────────────────────▼───────────────────────────────────────┐
            │ Persist SecurityAuditEvent  (Weeks 1–5 legacy log)         │
            └────────────────────┬───────────────────────────────────────┘
                                 │
            ┌────────────────────▼───────────────────────────────────────┐
            │ AuditLogger.log_event()  (Week 6)  ← NEW                   │
            │                                                             │
            │  1. Fetch chain tail (MAX sequence_number)                  │
            │  2. previous_hash = tail.entry_hash                        │
            │     (or GENESIS_HASH = "000...0" for the first entry)      │
            │  3. Compute entry_hash:                                     │
            │       sha256( canonical_json + "|" + previous_hash )       │
            │  4. Persist AuditLogEntry to audit_log_entries table       │
            │                                                             │
            │  ┌──────────────────────────────────────┐                  │
            │  │ risk_score >= 0.80 ?                  │                  │
            │  │  YES → raise_alert(HIGH_RISK_EVENT)   │                  │
            │  │  NO  → skip                           │                  │
            │  └──────────────────────────────────────┘                  │
            └────────────────────────────────────────────────────────────┘
                                 │
                          db.commit()
```

### Chain Verification Path

```
GET /api/v1/audit/verify
          │
          ▼
AuditLogger.verify_chain()
          │
          ├── Fetch all AuditLogEntry ORDER BY sequence_number ASC
          │
          ├── For each entry:
          │     recomputed = sha256( canonical(entry) + "|" + expected_previous )
          │     if recomputed != entry.entry_hash → mark as BROKEN
          │     else → advance expected_previous = entry.entry_hash
          │
          └── Any broken entries?
                YES → is_valid=False + auto-raise CHAIN_TAMPER CRITICAL alert
                NO  → is_valid=True
```

---

## 3. Hash Chain Algorithm

### Formula

```
entry_hash = SHA-256( canonical_json + "|" + previous_hash )
```

### Canonical JSON

All fields are serialized as a JSON object with **sorted keys** and no extra whitespace. `None` values are serialized as JSON `null`.

```json
{
  "action": "memory.store",
  "actor": "192.168.1.1",
  "created_at": "2026-09-12T10:00:00+00:00",
  "event_type": "FIREWALL_EVAL",
  "payload": { "decision": "ALLOW", "risk_score": 0.12 },
  "resource": "session-uuid",
  "sequence_number": 1,
  "severity": "INFO",
  "tenant_id": "tenant-uuid-string"
}
```

> **Important:** `created_at` is always stored as a UTC-aware ISO-8601 string (with `+00:00` suffix). This normalization ensures hashes are consistent across different database backends (PostgreSQL, SQLite).

### Genesis Entry

The very first entry in the global chain uses:

```python
previous_hash = "0" * 64   # 64 zero characters = GENESIS_HASH
sequence_number = 1
```

### Sequential Chain Linkage

```
Entry 1:  entry_hash_1 = sha256( canonical_1 + "|" + "000...0" )
Entry 2:  entry_hash_2 = sha256( canonical_2 + "|" + entry_hash_1 )
Entry 3:  entry_hash_3 = sha256( canonical_3 + "|" + entry_hash_2 )
   ...
Entry N:  entry_hash_N = sha256( canonical_N + "|" + entry_hash_{N-1} )
```

If entry 3 is retroactively altered, its recomputed hash will differ from its stored `entry_hash_3`. Every subsequent entry will also fail because their `previous_hash` references the original (now incorrect) chain value.

---

## 4. Database Schema

### `audit_log_entries` — The Global Hash Chain

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary key |
| `sequence_number` | BIGINT | No | Global monotonic position (UNIQUE) |
| `tenant_id` | UUID → `tenants.id` | Yes | Tenant scope; NULL = system event |
| `event_id` | UUID → `security_audit_events.id` | Yes | Back-link to originating audit event |
| `event_type` | VARCHAR(50) | No | `FIREWALL_EVAL` \| `AUTH_EVENT` \| `POLICY_CHANGE` \| `SECURITY_ALERT` \| `SYSTEM` |
| `severity` | VARCHAR(20) | No | `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `actor` | VARCHAR(255) | Yes | Who triggered the event |
| `action` | VARCHAR(100) | No | Short action label e.g. `memory.store` |
| `resource` | VARCHAR(255) | Yes | Target resource identifier |
| `payload` | JSONB | Yes | Structured event data |
| `previous_hash` | VARCHAR(64) | No | SHA-256 hex of the previous chain entry |
| `entry_hash` | VARCHAR(64) | No | SHA-256 hex of this entry (UNIQUE) |
| `created_at` | TIMESTAMPTZ | No | UTC creation timestamp |

**Indexes:**

- `UNIQUE(sequence_number)` — chain traversal
- `UNIQUE(entry_hash)` — tamper detection
- `INDEX(tenant_id, created_at)` — tenant-scoped time queries
- `INDEX(event_type)`, `INDEX(severity)`, `INDEX(created_at)`

---

### `security_alerts` — Auto-Generated Alerts

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary key |
| `tenant_id` | UUID → `tenants.id` | Yes | Tenant scope |
| `alert_type` | VARCHAR(50) | No | `CHAIN_TAMPER` \| `HIGH_RISK_EVENT` \| `AUTH_ANOMALY` \| `POLICY_VIOLATION` |
| `severity` | VARCHAR(20) | No | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `title` | VARCHAR(255) | No | Short alert title |
| `description` | TEXT | Yes | Detailed description |
| `related_entry_id` | UUID → `audit_log_entries.id` | Yes | Chain entry that triggered this alert |
| `is_resolved` | BOOLEAN | No | Default `false` |
| `resolved_at` | TIMESTAMPTZ | Yes | Resolution timestamp |
| `metadata_json` | JSONB | Yes | Extra context (scores, sequences, etc.) |
| `created_at` | TIMESTAMPTZ | No | UTC creation timestamp |
| `updated_at` | TIMESTAMPTZ | No | UTC last update timestamp |

**Indexes:**

- `INDEX(tenant_id, alert_type)`
- `INDEX(is_resolved, created_at)` — fast unresolved queries
- `INDEX(severity)`, `INDEX(related_entry_id)`

---

## 5. Files Delivered

### New Files

| File | Purpose |
|---|---|
| `migrations/versions/20260912_0004_add_audit_log_chain_and_alerts.py` | Alembic migration — creates both tables with all indexes |
| `src/engine/audit_logger.py` | Core engine: `AuditLogger`, `compute_entry_hash`, `ChainVerificationResult` |
| `src/schemas/audit.py` | Pydantic v2 request/response schemas for all 4 new endpoints |
| `src/services/audit_service.py` | DB query helpers: chain entries, chain length, alerts, resolve |
| `tests/test_audit_logger.py` | 44-scenario test suite (unit + integration + performance) |

### Modified Files

| File | Change |
|---|---|
| `src/models/audit.py` | Added `AuditLogEntry`, `SecurityAlert` models; added `AuditEventType`, `AlertType`, `AlertSeverity` enums |
| `src/api/routes/audit.py` | Added 4 new endpoints; preserved existing `/events` endpoint |
| `src/services/firewall_service.py` | `store_memory()` now appends to hash chain after writing `SecurityAuditEvent` |
| `src/engine/__init__.py` | Exported `AuditLogger`, `ChainVerificationResult`, `compute_entry_hash`, `GENESIS_HASH` |
| `src/models/__init__.py` | Exported `AuditLogEntry`, `SecurityAlert` and new enums |

---

## 6. API Reference

### Access Control

| Role | Permitted Endpoints |
|---|---|
| Any authenticated user (JWT / API key) | `GET /audit/events` `GET /audit/logs` `GET /audit/verify` `GET /audit/alerts` |
| **Admin only** | `PUT /audit/alerts/{id}/resolve` |

---

### `GET /api/v1/audit/logs`

Query the tamper-proof global hash chain.

**Query Parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tenant_id` | UUID | — | Filter to this tenant's entries |
| `event_type` | string | — | `FIREWALL_EVAL` \| `AUTH_EVENT` \| `POLICY_CHANGE` \| `SECURITY_ALERT` \| `SYSTEM` |
| `severity` | string | — | `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `from_dt` | datetime | — | ISO-8601 lower bound on `created_at` |
| `to_dt` | datetime | — | ISO-8601 upper bound on `created_at` |
| `limit` | int | 50 | Max entries to return (max 500) |
| `offset` | int | 0 | Pagination offset |

**Response `200 OK`**

```json
{
  "total": 2,
  "chain_length": 42,
  "entries": [
    {
      "id": "a1b2c3d4-...",
      "sequence_number": 42,
      "tenant_id": "tenant-uuid",
      "event_id": "audit-event-uuid",
      "event_type": "FIREWALL_EVAL",
      "severity": "HIGH",
      "actor": "10.0.0.5",
      "action": "memory.store",
      "resource": "session-uuid",
      "payload": {
        "decision": "QUARANTINE",
        "risk_score": 0.87,
        "violation_count": 2,
        "latency_ms": 31.4
      },
      "previous_hash": "abc123...def456",
      "entry_hash": "fed654...cba321",
      "created_at": "2026-09-12T10:05:00+00:00"
    }
  ]
}
```

---

### `GET /api/v1/audit/verify`

Run a full SHA-256 hash-chain integrity scan over the entire global chain.

**Query Parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `raise_alert` | bool | `true` | Auto-raise `CHAIN_TAMPER` CRITICAL alert if tampering is found |

**Response `200 OK` — Chain intact**

```json
{
  "is_valid": true,
  "total_entries": 42,
  "first_broken_sequence": null,
  "broken_entries": [],
  "verification_time_ms": 12.5,
  "message": "Chain integrity confirmed. All 42 entries verified successfully."
}
```

**Response `200 OK` — Tampering detected**

```json
{
  "is_valid": false,
  "total_entries": 42,
  "first_broken_sequence": 17,
  "broken_entries": [17, 18, 19],
  "verification_time_ms": 11.3,
  "message": "TAMPER DETECTED: 3 entries failed hash verification. First broken at sequence #17."
}
```

> **Note:** The endpoint always returns `200`. Use `is_valid` to determine chain status.

---

### `GET /api/v1/audit/alerts`

List auto-generated security alerts.

**Query Parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tenant_id` | UUID | — | Scope to this tenant's alerts |
| `is_resolved` | bool | — | `true` = resolved only · `false` = unresolved only |
| `severity` | string | — | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `alert_type` | string | — | `CHAIN_TAMPER` \| `HIGH_RISK_EVENT` \| `AUTH_ANOMALY` \| `POLICY_VIOLATION` |
| `limit` | int | 50 | Max alerts to return (max 200) |
| `offset` | int | 0 | Pagination offset |

**Response `200 OK`**

```json
{
  "total": 1,
  "unresolved_count": 1,
  "alerts": [
    {
      "id": "alert-uuid",
      "tenant_id": "tenant-uuid",
      "alert_type": "HIGH_RISK_EVENT",
      "severity": "HIGH",
      "title": "High-Risk Firewall Event (score=0.87)",
      "description": "Firewall evaluation produced risk_score=0.8700 >= threshold 0.8. Decision: QUARANTINE. Actor: 10.0.0.5.",
      "related_entry_id": "chain-entry-uuid",
      "is_resolved": false,
      "resolved_at": null,
      "metadata_json": { "risk_score": 0.87, "decision": "QUARANTINE" },
      "created_at": "2026-09-12T10:05:00+00:00",
      "updated_at": "2026-09-12T10:05:00+00:00"
    }
  ]
}
```

---

### `PUT /api/v1/audit/alerts/{alert_id}/resolve`

Mark a security alert as resolved. **Admin role required.**

**Path Parameter:** `alert_id` — UUID of the alert to resolve.

**Response `200 OK`**

```json
{
  "id": "alert-uuid",
  "is_resolved": true,
  "resolved_at": "2026-09-12T11:00:00+00:00",
  "message": "Alert 'alert-uuid' has been resolved successfully."
}
```

**Error Responses**

| Code | Reason |
|---|---|
| `401` | Missing or invalid Bearer token / API key |
| `403` | Authenticated user does not have admin role |
| `404` | Alert UUID not found |

---

## 7. Security Alert System

Alerts are raised **automatically** — no manual trigger is required.

### `HIGH_RISK_EVENT` Alert

Raised by `AuditLogger.log_event()` whenever a firewall evaluation produces `risk_score >= 0.80`.

| risk_score | Alert Severity |
|---|---|
| 0.80 – 0.94 | `HIGH` |
| 0.95 – 1.00 | `CRITICAL` |

Example payload stored in `metadata_json`:

```json
{
  "decision": "QUARANTINE",
  "risk_score": 0.92,
  "violation_count": 3,
  "latency_ms": 41.2,
  "session_id": "session-uuid"
}
```

### `CHAIN_TAMPER` Alert

Raised by `AuditLogger.verify_chain()` when any entry fails hash verification. Always severity **CRITICAL**.

Example payload stored in `metadata_json`:

```json
{
  "broken_count": 3,
  "broken_sequences": [17, 18, 19],
  "first_broken_sequence": 17,
  "total_entries": 42
}
```

### Alert Resolution Workflow

```
1. Security team reviews GET /api/v1/audit/alerts?is_resolved=false
2. Investigates related chain entries via GET /api/v1/audit/logs?tenant_id=...
3. Admin calls PUT /api/v1/audit/alerts/{id}/resolve
4. Alert marked is_resolved=true with resolved_at timestamp
```

---

## 8. Core Engine: `AuditLogger`

Located at `src/engine/audit_logger.py`.

### `log_event()` — Append to chain

```python
from src.engine.audit_logger import AuditLogger

entry = AuditLogger().log_event(
    db=db,
    action="memory.store",               # Short action label
    event_type="FIREWALL_EVAL",           # AuditEventType value
    severity="HIGH",                      # Severity string
    tenant_id="uuid-string",              # None for system events
    actor="10.0.0.5",                     # Who triggered the event
    resource="session-uuid",              # Target resource
    payload={                             # Arbitrary structured data
        "decision": "QUARANTINE",
        "risk_score": 0.87,
    },
    event_id="security-audit-event-uuid", # Optional back-link
    raise_alert_if_high_risk=True,        # Auto-alert at risk_score >= 0.80
)
# Returns: AuditLogEntry with computed entry_hash and sequence_number
```

### `verify_chain()` — Full integrity scan

```python
from src.engine.audit_logger import AuditLogger, ChainVerificationResult

result: ChainVerificationResult = AuditLogger().verify_chain(
    db=db,
    raise_alert_on_tamper=True,   # Auto-raise CHAIN_TAMPER alert if broken
)

print(result.is_valid)              # True or False
print(result.total_entries)         # Number of entries scanned
print(result.broken_entries)        # List of tampered sequence numbers
print(result.first_broken_sequence) # First tampered position (or None)
print(result.verification_time_ms)  # Wall-clock scan time in ms
```

### `raise_alert()` — Manual alert creation

```python
AuditLogger().raise_alert(
    db=db,
    alert_type="CHAIN_TAMPER",           # AlertType value
    severity="CRITICAL",                  # AlertSeverity value
    title="CRITICAL: Chain Integrity Failure",
    description="...",
    related_entry=entry,                  # Optional AuditLogEntry
    tenant_id=None,                       # None = global alert
    metadata={"broken_sequences": [17]},
    flush_only=False,                     # True = caller commits later
)
```

### `compute_entry_hash()` — Standalone hash computation

```python
from src.engine.audit_logger import compute_entry_hash, GENESIS_HASH

hash_val = compute_entry_hash(
    sequence_number=1,
    tenant_id=None,
    event_type="FIREWALL_EVAL",
    severity="INFO",
    actor="system",
    action="memory.store",
    resource="session-123",
    payload={"decision": "ALLOW"},
    created_at_iso="2026-09-12T10:00:00+00:00",
    previous_hash=GENESIS_HASH,  # "000...0" for genesis
)
# Returns: 64-character SHA-256 hex string
```

---

## 9. FirewallService Integration

`store_memory()` in `src/services/firewall_service.py` executes the following sequence:

```
Step 1  →  FirewallEvaluator.evaluate(text, rules)
           Returns: EvaluationResult (decision, risk_score, violations, sanitized_text)

Step 2  →  Persist MemoryRecord
           (quarantine=True if decision in [QUARANTINE, BLOCK])

Step 3  →  db.flush()  ← get MemoryRecord.id

Step 4  →  Persist SecurityAuditEvent (legacy audit log)
           Links to: tenant_id, session_id, rule_id

Step 5  →  db.flush()  ← get SecurityAuditEvent.id for chain linking

Step 6  →  AuditLogger.log_event()
           action       = "memory.store"
           event_type   = "FIREWALL_EVAL"
           severity     = computed from risk_score (INFO/LOW/MEDIUM/HIGH/CRITICAL)
           tenant_id    = tenant_id
           actor        = client_ip or "unknown"
           resource     = str(session_id)
           payload      = {decision, risk_score, violation_count, latency_ms, ...}
           event_id     = str(SecurityAuditEvent.id)
           raise_alert_if_high_risk = True

Step 7  →  db.commit()
```

### Severity mapping from risk_score

| risk_score | chain severity |
|---|---|
| 0.0 | `INFO` |
| 0.01 – 0.49 | `LOW` |
| 0.50 – 0.79 | `MEDIUM` |
| 0.80 – 0.89 | `HIGH` |
| 0.90 – 1.00 | `CRITICAL` |

### `inspect_text()` — Remains stateless

```python
# inspect_text() does NOT write any AuditLogEntry.
# It only runs the evaluation pipeline and returns the result.
# No db.add(), db.flush(), or db.commit() calls are made.
result = inspect_text(db=db, tenant_id=tenant_id, text="Hello world")
```

---

## 10. Test Suite

**File:** `tests/test_audit_logger.py`  
**Result:** `44 passed, 1 warning in 7.51s`

### Test Group Summary

| Group | Count | What Is Tested |
|---|---|---|
| `TestHashChainConstruction` | 8 | Genesis hash, 64-char output, determinism, sequential linking, action/sequence/tenant ID isolation |
| `TestChainVerification` | 8 | Empty chain, single valid, three valid, single tamper, middle tamper, multi-tamper (all found), timing, tamper auto-alert |
| `TestAuditLoggerLogEvent` | 6 | Genesis entry prev_hash, chain linking, hash correctness, high-risk alert trigger, low-risk no alert, flag suppression |
| `TestSecurityAlerts` | 5 | Alert creation, CRITICAL severity, flush-only mode, linked chain entry, metadata storage |
| `TestAuditAPIEndpoints` | 10 | `401` on all unauthenticated routes, `200` on authenticated routes, filter params, `403` for non-admin resolve, `404` for nonexistent alert |
| `TestFirewallServiceIntegration` | 4 | Chain entry created by `store_memory()`, hash validity verified, `verify_chain()` passes post-store, `inspect_text()` writes nothing |
| `TestPerformanceBenchmarks` | 3 | 1000 hashes < 500ms, 100-entry verify < 100ms, `ChainVerificationResult` structure |

### Running the Tests

```bash
# Run all Week 6 tests
pytest tests/test_audit_logger.py -v

# Run only hash chain unit tests
pytest tests/test_audit_logger.py::TestHashChainConstruction -v

# Run only integration tests
pytest tests/test_audit_logger.py::TestFirewallServiceIntegration -v

# Run only performance benchmarks
pytest tests/test_audit_logger.py::TestPerformanceBenchmarks -v
```

---

## 11. Migration

### Apply (upgrade)

```bash
alembic upgrade head
```

This creates:
- `audit_log_entries` table (14 columns, 10 indexes)
- `security_alerts` table (12 columns, 8 indexes)

### Verify migration applied

```bash
alembic current
# Should show: 20260912_0004 (head)
```

### Rollback

```bash
alembic downgrade 20260910_0003
```

This drops both `security_alerts` and `audit_log_entries` tables (alerts dropped first due to FK dependency).

---

## 12. Enums Reference

### `AuditEventType`

| Value | Description |
|---|---|
| `FIREWALL_EVAL` | Firewall pipeline evaluation event (default) |
| `AUTH_EVENT` | Login, logout, token refresh, API key usage |
| `POLICY_CHANGE` | Firewall rule created, updated, or deleted |
| `SECURITY_ALERT` | Security alert generated |
| `SYSTEM` | System-level event (startup, health check, etc.) |

### `AlertType`

| Value | Description |
|---|---|
| `CHAIN_TAMPER` | Hash chain integrity failure detected |
| `HIGH_RISK_EVENT` | Firewall evaluation produced risk_score >= 0.80 |
| `AUTH_ANOMALY` | Unusual authentication pattern |
| `POLICY_VIOLATION` | Policy rule breach |

### `AlertSeverity`

| Value | Description |
|---|---|
| `LOW` | Informational, low urgency |
| `MEDIUM` | Requires attention |
| `HIGH` | Prompt investigation required |
| `CRITICAL` | Immediate action required |

---

## 13. Week 6 Goals — Completion Checklist

| Deliverable | Status | Location |
|---|---|---|
| SHA-256 hash chain implementation | ✅ | `src/engine/audit_logger.py` |
| Log verification logic | ✅ | `AuditLogger.verify_chain()` |
| `GET /audit/logs` endpoint | ✅ | `src/api/routes/audit.py` |
| `GET /audit/verify` endpoint | ✅ | `src/api/routes/audit.py` |
| `GET /audit/alerts` endpoint | ✅ | `src/api/routes/audit.py` |
| `PUT /audit/alerts/{id}/resolve` | ✅ | `src/api/routes/audit.py` |
| Security alerts (high-risk + tamper) | ✅ | `AuditLogger.log_event()` + `verify_chain()` |
| `audit_logger.py` module | ✅ | `src/engine/audit_logger.py` |
| Alembic migration | ✅ | `migrations/versions/20260912_0004_...py` |
| Hash chain verification tests | ✅ | `tests/test_audit_logger.py` — **44/44 passed** |
