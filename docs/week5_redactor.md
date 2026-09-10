# Week 5 Comprehensive Guide: Data Redaction Engine

> **Audience**: Security Engineers, AI Platform Developers & Compliance Teams  
> **Goal**: Understand the complete architecture, masking strategy design, entity-type strategy map, reversible tokenization system, and integration into the `FirewallEvaluator` pipeline.

---

## 1. Executive Summary

Weeks 1–4 produced a full detection pipeline: regex rules → NLP classifier → PII detector → policy engine. However, the sanitized output produced by those stages was uniformly blunt — every detected entity was replaced with a static placeholder like `[REDACTED_EMAIL]`.

This works for security enforcement, but fails in operational contexts that require:

- **Partial fidelity** — a support agent needs to see the last 4 digits of a credit card.
- **Audit correlation** — security logs need to match API key mentions across time without re-exposing the key.
- **Legal compliance** — HIPAA/GDPR workflows require reversible de-identification of SSNs and passport numbers, not permanent deletion.

**Week 5 introduces `DataRedactor`** — a strategy-aware data masking module that applies the most appropriate treatment per entity type. It integrates as **Stage 5.5** in the `FirewallEvaluator` pipeline and replaces the classifier's placeholder substitution with precision-masked output.

---

## 2. Architecture Overview

```
                     ┌─────────────────────────────────────────────┐
                     │     AI Memory Firewall – Evaluation Pipeline│
                     └────────────────────┬────────────────────────┘
                                          │
            ┌─────────────────────────────▼──────────────────────────────┐
            │ Stage 1.5: SensitivityClassifier (Weeks 1–3)               │
            │  • Regex + spaCy NER + Presidio → ClassificationResult     │
            │  • entities: List[EntityDetection]                          │
            └────────────────────┬───────────────────────────────────────┘
                                 │
            ┌────────────────────▼───────────────────────────────────────┐
            │ Stage 4.5: PolicyEngine (Week 4)                            │
            │  • RBAC + risk thresholds → PolicyEvaluationResult         │
            │  • decision: ALLOW / REDACT / BLOCK / QUARANTINE / AUDIT   │
            └────────────────────┬───────────────────────────────────────┘
                                 │
            ┌────────────────────▼───────────────────────────────────────┐
            │ Stage 5.5: DataRedactor (Week 5)  ← NEW                    │
            │                                                             │
            │  For each EntityDetection:                                  │
            │    strategy = ENTITY_STRATEGY_MAP[entity.entity_type]       │
            │              or strategy_override                           │
            │                                                             │
            │  ┌──────────┬──────────┬──────────┬──────────────┐         │
            │  │   FULL   │ PARTIAL  │   HASH   │  TOKENIZE    │         │
            │  │Placeholder│Type-aware│ SHA-256  │Random token  │         │
            │  │replacement│ masking │fingerprint│+ RedactionMap│         │
            │  └──────────┴──────────┴──────────┴──────────────┘         │
            │                                                             │
            │  Output: RedactionResult                                    │
            │    • redacted_text: strategy-masked sanitized output        │
            │    • entries: List[RedactionEntry]                          │
            │    • redaction_map: RedactionMap (TOKENIZE tokens)          │
            └────────────────────────────────────────────────────────────┘
```

---

## 3. Masking Strategies

Defined in [`src/engine/redactor.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/engine/redactor.py) as `RedactionStrategy(str, Enum)`.

### 3.1 FULL — Complete Replacement

The original value is entirely replaced with a static placeholder tag derived from the entity type's built-in `redacted_text` field.

| Input | Output |
|:------|:-------|
| `-----BEGIN RSA PRIVATE KEY-----...` | `[REDACTED_PRIVATE_KEY]` |
| `Acme Corp` (ORGANIZATION) | `[REDACTED_ORGANIZATION]` |
| `MH58-ABC` (VEHICLE_REG) | `[REDACTED_VEHICLE_REG]` |

> Use when: no fidelity is needed and partial exposure is never acceptable.

---

### 3.2 PARTIAL — Type-Aware Selective Masking

Masks the sensitive portion of a value while preserving a safe, recognizable portion. The visible portion is determined by the entity type:

| Entity Type | Format | Example Input | Example Output |
|:---|:---|:---|:---|
| `EMAIL` | `XX***@***.TLD` | `alice@example.com` | `al***@***.com` |
| `PHONE_NUMBER` | `***-***-XXXX` | `+1 (800) 555-0199` | `***-***-0199` |
| `CREDIT_CARD` | `****-****-****-XXXX` | `4111 1111 1111 1234` | `****-****-****-1234` |
| `IP_ADDRESS` | `A.B.*.*` | `192.168.10.25` | `192.168.*.*` |
| `SSN` | `***-**-XXXX` | `123-45-6789` | `***-**-6789` |
| `IBAN` | `CC**...XXXX` | `GB82WEST12345698765432` | `GB****...5432` |
| `PERSON` | `X**** Y******` | `Alice Johnson` | `A**** J******` |
| `DATE` | Year preserved | `12/25/1990` | `**/**/1990` |

> Use when: human readability or partial confirmation is needed (e.g. support workflows, logs).

---

### 3.3 HASH — Deterministic SHA-256 Fingerprint

The original value is replaced with a truncated (16-char) SHA-256 hex digest tag. The same input always produces the same hash — enabling log correlation without re-exposing the secret.

| Input | Output |
|:------|:-------|
| `sk-abc123xyz456def789ghi012` (API_KEY) | `[HASH_API_KEY:3d4f8a2b1c9e0f7a]` |
| `AKIAIOSFODNN7EXAMPLE1234` (AWS_KEY) | `[HASH_AWS_KEY:b2e1d4c3a9f8e7d6]` |

> Use when: audit correlation without re-exposure is needed (API keys, secrets, credentials).

---

### 3.4 TOKENIZE — Reversible Random Token

The original value is replaced with a random opaque token (`[TOKEN_SSN_a3f9]`) which is stored in a `RedactionMap`. The original value can be retrieved via `RedactionMap.restore(token)`.

| Input | Output |
|:------|:-------|
| `123-45-6789` (SSN) | `[TOKEN_SSN_a3f9]` |
| `A12345678` (PASSPORT_NUMBER) | `[TOKEN_PASSPORT_NUMBER_c2d8]` |
| `D123-4567-8901` (DRIVERS_LICENSE) | `[TOKEN_DRIVERS_LICENSE_f1e5]` |

> Use when: reversible de-identification is required for compliance workflows (HIPAA, GDPR Article 4(5) pseudonymization).

---

## 4. Entity-Type Strategy Map

`ENTITY_STRATEGY_MAP` in [`src/engine/redactor.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/engine/redactor.py) assigns each entity type its default strategy:

| Entity Type | Default Strategy | Rationale |
|:---|:---|:---|
| `SSN` | TOKENIZE | Reversible for legal audit trails |
| `PASSPORT_NUMBER` | TOKENIZE | Reversible for border/compliance workflows |
| `DRIVERS_LICENSE` | TOKENIZE | Reversible for identity verification |
| `CREDIT_CARD` | PARTIAL | Last-4 for support confirmation |
| `IBAN` | PARTIAL | Country code + last-4 for banking ops |
| `EMAIL` | PARTIAL | Human-readable in logs |
| `PHONE_NUMBER` | PARTIAL | Area code context preserved |
| `IP_ADDRESS` | PARTIAL | Subnet prefix for network logging |
| `API_KEY` | HASH | Deterministic fingerprint, no partial exposure |
| `AWS_KEY` | HASH | Same rationale as API_KEY |
| `PRIVATE_KEY` | FULL | Complete erasure; no partial exposure permissible |
| `VEHICLE_REG` | FULL | Low-sensitivity; no fidelity needed |
| `PERSON` | PARTIAL | Initial-only name for human readability |
| `ORGANIZATION` | FULL | Full removal |
| `LOCATION` | FULL | Full removal |
| `DATE` | PARTIAL | Year preserved, day/month masked |

---

## 5. Core Classes

### 5.1 `DataRedactor`

Main entry point. Located in [`src/engine/redactor.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/engine/redactor.py).

```python
from src.engine.redactor import DataRedactor, RedactionStrategy

redactor = DataRedactor()

# Using classifier output
result = redactor.redact(text, classifier_result.entities)
print(result.redacted_text)           # Strategy-masked output
print(result.strategy_summary)        # {"PARTIAL": 2, "TOKENIZE": 1}

# Force a single strategy across all entities
result = redactor.redact(text, entities, strategy_override=RedactionStrategy.HASH)

# Always tokenize (for full audit trail)
result = redactor.redact_with_map(text, entities)
token  = result.entries[0].token
entry  = result.redaction_map.restore(token)
print(entry.original_text)            # Original sensitive value
```

### 5.2 `RedactionMap`

In-process store for TOKENIZE tokens. Does **not** persist to disk.

```python
log = result.redaction_map.export_audit_log()  # Sorted by document offset
for entry in log:
    print(entry.entity_type, entry.token, entry.original_text)
```

### 5.3 `RedactionResult`

```python
result.original_text       # Unmodified source text
result.redacted_text       # Strategy-masked output
result.entries             # List[RedactionEntry] in document order
result.tokenized_count     # Count of TOKENIZE entries
result.strategy_summary    # {"PARTIAL": 2, "HASH": 1}
result.latency_ms          # Wall time of redaction pass
```

---

## 6. FirewallEvaluator Integration (Stage 5.5)

The `DataRedactor` is integrated in [`src/engine/evaluator.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/engine/evaluator.py) as Stage 5.5:

```python
# Stage 5.5: DataRedactor strategy-aware masking
if classifier_result and classifier_result.entities:
    redaction_result = self._redactor.redact(
        text=text,
        entities=classifier_result.entities,
    )
    sanitized = redaction_result.redacted_text   # Replaces raw placeholder output
```

`EvaluationResult` now includes a `redaction_result` field:

```python
result = FirewallEvaluator().evaluate("SSN 123-45-6789")
print(result.sanitized_text)           # "SSN [TOKEN_SSN_a3f9]"
print(result.redaction_result.entries) # [RedactionEntry(entity_type='SSN', ...)]
```

---

## 7. Span Collision Resolution

When two entity spans overlap (e.g. a PERSON span contains a shorter regex span), `DataRedactor._resolve_spans()` keeps the **longer span** and drops the shorter one, preventing double-replacement or garbled output.

---

## 8. Verification & Test Suite Coverage

The Week 5 test suite is in [`tests/test_redactor.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/tests/test_redactor.py).

### 8.1 Coverage (37 Scenarios)

| Group | Scenarios | Focus |
|:---|:---:|:---|
| FULL strategy | 3 | Placeholder substitution, PRIVATE_KEY, ORGANIZATION |
| PARTIAL strategy | 7 | Email, CC, phone, IP, SSN, IBAN, PERSON masking formats |
| HASH strategy | 3 | Format, determinism, collision avoidance |
| TOKENIZE strategy | 4 | Token tag format, restore, unknown token, `redact_with_map` |
| Strategy Map | 5 | Default strategies, `strategy_override` |
| Multi-entity & spans | 5 | Non-overlapping, 3-entity mixed, overlap resolution, empty, summary |
| RedactionMap | 5 | Store/retrieve, len, unknown key, sort order, uniqueness |
| Evaluator integration | 3 | Populated result, clean text, strategy-masked sanitized_text |
| Performance | 2 | 5000-char text < 100ms, 100-token map < 50ms |

### 8.2 Running Tests

```bash
# Week 5 test suite only
.\venv\Scripts\python.exe -m pytest tests/test_redactor.py -v

# Full suite (must remain green)
.\venv\Scripts\python.exe -m pytest --tb=short -q
```

Expected result:
```
37 passed in 3.68s   ← Week 5 suite
```
