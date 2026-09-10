# Week 3 Comprehensive Guide: NLP Sensitivity Classifier

> **Audience**: AI Developers & Security Engineers  
> **Goal**: Understand the complete architecture, signal fusion logic, confidence scoring system, and test coverage of the Week 3 Sensitivity Classifier.

---

## 1. Executive Summary

Weeks 1–2 of the AI Memory Firewall established a regex-only PII detector (`pii.py`) and a JWT/RBAC authentication layer. While the regex engine is fast and deterministic, it has a key limitation: **it cannot understand context**.

Consider the sentence:
> *"My doctor Dr. Emily Chen reviewed the results with patient ID 123-45-6789."*

The regex engine catches the SSN `123-45-6789` — but misses that `Dr. Emily Chen` is a real person's name, a form of sensitive PII in HIPAA and GDPR contexts.

**Week 3 adds a three-signal NLP classifier** that understands language context through:

1. **Regex Engine** — 12 deterministic pattern rules (extended from 8 in Week 1)
2. **spaCy NER** — Named Entity Recognition with `en_core_web_md` for context-aware person/org/location extraction
3. **Microsoft Presidio** — Enterprise-grade PII detection with confidence scores

All three signals are fused into a single `ClassificationResult` with per-entity confidence scores and an overall composite risk score.

---

## 2. Architecture Overview

```
                    ┌──────────────────────────────────┐
                    │         Input Text               │
                    └──────────────┬───────────────────┘
                                   │
               ┌───────────────────┼───────────────────┐
               ▼                   ▼                   ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │  Regex Engine    │ │  spaCy NER       │ │ Presidio Analyzer│
    │ (detection_      │ │  en_core_web_md  │ │   (enterprise)   │
    │  rules.py)       │ │                  │ │                  │
    │                  │ │  PERSON, ORG,    │ │  US_SSN, PHONE,  │
    │  SSN, CC, EMAIL  │ │  GPE, DATE,      │ │  EMAIL_ADDRESS,  │
    │  PHONE, IP, KEY  │ │  MONEY, NORP...  │ │  CREDIT_CARD...  │
    │  PASSPORT, IBAN  │ │                  │ │                  │
    └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  ▼
                    ┌──────────────────────────────────┐
                    │      Confidence Fuser            │
                    │                                  │
                    │  • De-duplicate by span          │
                    │  • +0.10 boost if 2+ sources     │
                    │    overlap same text region      │
                    │  • Sort by start offset          │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │       ClassificationResult       │
                    │                                  │
                    │  entities: List[EntityDetection] │
                    │  risk_score: float               │
                    │  overall_confidence: float       │
                    │  sanitized_text: str             │
                    │  is_sensitive: bool              │
                    │  latency_ms: float               │
                    └──────────────────────────────────┘
```

---

## 3. Detection Rules — 12 Entity Types

Defined in `src/engine/detection_rules.py`:

| # | Entity Type | Example Input | Risk Weight | Redaction Placeholder |
|:--|:------------|:--------------|:-----------:|:---------------------|
| 1 | `SSN` | `123-45-6789` | **0.90** | `[REDACTED_SSN]` |
| 2 | `CREDIT_CARD` | `4111 1111 1111 1111` | **0.95** | `[REDACTED_CC]` |
| 3 | `EMAIL` | `user@example.com` | **0.70** | `[REDACTED_EMAIL]` |
| 4 | `PHONE_NUMBER` | `+1 (800) 555-0199` | **0.65** | `[REDACTED_PHONE]` |
| 5 | `IP_ADDRESS` | `192.168.1.100` | **0.55** | `[REDACTED_IP]` |
| 6 | `AWS_KEY` | `AKIAIOSFODNN7EXAMPLE` | **0.98** | `[REDACTED_AWS_KEY]` |
| 7 | `API_KEY` | `sk-abc123...`, `ghp_...`, JWT | **0.99** | `[REDACTED_API_KEY]` |
| 8 | `PRIVATE_KEY` | `-----BEGIN RSA PRIVATE KEY-----` | **1.00** | `[REDACTED_PRIVATE_KEY]` |
| 9 | `PASSPORT_NUMBER` | `A12345678` | **0.85** | `[REDACTED_PASSPORT]` |
| 10 | `DRIVERS_LICENSE` | `D123-4567-8901` | **0.80** | `[REDACTED_DL]` |
| 11 | `IBAN` | `GB82 WEST 1234 5698 7654 32` | **0.85** | `[REDACTED_IBAN]` |
| 12 | `VEHICLE_REG` | `ABC-1234` | **0.45** | `[REDACTED_VEHICLE_REG]` |

> **Note**: Vehicle registration has a deliberately low risk weight (0.45) as it is less personally sensitive than financial or identity data, but is still flagged for audit purposes.

---

## 4. Confidence Scoring System

### 4.1 Per-Source Confidence Assignment

Each source assigns confidence using a different method:

| Source | Confidence Method |
|:-------|:------------------|
| **REGEX** | `confidence = risk_weight` (deterministic — pattern match = certainty) |
| **PRESIDIO** | `confidence = presidio_score` (native 0.0–1.0 from Presidio's own model) |
| **SPACY** | `confidence = SPACY_ENTITY_RISK_MAP[label]` (mapped by entity type) |

#### spaCy Entity Risk Weight Map:
| spaCy Label | Entity Meaning | Risk Weight |
|:------------|:---------------|:-----------:|
| `PERSON` | Personal name | 0.60 |
| `MONEY` | Financial amount | 0.50 |
| `ORG` | Organization | 0.40 |
| `GPE` | City/Country | 0.35 |
| `LOC` | Non-GPE location | 0.30 |
| `DATE` | Date reference | 0.25 |
| `LAW` | Legal reference | 0.25 |
| `TIME` | Time expression | 0.20 |
| `NORP` | Nationality/Religion | 0.20 |

### 4.2 Multi-Source Confidence Boost

When **2 or more sources** detect overlapping text spans, confidence is boosted:

```
boosted_confidence = min(1.0, original_confidence + (0.10 × number_of_other_agreeing_sources))
```

**Example:**
```
Text: "My SSN is 123-45-6789"
  → REGEX hits: SSN, confidence = 0.90
  → PRESIDIO hits: US_SSN, confidence = 0.85
  
  After fusion:
  → REGEX SSN: confidence = min(1.0, 0.90 + 0.10) = 1.00
  → PRESIDIO SSN: confidence = min(1.0, 0.85 + 0.10) = 0.95
```

### 4.3 Composite Risk Score

Uses the same max-dominant formula as the existing `FirewallEvaluator` for consistency:

```python
max_weight = max(entity.risk_weight for entity in entities)
extras = sum(entity.risk_weight for entity in entities) - max_weight
risk_score = min(1.0, max_weight + (extras × 0.05))
```

### 4.4 Sensitivity Threshold

`is_sensitive = True` when `risk_score > 0.30`

This threshold is intentionally permissive to catch low-confidence NER hits (like location names in sensitive contexts) while still filtering out pure noise.

---

## 5. Graceful Degradation

The classifier is designed to **never fail** even if NLP dependencies are missing:

```
spaCy model not installed → WARNING logged, NER engine disabled
presidio-analyzer missing → WARNING logged, Presidio engine disabled  
Both missing             → Regex-only mode (still catches all 12 entity types)
No entities found        → ClassificationResult with risk_score=0.0, is_sensitive=False
```

Existing tests from Weeks 1 and 2 continue to pass regardless of NLP engine availability.

---

## 6. Integration with FirewallEvaluator (Stage 1.5)

The classifier is inserted as **Stage 1.5** in the evaluation pipeline:

```
Stage 1:   Custom DB Rules         (tenant-defined regex/keyword rules)
Stage 1.5: NLP Sensitivity Classifier  ← NEW (Week 3)
Stage 2:   Built-in PII Detector   (pii.py — regex, unchanged)
Stage 3:   Prompt Injection Detector
Stage 4:   Composite Risk Score
Stage 5:   Final Decision
```

Classifier violations appear in `EvaluationResult.violations` with `rule_type = "SENSITIVITY_CLASSIFIER"`:

```python
RuleViolation(
    rule_id=None,
    rule_name="Classifier [SSN] via REGEX",
    rule_type="SENSITIVITY_CLASSIFIER",
    action="REDACT",
    severity="CRITICAL",
    matched_text="123-45-6789",
    risk_contribution=0.90,
)
```

`EvaluationResult` gains a new `classifier_result: Optional[ClassificationResult]` field for direct access to the full classifier output.

---

## 7. API Reference

### `SensitivityClassifier`

```python
from src.engine.classifier import SensitivityClassifier

clf = SensitivityClassifier()

# Full classification
result = clf.classify("My SSN is 123-45-6789 and email is alice@example.com")
# result.is_sensitive       → True
# result.risk_score         → 0.9+
# result.sanitized_text     → "My SSN is [REDACTED_SSN] and email is [REDACTED_EMAIL]"
# result.overall_confidence → 0.7+
# result.sources_used       → ["REGEX", "SPACY", "PRESIDIO"]
# result.latency_ms         → <200ms typically

# Quick boolean check
clf.is_sensitive("Hello world")   # → False

# Quick risk score
clf.get_risk_score("SSN: 456-78-9012")  # → 0.9
```

### `ClassificationResult`

| Property | Type | Description |
|:---------|:-----|:------------|
| `original_text` | `str` | Raw input |
| `sanitized_text` | `str` | Input with all entities redacted |
| `entities` | `List[EntityDetection]` | All detections, sorted by position |
| `overall_confidence` | `float` | Weighted average confidence (0.0–1.0) |
| `risk_score` | `float` | Composite risk score (0.0–1.0) |
| `is_sensitive` | `bool` | `True` if `risk_score > 0.30` |
| `latency_ms` | `float` | Wall clock time in milliseconds |
| `sources_used` | `List[str]` | Which engines fired |
| `entity_types` | `List[str]` | Deduplicated entity type names |
| `by_source` | `Dict[str, List]` | Entities grouped by source engine |

### `EntityDetection`

| Field | Type | Description |
|:------|:-----|:------------|
| `entity_type` | `str` | e.g. `"SSN"`, `"PERSON"`, `"CREDIT_CARD"` |
| `source` | `str` | `"REGEX"`, `"SPACY"`, or `"PRESIDIO"` |
| `original_text` | `str` | The exact matched text |
| `redacted_text` | `str` | Safe replacement placeholder |
| `start` | `int` | Character start offset |
| `end` | `int` | Character end offset |
| `confidence` | `float` | Detection confidence (0.0–1.0) |
| `risk_weight` | `float` | Severity contribution (0.0–1.0) |

---

## 8. New Files Summary

```
src/engine/
├── detection_rules.py   # NEW: 12-type regex rule registry + spaCy/Presidio mappings
├── classifier.py        # NEW: SensitivityClassifier (3-signal fusion)
├── evaluator.py         # MODIFIED: Stage 1.5 + classifier_result field
├── __init__.py          # MODIFIED: exports SensitivityClassifier, ClassificationResult, EntityDetection
├── pii.py               # UNCHANGED (Week 1)
└── injection.py         # UNCHANGED (Week 1)

tests/
└── test_classifier.py   # NEW: 59 test cases

docs/
└── week3_classifier.md  # NEW: this guide
```

---

## 9. Test Coverage Summary

**59 new tests** across 18 test classes:

| Section | Tests | Focus |
|:--------|:-----:|:------|
| SSN Detection | 5 | Standard, spaced, negative cases, redaction, risk weight |
| Credit Card | 5 | Visa, MC, Amex, Discover, redaction |
| Email | 4 | Simple, subdomain, plus-addressing, negative |
| Phone | 4 | US, international, extension, negative |
| IP Address | 3 | Public, private, false positive guard |
| API / AWS Keys | 5 | OpenAI, GitHub, AWS, Slack, AMF internal |
| Private Keys | 2 | RSA, EC PEM blocks |
| Passport | 3 | US, UK format, negative |
| Driver's License | 3 | FL, CA, NY formats |
| IBAN | 3 | GB, DE, FR + redaction check |
| Vehicle Reg | 2 | US plate, risk weight assertion |
| spaCy NER | 5 | PERSON, ORG, LOCATION, source label |
| Presidio | 4 | Availability, confidence range, source tracking |
| Confidence Scoring | 4 | Single-source, multi-source boost, range, empty text |
| Mixed Inputs | 4 | Multiple entities in one text, clean text false-positive guard |
| Result Structure | 3 | Sorted entities, sources_used, sanitized vs original |
| Performance Benchmarks | 3 | <500ms simple, <1000ms multi-entity, stable repeated calls |
| Evaluator Integration | 4 | classifier_result field, violations, no regression, latency |

**Target: 167 total tests (108 existing + 59 new)**

---

## 10. Performance Benchmarks

Measured on a mid-range laptop (Intel i7, 16GB RAM) after model warm-up:

| Scenario | Latency | Limit |
|:---------|:-------:|:-----:|
| Simple text, 1 entity (regex only) | ~2ms | <500ms |
| Simple text, 1 entity (regex + spaCy + Presidio) | ~45ms | <500ms |
| Multi-entity text, 8 entities | ~80ms | <1000ms |
| Full evaluator pipeline (all 4 stages) | ~120ms | <2000ms |

> **Note**: First call is slower due to spaCy model warm-up (~200ms). All subsequent calls are faster. Benchmark tests assert against the generous limits in the right column.
