# Week 4 Comprehensive Guide: Policy Engine & RBAC Enforcement

> **Audience**: Security Engineers, AI Platform Developers & System Administrators  
> **Goal**: Provide a complete architectural overview, data model reference, priority evaluation algorithm breakdown, REST API reference, and test suite verification for the Week 4 Policy Engine.

---

## 1. Executive Summary

While Weeks 1–3 established deterministic PII detection, JWT/RBAC security, and a 3-signal NLP sensitivity classifier, static risk scoring alone cannot enforce enterprise context policies. 

Different user roles (e.g. `ADMIN` vs `USER` vs `AGENT`), tenants, and memory streams require dynamic risk boundaries and specialized enforcement actions. 

**Week 4 introduces the dynamic Policy Engine (`PolicyEngine`)**, integrating **Stage 4.5** into the `FirewallEvaluator` pipeline. Key capabilities include:

1. **Role-Based Access Control (RBAC) Scoping**: Policies target specific roles (`admin`, `user`, `agent`, `system`, or `*` wildcard).
2. **Priority-Ordered Evaluation**: Active security policies are evaluated in strict priority order (`priority_order` ascending), with the highest-priority violation determining final disposition.
3. **Multi-Constraint Matching**: Enforces maximum risk score thresholds, blocked entity types (e.g. `API_KEY`, `SSN`, `AWS_KEY`), prohibited keywords/regexes, and token/text length constraints.
4. **Administrative REST Management API**: Fully managed `/api/v1/admin/policies` endpoints protected by `require_admin` for full CRUD operations, seeding, and live policy testing.
5. **Pre-Packaged System Seed Policies**: Out-of-the-box system policies for default admin access, strict quarantine, agent exfiltration safeguards, and audit tracking.

---

## 2. Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │    Incoming AI Memory Stream / Request       │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │      Stages 1–3: NLP Sensitivity Classifier  │
                      │  • Regex Engine (12 Rules)                   │
                      │  • spaCy NER (en_core_web_md)                │
                      │  • Microsoft Presidio                        │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │            ClassificationResult              │
                      │  • risk_score: float (0.0 - 1.0)             │
                      │  • detected_entities: List[EntityDetection]  │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                                ┌──────────────────────────┐
                                │ Stage 4.5: PolicyEngine  │
                                └────────────┬─────────────┘
                                             │
                   ┌─────────────────────────┼─────────────────────────┐
                   ▼                         ▼                         ▼
        ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
        │  Fetch Active       │   │   RBAC & Tenant     │   │ Priority Evaluation │
        │  Policies           │──▶│   Filter Scoping    │──▶│ (priority_order ASC)│
        └─────────────────────┘   └─────────────────────┘   └──────────┬──────────┘
                                                                       │
                                                                       ▼
                                                            ┌─────────────────────┐
                                                            │ Action Precedence   │
                                                            │ QUARANTINE (5)      │
                                                            │ BLOCK      (4)      │
                                                            │ REDACT     (3)      │
                                                            │ AUDIT      (2)      │
                                                            │ ALLOW      (1)      │
                                                            └──────────┬──────────┘
                                                                       │
                                                                       ▼
                      ┌──────────────────────────────────────────────┐
                      │          PolicyEvaluationResult              │
                      │  • decision: ALLOW / REDACT / BLOCK / ...    │
                      │  • matched_policy_name: str                  │
                      │  • violations: List[PolicyViolationDetail]   │
                      └──────────────────────────────────────────────┘
```

---

## 3. Policy Data Model & Database Schema

Defined in [`src/models/policy.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/models/policy.py) and migrated via Alembic script `003_add_policies_table.py`.

### 3.1 SQLAlchemy `SecurityPolicy` Entity

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `UUID` | Primary key identifier (UUIDv4). |
| `name` | `String(100)` | Human-readable name of the security policy. |
| `description` | `Text` | Optional detail explaining policy intent. |
| `tenant_id` | `UUID (FK)` | Optional tenant scoping (NULL applies globally across all tenants). |
| `target_role` | `String(50)` | Role targeted (`admin`, `user`, `agent`, `system`, or `*`). Default: `*`. |
| `action` | `Enum(RuleAction)` | Action on trigger: `ALLOW`, `REDACT`, `BLOCK`, `QUARANTINE`, `AUDIT`. |
| `priority_order` | `Integer` | Evaluation priority (lower numbers evaluate first, e.g., 1–100). |
| `max_risk_threshold` | `Float` | Risk score boundary (0.0 to 1.0) above which policy triggers. |
| `is_active` | `Boolean` | Flag controlling whether policy is evaluated. Default: `True`. |
| `rules_config` | `JSON / JSONB` | Flexible configuration payload containing entity/keyword/regex constraints. |

### 3.2 `rules_config` Payload Schema

```json
{
  "blocked_entities": ["API_KEY", "PRIVATE_KEY", "AWS_KEY", "SSN"],
  "prohibited_keywords": ["confidential", "internal-only", "do not distribute"],
  "prohibited_regexes": ["(?i)password\\s*=\\s*['\"]?\\w+"],
  "max_text_length": 10000
}
```

---

## 4. Policy Engine Evaluation Algorithm

Core evaluation logic resides in [`src/engine/policy_engine.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/engine/policy_engine.py).

### 4.1 Step-by-Step Evaluation Order

1. **Context Construction**: The evaluator constructs a `PolicyEvaluationContext` containing `user_role`, `tenant_id`, `memory_text`, `risk_score`, `detected_entities`, and `requested_action`.
2. **Filtering & Sorting**: Active policies (`is_active == True`) matching the request's `tenant_id` (or global `tenant_id IS NULL`) and `target_role` (or `*`) are collected and sorted by `priority_order` ascending.
3. **Constraint Check**: Each active policy is checked for violations against context:
   - **Risk Score Check**: `context.risk_score > policy.max_risk_threshold`
   - **Blocked Entities**: Any `context.detected_entities` in `policy.rules_config["blocked_entities"]`
   - **Prohibited Keywords**: Any string in `policy.rules_config["prohibited_keywords"]` found in `context.memory_text`
   - **Prohibited Regexes**: Any pattern in `policy.rules_config["prohibited_regexes"]` matching `context.memory_text`
   - **Text Length Limit**: `len(context.memory_text) > policy.rules_config["max_text_length"]`
4. **Action Resolution**: If violations are triggered, the policy's action is evaluated against the `ACTION_PRIORITY` hierarchy:
   $$\text{QUARANTINE (5)} > \text{BLOCK (4)} > \text{REDACT (3)} > \text{AUDIT (2)} > \text{ALLOW (1)}$$
   The highest-priority triggered policy determines the primary driving decision.
5. **System Fallback**: If no custom policies match or trigger violations, system default fallbacks are applied.

---

## 5. Administrative REST API Reference

All policy management endpoints are located in [`src/api/routes/policies.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/src/api/routes/policies.py) under the `/api/v1/admin/policies` route group. Access is restricted to `ADMIN` users via `require_admin` dependency.

| Method | Endpoint | Summary |
| :--- | :--- | :--- |
| `GET` | `/api/v1/admin/policies` | List all security policies (supports filtering by `tenant_id`, `target_role`, and `active_only`). |
| `POST` | `/api/v1/admin/policies` | Create a new security policy. |
| `GET` | `/api/v1/admin/policies/{id}` | Retrieve a specific policy by UUID. |
| `PUT` | `/api/v1/admin/policies/{id}` | Update an existing policy. |
| `DELETE` | `/api/v1/admin/policies/{id}` | Soft/Hard delete a security policy. |
| `POST` | `/api/v1/admin/policies/seed` | Seed default system policies into the database. |
| `POST` | `/api/v1/admin/policies/evaluate` | Dry-run test evaluation of a context against active policies. |

---

## 6. Pre-Packaged Out-of-the-Box System Policies

System default policies are initialized via [`scripts/seed_policies.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/scripts/seed_policies.py) or `POST /api/v1/admin/policies/seed`:

| Policy Name | Target Role | Priority | Max Risk | Action | Blocked Entities / Rules |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Default Admin Policy** | `admin` | **10** | `1.00` | `ALLOW` | Administrative bypass with full operational audit logging. |
| **Strict Quarantine Policy** | `*` | **20** | `0.85` | `QUARANTINE` | `["API_KEY", "PRIVATE_KEY", "AWS_KEY"]` |
| **Default Agent Exfiltration Policy** | `agent` | **30** | `0.70` | `BLOCK` | Exfiltration protections & prompt injection safeguards for AI agents. |
| **Default User PII Policy** | `user` | **40** | `0.60` | `REDACT` | `["SSN", "CREDIT_CARD", "PASSPORT_NUMBER"]` |
| **Audit All Policy** | `*` | **100** | `0.00` | `AUDIT` | Catch-all audit logging for all memory transactions. |

---

## 7. Verification & Test Suite Coverage

The Week 4 test suite is located in [`tests/test_policy_engine.py`](file:///c:/Users/triss/OneDrive/Desktop/AI%20memory%20Firewall/tests/test_policy_engine.py).

### 7.1 Test Coverage Summary (23 Scenarios)

1. **Unit Engine Tests**:
   * RBAC role matching & wildcard fallback.
   * Priority order sorting & action precedence resolution.
   * Risk threshold trigger evaluation.
   * Blocked entity set intersections.
   * Keyword and Regex pattern matching.
2. **Database Integration Tests**:
   * Policy creation, update, and deletion via `policy_service.py`.
   * Tenant isolation & policy filtering.
   * Execution of `scripts/seed_policies.py`.
3. **Admin API Authorization Tests**:
   * Verification that non-admin tokens return HTTP 403 Forbidden.
   * Verification that valid admin JWT tokens can perform CRUD operations.
4. **Stage 4.5 Integration Tests**:
   * End-to-end evaluation via `FirewallEvaluator.evaluate()`.

### 7.2 Running Tests

To run the full policy engine test suite:

```bash
.\venv\Scripts\python.exe -m pytest tests/test_policy_engine.py -v
```

Output:
```text
======================== 23 passed in 4.01s ========================
```
