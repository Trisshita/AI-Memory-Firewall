# Week 2 Comprehensive Guide: Authentication & Security

> **Audience**: AI Developers, Security Engineers & Architects  
> **Goal**: Understand the complete authentication architecture, cryptographic subsystems, JWT lifecycle, RBAC middleware, and API key management implemented in Week 2.

---

## 1. Executive Summary & Threat Model

In Week 1, the AI Memory Firewall introduced real-time PII redaction and prompt injection detection for AI memory storage. However, in enterprise multi-tenant deployments, the firewall must also ensure:

1. **Identity & Authentication**: Only authenticated users and registered AI agents can store or recall memory context.
2. **Access Authorization (RBAC)**: Distinct permissions for standard users, tenant administrators, and autonomous AI agents.
3. **Data Protection at Rest**: Sensitive data and custom credentials encrypted using **AES-256 (Fernet)**.
4. **Machine-to-Machine Credentials**: High-entropy **API keys** with constant-time verification for backend AI microservices (e.g. LangChain, LlamaIndex, AutoGen).
5. **Audit Immutability**: Deterministic SHA-256 hashing to verify audit log integrity and prevent log tampering.

---

## 2. Architecture Overview

```
 ┌──────────────────────────────────────────────────────────┐
 │                      Client Layer                        │
 │  (Web Browser / Admin UI / Mobile App / AI Agent SDK)    │
 └────────────────────────────┬─────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       [Bearer JWT Token]              [X-API-Key Header]
              │                               │
 ┌────────────▼───────────────────────────────▼─────────────┐
 │            FastAPI Security Middleware Layer             │
 │  • oauth2_scheme (Bearer token extraction)               │
 │  • decode_token & verify_token (Signature, Expiry, Type) │
 │  • verify_api_key_header (Constant-time SHA-256 compare) │
 │  • require_role('admin' | 'user' | 'agent') (RBAC)       │
 └────────────────────────────┬─────────────────────────────┘
                              │
 ┌────────────────────────────▼─────────────────────────────┐
 │                Core Security Module                      │
 │                   (src/security.py)                      │
 │  • AES-256 Fernet Field-Level Encryption & Decryption    │
 │  • bcrypt Password Hashing (12 rounds)                   │
 │  • PyJWT Token Generation & Lifecycle (Access + Refresh) │
 │  • SHA-256 Deterministic Audit Log Hashing               │
 │  • API Key Generation & Masking (amf_live_...)           │
 └────────────────────────────┬─────────────────────────────┘
                              │
 ┌────────────────────────────▼─────────────────────────────┐
 │                Database Layer (PostgreSQL)               │
 │  • users (UUID, email, hashed_password, role, tenant_id) │
 │  • api_keys (UUID, name, key_prefix, key_hash, expires)  │
 └──────────────────────────────────────────────────────────┘
```

---

## 3. Core Subsystems Deep Dive

### 3.1. AES-256 (Fernet) Encryption Engine

- **Standard**: Fernet is an implementation of symmetric authenticated cryptography.
- **Under the hood**: Uses **AES-128/256 in CBC mode** with PKCS7 padding and **HMAC-SHA256 authentication**.
- **Tamper Protection**: Any bit-level modification to the ciphertext triggers an `InvalidToken` error, preventing chosen-ciphertext attacks.

```python
from src.security import encrypt_data, decrypt_data

# Encrypt sensitive memory payload
ciphertext = encrypt_data("User SSN: 123-45-6789")

# Decrypt safely
plaintext = decrypt_data(ciphertext)
```

---

### 3.2. Password Hashing with bcrypt

- **Standard**: Modern `bcrypt` adaptive hashing algorithm.
- **Salt Generation**: Automatically generates a unique, cryptographically random salt per user password with 12 cost rounds (`bcrypt.gensalt(12)`).
- **Protection**: Mitigates rainbow table precomputation attacks and GPU-accelerated brute-force cracking.

```python
from src.security import hash_password, verify_password

# During registration
hashed = hash_password("UserPassword123!")

# During login
is_valid = verify_password("UserPassword123!", hashed)
```

---

### 3.3. JWT Token Management & Refresh Flow

The system implements a dual-token architecture:

1. **Access Token (Short-lived, e.g., 60 minutes)**:
   - Contains claims: `sub` (User ID), `role` (`user` / `admin` / `agent`), `email`, `tenant_id`, `type` (`access`), `iat`, `exp`, `jti`.
   - Sent in the `Authorization: Bearer <token>` HTTP header for every API request.
2. **Refresh Token (Long-lived, e.g., 7 days)**:
   - Contains claims: `sub` (User ID), `type` (`refresh`), `iat`, `exp`, `jti`.
   - Used solely at `POST /auth/refresh` to obtain a fresh access token without requiring re-entry of user credentials.

```
 Client                          Auth Server (/auth)
   │                                     │
   ├────── POST /auth/login ────────────►│ (Validates email/password)
   │◄───── {access_token, refresh_token}─┤
   │                                     │
   ├────── (Calls protected APIs...) ───►│ (Validates access_token)
   │                                     │
   │  [Access Token Expires]             │
   │                                     │
   ├────── POST /auth/refresh ──────────►│ (Validates refresh_token)
   │◄───── {new access_token}────────────┤
```

---

### 3.4. Role-Based Access Control (RBAC)

RBAC is enforced via FastAPI dependency injection:

| Role | Permissions |
|:---|:---|
| **`admin`** | Full control: create firewall rules, inspect all tenant memories, manage tenant API keys, view complete audit logs. |
| **`user`** | Standard access: inspect text, store/recall own session memories, manage personal API keys. |
| **`agent`** | Headless machine access: programmatic inspection and memory persistence via API keys. |

```python
@router.post("/rules", dependencies=[Depends(require_role("admin"))])
def create_tenant_firewall_rule(...):
    ...
```

---

### 3.5. Application & Agent API Key Management

For autonomous AI agents (LangChain, LlamaIndex, OpenAI Assistants), the firewall provides programmatic API keys:
- **Format**: Prefixed `amf_live_<32 urlsafe random characters>` (e.g. `amf_live_d8F3aK...`).
- **One-time Display**: The full secret key is shown once to the user upon creation.
- **Storage**: Only the **SHA-256 cryptographic hash** of the key is stored in the database.
- **Constant-Time Verification**: Verification uses `hmac.compare_digest` to prevent side-channel timing attacks.

---

## 4. API Endpoints Reference

| Method | Endpoint | Auth Required | Description |
|:------:|:---------|:-------------:|:------------|
| `POST` | `/auth/register` | None | Register a new user with email & password |
| `POST` | `/auth/login` | None | Authenticate user; returns access + refresh JWT |
| `POST` | `/auth/refresh` | None | Exchange valid refresh token for a new access token |
| `GET`  | `/auth/me` | Bearer JWT | Retrieve profile of the authenticated user |
| `POST` | `/auth/api-keys` | Bearer JWT | Create new API key for applications/agents |
| `GET`  | `/auth/api-keys` | Bearer JWT | List active API keys belonging to the user |
| `DELETE`| `/auth/api-keys/{id}`| Bearer JWT | Revoke/deactivate an API key |

*(All endpoints are also available under the `/api/v1/auth/*` prefix).*

---

## 5. Automated Test Coverage

Week 2 introduces **27 new unit and integration tests**, expanding total test coverage to **108 tests with 100% pass rate**:

```
tests/
├── test_security.py       # 14 tests (AES-256 Fernet, bcrypt, JWT tokens, audit hashing, API keys)
├── test_auth_api.py       # 12 tests (register, login, refresh, profile, RBAC, API keys, prefix compat)
├── test_models.py         # +1 test (User & APIKey ORM models & relationships)
├── test_engine.py         # 48 tests (PII, injection detection, evaluator)
├── test_firewall_api.py   # 25 tests (Inspection, memory storage, rules, audit APIs)
├── test_app.py            # 2 tests (Health endpoints)
└── test_settings.py       # 2 tests (Settings validation)
```
