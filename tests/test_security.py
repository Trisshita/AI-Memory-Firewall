"""
Unit Tests - Security & Cryptography Module
===========================================
Tests for AES-256 Fernet encryption, bcrypt password hashing,
JWT token creation/verification, audit log hashing, and API key management.
"""

from datetime import timedelta
import pytest
from cryptography.fernet import Fernet
import jwt

from config.settings import settings
from src.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_data,
    encrypt_data,
    generate_api_key,
    generate_encryption_key,
    hash_audit_log,
    hash_password,
    verify_api_key,
    verify_password,
    verify_token,
)


# ─── 1. Password Hashing (bcrypt) Tests ────────────────────────────────────────

def test_hash_password_generates_valid_bcrypt_hash():
    """Test that hash_password generates standard bcrypt hashes."""
    pwd = "super-secret-password-123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")


def test_verify_password_success_and_failure():
    """Test verifying correct vs incorrect passwords."""
    pwd = "mySecurePassword!987"
    hashed = hash_password(pwd)

    # Correct password
    assert verify_password(pwd, hashed) is True

    # Incorrect password
    assert verify_password("wrongPassword!987", hashed) is False

    # Empty attempts
    assert verify_password("", hashed) is False
    assert verify_password(pwd, "") is False


def test_hash_password_empty_raises_error():
    """Test that empty password string raises ValueError."""
    with pytest.raises(ValueError, match="Password cannot be empty"):
        hash_password("")


# ─── 2. AES-256 (Fernet) Encryption & Decryption Tests ────────────────────────

def test_generate_encryption_key():
    """Test that key generator returns a valid 32-byte url-safe Fernet key."""
    key = generate_encryption_key()
    assert isinstance(key, str)
    assert len(key) == 44  # 32 bytes in base64 URL-safe is 44 chars
    # Ensure Fernet accepts it
    f = Fernet(key.encode("utf-8"))
    assert f is not None


def test_encrypt_and_decrypt_data_roundtrip():
    """Test symmetric encryption and decryption roundtrip."""
    plain_text = "Patient SSN: 123-45-6789 and private notes."
    cipher_text = encrypt_data(plain_text)
    
    assert cipher_text != plain_text
    assert len(cipher_text) > 0

    decrypted = decrypt_data(cipher_text)
    assert decrypted == plain_text


def test_encrypt_and_decrypt_with_custom_key():
    """Test encryption and decryption with an explicit custom Fernet key."""
    custom_key = generate_encryption_key()
    plain_text = "Tenant custom secret token"
    cipher_text = encrypt_data(plain_text, key=custom_key)

    decrypted = decrypt_data(cipher_text, key=custom_key)
    assert decrypted == plain_text


def test_decrypt_tampered_ciphertext_raises_error():
    """Test that tampered ciphertext fails decryption safely."""
    plain_text = "Sensitive data"
    cipher_text = encrypt_data(plain_text)

    # Tamper with the ciphertext by replacing characters in the middle
    tampered = cipher_text[:-5] + "XXXXX"
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_data(tampered)


def test_encrypt_empty_string_returns_empty():
    """Test that encrypting/decrypting empty strings returns empty string."""
    assert encrypt_data("") == ""
    assert decrypt_data("") == ""


# ─── 3. JWT Token Management Tests ────────────────────────────────────────────

def test_create_and_decode_access_token():
    """Test access token generation and claims decoding."""
    subject = "user-uuid-1234-5678"
    token = create_access_token(
        subject=subject,
        role="admin",
        claims={"tenant_id": "tenant-abc-999"},
        expires_delta=timedelta(minutes=15),
    )

    payload = decode_token(token)
    assert payload["sub"] == subject
    assert payload["role"] == "admin"
    assert payload["tenant_id"] == "tenant-abc-999"
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_verify_access_token_success():
    """Test verify_token validates expected token type."""
    token = create_access_token(subject="user-1", role="user")
    payload = verify_token(token, expected_type="access")
    assert payload["sub"] == "user-1"
    assert payload["role"] == "user"


def test_create_and_verify_refresh_token():
    """Test refresh token generation and verification."""
    token = create_refresh_token(subject="user-refresh-test")
    payload = verify_token(token, expected_type="refresh")
    assert payload["sub"] == "user-refresh-test"
    assert payload["type"] == "refresh"


def test_verify_token_type_mismatch_raises_error():
    """Test that passing an access token when refresh is expected raises ValueError."""
    access_token = create_access_token(subject="user-1")
    with pytest.raises(ValueError, match="Invalid token type: expected 'refresh'"):
        verify_token(access_token, expected_type="refresh")


def test_expired_token_raises_expired_signature_error():
    """Test that expired token raises ExpiredSignatureError."""
    # Create a token that expired 10 minutes ago
    expired_token = create_access_token(
        subject="user-expired",
        expires_delta=timedelta(minutes=-10),
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(expired_token)


def test_invalid_token_signature_raises_error():
    """Test that a token signed with a different key is rejected."""
    tampered_token = jwt.encode(
        {"sub": "hacker", "type": "access"},
        "wrong-secret-key-12345",
        algorithm="HS256",
    )
    with pytest.raises(jwt.InvalidSignatureError):
        decode_token(tampered_token)


# ─── 4. Audit Log Hashing Tests ───────────────────────────────────────────────

def test_hash_audit_log_deterministic():
    """Test that hash_audit_log produces deterministic SHA-256 digests."""
    data1 = {"event": "INSPECT", "tenant_id": "t1", "action": "BLOCK"}
    data2 = {"tenant_id": "t1", "action": "BLOCK", "event": "INSPECT"}  # different key order

    hash1 = hash_audit_log(data1)
    hash2 = hash_audit_log(data2)

    assert len(hash1) == 64
    assert hash1 == hash2  # key sorting ensures identical hash


def test_hash_audit_log_string_and_bytes():
    """Test hash_audit_log on raw string and bytes."""
    h_str = hash_audit_log("system security event log entry")
    h_bytes = hash_audit_log(b"system security event log entry")
    assert len(h_str) == 64
    assert h_str == h_bytes


# ─── 5. API Key Generation & Verification Tests ───────────────────────────────

def test_generate_and_verify_api_key():
    """Test API key generation, structure, and constant-time verification."""
    full_key, key_hash, masked_key = generate_api_key(prefix="amf_live_")

    assert full_key.startswith("amf_live_")
    assert len(full_key) > 40
    assert len(key_hash) == 64  # SHA-256 hex digest
    assert masked_key.startswith("amf_live_...")
    assert masked_key.endswith(full_key[-4:])

    # Verification
    assert verify_api_key(full_key, key_hash) is True
    assert verify_api_key("amf_live_invalid_key_attempt", key_hash) is False
    assert verify_api_key("", key_hash) is False
    assert verify_api_key(full_key, "") is False
