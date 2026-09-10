"""
AI Memory Firewall - Core Security & Cryptography Module
=========================================================
Provides enterprise-grade encryption, secure password hashing, JWT token management,
cryptographic audit log hashing, and API key generation.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Optional, Tuple, Union
import uuid

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
import jwt

from config.settings import settings


# ─── 1. AES-256 (Fernet) Symmetric Encryption ─────────────────────────────────

def generate_encryption_key() -> str:
    """Generate a new url-safe base64-encoded 32-byte Fernet key."""
    return Fernet.generate_key().decode("utf-8")


def _resolve_fernet(key: Optional[str] = None) -> Fernet:
    """Resolve a Fernet cipher instance using either the provided key or settings."""
    raw_key = key or settings.encryption_key
    if not raw_key:
        raise ValueError("Encryption key is required but not configured.")
    if isinstance(raw_key, str):
        key_bytes = raw_key.encode("utf-8")
    else:
        key_bytes = raw_key
    return Fernet(key_bytes)


def encrypt_data(plain_text: str, key: Optional[str] = None) -> str:
    """
    Encrypt plaintext using AES-256 (Fernet authenticated symmetric encryption).
    
    Args:
        plain_text: The string to encrypt.
        key: Optional 32-byte url-safe base64 key (defaults to settings.encryption_key).
        
    Returns:
        Base64-encoded ciphertext string.
    """
    if not plain_text:
        return ""
    fernet = _resolve_fernet(key)
    encrypted_bytes = fernet.encrypt(plain_text.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_data(cipher_text: str, key: Optional[str] = None) -> str:
    """
    Decrypt AES-256 Fernet ciphertext back to plaintext string.
    
    Args:
        cipher_text: The base64-encoded ciphertext string.
        key: Optional 32-byte url-safe base64 key.
        
    Returns:
        Decrypted UTF-8 plaintext string.
        
    Raises:
        ValueError: If ciphertext is empty, invalid, or tampered with.
    """
    if not cipher_text:
        return ""
    try:
        fernet = _resolve_fernet(key)
        decrypted_bytes = fernet.decrypt(cipher_text.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Decryption failed: invalid or tampered ciphertext.") from exc
    except Exception as exc:
        raise ValueError(f"Decryption failed: {str(exc)}") from exc


# ─── 2. Password Hashing (bcrypt) ────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt with a randomized salt.
    
    Args:
        password: Raw plaintext password.
        
    Returns:
        Hashed password string (UTF-8).
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    
    Args:
        plain_password: Raw plaintext password attempt.
        hashed_password: Stored bcrypt password hash.
        
    Returns:
        True if password matches hash, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ─── 3. JWT Token Management ──────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: str = "user",
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a signed JWT access token.
    
    Args:
        subject: Unique identifier of the subject (e.g. user ID / email).
        role: User role (e.g. 'admin', 'user', 'agent').
        claims: Optional additional custom claims dict.
        expires_delta: Optional explicit expiration duration.
        
    Returns:
        Encoded JWT token string.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if claims:
        payload.update(claims)

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a signed JWT refresh token with longer expiration window.
    
    Args:
        subject: Unique identifier of the subject.
        claims: Optional additional claims.
        expires_delta: Optional explicit expiration duration.
        
    Returns:
        Encoded refresh JWT token string.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.refresh_token_expire_days)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if claims:
        payload.update(claims)

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate signature & expiration of a JWT token.
    
    Args:
        token: Encoded JWT string.
        
    Returns:
        Decoded payload dict.
        
    Raises:
        jwt.ExpiredSignatureError: If token is expired.
        jwt.InvalidTokenError: If token is malformed or signature is invalid.
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )


def verify_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """
    Verify token validity and assert expected token type ('access' or 'refresh').
    
    Args:
        token: Encoded JWT string.
        expected_type: Expected 'type' claim ('access' or 'refresh').
        
    Returns:
        Decoded payload dict.
        
    Raises:
        ValueError: If token type does not match expected_type.
        jwt.PyJWTError: On signature or expiry errors.
    """
    payload = decode_token(token)
    token_type = payload.get("type")
    if token_type != expected_type:
        raise ValueError(f"Invalid token type: expected '{expected_type}', got '{token_type}'")
    return payload


# ─── 4. Cryptographic Hashing for Audit Logs & Tamper Proofing ────────────────

def hash_audit_log(payload: Union[str, Dict[str, Any], bytes]) -> str:
    """
    Compute a deterministic SHA-256 cryptographic hash of an audit log entry or payload.
    
    Args:
        payload: String, dictionary, or bytes representing audit content.
        
    Returns:
        Hex-encoded 64-character SHA-256 hash.
    """
    if isinstance(payload, dict):
        normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        data_bytes = normalized.encode("utf-8")
    elif isinstance(payload, str):
        data_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        data_bytes = payload
    else:
        data_bytes = str(payload).encode("utf-8")

    return hashlib.sha256(data_bytes).hexdigest()


# ─── 5. API Key Generation & Management ───────────────────────────────────────

def generate_api_key(prefix: str = "amf_live_") -> Tuple[str, str, str]:
    """
    Generate a secure random API key for AI agent applications.
    
    Args:
        prefix: Prefix for key readability (e.g. 'amf_live_', 'amf_test_').
        
    Returns:
        Tuple of (full_key, key_hash, masked_key):
        - full_key: Full plaintext secret key to display once to user (e.g. 'amf_live_abc123...').
        - key_hash: SHA-256 hash to store safely in the database.
        - masked_key: Safe display representation (e.g. 'amf_live_...a1b2').
    """
    random_secret = secrets.token_urlsafe(32)
    full_key = f"{prefix}{random_secret}"
    key_hash = hashlib.sha256(full_key.encode("utf-8")).hexdigest()
    masked_key = f"{prefix}...{full_key[-4:]}"
    return full_key, key_hash, masked_key


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """
    Verify a provided API key against a stored SHA-256 hash in constant time.
    
    Args:
        provided_key: The plaintext API key supplied in request header.
        stored_hash: The SHA-256 hash stored in the database.
        
    Returns:
        True if valid, False otherwise.
    """
    if not provided_key or not stored_hash:
        return False
    computed_hash = hashlib.sha256(provided_key.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed_hash, stored_hash)
