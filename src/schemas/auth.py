"""
AI Memory Firewall - Authentication & Authorization Schemas
===========================================================
Pydantic v2 validation models for user authentication, JWT tokens, RBAC, and API keys.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ─── User Authentication Schemas ──────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    """Payload for registering a new user."""
    email: EmailStr = Field(..., description="Unique email address for user login")
    password: str = Field(..., min_length=8, max_length=128, description="User password (min 8 characters)")
    role: str = Field(default="user", description="Role: 'user', 'admin', or 'agent'")
    tenant_id: Optional[uuid.UUID] = Field(default=None, description="Optional tenant association UUID")


class UserLoginRequest(BaseModel):
    """Payload for user login authentication."""
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="Account password")


class TokenRefreshRequest(BaseModel):
    """Payload for refreshing an expired access token."""
    refresh_token: str = Field(..., description="Valid JWT refresh token")


class TokenResponse(BaseModel):
    """Response containing JWT access and refresh token pair."""
    access_token: str = Field(..., description="Bearer JWT access token")
    refresh_token: str = Field(..., description="Long-lived JWT refresh token")
    token_type: str = Field(default="bearer", description="OAuth2 token type")
    expires_in: int = Field(..., description="Access token expiration window in seconds")


class UserResponse(BaseModel):
    """Public representation of a user profile."""
    id: uuid.UUID
    email: str
    role: str
    is_active: bool
    tenant_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── API Key Schemas ──────────────────────────────────────────────────────────

class APIKeyCreateRequest(BaseModel):
    """Payload for generating a new application or agent API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Descriptive label for this key")
    tenant_id: Optional[uuid.UUID] = Field(default=None, description="Optional tenant boundary UUID")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Optional lifetime in days")


class APIKeyCreatedResponse(BaseModel):
    """Response returned upon key generation — displays plaintext secret once."""
    id: uuid.UUID
    name: str
    key: str = Field(..., description="Full secret API key. Store this securely — it cannot be retrieved again.")
    key_prefix: str
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    """Metadata response for an existing API key (without plaintext secret)."""
    id: uuid.UUID
    name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
