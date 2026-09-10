"""
AI Memory Firewall - Authentication & Authorization Dependencies
=================================================================
FastAPI dependency injection utilities for JWT token extraction, user validation,
Role-Based Access Control (RBAC), and API key verification.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Callable, Optional
import uuid

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
import jwt
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.models.api_key import APIKey
from src.models.user import User, UserRole
from src.security import decode_token, verify_api_key, verify_token


# ─── Security Schemes ─────────────────────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


# ─── JWT User Authentication ──────────────────────────────────────────────────

def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_sync_db),
) -> User:
    """
    Extract and validate JWT Bearer token, then load the corresponding user.
    
    Raises:
        HTTPException(401): If token is missing, expired, invalid, or user does not exist.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_token(token, expected_type="access")
        user_id_str: Optional[str] = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing subject identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Resolve user by UUID primary key or email
    try:
        user_uuid = uuid.UUID(user_id_str)
        user = db.query(User).filter(User.id == user_uuid).first()
    except ValueError:
        user = db.query(User).filter(User.email == user_id_str).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user account is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )
    return current_user


# ─── Role-Based Access Control (RBAC) ─────────────────────────────────────────

def require_role(*allowed_roles: str) -> Callable[[User], User]:
    """
    Dependency factory enforcing Role-Based Access Control on endpoint routes.
    
    Example:
        @router.get("/admin/metrics", dependencies=[Depends(require_role("admin"))])
    """
    def role_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. Required role in {list(allowed_roles)}, "
                    f"current role is '{current_user.role}'."
                ),
            )
        return current_user

    return role_checker


require_admin = require_role(UserRole.ADMIN.value)
require_user = require_role(UserRole.USER.value, UserRole.ADMIN.value)


# ─── API Key Verification ─────────────────────────────────────────────────────

def verify_api_key_header(
    api_key: Optional[str] = Security(api_key_header_scheme),
    db: Session = Depends(get_sync_db),
) -> APIKey:
    """
    Verify X-API-Key header credential for programmatic AI agent applications.
    
    Raises:
        HTTPException(401): If header is missing or key is invalid/expired/deactivated.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key header 'X-API-Key' is required",
        )

    # Search by key_prefix or scan active keys
    active_keys = db.query(APIKey).filter(APIKey.is_active.is_(True)).all()
    matched_key: Optional[APIKey] = None

    for candidate in active_keys:
        if verify_api_key(api_key, candidate.key_hash):
            matched_key = candidate
            break

    if not matched_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Check expiration if configured
    if matched_key.expires_at is not None:
        now = datetime.now(timezone.utc)
        if matched_key.expires_at < now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )

    return matched_key
