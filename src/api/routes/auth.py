"""
AI Memory Firewall - Authentication & Security Router
=====================================================
REST API endpoints for user registration, login, JWT token refresh,
profile retrieval, and API key management.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
import jwt
from sqlalchemy.orm import Session

from config.database import get_sync_db
from config.settings import settings
from src.api.deps import get_current_active_user
from src.models.api_key import APIKey
from src.models.user import User, UserRole
from src.schemas.auth import (
    APIKeyCreatedResponse,
    APIKeyCreateRequest,
    APIKeyResponse,
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from src.security import (
    create_access_token,
    create_refresh_token,
    generate_api_key,
    hash_password,
    verify_password,
    verify_token,
)

router = APIRouter(tags=["Authentication & Security"])


# ─── 1. User Registration ─────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register_user(
    request: UserRegisterRequest,
    db: Session = Depends(get_sync_db),
) -> UserResponse:
    """Create a new user account with secure bcrypt password hashing."""
    # Check if email is already taken
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists.",
        )

    # Validate role value
    valid_roles = {r.value for r in UserRole}
    if request.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{request.role}'. Allowed roles: {list(valid_roles)}",
        )

    # Hash password with bcrypt
    password_hash = hash_password(request.password)

    new_user = User(
        email=str(request.email),
        hashed_password=password_hash,
        role=request.role,
        tenant_id=request.tenant_id,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse.model_validate(new_user)


# ─── 2. User Login ────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and return JWT tokens",
)
def login_user(
    request: UserLoginRequest,
    db: Session = Depends(get_sync_db),
) -> TokenResponse:
    """Authenticate email & password and issue JWT access and refresh token pair."""
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    access_token = create_access_token(
        subject=str(user.id),
        role=user.role,
        claims={"email": user.email, "tenant_id": str(user.tenant_id) if user.tenant_id else None},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


# ─── 3. Token Refresh ─────────────────────────────────────────────────────────

@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh an expired access token using a refresh token",
)
def refresh_token(
    request: TokenRefreshRequest,
    db: Session = Depends(get_sync_db),
) -> TokenResponse:
    """Validate a JWT refresh token and issue a new access token."""
    try:
        payload = verify_token(request.refresh_token, expected_type="refresh")
        user_id_str = payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(exc)}",
        )

    try:
        user_uuid = uuid.UUID(user_id_str)
        user = db.query(User).filter(User.id == user_uuid).first()
    except (ValueError, TypeError):
        user = None

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with refresh token is not found or inactive.",
        )

    new_access_token = create_access_token(
        subject=str(user.id),
        role=user.role,
        claims={"email": user.email, "tenant_id": str(user.tenant_id) if user.tenant_id else None},
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


# ─── 4. Current User Profile ──────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
def get_current_user_profile(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Retrieve details of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


# ─── 5. API Key Management ────────────────────────────────────────────────────

@router.post(
    "/api-keys",
    response_model=APIKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new API key for applications or AI agents",
)
def create_app_api_key(
    request: APIKeyCreateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_sync_db),
) -> APIKeyCreatedResponse:
    """Generate a high-entropy API key. Plaintext is returned once upon creation."""
    full_key, key_hash, masked_key = generate_api_key(prefix="amf_live_")

    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)

    target_tenant_id = request.tenant_id or current_user.tenant_id

    api_key_record = APIKey(
        name=request.name,
        key_prefix=full_key[:12],
        key_hash=key_hash,
        user_id=current_user.id,
        tenant_id=target_tenant_id,
        is_active=True,
        expires_at=expires_at,
    )
    db.add(api_key_record)
    db.commit()
    db.refresh(api_key_record)

    return APIKeyCreatedResponse(
        id=api_key_record.id,
        name=api_key_record.name,
        key=full_key,
        key_prefix=api_key_record.key_prefix,
        is_active=api_key_record.is_active,
        created_at=api_key_record.created_at,
        expires_at=api_key_record.expires_at,
    )


@router.get(
    "/api-keys",
    response_model=List[APIKeyResponse],
    status_code=status.HTTP_200_OK,
    summary="List API keys for current user",
)
def list_app_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_sync_db),
) -> List[APIKeyResponse]:
    """List metadata for API keys associated with the current user."""
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).all()
    return [APIKeyResponse.model_validate(k) for k in keys]


@router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
)
def revoke_api_key(
    key_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_sync_db),
) -> None:
    """Deactivate or revoke an API key."""
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found or access denied.",
        )
    key.is_active = False
    db.commit()
