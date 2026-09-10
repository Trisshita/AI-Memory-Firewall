"""
Tests for Authentication & Security REST API Endpoints
======================================================
Tests /auth/register, /auth/login, /auth/refresh, /auth/me, /auth/api-keys,
JWT middleware verification, and Role-Based Access Control (RBAC).
Uses an in-memory SQLite test database.
"""

from typing import Generator
import uuid

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config.database import Base, get_sync_db
from src.api.deps import get_current_active_user, require_admin
from src.app import create_app
from src.models import Tenant, User, UserRole


# ─── Test Fixtures & In-Memory SQLite Database ────────────────────────────────

@pytest.fixture(scope="module")
def test_engine():
    """In-memory SQLite engine for test isolation."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def session_factory(test_engine):
    """SQLAlchemy sessionmaker bound to SQLite engine."""
    return sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


@pytest.fixture(scope="module")
def app_and_client(test_engine, session_factory):
    """FastAPI test app and client with overridden database dependency."""
    app = create_app()

    # Add a mock admin-only route for testing RBAC
    @app.get("/admin/test-rbac")
    def admin_only_endpoint(admin: User = Depends(require_admin)):
        return {"message": f"Welcome Admin {admin.email}"}

    def override_get_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_sync_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ─── 1. User Registration Tests ───────────────────────────────────────────────

def test_register_user_success(app_and_client):
    """Test standard user registration returns 201 and public user profile."""
    client = app_and_client
    payload = {
        "email": "user1@example.com",
        "password": "Password12345!",
        "role": "user",
    }
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "user1@example.com"
    assert data["role"] == "user"
    assert data["is_active"] is True
    assert "id" in data
    assert "hashed_password" not in data  # Never expose password hashes


def test_register_user_duplicate_email_rejected(app_and_client):
    """Test duplicate email registration fails with 409 Conflict."""
    client = app_and_client
    payload = {
        "email": "user1@example.com",
        "password": "AnotherPassword999!",
    }
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 409
    assert "already exists" in resp.json()["detail"]


def test_register_user_short_password_rejected(app_and_client):
    """Test registration with password under 8 chars fails with 422 Unprocessable Entity."""
    client = app_and_client
    payload = {
        "email": "shortpwd@example.com",
        "password": "123",  # Under 8 chars
    }
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_register_admin_user_success(app_and_client):
    """Test registering an admin user."""
    client = app_and_client
    payload = {
        "email": "admin@example.com",
        "password": "AdminSecretPassword99!",
        "role": "admin",
    }
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 201
    assert resp.json()["role"] == "admin"


# ─── 2. User Login Tests ──────────────────────────────────────────────────────

def test_login_user_success_returns_jwt_pair(app_and_client):
    """Test valid user login returns access and refresh JWT tokens."""
    client = app_and_client
    payload = {
        "email": "user1@example.com",
        "password": "Password12345!",
    }
    resp = client.post("/auth/login", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


def test_login_user_wrong_password_rejected(app_and_client):
    """Test login with incorrect password returns 401 Unauthorized."""
    client = app_and_client
    payload = {
        "email": "user1@example.com",
        "password": "IncorrectPassword999!",
    }
    resp = client.post("/auth/login", json=payload)
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_login_nonexistent_user_rejected(app_and_client):
    """Test login with unregistered email returns 401 Unauthorized."""
    client = app_and_client
    payload = {
        "email": "ghost@example.com",
        "password": "AnyPassword123!",
    }
    resp = client.post("/auth/login", json=payload)
    assert resp.status_code == 401


# ─── 3. Token Refresh Tests ───────────────────────────────────────────────────

def test_refresh_token_flow(app_and_client):
    """Test using a refresh token to obtain a new access token."""
    client = app_and_client
    
    # 1. Login to get refresh token
    login_resp = client.post(
        "/auth/login",
        json={"email": "user1@example.com", "password": "Password12345!"},
    )
    refresh_token = login_resp.json()["refresh_token"]

    # 2. Refresh token
    refresh_resp = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    new_data = refresh_resp.json()
    assert "access_token" in new_data
    assert "refresh_token" in new_data


def test_refresh_token_with_invalid_token_rejected(app_and_client):
    """Test refresh endpoint with invalid token returns 401."""
    client = app_and_client
    resp = client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid.jwt.token.string"},
    )
    assert resp.status_code == 401


# ─── 4. Current User Profile (/auth/me) Tests ─────────────────────────────────

def test_get_current_user_profile_success(app_and_client):
    """Test /auth/me returns current user info when valid Bearer token is provided."""
    client = app_and_client

    login_resp = client.post(
        "/auth/login",
        json={"email": "user1@example.com", "password": "Password12345!"},
    )
    access_token = login_resp.json()["access_token"]

    resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["email"] == "user1@example.com"


def test_get_current_user_profile_unauthorized_without_token(app_and_client):
    """Test /auth/me returns 401 when Authorization header is missing."""
    client = app_and_client
    resp = client.get("/auth/me")
    assert resp.status_code == 401


# ─── 5. Role-Based Access Control (RBAC) Tests ────────────────────────────────

def test_rbac_admin_allowed_and_user_forbidden(app_and_client):
    """Test RBAC: admin can access admin routes, standard user gets 403 Forbidden."""
    client = app_and_client

    # 1. Admin login
    admin_login = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "AdminSecretPassword99!"},
    )
    admin_token = admin_login.json()["access_token"]

    # 2. Standard user login
    user_login = client.post(
        "/auth/login",
        json={"email": "user1@example.com", "password": "Password12345!"},
    )
    user_token = user_login.json()["access_token"]

    # Admin access -> 200 OK
    admin_resp = client.get(
        "/admin/test-rbac",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_resp.status_code == 200
    assert "Welcome Admin admin@example.com" in admin_resp.json()["message"]

    # User access -> 403 Forbidden
    user_resp = client.get(
        "/admin/test-rbac",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert user_resp.status_code == 403
    assert "Insufficient permissions" in user_resp.json()["detail"]


# ─── 6. API Key Endpoints Tests ───────────────────────────────────────────────

def test_create_and_list_and_revoke_api_keys(app_and_client):
    """Test full lifecycle of API key creation, listing, and revocation."""
    client = app_and_client

    # Authenticate
    login_resp = client.post(
        "/auth/login",
        json={"email": "user1@example.com", "password": "Password12345!"},
    )
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 1. Create API key
    create_resp = client.post(
        "/auth/api-keys",
        json={"name": "LangChain Agent Key", "expires_in_days": 30},
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    key_data = create_resp.json()
    assert key_data["name"] == "LangChain Agent Key"
    assert key_data["key"].startswith("amf_live_")
    assert key_data["is_active"] is True
    key_id = key_data["id"]

    # 2. List API keys
    list_resp = client.get("/auth/api-keys", headers=auth_headers)
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert len(keys) >= 1
    assert any(k["id"] == key_id for k in keys)

    # 3. Revoke API key
    revoke_resp = client.delete(f"/auth/api-keys/{key_id}", headers=auth_headers)
    assert revoke_resp.status_code == 204


# ─── 7. /api/v1/auth Prefix Compatibility Tests ───────────────────────────────

def test_api_v1_auth_prefix_endpoint_works(app_and_client):
    """Verify endpoints are also accessible at /api/v1/auth/*."""
    client = app_and_client
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "user1@example.com", "password": "Password12345!"},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
