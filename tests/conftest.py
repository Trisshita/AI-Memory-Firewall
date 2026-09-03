"""
Pytest Fixtures & Test Setup
============================
Provides test client, isolated test database sessions, and mock configurations.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from config.database import Base
from src.app import create_app


@pytest.fixture(scope="session")
def test_engine():
    """In-memory SQLite database engine for fast unit tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(test_engine):
    """Provides an isolated database session per test function."""
    connection = test_engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(bind=connection, expire_on_commit=False)
    session = SessionLocal()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="module")
def client():
    """Provides a FastAPI test client."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
