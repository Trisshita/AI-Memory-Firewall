"""
AI Memory Firewall - Database Configuration & Session Management
================================================================
SQLAlchemy 2.0 engine, declarative base, and session generators.
"""

from typing import AsyncGenerator, Generator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config.settings import settings


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy 2.0 ORM models."""
    pass


# ─── Synchronous Engine & Session (Alembic, Migrations, Sync scripts) ───────────
is_sqlite = settings.sync_database_url.startswith("sqlite")

if is_sqlite:
    sync_engine = create_engine(
        settings.sync_database_url,
        echo=settings.db_echo,
        connect_args={"check_same_thread": False},
    )
else:
    sync_engine = create_engine(
        settings.sync_database_url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_sync_db() -> Generator[Session, None, None]:
    """Dependency for yielding a synchronous database session."""
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Asynchronous Engine & Session (FastAPI Async Endpoints) ───────────────────
# Check if running async-compatible driver
is_async_supported = not settings.async_database_url.startswith("sqlite://")

if is_async_supported:
    async_engine = create_async_engine(
        settings.async_database_url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )
    AsyncSessionLocal = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
else:
    async_engine = None
    AsyncSessionLocal = None


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for yielding an asynchronous database session."""
    if AsyncSessionLocal is None:
        raise RuntimeError("Async engine not configured for current database dialect.")
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
