"""
AI Memory Firewall - Application Configuration
==============================================
Typed application settings loaded from environment variables and .env file.
"""

from functools import lru_cache
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application and infrastructure configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application Settings ────────────────────────────────────
    app_name: str = Field(default="AI Memory Firewall", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    secret_key: str = Field(default="dev-secret-key-change-in-prod", alias="SECRET_KEY")
    api_version: str = Field(default="0.1.0", alias="API_VERSION")

    # ─── Server Settings ─────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")

    # ─── Database Settings ───────────────────────────────────────
    db_host: str = Field(default="localhost", alias="DB_HOST")
    db_port: int = Field(default=5432, alias="DB_PORT")
    db_name: str = Field(default="ai_memory_firewall_dev", alias="DB_NAME")
    db_user: str = Field(default="ai_firewall_user", alias="DB_USER")
    db_password: str = Field(default="change-me", alias="DB_PASSWORD")
    database_url: Optional[str] = Field(default=None, alias="DATABASE_URL")
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    @property
    def sync_database_url(self) -> str:
        """Returns the synchronous SQLAlchemy connection string (for Alembic & sync drivers)."""
        if self.database_url:
            # If user provided a postgresql:// URL, convert to postgresql+psycopg2 if needed
            if self.database_url.startswith("postgresql://"):
                return self.database_url.replace("postgresql://", "postgresql+psycopg2://", 1)
            return self.database_url
        return f"postgresql+psycopg2://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def async_database_url(self) -> str:
        """Returns the asynchronous SQLAlchemy connection string (for async engine)."""
        if self.database_url:
            if self.database_url.startswith("postgresql://"):
                return self.database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            if self.database_url.startswith("postgresql+psycopg2://"):
                return self.database_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
            return self.database_url
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"


@lru_cache()
def get_settings() -> Settings:
    """Cached singleton provider for application settings."""
    return Settings()


settings = get_settings()
