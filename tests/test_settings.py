"""
Tests for Application Settings Configuration
============================================
"""

from config.settings import Settings


def test_settings_defaults():
    """Verify default setting properties."""
    settings = Settings(
        APP_NAME="AI Memory Firewall",
        DB_HOST="localhost",
        DB_PORT=5432,
        DB_NAME="ai_memory_firewall_dev",
        DB_USER="ai_firewall_user",
        DB_PASSWORD="change-me",
    )
    expected_sync = "postgresql+psycopg2://ai_firewall_user:change-me@localhost:5432/ai_memory_firewall_dev"
    expected_async = "postgresql+asyncpg://ai_firewall_user:change-me@localhost:5432/ai_memory_firewall_dev"
    assert settings.app_name == "AI Memory Firewall"
    assert settings.sync_database_url == expected_sync
    assert settings.async_database_url == expected_async


def test_settings_custom_database_url():
    """Verify custom database_url parsing."""
    settings = Settings(
        DATABASE_URL="postgresql://user:pass@remotehost:5433/custom_db"
    )
    assert settings.sync_database_url == "postgresql+psycopg2://user:pass@remotehost:5433/custom_db"
    assert settings.async_database_url == "postgresql+asyncpg://user:pass@remotehost:5433/custom_db"
