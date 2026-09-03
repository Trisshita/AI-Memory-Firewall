"""
AI Memory Firewall - Application Factory
========================================
Initializes and configures the FastAPI application instance with middleware and routes.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from config.database import sync_engine
from config.settings import settings


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title=settings.app_name,
        description=(
            "A real-time security proxy & guardrail layer for AI memory systems. "
            "Prevents unauthorized data access, prompt injection attacks, and sensitive "
            "information leakage across AI agent sessions."
        ),
        version=settings.api_version,
        debug=settings.app_debug,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS Middleware ────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.app_env == "development" else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── System Health Routes ───────────────────────────────────────────────
    @app.get("/health", tags=["System"])
    async def health_check():
        """General health status check."""
        return {
            "status": "healthy",
            "service": settings.app_name,
            "version": settings.api_version,
            "environment": settings.app_env,
        }

    @app.get("/health/db", tags=["System"])
    async def db_health_check():
        """Database connectivity diagnostic."""
        try:
            with sync_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {
                "status": "connected",
                "database": settings.db_name,
                "host": settings.db_host,
            }
        except Exception as exc:
            return {
                "status": "disconnected",
                "error": str(exc),
                "database": settings.db_name,
                "host": settings.db_host,
            }

    # ── API v1 Router ──────────────────────────────────────────────────────
    from src.api.router import api_v1_router  # imported here to avoid circular imports

    app.include_router(api_v1_router)

    return app
