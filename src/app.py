"""
AI Memory Firewall - Application Factory
"""

from fastapi import FastAPI


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AI Memory Firewall",
        description="A security layer for AI memory systems",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "service": "AI Memory Firewall"}

    return app
