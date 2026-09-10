"""
AI Memory Firewall - API v1 Main Router
=========================================
Aggregates all sub-routers under the /api/v1 prefix.
"""

from fastapi import APIRouter

from src.api.routes.audit import router as audit_router
from src.api.routes.auth import router as auth_router
from src.api.routes.firewall import router as firewall_router
from src.api.routes.memory import router as memory_router
from src.api.routes.policies import router as policies_router
from src.api.routes.rules import router as rules_router

# Root v1 router — mounted at /api/v1 in app.py
api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router, prefix="/auth")
api_v1_router.include_router(firewall_router)
api_v1_router.include_router(memory_router)
api_v1_router.include_router(rules_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(policies_router)


