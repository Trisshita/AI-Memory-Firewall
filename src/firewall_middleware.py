"""
AI Memory Firewall - Core Firewall Middleware Facade
====================================================
Re-exports the core FirewallMiddleware components for convenient top-level access.
"""

from src.middleware.firewall_middleware import (
    FirewallMiddleware,
    MessageProcessResult,
    get_firewall_middleware,
)

__all__ = [
    "FirewallMiddleware",
    "MessageProcessResult",
    "get_firewall_middleware",
]
