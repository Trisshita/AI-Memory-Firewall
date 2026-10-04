"""
AI Memory Firewall - Domain Models Package
==========================================
Exports all database entity models for application access and Alembic migrations.
"""

from config.database import Base
from src.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from src.models.agent import AgentSession, Tenant
from src.models.memory import MemoryRecord, MemoryType, SensitivityLevel
from src.models.policy import FirewallRule, RuleAction, RuleType
from src.models.audit import (
    AlertSeverity,
    AlertType,
    AuditEventType,
    AuditLogEntry,
    SecurityAlert,
    SecurityAuditEvent,
    ViolationStatus,
)
from src.models.user import User, UserRole
from src.models.api_key import APIKey
from src.models.decision import (
    DecisionChoice,
    DecisionScope,
    DecisionStatus,
    UserDecision,
)

__all__ = [
    "Base",
    "UUIDPrimaryKeyMixin",
    "TimestampMixin",
    "Tenant",
    "AgentSession",
    "MemoryRecord",
    "SensitivityLevel",
    "MemoryType",
    "FirewallRule",
    "RuleAction",
    "RuleType",
    "SecurityAuditEvent",
    "ViolationStatus",
    # Week 6
    "AuditLogEntry",
    "SecurityAlert",
    "AuditEventType",
    "AlertType",
    "AlertSeverity",
    "User",
    "UserRole",
    "APIKey",
    # Week 8
    "UserDecision",
    "DecisionStatus",
    "DecisionChoice",
    "DecisionScope",
]
