"""
AI Memory Firewall - Policy & Audit Schemas
============================================
Pydantic schemas for firewall rule management and security audit event endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ─── FirewallRule Schemas ─────────────────────────────────────────────────────

class CreateRuleRequest(BaseModel):
    """Request payload for POST /api/v1/rules — creates a new custom firewall rule."""

    tenant_id: UUID = Field(..., description="UUID of the tenant that owns this rule.")
    name: str = Field(..., min_length=3, max_length=255, description="Descriptive name for the rule.")
    description: Optional[str] = Field(default=None, description="Optional detailed description.")
    rule_type: str = Field(
        ...,
        description="REGEX_PATTERN | KEYWORD_FILTER | PII_DETECTION | PROMPT_INJECTION | DATA_EXFILTRATION | SEMANTIC_SIMILARITY",
    )
    pattern_payload: str = Field(
        ...,
        description="Regex pattern, comma-separated keyword list, or rule-specific payload.",
    )
    action: str = Field(
        default="AUDIT",
        description="Action to take when rule matches: ALLOW | REDACT | BLOCK | QUARANTINE | AUDIT",
    )
    severity: str = Field(default="MEDIUM", description="LOW | MEDIUM | HIGH | CRITICAL")
    priority_order: int = Field(default=100, ge=1, le=9999, description="Lower number = evaluated first.")
    is_active: bool = Field(default=True, description="Whether the rule is actively evaluated.")
    rule_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional JSON config for advanced rule parameters.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Block Competitor Mentions",
            "rule_type": "KEYWORD_FILTER",
            "pattern_payload": "competitor_alpha, rival_corp, enemy_brand",
            "action": "BLOCK",
            "severity": "HIGH",
            "priority_order": 20,
        }
    }}


class FirewallRuleResponse(BaseModel):
    """Serialized view of a FirewallRule for API responses."""

    id: UUID
    tenant_id: UUID
    name: str
    description: Optional[str]
    rule_type: str
    pattern_payload: str
    action: str
    severity: str
    priority_order: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FirewallRuleListResponse(BaseModel):
    """Paginated list of firewall rules for a tenant."""
    tenant_id: UUID
    total: int
    rules: List[FirewallRuleResponse]


# ─── SecurityAuditEvent Schemas ───────────────────────────────────────────────

class AuditEventResponse(BaseModel):
    """Serialized view of a SecurityAuditEvent for API responses."""

    id: UUID
    tenant_id: UUID
    session_id: Optional[UUID]
    rule_id: Optional[UUID]
    action_taken: str
    violation_status: str
    risk_score: float
    original_snippet: Optional[str]
    sanitized_snippet: Optional[str]
    detected_entities: Optional[Dict[str, Any]]
    latency_ms: Optional[float]
    client_ip: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditEventListResponse(BaseModel):
    """Paginated list of audit events."""
    tenant_id: UUID
    total: int
    events: List[AuditEventResponse]
