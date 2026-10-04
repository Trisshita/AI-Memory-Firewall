"""
AI Memory Firewall - Audit Log & Alert Schemas (Week 6)
=======================================================
Pydantic v2 schemas for the tamper-proof global hash-chain audit log
endpoints and security alert management API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ─── AuditLogEntry Schemas ─────────────────────────────────────────────────────

class AuditLogEntryResponse(BaseModel):
    """Serialized view of a single AuditLogEntry chain node."""

    id: UUID
    sequence_number: int
    tenant_id: Optional[UUID]
    event_id: Optional[UUID]
    event_type: str
    severity: str
    actor: Optional[str]
    action: str
    resource: Optional[str]
    payload: Optional[Dict[str, Any]]
    previous_hash: str
    entry_hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    """Paginated list of chain log entries."""

    total: int
    chain_length: int = Field(
        description="Total number of entries in the global chain at query time."
    )
    entries: List[AuditLogEntryResponse]


class AuditSummaryResponse(BaseModel):
    """Aggregated system metrics for the dashboard."""

    total_events: int
    total_blocked: int
    total_memories: int
    quarantined_memories: int
    active_alerts: int
    chain_length: int
    pending_decisions: int
    is_chain_valid: bool


# ─── Chain Verification Schemas ────────────────────────────────────────────────

class ChainVerificationResponse(BaseModel):
    """
    Result of GET /api/v1/audit/verify — full hash-chain integrity scan.

    is_valid is True only when every entry's stored entry_hash matches
    the value recomputed from its canonical content + previous_hash.
    """

    is_valid: bool = Field(description="True if all chain hashes are intact.")
    total_entries: int = Field(description="Number of chain entries scanned.")
    first_broken_sequence: Optional[int] = Field(
        default=None,
        description="Sequence number of the first tampered entry (null if valid).",
    )
    broken_entries: List[int] = Field(
        default_factory=list,
        description="All sequence numbers where hash mismatch was detected.",
    )
    verification_time_ms: float = Field(
        description="Wall-clock time of the verification pass in milliseconds."
    )
    message: str = Field(description="Human-readable summary of the verification result.")


# ─── SecurityAlert Schemas ─────────────────────────────────────────────────────

class SecurityAlertResponse(BaseModel):
    """Serialized view of a SecurityAlert."""

    id: UUID
    tenant_id: Optional[UUID]
    alert_type: str
    severity: str
    title: str
    description: Optional[str]
    related_entry_id: Optional[UUID]
    is_resolved: bool
    resolved_at: Optional[datetime]
    metadata_json: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SecurityAlertListResponse(BaseModel):
    """Paginated list of security alerts."""

    total: int
    unresolved_count: int
    alerts: List[SecurityAlertResponse]


class ResolveAlertResponse(BaseModel):
    """Response after resolving a security alert."""

    id: UUID
    is_resolved: bool
    resolved_at: Optional[datetime]
    message: str
