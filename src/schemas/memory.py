"""
AI Memory Firewall - Memory Record Schemas
==========================================
Pydantic schemas for memory storage and retrieval API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class StoreMemoryRequest(BaseModel):
    """Request payload for POST /api/v1/memory/store"""

    text: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
        description="Raw memory content to be inspected and stored.",
    )
    tenant_id: UUID = Field(..., description="UUID of the tenant that owns this memory.")
    session_id: UUID = Field(..., description="UUID of the AI agent session this memory belongs to.")
    memory_type: Optional[str] = Field(
        default="SHORT_TERM",
        description="Memory type: SHORT_TERM, LONG_TERM, EPISODIC, SEMANTIC, SYSTEM_PROMPT, USER_CONTEXT",
    )
    sensitivity_tier: Optional[str] = Field(
        default="INTERNAL",
        description="Sensitivity classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, CRITICAL",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional key-value metadata to attach to the memory record.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "text": "User asked about Q3 financial results. Their account number is 4532-1234-5678-9010",
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "session_id": "550e8400-e29b-41d4-a716-446655440001",
            "memory_type": "EPISODIC",
            "sensitivity_tier": "CONFIDENTIAL",
        }
    }}


class MemoryRecordResponse(BaseModel):
    """Serialized view of a stored MemoryRecord for API responses."""

    id: UUID
    session_id: UUID
    memory_type: str
    sensitivity_tier: str
    sanitized_content: str = Field(..., description="The cleaned, redacted version of the stored memory")
    is_quarantined: bool
    quarantine_reason: Optional[str]
    content_hash: str
    vector_id: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class MemoryListResponse(BaseModel):
    """Paginated list of memory records for a session."""

    session_id: UUID
    total: int
    memories: List[MemoryRecordResponse]
