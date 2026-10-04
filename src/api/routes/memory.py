"""
AI Memory Firewall - Memory Storage & Retrieval Routes
======================================================
POST /api/v1/memory/store   — Inspect and persist a memory record
GET  /api/v1/memory/{session_id} — Retrieve safe memories for agent recall
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.schemas.memory import (
    GlobalMemoryListResponse,
    MemoryListResponse,
    MemoryRecordResponse,
    StoreMemoryRequest,
)
from src.schemas.firewall import DetectedViolation, InspectResponse
from src.services import firewall_service

router = APIRouter(prefix="/memory", tags=["Memory"])


@router.get(
    "",
    response_model=GlobalMemoryListResponse,
    summary="List All Memory Records",
    description="Query memory records with optional filters for session_id, sensitivity_tier, is_quarantined, and text search.",
)
def list_all_memories(
    session_id: Optional[UUID] = Query(default=None, description="Filter by session ID."),
    sensitivity_tier: Optional[str] = Query(default=None, description="Filter by sensitivity tier."),
    is_quarantined: Optional[bool] = Query(default=None, description="Filter by quarantine status."),
    search: Optional[str] = Query(default=None, description="Search keyword in sanitized content or metadata."),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
) -> GlobalMemoryListResponse:
    from src.models.memory import MemoryRecord

    query = db.query(MemoryRecord)
    if session_id:
        query = query.filter(MemoryRecord.session_id == session_id)
    if sensitivity_tier:
        query = query.filter(MemoryRecord.sensitivity_tier == sensitivity_tier)
    if is_quarantined is not None:
        query = query.filter(MemoryRecord.is_quarantined == is_quarantined)
    if search:
        query = query.filter(MemoryRecord.sanitized_content.ilike(f"%{search}%"))

    total = query.count()
    records = (
        query.order_by(MemoryRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return GlobalMemoryListResponse(
        total=total,
        memories=[
            MemoryRecordResponse(
                id=m.id,
                session_id=m.session_id,
                memory_type=m.memory_type.value if hasattr(m.memory_type, "value") else m.memory_type,
                sensitivity_tier=m.sensitivity_tier.value if hasattr(m.sensitivity_tier, "value") else m.sensitivity_tier,
                sanitized_content=m.sanitized_content,
                is_quarantined=m.is_quarantined,
                quarantine_reason=m.quarantine_reason,
                content_hash=m.content_hash,
                vector_id=m.vector_id,
                raw_content=m.raw_content,
                metadata_json=m.metadata_json,
                created_at=m.created_at,
            )
            for m in records
        ],
    )


@router.post(
    "/store",
    status_code=status.HTTP_201_CREATED,
    summary="Inspect & Store Memory",
    description=(
        "Runs the raw text through the full firewall evaluation pipeline, then persists "
        "the sanitized result as a MemoryRecord linked to the specified agent session. "
        "If the decision is BLOCK or QUARANTINE, the record is saved but flagged as "
        "quarantined — the agent **cannot recall it**. The evaluation result is returned "
        "alongside the stored record metadata."
    ),
)
def store_memory(
    payload: StoreMemoryRequest,
    request: Request,
    db: Session = Depends(get_sync_db),
) -> dict:
    """Store an inspected and sanitized memory record for an AI agent session."""
    client_ip = request.client.host if request.client else None

    memory, result = firewall_service.store_memory(
        db=db,
        tenant_id=payload.tenant_id,
        session_id=payload.session_id,
        text=payload.text,
        memory_type=payload.memory_type or "SHORT_TERM",
        sensitivity_tier=payload.sensitivity_tier or "INTERNAL",
        metadata=payload.metadata,
        client_ip=client_ip,
    )

    violations = [
        DetectedViolation(
            rule_id=v.rule_id,
            rule_name=v.rule_name,
            rule_type=v.rule_type,
            action=v.action,
            severity=v.severity,
            matched_text=v.matched_text,
            risk_contribution=v.risk_contribution,
        )
        for v in result.violations
    ]

    return {
        "memory": MemoryRecordResponse(
            id=memory.id,
            session_id=memory.session_id,
            memory_type=memory.memory_type.value if hasattr(memory.memory_type, "value") else memory.memory_type,
            sensitivity_tier=memory.sensitivity_tier.value if hasattr(memory.sensitivity_tier, "value") else memory.sensitivity_tier,
            sanitized_content=memory.sanitized_content,
            is_quarantined=memory.is_quarantined,
            quarantine_reason=memory.quarantine_reason,
            content_hash=memory.content_hash,
            vector_id=memory.vector_id,
            created_at=memory.created_at,
        ),
        "evaluation": InspectResponse(
            decision=result.decision,
            original_text=result.original_text,
            sanitized_text=result.sanitized_text,
            risk_score=result.risk_score,
            violations=violations,
            detected_entity_types=result.detected_entity_types,
            latency_ms=result.latency_ms,
            is_clean=result.is_clean,
        ),
    }


@router.get(
    "/{session_id}",
    response_model=MemoryListResponse,
    summary="Retrieve Agent Session Memories",
    description=(
        "Retrieves stored, non-quarantined memory records for the given agent session. "
        "By default, quarantined (dangerous) memories are excluded to protect the agent's context. "
        "Use `include_quarantined=true` only for admin/compliance review purposes."
    ),
)
def get_memories(
    session_id: UUID,
    include_quarantined: bool = Query(
        default=False,
        description="If true, includes quarantined (flagged) memory records in the response.",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_sync_db),
) -> MemoryListResponse:
    """Retrieve safe memory records for an AI agent session."""
    memories = firewall_service.get_session_memories(
        db=db,
        session_id=session_id,
        include_quarantined=include_quarantined,
        limit=limit,
        offset=offset,
    )

    return MemoryListResponse(
        session_id=session_id,
        total=len(memories),
        memories=[
            MemoryRecordResponse(
                id=m.id,
                session_id=m.session_id,
                memory_type=m.memory_type.value if hasattr(m.memory_type, "value") else m.memory_type,
                sensitivity_tier=m.sensitivity_tier.value if hasattr(m.sensitivity_tier, "value") else m.sensitivity_tier,
                sanitized_content=m.sanitized_content,
                is_quarantined=m.is_quarantined,
                quarantine_reason=m.quarantine_reason,
                content_hash=m.content_hash,
                vector_id=m.vector_id,
                created_at=m.created_at,
            )
            for m in memories
        ],
    )
