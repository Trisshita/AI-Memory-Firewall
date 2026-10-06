"""
AI Memory Firewall - Core Message & Decision Routes (Weeks 7 & 8)
=================================================================
POST /api/message and POST /api/v1/message
POST /api/message/decide and POST /api/v1/message/decide
GET  /api/message/pending/{session_id}

Coordinates end-to-end prompt inspection, memory encryption, OpenAI invocation,
human-in-the-loop (HITL) confirmation flows, and tamper-proof hash-chain audit logging.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.middleware.firewall_middleware import (
    FirewallMiddleware,
    MessageProcessResult,
    get_firewall_middleware,
)
from src.models.decision import UserDecision
from src.schemas.message import (
    DecideRequest,
    DecideResponse,
    MessageRequest,
    MessageResponse,
)
from src.security import decode_token
from src.services import decision_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Message Gateway"])


def _extract_actor_and_role(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    db: Optional[Session] = None,
) -> tuple[Optional[str], Optional[str], Optional[uuid.UUID]]:
    """
    Optional authentication resolver.
    If credentials are provided, validate them. Returns (actor_id, role, tenant_id).
    """
    actor: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[uuid.UUID] = None

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        try:
            payload = decode_token(token)
            actor = payload.get("sub")
            role = payload.get("role")
            tid_str = payload.get("tenant_id")
            if tid_str:
                tenant_id = uuid.UUID(tid_str)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {str(exc)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return actor, role, tenant_id


@router.post(
    "/message",
    response_model=MessageResponse,
    summary="Process Message Through Core Firewall Gateway",
    description=(
        "Full-pipeline AI interaction gateway: "
        "1. Inbound PII / prompt injection screening & strategy-aware redaction. "
        "2. Short-circuit blocking or HITL ASK_USER confirmation requests. "
        "3. Memory encryption at rest with AES-256 Fernet. "
        "4. Safe conversation context assembly (excluding quarantined records). "
        "5. OpenAI Chat Completion generation with automatic retries. "
        "6. Outbound LLM response safety evaluation. "
        "7. Outbound memory storage & SHA-256 tamper-proof ledger audit logging."
    ),
)
def process_message(
    payload: MessageRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_sync_db),
    middleware: FirewallMiddleware = Depends(get_firewall_middleware),
) -> MessageResponse:
    """Execute complete message lifecycle through the firewall."""
    actor, user_role, auth_tenant_id = _extract_actor_and_role(
        request=request,
        authorization=authorization,
        x_api_key=x_api_key,
        db=db,
    )

    client_ip = request.client.host if request.client else None
    effective_tenant_id = payload.tenant_id or auth_tenant_id

    result: MessageProcessResult = middleware.process_message(
        db=db,
        session_id=payload.session_id,
        message=payload.message,
        tenant_id=effective_tenant_id,
        model=payload.model,
        system_prompt=payload.system_prompt,
        temperature=payload.temperature,
        max_tokens=payload.max_tokens,
        metadata=payload.metadata,
        client_ip=actor or client_ip,
        skip_llm=payload.skip_llm,
        mock_llm_response=payload.mock_llm_response,
        user_role=user_role,
        interactive_privacy=payload.interactive_privacy,
    )

    return result.to_response()


@router.post(
    "/message/decide",
    response_model=DecideResponse,
    summary="Submit Human User Decision for ASK_USER Flow",
    description=(
        "Resumes a paused message turn after human-in-the-loop review. "
        "Supported choices: "
        "- **ALLOW**: Proceed with original prompt as-is for this turn. "
        "- **REDACT**: Mask detected sensitive entities and proceed. "
        "- **BLOCK**: Cancel message execution without calling the LLM. "
        "- **REMEMBER_FOR_SESSION**: Apply choice and remember for future turns in this session."
    ),
)
def submit_user_decision(
    payload: DecideRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_sync_db),
    middleware: FirewallMiddleware = Depends(get_firewall_middleware),
) -> DecideResponse:
    """Submit human decision to resolve a pending confirmation request."""
    actor, user_role, auth_tenant_id = _extract_actor_and_role(
        request=request,
        authorization=authorization,
        x_api_key=x_api_key,
        db=db,
    )
    client_ip = request.client.host if request.client else None

    # Check if decision exists
    existing = decision_service.get_decision(db, payload.decision_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pending decision '{payload.decision_id}' not found.",
        )

    if existing.status.value != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Decision '{payload.decision_id}' has already been resolved with status '{existing.status.value}'.",
        )

    try:
        response = middleware.process_decision(
            db=db,
            decision_id=payload.decision_id,
            choice=payload.decision,
            scope=payload.scope,
            mock_llm_response=payload.mock_llm_response,
            client_ip=actor or client_ip,
        )
        return response
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/message/pending/{session_id}",
    response_model=List[dict],
    summary="List Pending ASK_USER Decisions for Session",
    description="Returns all active confirmation requests awaiting human input for an agent session.",
)
def list_pending_decisions(
    session_id: uuid.UUID = Path(..., description="UUID of the agent session."),
    db: Session = Depends(get_sync_db),
) -> List[dict]:
    """List pending decisions for an active session."""
    pending = decision_service.get_pending_decisions_for_session(db, session_id)
    return [
        {
            "id": str(d.id),
            "session_id": str(d.session_id),
            "tenant_id": str(d.tenant_id),
            "message_id": str(d.message_id),
            "trigger_reason": d.trigger_reason,
            "entity_type": d.entity_type,
            "matched_text": d.matched_text,
            "status": d.status.value,
            "sanitized_prompt": d.sanitized_prompt,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        }
        for d in pending
    ]
