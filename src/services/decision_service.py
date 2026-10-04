"""
AI Memory Firewall - User Decision Service (Week 8)
===================================================
Manages human-in-the-loop (HITL) ASK_USER confirmation requests,
decision resolution, session-level consent preferences, and timeout fallbacks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from src.models.decision import (
    DecisionChoice,
    DecisionScope,
    DecisionStatus,
    UserDecision,
)
from src.security import decrypt_data, encrypt_data

logger = logging.getLogger(__name__)


def create_pending_decision(
    db: Session,
    session_id: UUID,
    tenant_id: UUID,
    message_id: UUID,
    raw_prompt: str,
    sanitized_prompt: str,
    trigger_reason: str,
    entity_type: Optional[str] = None,
    matched_text: Optional[str] = None,
    model: str = "gpt-4o-mini",
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
    user_id: Optional[UUID] = None,
    timeout_seconds: int = 300,
) -> UserDecision:
    """
    Create and persist a pending user confirmation request with encrypted prompt payload.
    """
    encrypted_prompt = encrypt_data(raw_prompt)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=timeout_seconds)

    decision = UserDecision(
        session_id=session_id,
        tenant_id=tenant_id,
        user_id=user_id,
        message_id=message_id,
        original_prompt=encrypted_prompt,
        sanitized_prompt=sanitized_prompt,
        trigger_reason=trigger_reason,
        entity_type=entity_type,
        matched_text=matched_text,
        status=DecisionStatus.PENDING,
        selected_decision=None,
        scope=DecisionScope.ONCE,
        model=model,
        system_prompt=system_prompt,
        temperature=temperature,
        max_tokens=max_tokens,
        metadata_json=metadata,
        expires_at=expires_at,
    )
    db.add(decision)
    db.flush()
    return decision


def get_decision(db: Session, decision_id: UUID) -> Optional[UserDecision]:
    """Retrieve a UserDecision by ID."""
    return db.query(UserDecision).filter(UserDecision.id == decision_id).first()


def get_pending_decisions_for_session(
    db: Session, session_id: UUID
) -> List[UserDecision]:
    """List all pending decisions for an active agent session."""
    return (
        db.query(UserDecision)
        .filter(
            UserDecision.session_id == session_id,
            UserDecision.status == DecisionStatus.PENDING,
        )
        .order_by(UserDecision.created_at.desc())
        .all()
    )


def resolve_decision(
    db: Session,
    decision_id: UUID,
    choice: str,
    scope: str = "ONCE",
) -> UserDecision:
    """
    Resolve a pending decision with the human user's choice and scope.
    
    Raises:
        ValueError: If decision not found or already resolved/expired.
    """
    decision = get_decision(db, decision_id)
    if not decision:
        raise ValueError(f"Decision request '{decision_id}' not found.")

    if decision.status != DecisionStatus.PENDING:
        raise ValueError(
            f"Decision request '{decision_id}' cannot be resolved; current status is '{decision.status.value}'."
        )

    try:
        dec_choice = DecisionChoice(choice)
    except ValueError:
        dec_choice = DecisionChoice.ALLOW if choice.upper() == "ALLOW" else DecisionChoice.REDACT

    try:
        dec_scope = DecisionScope(scope)
    except ValueError:
        dec_scope = DecisionScope.SESSION if choice == DecisionChoice.REMEMBER_FOR_SESSION.value else DecisionScope.ONCE

    decision.selected_decision = dec_choice
    decision.scope = dec_scope
    decision.status = DecisionStatus.RESOLVED
    decision.resolved_at = datetime.now(timezone.utc)
    db.flush()
    return decision


def get_session_preference(
    db: Session,
    session_id: UUID,
    entity_type: Optional[str] = None,
) -> Optional[DecisionChoice]:
    """
    Check if the user previously selected REMEMBER_FOR_SESSION for this session.
    """
    query = db.query(UserDecision).filter(
        UserDecision.session_id == session_id,
        UserDecision.status == DecisionStatus.RESOLVED,
        UserDecision.scope == DecisionScope.SESSION,
    )
    if entity_type:
        # Check specific entity match or general match
        specific = query.filter(UserDecision.entity_type == entity_type).order_by(UserDecision.resolved_at.desc()).first()
        if specific and specific.selected_decision:
            return specific.selected_decision

    general = query.order_by(UserDecision.resolved_at.desc()).first()
    if general and general.selected_decision:
        return general.selected_decision

    return None


def get_decrypted_prompt(decision: UserDecision) -> str:
    """Safely decrypt original raw prompt from the decision record."""
    return decrypt_data(decision.original_prompt)


def apply_timeout_fallback(
    db: Session,
    decision_id: UUID,
    default_choice: DecisionChoice = DecisionChoice.REDACT,
) -> UserDecision:
    """
    Apply safe fallback decision (Option A: REDACT) when a decision times out.
    """
    decision = get_decision(db, decision_id)
    if not decision or decision.status != DecisionStatus.PENDING:
        return decision

    decision.selected_decision = default_choice
    decision.scope = DecisionScope.ONCE
    decision.status = DecisionStatus.EXPIRED
    decision.resolved_at = datetime.now(timezone.utc)
    db.flush()
    return decision
