"""
AI Memory Firewall - Message & Decision API Schemas (Weeks 7 & 8)
=================================================================
Pydantic v2 schemas for the Core Firewall Middleware /api/message and
human-in-the-loop /api/message/decide endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MessageViolation(BaseModel):
    """Schema representing an individual safety rule violation."""
    model_config = ConfigDict(from_attributes=True)

    rule_name: str
    rule_type: str
    action: str
    severity: str
    matched_text: str
    risk_contribution: float = 0.0


class MessageLatencyBreakdown(BaseModel):
    """Detailed latency measurement per pipeline stage in milliseconds."""
    inbound_eval_ms: float = 0.0
    memory_store_ms: float = 0.0
    llm_ms: float = 0.0
    outbound_eval_ms: float = 0.0
    audit_log_ms: float = 0.0
    total_ms: float = 0.0


class MessageRequest(BaseModel):
    """Request payload for /api/message."""
    model_config = ConfigDict(extra="ignore")

    message: str = Field(
        ...,
        min_length=1,
        max_length=20000,
        description="The raw input prompt / message to be screened and processed.",
    )
    session_id: uuid.UUID = Field(
        ...,
        description="UUID of the active agent conversation session.",
    )
    tenant_id: Optional[uuid.UUID] = Field(
        default=None,
        description="UUID of the tenant. If omitted, resolved from session or authenticated user.",
    )
    model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model identifier to query.",
    )
    system_prompt: Optional[str] = Field(
        default=None,
        description="Optional system prompt to guide LLM behavior.",
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for LLM generation.",
    )
    max_tokens: Optional[int] = Field(
        default=None,
        ge=1,
        le=8192,
        description="Maximum tokens to generate.",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Arbitrary metadata dictionary attached to session memory records.",
    )
    skip_llm: bool = Field(
        default=False,
        description="If True, only execute firewall inspection, memory storage, and audit logging without invoking LLM.",
    )
    mock_llm_response: Optional[str] = Field(
        default=None,
        description="Optional mock LLM response string to inject for deterministic E2E testing.",
    )
    interactive_privacy: bool = Field(
        default=False,
        description="If True, prompts with sensitive data pause for user confirmation (apply privacy policy vs send as-is).",
    )


class AskUserDetails(BaseModel):
    """Context details explaining why human confirmation is requested."""
    model_config = ConfigDict(from_attributes=True)

    trigger_reason: str = Field(..., description="Explanation of why confirmation is required.")
    entity_type: Optional[str] = Field(default=None, description="Sensitive entity type detected.")
    matched_text: Optional[str] = Field(default=None, description="Snippet that triggered confirmation.")
    available_choices: List[str] = Field(
        default_factory=lambda: ["ALLOW", "REDACT", "BLOCK", "REMEMBER_FOR_SESSION"],
        description="Available actions for human selection.",
    )


class MessageResponse(BaseModel):
    """Response payload returned by /api/message."""
    model_config = ConfigDict(from_attributes=True)

    message_id: uuid.UUID = Field(
        ...,
        description="Unique identifier for this processed message turn.",
    )
    session_id: uuid.UUID = Field(
        ...,
        description="Agent session UUID associated with this conversation turn.",
    )
    tenant_id: uuid.UUID = Field(
        ...,
        description="Owning tenant UUID.",
    )
    decision: str = Field(
        ...,
        description="Final firewall decision: ALLOW | REDACT | BLOCK | QUARANTINE | AUDIT | ASK_USER.",
    )
    inbound_risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite risk score of the inbound user prompt.",
    )
    outbound_risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Composite risk score of the outbound LLM response (if LLM was called).",
    )
    reply: Optional[str] = Field(
        default=None,
        description="The AI response text (sanitized/redacted if needed). None if blocked/quarantined or pending user decision.",
    )
    sanitized_prompt: str = Field(
        ...,
        description="The sanitized/redacted user prompt.",
    )
    violations: List[MessageViolation] = Field(
        default_factory=list,
        description="All security violations detected across inbound and outbound stages.",
    )
    memory_stored: bool = Field(
        default=True,
        description="Indicates whether this message was stored in persistent memory.",
    )
    memory_encrypted: bool = Field(
        default=True,
        description="Indicates whether memory payload was encrypted at rest with AES-256 Fernet.",
    )
    audit_logged: bool = Field(
        default=True,
        description="Indicates whether execution was cryptographically sealed in the SHA-256 hash chain.",
    )
    latency_ms: MessageLatencyBreakdown = Field(
        ...,
        description="Per-stage latency breakdown in milliseconds.",
    )
    is_mock: bool = Field(
        default=False,
        description="True if the response was generated via mock simulation rather than live OpenAI API.",
    )
    pending_decision_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Unique identifier for the pending ASK_USER confirmation request (if decision is ASK_USER).",
    )
    ask_user_details: Optional[AskUserDetails] = Field(
        default=None,
        description="Contextual guidance for human decision selection.",
    )


class DecideRequest(BaseModel):
    """Request payload for /api/message/decide."""
    model_config = ConfigDict(extra="ignore")

    decision_id: uuid.UUID = Field(
        ...,
        description="UUID of the pending ASK_USER decision request.",
    )
    decision: str = Field(
        ...,
        description="Selected decision action: ALLOW | REDACT | BLOCK | REMEMBER_FOR_SESSION.",
    )
    scope: str = Field(
        default="ONCE",
        description="Scope for applying preference: ONCE | SESSION | TENANT.",
    )
    mock_llm_response: Optional[str] = Field(
        default=None,
        description="Optional mock response string to inject for testing.",
    )


class DecideResponse(BaseModel):
    """Response payload returned by /api/message/decide."""
    model_config = ConfigDict(from_attributes=True)

    decision_id: uuid.UUID = Field(
        ...,
        description="UUID of the resolved decision.",
    )
    session_id: uuid.UUID = Field(
        ...,
        description="Associated agent session UUID.",
    )
    tenant_id: uuid.UUID = Field(
        ...,
        description="Owning tenant UUID.",
    )
    status: str = Field(
        ...,
        description="Resolution status: RESOLVED | CANCELLED | EXPIRED.",
    )
    applied_decision: str = Field(
        ...,
        description="Action applied to the message: ALLOW | REDACT | BLOCK | REMEMBER_FOR_SESSION.",
    )
    reply: Optional[str] = Field(
        default=None,
        description="The resulting AI response (None if blocked).",
    )
    sanitized_prompt: str = Field(
        ...,
        description="The prompt forwarded to memory and model.",
    )
    memory_stored: bool = Field(
        default=True,
        description="Indicates whether memory was stored.",
    )
    audit_logged: bool = Field(
        default=True,
        description="Indicates whether decision was sealed in the audit hash chain.",
    )
    latency_ms: MessageLatencyBreakdown = Field(
        ...,
        description="Latency breakdown for the decision resumption turn.",
    )
