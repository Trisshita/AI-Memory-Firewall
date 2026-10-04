"""
AI Memory Firewall - Core Firewall Middleware (Weeks 7 & 8)
===========================================================
Wires all firewall modules together and integrates with OpenAI:
  1. Inbound evaluation (PII, injection, rules, classifier, policy, redaction)
  2. Short-circuit blocking/quarantine gate & HITL ASK_USER confirmation gate
  3. Session-level preference resolution (REMEMBER_FOR_SESSION)
  4. Inbound memory encryption at rest (AES-256 Fernet) & persistence
  5. Historical context retrieval & memory synthesis (quarantine-isolated)
  6. OpenAI Chat Completions execution (live or mock simulation with retry logic)
  7. Outbound safety evaluation (prevent LLM data exfiltration/hallucination)
  8. Outbound memory encryption & persistence
  9. SHA-256 hash-chain audit logging & automatic alert generation
  10. Human-in-the-Loop decision resumption (process_decision)
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from src.engine.audit_logger import AuditLogger
from src.engine.evaluator import (
    DECISION_ALLOW,
    DECISION_ASK_USER,
    DECISION_BLOCK,
    DECISION_QUARANTINE,
    DECISION_REDACT,
    EvaluationResult,
    FirewallEvaluator,
    RuleViolation,
)
from src.models.agent import AgentSession, Tenant
from src.models.audit import AlertSeverity, AuditEventType
from src.models.decision import (
    DecisionChoice,
    DecisionScope,
    DecisionStatus,
    UserDecision,
)
from src.models.memory import MemoryRecord, MemoryType, SensitivityLevel
from src.schemas.message import (
    AskUserDetails,
    DecideResponse,
    MessageLatencyBreakdown,
    MessageResponse,
    MessageViolation,
)
from src.security import decrypt_data, encrypt_data
from src.services import decision_service
from src.services.firewall_service import load_active_rules
from src.services.openai_service import OpenAIService

logger = logging.getLogger(__name__)


def _sha256(text: str) -> str:
    """Compute SHA-256 hex digest of UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class MessageProcessResult:
    """Internal orchestration result for a processed message turn."""
    message_id: UUID
    session_id: UUID
    tenant_id: UUID
    decision: str
    inbound_risk_score: float
    outbound_risk_score: Optional[float]
    reply: Optional[str]
    sanitized_prompt: str
    violations: List[RuleViolation]
    memory_stored: bool
    memory_encrypted: bool
    audit_logged: bool
    latency_breakdown: MessageLatencyBreakdown
    is_mock: bool = False
    pending_decision_id: Optional[UUID] = None
    ask_user_details: Optional[AskUserDetails] = None

    def to_response(self) -> MessageResponse:
        """Convert internal result to Pydantic MessageResponse schema."""
        return MessageResponse(
            message_id=self.message_id,
            session_id=self.session_id,
            tenant_id=self.tenant_id,
            decision=self.decision,
            inbound_risk_score=self.inbound_risk_score,
            outbound_risk_score=self.outbound_risk_score,
            reply=self.reply,
            sanitized_prompt=self.sanitized_prompt,
            violations=[
                MessageViolation(
                    rule_name=v.rule_name,
                    rule_type=v.rule_type,
                    action=v.action,
                    severity=v.severity,
                    matched_text=v.matched_text,
                    risk_contribution=v.risk_contribution,
                )
                for v in self.violations
            ],
            memory_stored=self.memory_stored,
            memory_encrypted=self.memory_encrypted,
            audit_logged=self.audit_logged,
            latency_ms=self.latency_breakdown,
            is_mock=self.is_mock,
            pending_decision_id=self.pending_decision_id,
            ask_user_details=self.ask_user_details,
        )


class FirewallMiddleware:
    """
    Central orchestration engine for the AI Memory Firewall.
    
    Coordinates safety screening, memory lifecycle with AES-256 encryption,
    human-in-the-loop confirmation flow, LLM prompt synthesis, and tamper-proof ledger auditing.
    """

    def __init__(
        self,
        evaluator: Optional[FirewallEvaluator] = None,
        openai_service: Optional[OpenAIService] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.evaluator = evaluator or FirewallEvaluator()
        self.openai_service = openai_service or OpenAIService()
        self.audit_logger = audit_logger or AuditLogger()

    def _resolve_session_and_tenant(
        self,
        db: Session,
        session_id: UUID,
        tenant_id: Optional[UUID],
    ) -> tuple[AgentSession, UUID]:
        """
        Verify or initialize the AgentSession and resolve the associated tenant_id.
        """
        session = db.query(AgentSession).filter(AgentSession.id == session_id).first()

        if session:
            effective_tenant_id = session.tenant_id
            return session, effective_tenant_id

        # Session does not exist yet; verify tenant or auto-resolve
        if not tenant_id:
            first_tenant = db.query(Tenant).filter(Tenant.is_active == True).first()
            if first_tenant:
                tenant_id = first_tenant.id
            else:
                tenant_id = uuid.uuid4()
                default_tenant = Tenant(
                    id=tenant_id,
                    name="Default Organization",
                    slug=f"org-{tenant_id.hex[:8]}",
                    api_key_hash=_sha256("default-api-key"),
                )
                db.add(default_tenant)
                db.flush()

        new_session = AgentSession(
            id=session_id,
            tenant_id=tenant_id,
            agent_name="AssistantSession",
            session_token=f"sess_{uuid.uuid4().hex}",
            status="ACTIVE",
        )
        db.add(new_session)
        db.flush()
        return new_session, tenant_id

    def _retrieve_safe_context(
        self,
        db: Session,
        session_id: UUID,
        max_history_turns: int = 10,
    ) -> List[Dict[str, str]]:
        """
        Retrieve non-quarantined memory history for context assembly.
        Ensures quarantined records are NEVER recalled into LLM context.
        """
        records = (
            db.query(MemoryRecord)
            .filter(
                MemoryRecord.session_id == session_id,
                MemoryRecord.is_quarantined == False,
            )
            .order_by(MemoryRecord.created_at.asc())
            .limit(max_history_turns * 2)
            .all()
        )

        history: List[Dict[str, str]] = []
        for rec in records:
            role = "user" if rec.memory_type == MemoryType.USER_CONTEXT else "assistant"
            if rec.sanitized_content:
                history.append({"role": role, "content": rec.sanitized_content})

        return history

    def process_message(
        self,
        db: Session,
        session_id: UUID,
        message: str,
        tenant_id: Optional[UUID] = None,
        model: str = "gpt-4o-mini",
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        skip_llm: bool = False,
        mock_llm_response: Optional[str] = None,
        user_role: Optional[str] = None,
    ) -> MessageProcessResult:
        """
        Execute the full end-to-end AI Memory Firewall pipeline on an incoming message.
        """
        overall_start = time.perf_counter()
        message_id = uuid.uuid4()
        all_violations: List[RuleViolation] = []

        # ─── 0. Resolve Session & Tenant ───────────────────────────────────────
        agent_session, resolved_tenant_id = self._resolve_session_and_tenant(
            db=db,
            session_id=session_id,
            tenant_id=tenant_id,
        )

        # ─── 1. Inbound Evaluation ─────────────────────────────────────────────
        t0 = time.perf_counter()
        active_rules = load_active_rules(db, resolved_tenant_id)
        
        # Run full inspection pipeline
        inbound_result: EvaluationResult = self.evaluator.evaluate(
            text=message,
            db_rules=active_rules,
            user_role=user_role or "user",
        )
        inbound_eval_ms = round((time.perf_counter() - t0) * 1000, 2)
        all_violations.extend(inbound_result.violations)

        # ─── 1.5 Check Session Preference (Week 8) ─────────────────────────────
        effective_decision = inbound_result.decision
        session_pref = decision_service.get_session_preference(db=db, session_id=session_id)
        if session_pref and effective_decision == DECISION_ASK_USER:
            if session_pref in (DecisionChoice.ALLOW, DecisionChoice.REMEMBER_FOR_SESSION):
                effective_decision = DECISION_ALLOW
            elif session_pref == DecisionChoice.REDACT:
                effective_decision = DECISION_REDACT
            elif session_pref == DecisionChoice.BLOCK:
                effective_decision = DECISION_BLOCK

        # ─── 2. Short-Circuit Gate: BLOCK or QUARANTINE ─────────────────────────
        if effective_decision in (DECISION_BLOCK, DECISION_QUARANTINE):
            t1 = time.perf_counter()
            encrypted_content = encrypt_data(message)

            quarantine_reason = "; ".join(
                f"{v.rule_type}: {v.rule_name}" for v in inbound_result.violations[:3]
            ) or "Safety policy violation"

            quarantined_record = MemoryRecord(
                session_id=session_id,
                memory_type=MemoryType.USER_CONTEXT,
                sensitivity_tier=SensitivityLevel.CRITICAL,
                raw_content=encrypted_content,
                sanitized_content="[CONTENT QUARANTINED BY FIREWALL]",
                content_hash=_sha256(message),
                is_quarantined=True,
                quarantine_reason=quarantine_reason,
                metadata_json={
                    "is_encrypted": True,
                    "encryption_cipher": "AES-256-Fernet",
                    "decision": effective_decision,
                    "risk_score": inbound_result.risk_score,
                    **(metadata or {}),
                },
            )
            db.add(quarantined_record)
            db.flush()
            memory_store_ms = round((time.perf_counter() - t1) * 1000, 2)

            t_audit = time.perf_counter()
            severity = (
                AlertSeverity.CRITICAL.value
                if effective_decision == DECISION_QUARANTINE
                else AlertSeverity.HIGH.value
            )
            self.audit_logger.log_event(
                db=db,
                action=f"message.{effective_decision.lower()}",
                event_type=AuditEventType.FIREWALL_EVAL.value,
                severity=severity,
                tenant_id=str(resolved_tenant_id),
                actor=client_ip or "user",
                resource=f"session:{session_id}",
                payload={
                    "message_id": str(message_id),
                    "decision": effective_decision,
                    "risk_score": inbound_result.risk_score,
                    "violation_count": len(inbound_result.violations),
                    "quarantine_reason": quarantine_reason,
                },
            )
            db.commit()
            audit_log_ms = round((time.perf_counter() - t_audit) * 1000, 2)

            total_ms = round((time.perf_counter() - overall_start) * 1000, 2)
            latency = MessageLatencyBreakdown(
                inbound_eval_ms=inbound_eval_ms,
                memory_store_ms=memory_store_ms,
                llm_ms=0.0,
                outbound_eval_ms=0.0,
                audit_log_ms=audit_log_ms,
                total_ms=total_ms,
            )

            return MessageProcessResult(
                message_id=message_id,
                session_id=session_id,
                tenant_id=resolved_tenant_id,
                decision=effective_decision,
                inbound_risk_score=inbound_result.risk_score,
                outbound_risk_score=None,
                reply=None,
                sanitized_prompt=inbound_result.sanitized_text,
                violations=all_violations,
                memory_stored=True,
                memory_encrypted=True,
                audit_logged=True,
                latency_breakdown=latency,
                is_mock=False,
            )

        # ─── 2.5 Short-Circuit Gate: ASK_USER Confirmation Flow (Week 8) ───────
        if effective_decision == DECISION_ASK_USER:
            trigger_reason = "Rule or sensitivity policy requires human confirmation."
            matched_text: Optional[str] = None
            entity_type: Optional[str] = None
            if inbound_result.violations:
                trigger_reason = f"Triggered by rule: {inbound_result.violations[0].rule_name}"
                matched_text = inbound_result.violations[0].matched_text
                entity_type = inbound_result.violations[0].rule_type

            # Create pending decision record
            pending_dec = decision_service.create_pending_decision(
                db=db,
                session_id=session_id,
                tenant_id=resolved_tenant_id,
                message_id=message_id,
                raw_prompt=message,
                sanitized_prompt=inbound_result.sanitized_text,
                trigger_reason=trigger_reason,
                entity_type=entity_type,
                matched_text=matched_text,
                model=model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                metadata=metadata,
            )

            # Audit log the ASK_USER event
            t_audit = time.perf_counter()
            self.audit_logger.log_event(
                db=db,
                action="message.ask_user_pending",
                event_type=AuditEventType.FIREWALL_EVAL.value,
                severity=AlertSeverity.MEDIUM.value,
                tenant_id=str(resolved_tenant_id),
                actor=client_ip or "user",
                resource=f"decision:{pending_dec.id}",
                payload={
                    "message_id": str(message_id),
                    "decision_id": str(pending_dec.id),
                    "trigger_reason": trigger_reason,
                    "entity_type": entity_type,
                    "risk_score": inbound_result.risk_score,
                },
            )
            db.commit()
            audit_log_ms = round((time.perf_counter() - t_audit) * 1000, 2)

            total_ms = round((time.perf_counter() - overall_start) * 1000, 2)
            latency = MessageLatencyBreakdown(
                inbound_eval_ms=inbound_eval_ms,
                memory_store_ms=0.0,
                llm_ms=0.0,
                outbound_eval_ms=0.0,
                audit_log_ms=audit_log_ms,
                total_ms=total_ms,
            )

            ask_details = AskUserDetails(
                trigger_reason=trigger_reason,
                entity_type=entity_type,
                matched_text=matched_text,
                available_choices=["ALLOW", "REDACT", "BLOCK", "REMEMBER_FOR_SESSION"],
            )

            return MessageProcessResult(
                message_id=message_id,
                session_id=session_id,
                tenant_id=resolved_tenant_id,
                decision=DECISION_ASK_USER,
                inbound_risk_score=inbound_result.risk_score,
                outbound_risk_score=None,
                reply=None,
                sanitized_prompt=inbound_result.sanitized_text,
                violations=all_violations,
                memory_stored=False,
                memory_encrypted=False,
                audit_logged=True,
                latency_breakdown=latency,
                is_mock=False,
                pending_decision_id=pending_dec.id,
                ask_user_details=ask_details,
            )

        # ─── 3. Inbound Memory Storage with AES-256 Encryption ───────────────────
        t1 = time.perf_counter()
        encrypted_raw = encrypt_data(message)
        
        tier = SensitivityLevel.INTERNAL
        if effective_decision == DECISION_REDACT:
            tier = SensitivityLevel.CONFIDENTIAL

        user_memory = MemoryRecord(
            session_id=session_id,
            memory_type=MemoryType.USER_CONTEXT,
            sensitivity_tier=tier,
            raw_content=encrypted_raw,
            sanitized_content=inbound_result.sanitized_text,
            content_hash=_sha256(message),
            is_quarantined=False,
            metadata_json={
                "is_encrypted": True,
                "encryption_cipher": "AES-256-Fernet",
                "risk_score": inbound_result.risk_score,
                "decision": effective_decision,
                **(metadata or {}),
            },
        )
        db.add(user_memory)
        db.flush()
        memory_store_ms = round((time.perf_counter() - t1) * 1000, 2)

        # ─── 4. Context Synthesis & Memory Recall ───────────────────────────────
        safe_history = self._retrieve_safe_context(db=db, session_id=session_id)
        messages_payload: List[Dict[str, str]] = []

        if system_prompt:
            messages_payload.append({"role": "system", "content": system_prompt})
        
        messages_payload.extend(safe_history)

        # Inbound prompt forwarded to LLM
        forward_prompt = (
            message if effective_decision == DECISION_ALLOW else inbound_result.sanitized_text
        )
        messages_payload.append({"role": "user", "content": forward_prompt})

        # ─── 5. OpenAI Execution ────────────────────────────────────────────────
        llm_ms = 0.0
        is_mock = False
        raw_llm_reply: Optional[str] = None

        if not skip_llm:
            llm_res = self.openai_service.generate_chat_completion(
                messages=messages_payload,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                mock_response=mock_llm_response,
            )
            llm_ms = llm_res.latency_ms
            is_mock = llm_res.is_mock
            raw_llm_reply = llm_res.content

        # ─── 6. Outbound Safety Evaluation ──────────────────────────────────────
        t3 = time.perf_counter()
        final_reply = raw_llm_reply
        outbound_risk_score: Optional[float] = None

        if raw_llm_reply:
            outbound_result: EvaluationResult = self.evaluator.evaluate(
                text=raw_llm_reply,
                db_rules=active_rules,
            )
            outbound_risk_score = outbound_result.risk_score
            all_violations.extend(outbound_result.violations)

            if outbound_result.decision in (DECISION_BLOCK, DECISION_QUARANTINE):
                final_reply = (
                    "I cannot provide this response because it contains content "
                    "that violates our enterprise safety and data protection policy."
                )
            elif outbound_result.decision == DECISION_REDACT:
                final_reply = outbound_result.sanitized_text
            else:
                final_reply = raw_llm_reply

        outbound_eval_ms = round((time.perf_counter() - t3) * 1000, 2)

        # ─── 7. Outbound Memory Persistence ─────────────────────────────────────
        if final_reply:
            encrypted_reply = encrypt_data(final_reply)
            assistant_memory = MemoryRecord(
                session_id=session_id,
                memory_type=MemoryType.SHORT_TERM,
                sensitivity_tier=SensitivityLevel.INTERNAL,
                raw_content=encrypted_reply,
                sanitized_content=final_reply,
                content_hash=_sha256(final_reply),
                is_quarantined=False,
                metadata_json={
                    "is_encrypted": True,
                    "encryption_cipher": "AES-256-Fernet",
                    "model": model,
                    "is_mock": is_mock,
                },
            )
            db.add(assistant_memory)
            db.flush()

        # ─── 8. SHA-256 Hash-Chain Audit Logging ────────────────────────────────
        t_audit = time.perf_counter()
        highest_risk = max(inbound_result.risk_score, outbound_risk_score or 0.0)
        overall_severity = "INFO"
        if highest_risk >= 0.80:
            overall_severity = AlertSeverity.CRITICAL.value
        elif highest_risk >= 0.50:
            overall_severity = AlertSeverity.HIGH.value
        elif highest_risk >= 0.20:
            overall_severity = AlertSeverity.MEDIUM.value

        self.audit_logger.log_event(
            db=db,
            action="message.processed",
            event_type=AuditEventType.FIREWALL_EVAL.value,
            severity=overall_severity,
            tenant_id=str(resolved_tenant_id),
            actor=client_ip or "user",
            resource=f"session:{session_id}",
            payload={
                "message_id": str(message_id),
                "inbound_decision": effective_decision,
                "inbound_risk": inbound_result.risk_score,
                "outbound_risk": outbound_risk_score,
                "violation_count": len(all_violations),
                "model": model,
                "is_mock": is_mock,
                "risk_score": highest_risk,
            },
        )
        db.commit()
        audit_log_ms = round((time.perf_counter() - t_audit) * 1000, 2)

        total_ms = round((time.perf_counter() - overall_start) * 1000, 2)
        latency = MessageLatencyBreakdown(
            inbound_eval_ms=inbound_eval_ms,
            memory_store_ms=memory_store_ms,
            llm_ms=llm_ms,
            outbound_eval_ms=outbound_eval_ms,
            audit_log_ms=audit_log_ms,
            total_ms=total_ms,
        )

        final_decision = effective_decision
        if outbound_risk_score and outbound_risk_score >= 0.80:
            final_decision = DECISION_BLOCK

        return MessageProcessResult(
            message_id=message_id,
            session_id=session_id,
            tenant_id=resolved_tenant_id,
            decision=final_decision,
            inbound_risk_score=inbound_result.risk_score,
            outbound_risk_score=outbound_risk_score,
            reply=final_reply,
            sanitized_prompt=inbound_result.sanitized_text,
            violations=all_violations,
            memory_stored=True,
            memory_encrypted=True,
            audit_logged=True,
            latency_breakdown=latency,
            is_mock=is_mock,
        )

    def process_decision(
        self,
        db: Session,
        decision_id: UUID,
        choice: str,
        scope: str = "ONCE",
        mock_llm_response: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> DecideResponse:
        """
        Resume message processing after a human user decision is submitted (Week 8).
        """
        start_time = time.perf_counter()

        # Resolve decision record
        decision = decision_service.resolve_decision(
            db=db,
            decision_id=decision_id,
            choice=choice,
            scope=scope,
        )

        session_id = decision.session_id
        tenant_id = decision.tenant_id
        selected_choice = decision.selected_decision

        # ── Handle BLOCK choice ───────────────────────────────────────────────
        if selected_choice == DecisionChoice.BLOCK:
            t1 = time.perf_counter()
            quarantined_record = MemoryRecord(
                session_id=session_id,
                memory_type=MemoryType.USER_CONTEXT,
                sensitivity_tier=SensitivityLevel.CRITICAL,
                raw_content=decision.original_prompt,
                sanitized_content="[BLOCKED BY USER CHOICE]",
                content_hash=_sha256(decision.sanitized_prompt),
                is_quarantined=True,
                quarantine_reason=f"User rejected prompt ({decision.trigger_reason})",
                metadata_json={"decision_id": str(decision.id), "choice": "BLOCK"},
            )
            db.add(quarantined_record)
            db.flush()
            store_ms = round((time.perf_counter() - t1) * 1000, 2)

            t_audit = time.perf_counter()
            self.audit_logger.log_event(
                db=db,
                action="message.user_decide_blocked",
                event_type=AuditEventType.FIREWALL_EVAL.value,
                severity=AlertSeverity.HIGH.value,
                tenant_id=str(tenant_id),
                actor=client_ip or "user",
                resource=f"decision:{decision.id}",
                payload={"decision_id": str(decision.id), "choice": "BLOCK"},
            )
            db.commit()
            audit_ms = round((time.perf_counter() - t_audit) * 1000, 2)
            total_ms = round((time.perf_counter() - start_time) * 1000, 2)

            return DecideResponse(
                decision_id=decision.id,
                session_id=session_id,
                tenant_id=tenant_id,
                status=DecisionStatus.CANCELLED.value,
                applied_decision=DecisionChoice.BLOCK.value,
                reply=None,
                sanitized_prompt=decision.sanitized_prompt,
                memory_stored=True,
                audit_logged=True,
                latency_ms=MessageLatencyBreakdown(
                    inbound_eval_ms=0.0,
                    memory_store_ms=store_ms,
                    llm_ms=0.0,
                    outbound_eval_ms=0.0,
                    audit_log_ms=audit_ms,
                    total_ms=total_ms,
                ),
            )

        # ── Handle ALLOW / REDACT / REMEMBER_FOR_SESSION ──────────────────────
        decrypted_prompt = decision_service.get_decrypted_prompt(decision)
        use_unredacted = selected_choice in (DecisionChoice.ALLOW, DecisionChoice.REMEMBER_FOR_SESSION)
        forward_prompt = decrypted_prompt if use_unredacted else decision.sanitized_prompt

        t1 = time.perf_counter()
        tier = SensitivityLevel.INTERNAL if use_unredacted else SensitivityLevel.CONFIDENTIAL
        user_memory = MemoryRecord(
            session_id=session_id,
            memory_type=MemoryType.USER_CONTEXT,
            sensitivity_tier=tier,
            raw_content=decision.original_prompt,
            sanitized_content=decision.sanitized_prompt,
            content_hash=_sha256(decrypted_prompt),
            is_quarantined=False,
            metadata_json={
                "decision_id": str(decision.id),
                "choice": selected_choice.value if selected_choice else "ALLOW",
                "scope": decision.scope.value,
            },
        )
        db.add(user_memory)
        db.flush()
        store_ms = round((time.perf_counter() - t1) * 1000, 2)

        # Context assembly & LLM call
        safe_history = self._retrieve_safe_context(db=db, session_id=session_id)
        messages_payload: List[Dict[str, str]] = []
        if decision.system_prompt:
            messages_payload.append({"role": "system", "content": decision.system_prompt})
        messages_payload.extend(safe_history)
        messages_payload.append({"role": "user", "content": forward_prompt})

        llm_res = self.openai_service.generate_chat_completion(
            messages=messages_payload,
            model=decision.model,
            temperature=decision.temperature,
            max_tokens=decision.max_tokens,
            mock_response=mock_llm_response,
        )
        llm_reply = llm_res.content

        # Outbound evaluation
        t3 = time.perf_counter()
        active_rules = load_active_rules(db, tenant_id)
        outbound_result = self.evaluator.evaluate(text=llm_reply, db_rules=active_rules)
        if outbound_result.decision in (DECISION_BLOCK, DECISION_QUARANTINE):
            final_reply = "I cannot provide this response because it contains content that violates our security policy."
        elif outbound_result.decision == DECISION_REDACT:
            final_reply = outbound_result.sanitized_text
        else:
            final_reply = llm_reply
        outbound_ms = round((time.perf_counter() - t3) * 1000, 2)

        # Store assistant memory
        encrypted_reply = encrypt_data(final_reply)
        assistant_memory = MemoryRecord(
            session_id=session_id,
            memory_type=MemoryType.SHORT_TERM,
            sensitivity_tier=SensitivityLevel.INTERNAL,
            raw_content=encrypted_reply,
            sanitized_content=final_reply,
            content_hash=_sha256(final_reply),
            is_quarantined=False,
            metadata_json={"decision_id": str(decision.id)},
        )
        db.add(assistant_memory)
        db.flush()

        # Audit logging
        t_audit = time.perf_counter()
        self.audit_logger.log_event(
            db=db,
            action="message.user_decide_resolved",
            event_type=AuditEventType.FIREWALL_EVAL.value,
            severity=AlertSeverity.LOW.value,
            tenant_id=str(tenant_id),
            actor=client_ip or "user",
            resource=f"decision:{decision.id}",
            payload={
                "decision_id": str(decision.id),
                "choice": selected_choice.value if selected_choice else "ALLOW",
                "scope": decision.scope.value,
            },
        )
        db.commit()
        audit_ms = round((time.perf_counter() - t_audit) * 1000, 2)
        total_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return DecideResponse(
            decision_id=decision.id,
            session_id=session_id,
            tenant_id=tenant_id,
            status=DecisionStatus.RESOLVED.value,
            applied_decision=selected_choice.value if selected_choice else "ALLOW",
            reply=final_reply,
            sanitized_prompt=decision.sanitized_prompt,
            memory_stored=True,
            audit_logged=True,
            latency_ms=MessageLatencyBreakdown(
                inbound_eval_ms=0.0,
                memory_store_ms=store_ms,
                llm_ms=llm_res.latency_ms,
                outbound_eval_ms=outbound_ms,
                audit_log_ms=audit_ms,
                total_ms=total_ms,
            ),
        )


_middleware_singleton: Optional[FirewallMiddleware] = None


def get_firewall_middleware() -> FirewallMiddleware:
    """Singleton factory for FirewallMiddleware."""
    global _middleware_singleton
    if _middleware_singleton is None:
        _middleware_singleton = FirewallMiddleware()
    return _middleware_singleton
