"""
AI Memory Firewall - Firewall Inspection Route
==============================================
POST /api/v1/firewall/inspect
Real-time text inspection without mandatory memory storage.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from config.database import get_sync_db
from src.schemas.firewall import DetectedViolation, InspectRequest, InspectResponse
from src.services import firewall_service

router = APIRouter(prefix="/firewall", tags=["Firewall"])


@router.post(
    "/inspect",
    response_model=InspectResponse,
    summary="Inspect Text Through the Firewall",
    description=(
        "Runs the provided text through the full AI Memory Firewall evaluation pipeline. "
        "Applies active tenant rules, built-in PII detection, and prompt injection detection. "
        "Returns the final decision, sanitized text, risk score, and all violations found. "
        "**Does not persist the text** — use `/memory/store` to inspect and save."
    ),
)
def inspect_text(
    payload: InspectRequest,
    request: Request,
    db: Session = Depends(get_sync_db),
) -> InspectResponse:
    """
    Real-time inspection endpoint.

    Decision outcomes:
    - **ALLOW**: Text is clean. No violations detected.
    - **REDACT**: PII was found and replaced with placeholders.
    - **BLOCK**: High-risk content that should not be stored or recalled.
    - **QUARANTINE**: Adversarial injection or critical threat detected.
    - **AUDIT**: Low-confidence signal logged for human review.
    """
    result = firewall_service.inspect_text(
        db=db,
        tenant_id=payload.tenant_id,
        text=payload.text,
        session_id=payload.session_id,
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

    return InspectResponse(
        decision=result.decision,
        original_text=result.original_text,
        sanitized_text=result.sanitized_text,
        risk_score=result.risk_score,
        violations=violations,
        detected_entity_types=result.detected_entity_types,
        latency_ms=result.latency_ms,
        is_clean=result.is_clean,
    )
