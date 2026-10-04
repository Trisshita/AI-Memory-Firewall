"""
AI Memory Firewall - Audit Logger & Global Hash-Chain Engine
=============================================================
Week 6: Implements the tamper-proof global audit log with SHA-256 hash chain,
full chain integrity verification, and automatic security alert generation.

Architecture:
  - Global chain: all tenants share a single monotonic sequence
  - Each AuditLogEntry seals: canonical_content + previous_hash → entry_hash
  - Genesis entry uses previous_hash = '0' * 64
  - Verification re-computes every hash; any mismatch = tamper detected
  - High-risk events (risk_score >= 0.8) auto-raise HIGH_RISK_EVENT alerts
  - Chain tamper detected during verify → CHAIN_TAMPER CRITICAL alert
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.models.audit import (
    AlertSeverity,
    AlertType,
    AuditEventType,
    AuditLogEntry,
    SecurityAlert,
)

# ── Constants ─────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64
HIGH_RISK_ALERT_THRESHOLD = 0.80  # risk_score >= this triggers HIGH_RISK_EVENT alert
CHAIN_TAMPER_ALERT_SEVERITY = AlertSeverity.CRITICAL.value


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class ChainVerificationResult:
    """
    Result of a full hash-chain integrity verification pass.

    Attributes:
        is_valid:              True if every entry's hash matches recomputed value.
        total_entries:         Total number of chain entries scanned.
        first_broken_sequence: Sequence number of the first tampered entry (None if valid).
        broken_entries:        All tampered sequence numbers found during scan.
        verification_time_ms:  Wall-clock time of the verification pass in milliseconds.
    """
    is_valid: bool
    total_entries: int
    first_broken_sequence: Optional[int] = None
    broken_entries: List[int] = field(default_factory=list)
    verification_time_ms: float = 0.0


# ── Hash helpers ──────────────────────────────────────────────────────────────

def _canonical_entry_data(
    sequence_number: int,
    tenant_id: Optional[str],
    event_type: str,
    severity: str,
    actor: Optional[str],
    action: str,
    resource: Optional[str],
    payload: Optional[Dict[str, Any]],
    created_at_iso: str,
) -> str:
    """
    Produce the canonical JSON string for hashing an audit log entry.

    Keys are sorted for determinism. All None values are serialized as null.
    """
    canonical: Dict[str, Any] = {
        "action": action,
        "actor": actor,
        "created_at": created_at_iso,
        "event_type": event_type,
        "payload": payload,
        "resource": resource,
        "sequence_number": sequence_number,
        "severity": severity,
        "tenant_id": tenant_id,
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(
    sequence_number: int,
    tenant_id: Optional[str],
    event_type: str,
    severity: str,
    actor: Optional[str],
    action: str,
    resource: Optional[str],
    payload: Optional[Dict[str, Any]],
    created_at_iso: str,
    previous_hash: str,
) -> str:
    """
    Compute the SHA-256 hash for a chain entry.

    Formula:
        entry_hash = sha256( canonical_json + "|" + previous_hash )

    Args:
        sequence_number: Monotonic sequence position in the global chain.
        tenant_id:       Tenant UUID string (or None for system events).
        event_type:      AuditEventType string value.
        severity:        Severity string.
        actor:           Actor identifier string (user email, API key prefix, etc.).
        action:          Short action label (e.g. "memory.store").
        resource:        Target resource identifier.
        payload:         Arbitrary structured event data dict.
        created_at_iso:  ISO-8601 timestamp string of the entry creation time.
        previous_hash:   SHA-256 hex of the previous entry (GENESIS_HASH for first).

    Returns:
        Hex-encoded 64-character SHA-256 hash string.
    """
    canonical = _canonical_entry_data(
        sequence_number=sequence_number,
        tenant_id=tenant_id,
        event_type=event_type,
        severity=severity,
        actor=actor,
        action=action,
        resource=resource,
        payload=payload,
        created_at_iso=created_at_iso,
    )
    raw = f"{canonical}|{previous_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _entry_to_hash_inputs(entry: AuditLogEntry) -> Dict[str, Any]:
    """
    Extract hash-computation arguments from a persisted AuditLogEntry.

    Normalizes created_at to a consistent UTC ISO-8601 string so that
    hashes match across databases that strip timezone info on retrieval
    (e.g. SQLite, which stores datetimes without tz offset).
    """
    tenant_id_str = str(entry.tenant_id) if entry.tenant_id else None

    if isinstance(entry.created_at, datetime):
        # Ensure timezone-aware UTC for consistent isoformat output
        dt = entry.created_at
        if dt.tzinfo is None:
            # SQLite returns naive datetimes — treat as UTC
            dt = dt.replace(tzinfo=timezone.utc)
        created_at_iso = dt.isoformat()
    else:
        created_at_iso = str(entry.created_at)

    return {
        "sequence_number": entry.sequence_number,
        "tenant_id": tenant_id_str,
        "event_type": entry.event_type,
        "severity": entry.severity,
        "actor": entry.actor,
        "action": entry.action,
        "resource": entry.resource,
        "payload": entry.payload,
        "created_at_iso": created_at_iso,
        "previous_hash": entry.previous_hash,
    }



# ── Main AuditLogger class ────────────────────────────────────────────────────

class AuditLogger:
    """
    The central audit logging service for the AI Memory Firewall.

    Responsibilities:
      1. Append-only writes to the global SHA-256 hash chain (AuditLogEntry).
      2. Full chain integrity verification (verify_chain).
      3. Automatic security alert generation for high-risk events and
         chain tampering.

    Thread safety:
      - The global sequence number is obtained with MAX(sequence_number) + 1
        under a DB lock (the DB commit serializes the write). In high-concurrency
        production deployments, a DB sequence object (PostgreSQL SEQUENCE) should
        be used instead.
    """

    # ── Write path ────────────────────────────────────────────────────────────

    def log_event(
        self,
        db: Session,
        action: str,
        event_type: str = AuditEventType.FIREWALL_EVAL.value,
        severity: str = "INFO",
        tenant_id: Optional[str] = None,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        raise_alert_if_high_risk: bool = True,
    ) -> AuditLogEntry:
        """
        Append a new entry to the global hash chain and persist it.

        Steps:
          1. Fetch the current chain tail (MAX sequence_number + hash).
          2. Compute next sequence number and previous_hash.
          3. Build created_at timestamp.
          4. Compute entry_hash from canonical content + previous_hash.
          5. Persist the AuditLogEntry.
          6. If payload contains risk_score >= HIGH_RISK_ALERT_THRESHOLD,
             auto-raise a HIGH_RISK_EVENT alert.

        Args:
            db:                    SQLAlchemy synchronous session.
            action:                Short action label (e.g. "memory.store").
            event_type:            AuditEventType value string.
            severity:              Severity string (INFO/LOW/MEDIUM/HIGH/CRITICAL).
            tenant_id:             Tenant UUID string (None for global/system events).
            actor:                 Identifier of who triggered the event.
            resource:              Target resource identifier.
            payload:               Dict of structured event data.
            event_id:              Optional UUID of originating SecurityAuditEvent.
            raise_alert_if_high_risk: Auto-raise HIGH_RISK_EVENT alert if applicable.

        Returns:
            The persisted AuditLogEntry.
        """
        # ── 1. Get chain tail ────────────────────────────────────────────────
        tail = self._get_tail(db)
        if tail is None:
            previous_hash = GENESIS_HASH
            next_seq = 1
        else:
            previous_hash = tail.entry_hash
            next_seq = tail.sequence_number + 1

        # ── 2. Build created_at ──────────────────────────────────────────────
        created_at = datetime.now(timezone.utc)
        created_at_iso = created_at.isoformat()

        # ── 3. Compute entry hash ────────────────────────────────────────────
        tenant_id_str = str(tenant_id) if tenant_id else None
        entry_hash = compute_entry_hash(
            sequence_number=next_seq,
            tenant_id=tenant_id_str,
            event_type=event_type,
            severity=severity,
            actor=actor,
            action=action,
            resource=resource,
            payload=payload,
            created_at_iso=created_at_iso,
            previous_hash=previous_hash,
        )

        # ── 4. Persist chain entry ───────────────────────────────────────────
        import uuid as _uuid
        entry = AuditLogEntry(
            id=_uuid.uuid4(),
            sequence_number=next_seq,
            tenant_id=_uuid.UUID(tenant_id) if tenant_id else None,
            event_id=_uuid.UUID(event_id) if event_id else None,
            event_type=event_type,
            severity=severity,
            actor=actor,
            action=action,
            resource=resource,
            payload=payload,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            created_at=created_at,
        )
        db.add(entry)
        db.flush()  # assign DB row without committing yet

        # ── 5. Auto-alert for high-risk events ───────────────────────────────
        if raise_alert_if_high_risk and payload:
            risk_score = payload.get("risk_score", 0.0)
            if isinstance(risk_score, (int, float)) and risk_score >= HIGH_RISK_ALERT_THRESHOLD:
                self.raise_alert(
                    db=db,
                    alert_type=AlertType.HIGH_RISK_EVENT.value,
                    severity=AlertSeverity.HIGH.value if risk_score < 0.95 else AlertSeverity.CRITICAL.value,
                    title=f"High-Risk Firewall Event (score={risk_score:.2f})",
                    description=(
                        f"Firewall evaluation produced risk_score={risk_score:.4f} "
                        f"≥ threshold {HIGH_RISK_ALERT_THRESHOLD}. "
                        f"Decision: {payload.get('decision', 'unknown')}. "
                        f"Actor: {actor or 'anonymous'}."
                    ),
                    related_entry=entry,
                    tenant_id=tenant_id,
                    metadata=payload,
                    flush_only=True,  # commit will happen in calling service
                )

        return entry

    # ── Verification path ─────────────────────────────────────────────────────

    def verify_chain(
        self,
        db: Session,
        raise_alert_on_tamper: bool = True,
    ) -> ChainVerificationResult:
        """
        Run a full integrity scan of the global hash chain.

        Fetches all entries in ascending sequence order, re-computes each
        entry_hash from stored fields, and reports any mismatches.

        Args:
            db:                    SQLAlchemy session.
            raise_alert_on_tamper: If True and tampering is found, auto-raise
                                   a CHAIN_TAMPER CRITICAL alert.

        Returns:
            ChainVerificationResult with validity flag and any broken sequences.
        """
        start = time.perf_counter()

        entries: List[AuditLogEntry] = (
            db.query(AuditLogEntry)
            .order_by(AuditLogEntry.sequence_number.asc())
            .all()
        )

        broken: List[int] = []
        expected_previous = GENESIS_HASH

        for entry in entries:
            kwargs = _entry_to_hash_inputs(entry)
            # Override previous_hash from our tracked expected value
            kwargs["previous_hash"] = expected_previous
            recomputed = compute_entry_hash(**kwargs)

            if recomputed != entry.entry_hash:
                broken.append(entry.sequence_number)
                # Continue scanning; don't short-circuit so we find all breaks
            else:
                # Advance expected_previous only on valid entries
                expected_previous = entry.entry_hash

        elapsed_ms = (time.perf_counter() - start) * 1000
        is_valid = len(broken) == 0
        first_broken = broken[0] if broken else None

        result = ChainVerificationResult(
            is_valid=is_valid,
            total_entries=len(entries),
            first_broken_sequence=first_broken,
            broken_entries=broken,
            verification_time_ms=round(elapsed_ms, 3),
        )

        if not is_valid and raise_alert_on_tamper:
            self.raise_alert(
                db=db,
                alert_type=AlertType.CHAIN_TAMPER.value,
                severity=CHAIN_TAMPER_ALERT_SEVERITY,
                title="CRITICAL: Audit Chain Integrity Failure Detected",
                description=(
                    f"Hash chain verification found {len(broken)} tampered "
                    f"entr{'y' if len(broken) == 1 else 'ies'}. "
                    f"First broken sequence: #{first_broken}. "
                    f"All broken sequences: {broken}."
                ),
                metadata={
                    "broken_count": len(broken),
                    "broken_sequences": broken,
                    "first_broken_sequence": first_broken,
                    "total_entries": len(entries),
                },
                flush_only=False,
            )

        return result

    # ── Alert management ──────────────────────────────────────────────────────

    def raise_alert(
        self,
        db: Session,
        alert_type: str,
        severity: str,
        title: str,
        description: Optional[str] = None,
        related_entry: Optional[AuditLogEntry] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        flush_only: bool = False,
    ) -> SecurityAlert:
        """
        Create and persist a SecurityAlert record.

        Args:
            db:            SQLAlchemy session.
            alert_type:    AlertType value string.
            severity:      AlertSeverity value string.
            title:         Short alert title.
            description:   Detailed alert description.
            related_entry: AuditLogEntry that triggered this alert.
            tenant_id:     Optional tenant UUID string for scoping.
            metadata:      Optional dict of extra context.
            flush_only:    If True, flush without commit (caller will commit).

        Returns:
            The persisted SecurityAlert.
        """
        import uuid as _uuid

        alert = SecurityAlert(
            id=_uuid.uuid4(),
            tenant_id=_uuid.UUID(tenant_id) if tenant_id else None,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            related_entry_id=related_entry.id if related_entry else None,
            is_resolved=False,
            metadata_json=metadata,
        )
        db.add(alert)
        if flush_only:
            db.flush()
        else:
            db.commit()
            db.refresh(alert)
        return alert

    # ── Query helpers ─────────────────────────────────────────────────────────

    def get_chain_tail(self, db: Session) -> Optional[AuditLogEntry]:
        """Return the most recent chain entry (highest sequence_number)."""
        return self._get_tail(db)

    def get_chain_head(self, db: Session) -> Optional[AuditLogEntry]:
        """Return the genesis (first) chain entry."""
        return (
            db.query(AuditLogEntry)
            .order_by(AuditLogEntry.sequence_number.asc())
            .first()
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_tail(db: Session) -> Optional[AuditLogEntry]:
        """Fetch the entry with the highest sequence_number (chain tail)."""
        return (
            db.query(AuditLogEntry)
            .order_by(AuditLogEntry.sequence_number.desc())
            .first()
        )
