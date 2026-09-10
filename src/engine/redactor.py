"""
AI Memory Firewall - Week 5 Data Redaction Engine
==================================================
Provides advanced data masking and redaction strategies for sensitive entities
detected by the NLP Sensitivity Classifier (Week 3).

Four masking strategies are supported:
  FULL      – Complete placeholder replacement  (e.g. [REDACTED_EMAIL])
  PARTIAL   – Type-aware partial masking        (e.g. al***@***.com)
  HASH      – Deterministic SHA-256 fingerprint (e.g. [HASH_EMAIL:3d4f…])
  TOKENIZE  – Reversible random token           (e.g. [TOKEN_EMAIL_a3f9]) stored
               in a RedactionMap for later retrieval / audit.

The ENTITY_STRATEGY_MAP assigns the default strategy per entity type based on
the sensitivity level and operational requirements:
  - High-ID entities (SSN, PASSPORT, DL) use TOKENIZE for reversible compliance.
  - Financial entities (CREDIT_CARD, IBAN) use PARTIAL to preserve last-4 digits.
  - Secrets (API_KEY, AWS_KEY, PRIVATE_KEY) use HASH/FULL — no partial exposure.
  - NLP entities (PERSON, EMAIL, PHONE, IP) use PARTIAL for human readability.

Usage:
    from src.engine.redactor import DataRedactor, RedactionStrategy

    redactor = DataRedactor()

    # Using classifier output directly
    clf_result = SensitivityClassifier().classify(text)
    result = redactor.redact(text, clf_result.entities)

    print(result.redacted_text)             # "al***@***.com called from [REDACTED_IP]"
    print(result.entries[0].strategy)       # RedactionStrategy.PARTIAL
    print(result.redaction_map.restore(token))  # original value (TOKENIZE only)
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from src.engine.detection_rules import SensitiveEntityType


# ---------------------------------------------------------------------------
# Strategy Enum
# ---------------------------------------------------------------------------

class RedactionStrategy(str, Enum):
    """
    The four supported data-masking strategies.

    FULL     – Replace the entire value with a static placeholder tag.
    PARTIAL  – Show a safe portion of the value; mask the rest with *.
    HASH     – Replace with a deterministic SHA-256 hex digest; useful for
               audit log correlation without re-exposing the original value.
    TOKENIZE – Replace with a random, opaque token stored in a RedactionMap;
               the original value can be recovered with RedactionMap.restore().
    """
    FULL     = "FULL"
    PARTIAL  = "PARTIAL"
    HASH     = "HASH"
    TOKENIZE = "TOKENIZE"


# ---------------------------------------------------------------------------
# Per-entity-type default strategy map
# ---------------------------------------------------------------------------

#: Default RedactionStrategy per SensitiveEntityType.
#: Can be overridden globally or per-call via strategy_override.
ENTITY_STRATEGY_MAP: Dict[str, RedactionStrategy] = {
    # Structured identity documents — reversible for compliance workflows
    SensitiveEntityType.SSN:             RedactionStrategy.TOKENIZE,
    SensitiveEntityType.PASSPORT_NUMBER: RedactionStrategy.TOKENIZE,
    SensitiveEntityType.DRIVERS_LICENSE: RedactionStrategy.TOKENIZE,

    # Financial — preserve last-4 for support/confirmation workflows
    SensitiveEntityType.CREDIT_CARD:     RedactionStrategy.PARTIAL,
    SensitiveEntityType.IBAN:            RedactionStrategy.PARTIAL,

    # Contact / network — partial mask for human readability in logs
    SensitiveEntityType.EMAIL:           RedactionStrategy.PARTIAL,
    SensitiveEntityType.PHONE_NUMBER:    RedactionStrategy.PARTIAL,
    SensitiveEntityType.IP_ADDRESS:      RedactionStrategy.PARTIAL,

    # Credentials — deterministic fingerprint, never show original
    SensitiveEntityType.API_KEY:         RedactionStrategy.HASH,
    SensitiveEntityType.AWS_KEY:         RedactionStrategy.HASH,

    # Private key — complete erasure, no partial exposure permissible
    SensitiveEntityType.PRIVATE_KEY:     RedactionStrategy.FULL,

    # Low-sensitivity transport entity
    SensitiveEntityType.VEHICLE_REG:     RedactionStrategy.FULL,

    # NLP-derived entities
    SensitiveEntityType.PERSON:          RedactionStrategy.PARTIAL,
    SensitiveEntityType.ORGANIZATION:    RedactionStrategy.FULL,
    SensitiveEntityType.LOCATION:        RedactionStrategy.FULL,
    SensitiveEntityType.DATE:            RedactionStrategy.PARTIAL,
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class RedactionEntry:
    """
    Records a single redaction operation performed on one detected entity.

    Attributes:
        entity_type:    The canonical entity type string (e.g. "EMAIL", "SSN").
        strategy:       The RedactionStrategy applied to this entity.
        original_text:  The raw, unmasked original value.
        redacted_text:  The masked/replaced output value.
        token:          Opaque lookup token (set only when strategy == TOKENIZE).
        hash_value:     Full SHA-256 hex digest (set only when strategy == HASH).
        start:          Character offset of the original match in source text.
        end:            Character offset (exclusive) of the original match.
    """
    entity_type:   str
    strategy:      RedactionStrategy
    original_text: str
    redacted_text: str
    token:         Optional[str] = None
    hash_value:    Optional[str] = None
    start:         int = 0
    end:           int = 0


class RedactionMap:
    """
    In-process store for reversible TOKENIZE redactions.

    Tokens are random 4-hex-char suffixes scoped to entity type, e.g.
    ``TOKEN_EMAIL_a3f9``.  The map is never persisted to disk; it lives
    for the duration of the ``DataRedactor`` instance.

    Usage::

        rmap = RedactionMap()
        token = rmap.store(entry)       # Returns the token string
        entry = rmap.restore(token)     # Returns the RedactionEntry or None
        log   = rmap.export_audit_log() # Returns all entries as a list
    """

    def __init__(self) -> None:
        self._store: Dict[str, RedactionEntry] = {}

    def store(self, entry: RedactionEntry) -> str:
        """Store a RedactionEntry and return its opaque token string."""
        suffix = secrets.token_hex(2)   # 4 hex chars → 65 536 possibilities
        token = f"TOKEN_{entry.entity_type}_{suffix}"
        entry.token = token
        self._store[token] = entry
        return token

    def restore(self, token: str) -> Optional[RedactionEntry]:
        """Return the RedactionEntry for a given token, or None if unknown."""
        return self._store.get(token)

    def export_audit_log(self) -> List[RedactionEntry]:
        """Return all stored RedactionEntry objects sorted by start offset."""
        return sorted(self._store.values(), key=lambda e: e.start)

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, token: str) -> bool:
        return token in self._store


@dataclass
class RedactionResult:
    """
    The complete output of a DataRedactor.redact() call.

    Attributes:
        original_text:  The unmodified source text.
        redacted_text:  Source text after all strategy-based masking.
        entries:        One RedactionEntry per detected entity, in document order.
        redaction_map:  The RedactionMap populated during this pass (may be empty
                        if no TOKENIZE strategy was used).
        latency_ms:     Wall time for the full redaction pass in milliseconds.
    """
    original_text: str
    redacted_text: str
    entries:       List[RedactionEntry]
    redaction_map: RedactionMap
    latency_ms:    float

    @property
    def tokenized_count(self) -> int:
        """Number of entities redacted with TOKENIZE strategy."""
        return sum(1 for e in self.entries if e.strategy == RedactionStrategy.TOKENIZE)

    @property
    def strategy_summary(self) -> Dict[str, int]:
        """Count of entries per strategy used in this pass."""
        summary: Dict[str, int] = {}
        for e in self.entries:
            summary[e.strategy.value] = summary.get(e.strategy.value, 0) + 1
        return summary


# ---------------------------------------------------------------------------
# Core DataRedactor
# ---------------------------------------------------------------------------

class DataRedactor:
    """
    Applies strategy-aware data masking to detected sensitive entities.

    The redactor accepts a list of ``EntityDetection`` objects (produced by the
    Week 3 ``SensitivityClassifier``) and applies the most appropriate masking
    strategy for each entity type.

    Strategy selection priority:
      1. ``strategy_override`` argument (applies to ALL entities in this call).
      2. ``ENTITY_STRATEGY_MAP[entity_type]`` (per-type default).
      3. ``RedactionStrategy.FULL`` (safe fallback for unmapped types).

    Span collision handling:
      When two entities overlap (e.g. a PERSON NER span fully contains a
      regex EMAIL span), the shorter span is dropped and only the longer
      (higher-priority) span's redaction is applied.

    Usage::

        redactor = DataRedactor()
        result = redactor.redact(text, classifier_result.entities)
        print(result.redacted_text)
    """

    def __init__(self) -> None:
        self._rmap = RedactionMap()

    # ── Public API ────────────────────────────────────────────────────────

    def redact(
        self,
        text: str,
        entities: List,          # List[EntityDetection] — typed loosely to avoid circular import
        strategy_override: Optional[RedactionStrategy] = None,
    ) -> RedactionResult:
        """
        Redact all detected entities from *text* using per-type strategies.

        Args:
            text:              Source text to redact.
            entities:          List of EntityDetection objects from SensitivityClassifier.
            strategy_override: If set, overrides ENTITY_STRATEGY_MAP for all entities.

        Returns:
            RedactionResult with redacted text, per-entity entries, and the
            populated RedactionMap (non-empty only when TOKENIZE was used).
        """
        start_time = time.perf_counter()

        # Fresh map per call so each RedactionResult is self-contained
        rmap = RedactionMap()
        entries: List[RedactionEntry] = []

        if not entities:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                entries=[],
                redaction_map=rmap,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 3),
            )

        # De-duplicate / resolve overlapping spans (longest span wins)
        resolved = self._resolve_spans(entities)

        # Sort by start offset descending so we can do right-to-left string
        # replacement without offset drift
        resolved_desc = sorted(resolved, key=lambda e: e.start, reverse=True)

        redacted = text

        for entity in resolved_desc:
            strategy = strategy_override or ENTITY_STRATEGY_MAP.get(
                entity.entity_type, RedactionStrategy.FULL
            )
            original = entity.original_text
            masked = self._apply_strategy(entity, strategy, rmap)

            entry = RedactionEntry(
                entity_type=entity.entity_type,
                strategy=strategy,
                original_text=original,
                redacted_text=masked,
                start=entity.start,
                end=entity.end,
            )

            if strategy == RedactionStrategy.HASH:
                entry.hash_value = masked  # full hex digest stored for reference

            if strategy == RedactionStrategy.TOKENIZE:
                token = rmap.store(entry)
                entry.token = token
                masked = f"[{token}]"
                entry.redacted_text = masked

            entries.append(entry)

            # Apply replacement at exact span (right-to-left keeps offsets valid)
            redacted = redacted[: entity.start] + masked + redacted[entity.end :]

        # Re-sort entries by original document order (start ASC)
        entries.sort(key=lambda e: e.start)

        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            entries=entries,
            redaction_map=rmap,
            latency_ms=latency_ms,
        )

    def redact_with_map(self, text: str, entities: List) -> RedactionResult:
        """
        Convenience method — always uses TOKENIZE for all entities.

        Returns a RedactionResult with a fully-populated RedactionMap so every
        redacted token can be reversed via ``result.redaction_map.restore(token)``.
        """
        return self.redact(text, entities, strategy_override=RedactionStrategy.TOKENIZE)

    # ── Strategy dispatch ────────────────────────────────────────────────

    def _apply_strategy(
        self,
        entity,
        strategy: RedactionStrategy,
        rmap: RedactionMap,
    ) -> str:
        """Dispatch to the correct masking implementation."""
        if strategy == RedactionStrategy.FULL:
            return self._full(entity)
        if strategy == RedactionStrategy.PARTIAL:
            return self._partial(entity)
        if strategy == RedactionStrategy.HASH:
            return self._hash(entity)
        if strategy == RedactionStrategy.TOKENIZE:
            # Token assignment is deferred to redact() — return a placeholder here
            return f"[TOKEN_{entity.entity_type}_PENDING]"
        return self._full(entity)  # safe fallback

    # ── FULL strategy ────────────────────────────────────────────────────

    @staticmethod
    def _full(entity) -> str:
        """Return the entity's built-in redaction placeholder."""
        # Use the placeholder defined by the detection rule if available
        if hasattr(entity, "redacted_text") and entity.redacted_text:
            return entity.redacted_text
        return f"[REDACTED_{entity.entity_type}]"

    # ── PARTIAL strategy ─────────────────────────────────────────────────

    @staticmethod
    def _partial(entity) -> str:
        """Type-aware partial masking. Falls back to generic masking."""
        etype = entity.entity_type
        value = entity.original_text

        if etype == SensitiveEntityType.EMAIL:
            return DataRedactor._mask_email(value)
        if etype == SensitiveEntityType.PHONE_NUMBER:
            return DataRedactor._mask_phone(value)
        if etype == SensitiveEntityType.CREDIT_CARD:
            return DataRedactor._mask_credit_card(value)
        if etype == SensitiveEntityType.IP_ADDRESS:
            return DataRedactor._mask_ip(value)
        if etype == SensitiveEntityType.SSN:
            return DataRedactor._mask_ssn(value)
        if etype == SensitiveEntityType.IBAN:
            return DataRedactor._mask_iban(value)
        if etype == SensitiveEntityType.PERSON:
            return DataRedactor._mask_person(value)
        if etype == SensitiveEntityType.DATE:
            return DataRedactor._mask_date(value)

        # Generic partial: show first 2 chars + stars + last 2 chars
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    # ── HASH strategy ────────────────────────────────────────────────────

    @staticmethod
    def _hash(entity) -> str:
        """Return a SHA-256 hex fingerprint tag for the original value."""
        digest = hashlib.sha256(entity.original_text.encode()).hexdigest()[:16]
        return f"[HASH_{entity.entity_type}:{digest}]"

    # ── Specific PARTIAL maskers ─────────────────────────────────────────

    @staticmethod
    def _mask_email(value: str) -> str:
        """
        Mask email: show first 2 chars of local part, mask domain name.
        Example: alice@example.com → al***@***.com
        """
        if "@" not in value:
            return DataRedactor._generic_mask(value)
        local, domain = value.rsplit("@", 1)
        masked_local = local[:2] + "***" if len(local) > 2 else "***"
        # Preserve TLD only
        parts = domain.rsplit(".", 1)
        masked_domain = f"***.{parts[1]}" if len(parts) == 2 else "***"
        return f"{masked_local}@{masked_domain}"

    @staticmethod
    def _mask_phone(value: str) -> str:
        """
        Mask phone: preserve last 4 digits, mask the rest.
        Example: +1 (800) 555-0199 → ***-***-0199
        """
        digits = re.sub(r"\D", "", value)
        if len(digits) < 4:
            return "***-***-****"
        last4 = digits[-4:]
        return f"***-***-{last4}"

    @staticmethod
    def _mask_credit_card(value: str) -> str:
        """
        Mask credit card: preserve last 4 digits, mask card groups.
        Example: 4111 1111 1111 1234 → ****-****-****-1234
        """
        digits = re.sub(r"\D", "", value)
        if len(digits) < 4:
            return "****-****-****-****"
        last4 = digits[-4:]
        return f"****-****-****-{last4}"

    @staticmethod
    def _mask_ip(value: str) -> str:
        """
        Mask IP: preserve first two octets (subnet), mask host octets.
        Example: 192.168.10.25 → 192.168.*.*
        """
        parts = value.split(".")
        if len(parts) != 4:
            return "*.*.*.*"
        return f"{parts[0]}.{parts[1]}.*.*"

    @staticmethod
    def _mask_ssn(value: str) -> str:
        """
        Mask SSN: show last 4 digits only.
        Example: 123-45-6789 → ***-**-6789
        """
        digits = re.sub(r"\D", "", value)
        if len(digits) < 4:
            return "***-**-****"
        last4 = digits[-4:]
        return f"***-**-{last4}"

    @staticmethod
    def _mask_iban(value: str) -> str:
        """
        Mask IBAN: preserve country code (first 2 chars) + last 4 digits.
        Example: GB82 WEST 1234 5698 7654 32 → GB**-****-****-****-****-32
        """
        clean = value.replace(" ", "")
        if len(clean) < 6:
            return "****"
        country = clean[:2]
        last4 = clean[-4:]
        masked_middle = "*" * max(0, len(clean) - 6)
        return f"{country}{'*' * 2}{masked_middle}{last4}"

    @staticmethod
    def _mask_person(value: str) -> str:
        """
        Mask person name: show first initial, mask rest of each word.
        Example: Alice Johnson → A**** J******
        """
        words = value.split()
        masked = []
        for word in words:
            if len(word) <= 1:
                masked.append(word)
            else:
                masked.append(word[0] + "*" * (len(word) - 1))
        return " ".join(masked)

    @staticmethod
    def _mask_date(value: str) -> str:
        """
        Mask date: preserve year, mask day and month.
        Example: 12/25/1990 → **/**/1990
                 January 1990 → ******* 1990
                 1990-01-15 → 1990-**-**
        """
        # Try to find a 4-digit year
        year_match = re.search(r"\b(19|20)\d{2}\b", value)
        if not year_match:
            return "**/**/****"
        year = year_match.group()
        # ISO format (YYYY-MM-DD)
        if re.match(r"\d{4}-\d{2}-\d{2}", value):
            return f"{year}-**-**"
        # Month name format
        month_name = re.search(
            r"\b(January|February|March|April|May|June|July|August|September|"
            r"October|November|December)\b", value, re.IGNORECASE
        )
        if month_name:
            return f"******* {year}"
        # Numeric formats (MM/DD/YYYY, DD-MM-YYYY, etc.)
        return f"**/**/{year}"

    @staticmethod
    def _generic_mask(value: str) -> str:
        """Generic partial mask: first 2 chars visible + stars + last 2 chars."""
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    # ── Span resolution ──────────────────────────────────────────────────

    @staticmethod
    def _resolve_spans(entities: List) -> List:
        """
        Remove overlapping entity spans. When spans overlap, the entity with the
        larger span (end - start) is kept; in case of a tie, the first is kept.

        Returns a list of non-overlapping entities sorted by start offset.
        """
        if not entities:
            return []

        # Sort by span length DESC so we always prefer longer spans
        sorted_entities = sorted(
            entities, key=lambda e: (e.end - e.start), reverse=True
        )
        accepted: List = []
        used_ranges: List[tuple] = []

        for entity in sorted_entities:
            s, en = entity.start, entity.end
            overlap = any(
                not (en <= us or s >= ue)
                for us, ue in used_ranges
            )
            if not overlap:
                accepted.append(entity)
                used_ranges.append((s, en))

        return sorted(accepted, key=lambda e: e.start)
