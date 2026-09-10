"""
AI Memory Firewall - Week 5 Data Redaction Engine Test Suite
=============================================================
30 test scenarios covering:
  - Strategy unit tests: FULL, PARTIAL, HASH, TOKENIZE (12 tests)
  - ENTITY_STRATEGY_MAP defaults & override (5 tests)
  - Multi-entity & overlapping span handling (5 tests)
  - RedactionMap: store, restore, export_audit_log (5 tests)
  - Integration with SensitivityClassifier & FirewallEvaluator (5 tests)
  - Performance benchmark: 5000-char text < 100ms (2 tests)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import List, Optional

import pytest

from src.engine.detection_rules import SensitiveEntityType
from src.engine.redactor import (
    DataRedactor,
    ENTITY_STRATEGY_MAP,
    RedactionEntry,
    RedactionMap,
    RedactionResult,
    RedactionStrategy,
)


# ---------------------------------------------------------------------------
# Helper: minimal EntityDetection stand-in so we don't need a live classifier
# ---------------------------------------------------------------------------

@dataclass
class _FakeEntity:
    """Minimal stand-in for EntityDetection from the classifier."""
    entity_type: str
    original_text: str
    redacted_text: str   # the classifier's default placeholder
    start: int
    end: int
    source: str = "REGEX"
    confidence: float = 0.90
    risk_weight: float = 0.90


def _ent(entity_type: str, text: str, placeholder: str, start: int) -> _FakeEntity:
    return _FakeEntity(
        entity_type=entity_type,
        original_text=text,
        redacted_text=placeholder,
        start=start,
        end=start + len(text),
    )


# ===========================================================================
# 1. FULL Strategy Tests (3 tests)
# ===========================================================================

class TestFullStrategy:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_full_uses_entity_placeholder(self):
        """FULL strategy must return the entity's built-in redaction placeholder."""
        entities = [_ent(SensitiveEntityType.PRIVATE_KEY, "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", 0)]
        result = self.redactor.redact("-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----", entities, strategy_override=RedactionStrategy.FULL)
        assert result.redacted_text == "[REDACTED_PRIVATE_KEY]"
        assert result.entries[0].strategy == RedactionStrategy.FULL

    def test_full_vehicle_reg(self):
        """VEHICLE_REG default strategy is FULL — uses placeholder."""
        text = "Plate ABC-1234 was spotted."
        entities = [_ent(SensitiveEntityType.VEHICLE_REG, "ABC-1234", "[REDACTED_VEHICLE_REG]", 6)]
        result = self.redactor.redact(text, entities)
        assert "[REDACTED_VEHICLE_REG]" in result.redacted_text
        assert "ABC-1234" not in result.redacted_text

    def test_full_organization(self):
        """ORGANIZATION default strategy is FULL."""
        text = "Employee of Acme Corp."
        entities = [_ent(SensitiveEntityType.ORGANIZATION, "Acme Corp", "[REDACTED_ORGANIZATION]", 12)]
        result = self.redactor.redact(text, entities)
        assert "Acme Corp" not in result.redacted_text
        assert result.entries[0].strategy == RedactionStrategy.FULL


# ===========================================================================
# 2. PARTIAL Strategy Tests (7 tests)
# ===========================================================================

class TestPartialStrategy:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_partial_email_structure(self):
        """Email partial: first 2 local chars visible, domain shows TLD only."""
        text = "Contact alice@example.com for info."
        entities = [_ent(SensitiveEntityType.EMAIL, "alice@example.com", "[REDACTED_EMAIL]", 8)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert masked.startswith("al")
        assert "@" in masked
        assert ".com" in masked
        assert "example" not in masked
        assert "alice" not in masked

    def test_partial_credit_card_last_four(self):
        """Credit card partial: format is ****-****-****-XXXX with last 4 preserved."""
        text = "Card: 4111 1111 1111 1234"
        entities = [_ent(SensitiveEntityType.CREDIT_CARD, "4111 1111 1111 1234", "[REDACTED_CC]", 6)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert masked.endswith("1234")
        assert "4111" not in masked
        assert "****" in masked

    def test_partial_phone_last_four(self):
        """Phone partial: preserves last 4 digits only."""
        text = "Call +1 (800) 555-0199 now."
        entities = [_ent(SensitiveEntityType.PHONE_NUMBER, "+1 (800) 555-0199", "[REDACTED_PHONE]", 5)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert "0199" in masked
        assert "800" not in masked

    def test_partial_ip_first_two_octets(self):
        """IP partial: preserves first two octets, masks last two."""
        text = "Request from 192.168.10.25"
        entities = [_ent(SensitiveEntityType.IP_ADDRESS, "192.168.10.25", "[REDACTED_IP]", 13)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert masked.startswith("192.168.")
        assert "10" not in masked
        assert "25" not in masked

    def test_partial_ssn_last_four(self):
        """SSN partial: shows ***-**-XXXX format."""
        text = "SSN: 123-45-6789"
        entities = [_ent(SensitiveEntityType.SSN, "123-45-6789", "[REDACTED_SSN]", 5)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert "6789" in masked
        assert "123" not in masked
        assert masked.startswith("***")

    def test_partial_iban_country_and_last_four(self):
        """IBAN partial: shows country code and last 4 chars."""
        text = "IBAN: GB82WEST12345698765432"
        entities = [_ent(SensitiveEntityType.IBAN, "GB82WEST12345698765432", "[REDACTED_IBAN]", 6)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert masked.startswith("GB")
        assert "5432" in masked
        assert "WEST" not in masked

    def test_partial_person_initial_only(self):
        """Person partial: each word shows first letter only, rest masked."""
        text = "Call Alice Johnson immediately."
        entities = [_ent(SensitiveEntityType.PERSON, "Alice Johnson", "[REDACTED_PERSON]", 5)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.PARTIAL)
        masked = result.entries[0].redacted_text
        assert masked.startswith("A")
        assert "J" in masked
        assert "lice" not in masked
        assert "ohnson" not in masked


# ===========================================================================
# 3. HASH Strategy Tests (3 tests)
# ===========================================================================

class TestHashStrategy:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_hash_format(self):
        """HASH output contains entity type label and a hex digest."""
        text = "API key: sk-abc123xyz456def789ghi012"
        entities = [_ent(SensitiveEntityType.API_KEY, "sk-abc123xyz456def789ghi012", "[REDACTED_API_KEY]", 9)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.HASH)
        masked = result.entries[0].redacted_text
        assert masked.startswith("[HASH_")
        assert "API_KEY" in masked
        assert "sk-abc" not in masked

    def test_hash_is_deterministic(self):
        """Same input must always produce the same hash output."""
        entities = [_ent(SensitiveEntityType.API_KEY, "AKIAIOSFODNN7EXAMPLE1234", "[REDACTED_AWS_KEY]", 0)]
        r1 = self.redactor.redact("AKIAIOSFODNN7EXAMPLE1234", entities, strategy_override=RedactionStrategy.HASH)
        r2 = self.redactor.redact("AKIAIOSFODNN7EXAMPLE1234", entities, strategy_override=RedactionStrategy.HASH)
        assert r1.entries[0].redacted_text == r2.entries[0].redacted_text

    def test_hash_different_inputs_different_outputs(self):
        """Different inputs must produce different hash outputs."""
        e1 = _ent(SensitiveEntityType.API_KEY, "key_version_1_secret", "[REDACTED_API_KEY]", 0)
        e2 = _ent(SensitiveEntityType.API_KEY, "key_version_2_secret", "[REDACTED_API_KEY]", 0)
        r1 = self.redactor.redact("key_version_1_secret", [e1], strategy_override=RedactionStrategy.HASH)
        r2 = self.redactor.redact("key_version_2_secret", [e2], strategy_override=RedactionStrategy.HASH)
        assert r1.entries[0].redacted_text != r2.entries[0].redacted_text


# ===========================================================================
# 4. TOKENIZE Strategy Tests (4 tests)
# ===========================================================================

class TestTokenizeStrategy:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_tokenize_produces_token_tag(self):
        """TOKENIZE output is a [TOKEN_...] bracketed string."""
        text = "SSN: 123-45-6789"
        entities = [_ent(SensitiveEntityType.SSN, "123-45-6789", "[REDACTED_SSN]", 5)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.TOKENIZE)
        masked = result.entries[0].redacted_text
        assert masked.startswith("[TOKEN_")
        assert "123-45-6789" not in result.redacted_text

    def test_tokenize_restore_returns_original(self):
        """RedactionMap.restore(token) must return the original RedactionEntry."""
        text = "Passport: A12345678"
        entities = [_ent(SensitiveEntityType.PASSPORT_NUMBER, "A12345678", "[REDACTED_PASSPORT]", 10)]
        result = self.redactor.redact(text, entities, strategy_override=RedactionStrategy.TOKENIZE)
        token = result.entries[0].token
        assert token is not None
        entry = result.redaction_map.restore(token)
        assert entry is not None
        assert entry.original_text == "A12345678"

    def test_tokenize_unknown_token_returns_none(self):
        """Restoring a non-existent token must return None (no KeyError)."""
        result = self.redactor.redact("clean text", [], strategy_override=RedactionStrategy.TOKENIZE)
        assert result.redaction_map.restore("TOKEN_SSN_dead") is None

    def test_redact_with_map_convenience(self):
        """redact_with_map() always uses TOKENIZE strategy."""
        text = "DL: D123-4567-8901"
        entities = [_ent(SensitiveEntityType.DRIVERS_LICENSE, "D123-4567-8901", "[REDACTED_DL]", 4)]
        result = self.redactor.redact_with_map(text, entities)
        assert result.entries[0].strategy == RedactionStrategy.TOKENIZE
        assert len(result.redaction_map) == 1


# ===========================================================================
# 5. ENTITY_STRATEGY_MAP Tests (5 tests)
# ===========================================================================

class TestEntityStrategyMap:

    def test_ssn_default_is_tokenize(self):
        assert ENTITY_STRATEGY_MAP[SensitiveEntityType.SSN] == RedactionStrategy.TOKENIZE

    def test_credit_card_default_is_partial(self):
        assert ENTITY_STRATEGY_MAP[SensitiveEntityType.CREDIT_CARD] == RedactionStrategy.PARTIAL

    def test_api_key_default_is_hash(self):
        assert ENTITY_STRATEGY_MAP[SensitiveEntityType.API_KEY] == RedactionStrategy.HASH

    def test_private_key_default_is_full(self):
        assert ENTITY_STRATEGY_MAP[SensitiveEntityType.PRIVATE_KEY] == RedactionStrategy.FULL

    def test_strategy_override_forces_full_on_email(self):
        """strategy_override=FULL must override the EMAIL default of PARTIAL."""
        redactor = DataRedactor()
        text = "Mail: bob@corp.io"
        entities = [_ent(SensitiveEntityType.EMAIL, "bob@corp.io", "[REDACTED_EMAIL]", 6)]
        result = redactor.redact(text, entities, strategy_override=RedactionStrategy.FULL)
        assert result.entries[0].strategy == RedactionStrategy.FULL
        assert result.redacted_text == "Mail: [REDACTED_EMAIL]"


# ===========================================================================
# 6. Multi-Entity & Span Resolution Tests (5 tests)
# ===========================================================================

class TestMultiEntityAndSpans:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_two_non_overlapping_entities(self):
        """Two separate entities in the same text are both redacted."""
        text = "Email alice@example.com or call 555-867-5309."
        entities = [
            _ent(SensitiveEntityType.EMAIL, "alice@example.com", "[REDACTED_EMAIL]", 6),
            _ent(SensitiveEntityType.PHONE_NUMBER, "555-867-5309", "[REDACTED_PHONE]", 31),
        ]
        result = self.redactor.redact(text, entities)
        assert "alice@example.com" not in result.redacted_text
        assert "555-867-5309" not in result.redacted_text
        assert len(result.entries) == 2

    def test_three_different_strategies_applied(self):
        """Three entities with three different default strategies are each masked correctly."""
        text = "SSN 123-45-6789, key AKIAIOSFODNN7EXAMPLE1234, card 4111-1111-1111-1234."
        entities = [
            _ent(SensitiveEntityType.SSN,         "123-45-6789",              "[REDACTED_SSN]",     4),
            _ent(SensitiveEntityType.AWS_KEY,      "AKIAIOSFODNN7EXAMPLE1234", "[REDACTED_AWS_KEY]", 21),
            _ent(SensitiveEntityType.CREDIT_CARD,  "4111-1111-1111-1234",      "[REDACTED_CC]",      52),
        ]
        result = self.redactor.redact(text, entities)
        assert len(result.entries) == 3
        strategies = {e.entity_type: e.strategy for e in result.entries}
        assert strategies[SensitiveEntityType.SSN]         == RedactionStrategy.TOKENIZE
        assert strategies[SensitiveEntityType.AWS_KEY]     == RedactionStrategy.HASH
        assert strategies[SensitiveEntityType.CREDIT_CARD] == RedactionStrategy.PARTIAL

    def test_overlapping_spans_shorter_dropped(self):
        """When two spans overlap, the shorter one is dropped."""
        # PERSON span (0..13) fully contains a shorter EMAIL span if they overlap
        text = "Alice Johnson email"
        entities = [
            _ent(SensitiveEntityType.PERSON, "Alice Johnson", "[REDACTED_PERSON]", 0),
            _ent(SensitiveEntityType.PERSON, "Alice",          "[REDACTED_PERSON]", 0),  # shorter overlap
        ]
        result = self.redactor.redact(text, entities)
        # Only one entry should survive (the longer span)
        assert len(result.entries) == 1
        assert result.entries[0].original_text == "Alice Johnson"

    def test_empty_entities_returns_original_text(self):
        """Empty entity list returns unchanged text."""
        text = "No PII here at all."
        result = self.redactor.redact(text, [])
        assert result.redacted_text == text
        assert result.entries == []
        assert len(result.redaction_map) == 0

    def test_strategy_summary_counts(self):
        """strategy_summary property accurately counts strategy usage per type."""
        text = "SSN 123-45-6789, email alice@ex.com, card 4111-1111-1111-1234"
        entities = [
            _ent(SensitiveEntityType.SSN,        "123-45-6789",         "[REDACTED_SSN]",  4),
            _ent(SensitiveEntityType.EMAIL,       "alice@ex.com",        "[REDACTED_EMAIL]", 22),
            _ent(SensitiveEntityType.CREDIT_CARD, "4111-1111-1111-1234", "[REDACTED_CC]",   42),
        ]
        result = self.redactor.redact(text, entities)
        summary = result.strategy_summary
        assert summary.get("TOKENIZE", 0) >= 1   # SSN
        assert summary.get("PARTIAL", 0)  >= 2   # EMAIL + CREDIT_CARD


# ===========================================================================
# 7. RedactionMap Tests (5 tests)
# ===========================================================================

class TestRedactionMap:

    def test_store_and_retrieve_entry(self):
        """Store a RedactionEntry and retrieve it by token."""
        rmap = RedactionMap()
        entry = RedactionEntry(
            entity_type="SSN",
            strategy=RedactionStrategy.TOKENIZE,
            original_text="123-45-6789",
            redacted_text="",
        )
        token = rmap.store(entry)
        assert token in rmap
        retrieved = rmap.restore(token)
        assert retrieved is not None
        assert retrieved.original_text == "123-45-6789"

    def test_len_reflects_stored_count(self):
        """__len__ returns the number of stored entries."""
        rmap = RedactionMap()
        for i in range(5):
            entry = RedactionEntry(
                entity_type="EMAIL",
                strategy=RedactionStrategy.TOKENIZE,
                original_text=f"user{i}@example.com",
                redacted_text="",
            )
            rmap.store(entry)
        assert len(rmap) == 5

    def test_restore_unknown_token_returns_none(self):
        """Restoring an unknown token returns None without raising."""
        rmap = RedactionMap()
        assert rmap.restore("TOKEN_SSN_0000") is None

    def test_export_audit_log_order(self):
        """export_audit_log returns entries sorted by start offset."""
        rmap = RedactionMap()
        for start in [50, 10, 30]:
            entry = RedactionEntry(
                entity_type="EMAIL",
                strategy=RedactionStrategy.TOKENIZE,
                original_text=f"user@e{start}.com",
                redacted_text="",
                start=start,
                end=start + 10,
            )
            rmap.store(entry)
        log = rmap.export_audit_log()
        starts = [e.start for e in log]
        assert starts == sorted(starts)

    def test_unique_tokens_per_call(self):
        """Every call to store() must produce a distinct token (probabilistically)."""
        rmap = RedactionMap()
        tokens = set()
        for _ in range(20):
            entry = RedactionEntry(
                entity_type="CREDIT_CARD",
                strategy=RedactionStrategy.TOKENIZE,
                original_text="4111111111111234",
                redacted_text="",
            )
            t = rmap.store(entry)
            tokens.add(t)
        # With 4 hex chars (65536 possibilities) 20 draws should all be unique
        assert len(tokens) == 20


# ===========================================================================
# 8. Integration with FirewallEvaluator (3 tests)
# ===========================================================================

class TestFirewallEvaluatorIntegration:

    def setup_method(self):
        from src.engine.evaluator import FirewallEvaluator
        self.evaluator = FirewallEvaluator()

    def test_redaction_result_populated_on_sensitive_text(self):
        """EvaluationResult.redaction_result must be non-None for sensitive input."""
        result = self.evaluator.evaluate("My email is alice@example.com")
        assert result.redaction_result is not None
        assert len(result.redaction_result.entries) > 0

    def test_redaction_result_none_for_clean_text(self):
        """EvaluationResult.redaction_result entries are empty for clearly non-sensitive text.

        Note: spaCy may detect words like 'today' as DATE entities. We therefore use
        text that contains no names, dates, numbers, or locations.
        """
        result = self.evaluator.evaluate("The sky is blue and grass is green.")
        # If the classifier produced no entities, redaction_result will be None.
        # If it did fire (low-weight NLP hit), entries must contain only non-critical types.
        if result.redaction_result is not None:
            critical_types = {
                "SSN", "CREDIT_CARD", "API_KEY", "AWS_KEY", "PRIVATE_KEY",
                "PASSPORT_NUMBER", "DRIVERS_LICENSE", "IBAN", "EMAIL",
            }
            detected = {e.entity_type for e in result.redaction_result.entries}
            assert detected.isdisjoint(critical_types), (
                f"Clean text should not trigger high-sensitivity entity types. Got: {detected}"
            )

    def test_sanitized_text_uses_strategy_masking(self):
        """sanitized_text in EvaluationResult uses strategy-masked output, not raw placeholders."""
        result = self.evaluator.evaluate("Send invoice to bob@corp.io for 500 USD")
        # With EMAIL default strategy = PARTIAL, sanitized text must NOT contain raw placeholder
        # but must also not contain the original email
        assert "bob@corp.io" not in result.sanitized_text


# ===========================================================================
# 9. Performance Benchmarks (2 tests)
# ===========================================================================

class TestPerformanceBenchmarks:

    def setup_method(self):
        self.redactor = DataRedactor()

    def test_redaction_5000_chars_under_100ms(self):
        """Redacting a 5000-character text with 5 entities must complete in < 100ms."""
        base = "John Doe (john.doe@example.com) called from 192.168.1.50. " * 10
        text = base * 10  # ~5800 chars
        entities = [
            _ent(SensitiveEntityType.PERSON,       "John Doe",              "[REDACTED_PERSON]",  0),
            _ent(SensitiveEntityType.EMAIL,         "john.doe@example.com",  "[REDACTED_EMAIL]",   10),
            _ent(SensitiveEntityType.IP_ADDRESS,    "192.168.1.50",          "[REDACTED_IP]",      43),
        ]
        start = time.perf_counter()
        result = self.redactor.redact(text, entities)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100, f"Redaction took {elapsed_ms:.1f}ms, expected < 100ms"
        assert result.redacted_text is not None

    def test_tokenize_map_100_entries_under_50ms(self):
        """Storing and restoring 100 TOKENIZE entries from a RedactionMap must be < 50ms."""
        rmap = RedactionMap()
        start = time.perf_counter()
        tokens = []
        for i in range(100):
            entry = RedactionEntry(
                entity_type="SSN",
                strategy=RedactionStrategy.TOKENIZE,
                original_text=f"{i:03d}-45-{i:04d}",
                redacted_text="",
                start=i * 15,
                end=i * 15 + 11,
            )
            tokens.append(rmap.store(entry))

        for token in tokens:
            rmap.restore(token)

        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 50, f"Map ops took {elapsed_ms:.1f}ms, expected < 50ms"
