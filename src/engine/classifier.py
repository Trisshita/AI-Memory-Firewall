"""
AI Memory Firewall - Week 3 NLP Sensitivity Classifier
=======================================================
Multi-signal classifier that fuses three independent detection sources:

  1. REGEX  – Pattern-based rules from detection_rules.py (deterministic, fast)
  2. SPACY  – Named Entity Recognition via en_core_web_md (context-aware)
  3. PRESIDIO – Microsoft Presidio Analyzer (enterprise PII detection with scores)

The three signal streams are fused into a single ClassificationResult with
per-entity confidence scores and an overall composite risk score.

Graceful Degradation:
  - If spaCy model is not installed → spaCy engine is skipped (regex + Presidio only)
  - If Presidio is not installed  → Presidio engine is skipped (regex + spaCy only)
  - No exceptions are raised; a warning is logged instead.

Usage:
    from src.engine.classifier import SensitivityClassifier

    clf = SensitivityClassifier()
    result = clf.classify("My SSN is 123-45-6789 and email is alice@example.com")
    print(result.is_sensitive)        # True
    print(result.risk_score)          # 0.9+
    print(result.sanitized_text)      # "My SSN is [REDACTED_SSN] and email is [REDACTED_EMAIL]"
    for entity in result.entities:
        print(entity.entity_type, entity.confidence, entity.source)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from src.engine.detection_rules import (
    DETECTION_RULES,
    PRESIDIO_ENTITY_RISK_MAP,
    PRESIDIO_TO_ENTITY,
    SPACY_ENTITY_RISK_MAP,
    SPACY_LABEL_TO_ENTITY,
    DetectionRule,
    SensitiveEntityType,
)

logger = logging.getLogger(__name__)

# Confidence boost when 2+ sources agree on overlapping text
_MULTI_SOURCE_BOOST = 0.10
# Minimum risk_score to mark result as sensitive
_SENSITIVITY_THRESHOLD = 0.40



# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class EntityDetection:
    """
    A single detected sensitive entity from any source.

    Attributes:
        entity_type:    Canonical type string (e.g. "SSN", "PERSON").
        source:         Detection source: "REGEX", "SPACY", or "PRESIDIO".
        original_text:  The exact matched text in the input.
        redacted_text:  The safe replacement placeholder.
        start:          Character offset where the match begins.
        end:            Character offset where the match ends.
        confidence:     Detection confidence from 0.0 to 1.0.
        risk_weight:    Severity contribution from 0.0 to 1.0.
    """
    entity_type: str
    source: str
    original_text: str
    redacted_text: str
    start: int
    end: int
    confidence: float
    risk_weight: float


@dataclass
class ClassificationResult:
    """
    The complete output of a SensitivityClassifier.classify() call.

    Attributes:
        original_text:      The raw input as received.
        sanitized_text:     Input with all detected entities replaced by placeholders.
        entities:           All EntityDetection objects, sorted by position.
        overall_confidence: Weighted average confidence across all detections.
        risk_score:         Composite risk score (0.0 = clean, 1.0 = critical).
        is_sensitive:       True if risk_score > SENSITIVITY_THRESHOLD (0.30).
        latency_ms:         Total classifier wall time in milliseconds.
        sources_used:       Which detection engines contributed results.
    """
    original_text: str
    sanitized_text: str
    entities: List[EntityDetection]
    overall_confidence: float
    risk_score: float
    is_sensitive: bool
    latency_ms: float
    sources_used: List[str]

    @property
    def entity_types(self) -> List[str]:
        """Deduplicated, sorted list of all detected entity type names."""
        return sorted({e.entity_type for e in self.entities})

    @property
    def by_source(self) -> Dict[str, List[EntityDetection]]:
        """Entities grouped by source engine."""
        groups: Dict[str, List[EntityDetection]] = {}
        for e in self.entities:
            groups.setdefault(e.source, []).append(e)
        return groups


# ---------------------------------------------------------------------------
# Internal Engine: Regex
# ---------------------------------------------------------------------------

class _RegexEngine:
    """Applies all DetectionRules from detection_rules.py to the input text."""

    def scan(self, text: str) -> List[EntityDetection]:
        results: List[EntityDetection] = []
        for rule in DETECTION_RULES:
            for m in rule.pattern.finditer(text):
                results.append(
                    EntityDetection(
                        entity_type=rule.entity_type.value,
                        source="REGEX",
                        original_text=m.group(),
                        redacted_text=rule.redaction_placeholder,
                        start=m.start(),
                        end=m.end(),
                        confidence=rule.risk_weight,   # regex is deterministic
                        risk_weight=rule.risk_weight,
                    )
                )
        return results

    def redact(self, text: str) -> str:
        """Apply all regex redactions to text and return sanitized copy."""
        sanitized = text
        for rule in DETECTION_RULES:
            sanitized = rule.pattern.sub(rule.redaction_placeholder, sanitized)
        return sanitized


# ---------------------------------------------------------------------------
# Module-level spaCy singleton — loaded at most once per process
# ---------------------------------------------------------------------------

_SPACY_NLP: object = None          # the loaded spacy.Language object
_SPACY_AVAILABLE: Optional[bool] = None  # None = not yet probed


def _init_spacy() -> None:
    """Load en_core_web_md exactly once per process, storing in module globals."""
    global _SPACY_NLP, _SPACY_AVAILABLE  # noqa: PLW0603
    if _SPACY_AVAILABLE is not None:
        return  # already probed by a previous instance
    try:
        import spacy  # noqa: PLC0415
        _SPACY_NLP = spacy.load("en_core_web_md")
        _SPACY_AVAILABLE = True
        logger.info("spaCy engine initialized with en_core_web_md (singleton)")
    except OSError:
        _SPACY_AVAILABLE = False
        logger.warning(
            "spaCy model 'en_core_web_md' not found. "
            "Run: python -m spacy download en_core_web_md. "
            "Falling back to regex-only mode for NER."
        )
    except ImportError:
        _SPACY_AVAILABLE = False
        logger.warning(
            "spaCy is not installed. Install with: pip install spacy. "
            "Falling back to regex-only mode for NER."
        )
    except (MemoryError, ValueError) as exc:
        _SPACY_AVAILABLE = False
        logger.warning(
            "spaCy model failed to load due to insufficient memory (%s). "
            "Falling back to regex-only mode for NER.",
            exc,
        )


# ---------------------------------------------------------------------------
# Internal Engine: spaCy NER
# ---------------------------------------------------------------------------

class _SpacyEngine:
    """
    Uses spaCy en_core_web_md Named Entity Recognition to detect entities.
    Silently disabled if the model is not available.
    Uses a module-level singleton so the model is loaded at most once per
    process, preventing MemoryError when many classifier instances are created
    concurrently (e.g. during a full test run).
    """

    def __init__(self) -> None:
        pass  # no per-instance state needed; singleton lives at module level

    def _ensure_initialized(self) -> None:
        """Delegate to the module-level loader (idempotent)."""
        _init_spacy()

    @property
    def available(self) -> bool:
        self._ensure_initialized()
        return bool(_SPACY_AVAILABLE)

    def scan(self, text: str) -> List[EntityDetection]:
        self._ensure_initialized()
        if not _SPACY_AVAILABLE or not _SPACY_NLP:
            return []
        doc = _SPACY_NLP(text)  # type: ignore[operator]
        results: List[EntityDetection] = []
        for ent in doc.ents:
            risk = SPACY_ENTITY_RISK_MAP.get(ent.label_, 0.10)
            entity_type = SPACY_LABEL_TO_ENTITY.get(
                ent.label_, ent.label_
            )
            if isinstance(entity_type, SensitiveEntityType):
                entity_type_str = entity_type.value
            else:
                entity_type_str = str(entity_type)
            results.append(
                EntityDetection(
                    entity_type=entity_type_str,
                    source="SPACY",
                    original_text=ent.text,
                    redacted_text=f"[REDACTED_{entity_type_str}]",
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=risk,
                    risk_weight=risk,
                )
            )
        return results


# ---------------------------------------------------------------------------
# Module-level Presidio singleton — loaded at most once per process
# ---------------------------------------------------------------------------

_PRESIDIO_ANALYZER: object = None          # the loaded AnalyzerEngine object
_PRESIDIO_AVAILABLE: Optional[bool] = None  # None = not yet probed


def _init_presidio() -> None:
    """Initialize Presidio AnalyzerEngine exactly once per process."""
    global _PRESIDIO_ANALYZER, _PRESIDIO_AVAILABLE  # noqa: PLW0603
    if _PRESIDIO_AVAILABLE is not None:
        return  # already probed by a previous instance
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
        from presidio_analyzer.nlp_engine import NlpEngineProvider  # noqa: PLC0415

        # Re-use the already-loaded spaCy model if available to avoid a
        # second en_core_web_md load (Presidio normally loads it internally).
        _init_spacy()  # ensure spaCy singleton is ready first
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_md"}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
        nlp_engine = provider.create_engine()
        _PRESIDIO_ANALYZER = AnalyzerEngine(nlp_engine=nlp_engine)
        _PRESIDIO_AVAILABLE = True
        logger.info("Presidio Analyzer engine initialized (singleton)")

    except ImportError:
        _PRESIDIO_AVAILABLE = False
        logger.warning(
            "presidio-analyzer is not installed. "
            "Install with: pip install presidio-analyzer. "
            "Falling back to regex + spaCy mode."
        )
    except (MemoryError, ValueError) as exc:
        _PRESIDIO_AVAILABLE = False
        logger.warning(
            "Presidio failed to initialize due to insufficient memory (%s). "
            "Falling back to regex + spaCy mode.",
            exc,
        )
    except Exception as exc:  # noqa: BLE001
        _PRESIDIO_AVAILABLE = False
        logger.warning("Presidio initialization failed: %s", exc)


# ---------------------------------------------------------------------------
# Internal Engine: Microsoft Presidio
# ---------------------------------------------------------------------------

class _PresidioEngine:
    """
    Uses Microsoft Presidio Analyzer for enterprise-grade PII detection.
    Silently disabled if presidio-analyzer is not installed.
    Uses a module-level singleton so the AnalyzerEngine (and its internal
    spaCy model) is created at most once per process.
    """

    def __init__(self) -> None:
        pass  # no per-instance state needed; singleton lives at module level

    def _ensure_initialized(self) -> None:
        """Delegate to the module-level loader (idempotent)."""
        _init_presidio()


    @property
    def available(self) -> bool:
        self._ensure_initialized()
        return bool(_PRESIDIO_AVAILABLE)

    def scan(self, text: str) -> List[EntityDetection]:
        self._ensure_initialized()
        if not _PRESIDIO_AVAILABLE or not _PRESIDIO_ANALYZER:
            return []
        try:
            results_raw = _PRESIDIO_ANALYZER.analyze(text=text, language="en")  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Presidio analysis failed: %s", exc)
            return []

        results: List[EntityDetection] = []
        for r in results_raw:
            entity_type_str = PRESIDIO_TO_ENTITY.get(r.entity_type, r.entity_type)
            if isinstance(entity_type_str, SensitiveEntityType):
                entity_type_str = entity_type_str.value

            # Cap risk_weight using PRESIDIO_ENTITY_RISK_MAP so that low-sensitivity
            # NLP entities (LOCATION, DATE_TIME, PERSON) cannot inflate risk_score
            # to critical levels when Presidio fires with high model confidence.
            # High-sensitivity structured PII (SSN, CREDIT_CARD) still gets the
            # full Presidio confidence score because their caps equal their
            # true severity weight.
            max_risk = PRESIDIO_ENTITY_RISK_MAP.get(r.entity_type, float(r.score))
            risk = min(float(r.score), max_risk)
            matched = text[r.start: r.end]

            results.append(
                EntityDetection(
                    entity_type=entity_type_str,
                    source="PRESIDIO",
                    original_text=matched,
                    redacted_text=f"[REDACTED_{entity_type_str}]",
                    start=r.start,
                    end=r.end,
                    confidence=float(r.score),
                    risk_weight=risk,
                )
            )
        return results


# ---------------------------------------------------------------------------
# Confidence Fuser
# ---------------------------------------------------------------------------

class _ConfidenceFuser:
    """
    Merges detections from multiple sources.

    Rules:
    - If 2+ sources produce overlapping matches for the same text region,
      their confidence is boosted by MULTI_SOURCE_BOOST (capped at 1.0).
    - Duplicate entries (same source + span) are de-duplicated.
    - Regex detections take precedence for redaction (most precise spans).
    """

    @staticmethod
    def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        """Return True if two spans overlap."""
        return a_start < b_end and b_start < a_end

    def fuse(
        self,
        regex_hits: List[EntityDetection],
        spacy_hits: List[EntityDetection],
        presidio_hits: List[EntityDetection],
    ) -> List[EntityDetection]:
        """
        Fuse all hits, apply multi-source confidence boost, and de-duplicate.

        Returns:
            Merged, de-duplicated list sorted by start offset.
        """
        all_hits = regex_hits + spacy_hits + presidio_hits
        if not all_hits:
            return []

        # Build overlap groups
        fused: List[EntityDetection] = []
        seen_spans: Set[Tuple[int, int, str]] = set()  # (start, end, source)

        for hit in all_hits:
            span_key = (hit.start, hit.end, hit.source)
            if span_key in seen_spans:
                continue
            seen_spans.add(span_key)

            # Count how many OTHER sources overlap this span
            other_sources = set()
            for other in all_hits:
                if other.source != hit.source and self._overlaps(
                    hit.start, hit.end, other.start, other.end
                ):
                    other_sources.add(other.source)

            boosted_confidence = hit.confidence
            if other_sources:
                boosted_confidence = min(
                    1.0, hit.confidence + _MULTI_SOURCE_BOOST * len(other_sources)
                )

            fused.append(
                EntityDetection(
                    entity_type=hit.entity_type,
                    source=hit.source,
                    original_text=hit.original_text,
                    redacted_text=hit.redacted_text,
                    start=hit.start,
                    end=hit.end,
                    confidence=round(boosted_confidence, 4),
                    risk_weight=hit.risk_weight,
                )
            )

        fused.sort(key=lambda e: e.start)
        return fused


# ---------------------------------------------------------------------------
# Public Classifier
# ---------------------------------------------------------------------------

class SensitivityClassifier:
    """
    NLP-based sensitivity classifier that fuses regex, spaCy NER, and
    Microsoft Presidio signals into a unified ClassificationResult.

    The classifier is designed to be instantiated once and reused:
        clf = SensitivityClassifier()
        result = clf.classify(text)

    Thread safety: classify() is safe to call from multiple threads since
    spaCy and Presidio are both read-only during inference.
    """

    def __init__(self) -> None:
        self._regex_engine   = _RegexEngine()
        self._spacy_engine   = _SpacyEngine()
        self._presidio_engine = _PresidioEngine()
        self._fuser          = _ConfidenceFuser()

    @property
    def spacy_available(self) -> bool:
        """True if the spaCy en_core_web_md model was successfully loaded."""
        return self._spacy_engine.available

    @property
    def presidio_available(self) -> bool:
        """True if presidio-analyzer was successfully imported."""
        return self._presidio_engine.available

    def classify(self, text: str) -> ClassificationResult:
        """
        Run the full multi-signal classification pipeline on a text string.

        Args:
            text: The raw input text to inspect.

        Returns:
            ClassificationResult with all detections, scores, and sanitized text.
        """
        if not text or not text.strip():
            return ClassificationResult(
                original_text=text,
                sanitized_text=text,
                entities=[],
                overall_confidence=0.0,
                risk_score=0.0,
                is_sensitive=False,
                latency_ms=0.0,
                sources_used=[],
            )

        start_time = time.perf_counter()

        # ── Run all engines ──────────────────────────────────────────────
        regex_hits    = self._regex_engine.scan(text)
        spacy_hits    = self._spacy_engine.scan(text)
        presidio_hits = self._presidio_engine.scan(text)

        # ── Fuse results ─────────────────────────────────────────────────
        fused = self._fuser.fuse(regex_hits, spacy_hits, presidio_hits)

        # ── Build sanitized text from regex redactions ───────────────────
        # Use regex engine for redaction (most precise spans; deterministic)
        sanitized = self._regex_engine.redact(text)

        # ── Compute composite risk score ─────────────────────────────────
        risk_score = 0.0
        if fused:
            weights = [e.risk_weight for e in fused]
            max_weight = max(weights)
            extras = sum(weights) - max_weight
            risk_score = min(1.0, max_weight + (extras * 0.05))

        # ── Compute overall confidence ────────────────────────────────────
        overall_confidence = 0.0
        if fused:
            overall_confidence = sum(e.confidence for e in fused) / len(fused)

        # ── Collect which sources fired ───────────────────────────────────
        sources_used: List[str] = []
        if regex_hits:
            sources_used.append("REGEX")
        if spacy_hits:
            sources_used.append("SPACY")
        if presidio_hits:
            sources_used.append("PRESIDIO")

        latency_ms = (time.perf_counter() - start_time) * 1000

        return ClassificationResult(
            original_text=text,
            sanitized_text=sanitized,
            entities=fused,
            overall_confidence=round(overall_confidence, 4),
            risk_score=round(risk_score, 4),
            is_sensitive=risk_score > _SENSITIVITY_THRESHOLD,
            latency_ms=round(latency_ms, 3),
            sources_used=sources_used,
        )

    def is_sensitive(self, text: str) -> bool:
        """Quick boolean check — returns True if any sensitivity is detected."""
        return self.classify(text).is_sensitive

    def get_risk_score(self, text: str) -> float:
        """Returns the composite risk score for the text (0.0–1.0)."""
        return self.classify(text).risk_score
