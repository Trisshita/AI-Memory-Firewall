"""
AI Memory Firewall - PII Detection & Redaction Engine
======================================================
Detects and redacts Personally Identifiable Information (PII) from text
using regex pattern matching across multiple PII entity categories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class PIIType(str, Enum):
    """Categories of PII that the detector can identify and redact."""
    SSN = "SSN"                       # US Social Security Numbers
    EMAIL = "EMAIL"                   # Email addresses
    CREDIT_CARD = "CREDIT_CARD"       # Credit/debit card numbers (Visa, Mastercard, Amex, Discover)
    PHONE_NUMBER = "PHONE_NUMBER"     # US phone numbers
    IP_ADDRESS = "IP_ADDRESS"         # IPv4 addresses
    API_KEY = "API_KEY"               # API keys, JWT tokens, Bearer tokens
    AWS_KEY = "AWS_KEY"               # AWS access/secret keys
    PRIVATE_KEY = "PRIVATE_KEY"       # PEM private key blocks


@dataclass
class PIIMatch:
    """Represents a single PII entity detected in the input text."""
    pii_type: PIIType                 # Category of PII detected
    original: str                     # The actual matched text
    redacted: str                     # The safe replacement placeholder
    start: int                        # Character offset where match begins
    end: int                          # Character offset where match ends
    risk_weight: float                # Severity contribution toward overall risk score


# ---------------------------------------------------------------------------
# Pattern Registry
# Each entry: (PIIType, compiled_regex, redaction_placeholder, risk_weight)
# ---------------------------------------------------------------------------
_PII_PATTERNS: List[tuple] = [
    (
        PIIType.SSN,
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]\d{2}[-\s]\d{4}\b"),
        "[REDACTED_SSN]",
        0.90,
    ),
    (
        PIIType.CREDIT_CARD,
        re.compile(
            r"\b(?:"
            r"4\d{3}"                             # Visa (4xxx)
            r"|5[1-5]\d{2}"                       # Mastercard (51xx–55xx)
            r"|3[47]\d{2}"                        # Amex (3[47]xx)
            r"|6(?:011|5\d{2})"                   # Discover (6011, 65xx)
            r")"
            r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
            r"(?:[-\s]?\d{3})?\b"
        ),
        "[REDACTED_CC]",
        0.95,
    ),
    (
        PIIType.EMAIL,
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "[REDACTED_EMAIL]",
        0.70,
    ),
    (
        PIIType.PHONE_NUMBER,
        re.compile(
            r"\b(?:\+?1[-.\s]?)?"
            r"(?:\(\d{3}\)|\d{3})"
            r"[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        "[REDACTED_PHONE]",
        0.65,
    ),
    (
        PIIType.IP_ADDRESS,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "[REDACTED_IP]",
        0.55,
    ),
    (
        PIIType.AWS_KEY,
        re.compile(r"\b(?:AKIA|AIPA|AIDA|AROA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_KEY]",
        0.98,
    ),
    (
        PIIType.API_KEY,
        re.compile(
            r"(?:"
            r"(?:Bearer\s+)[A-Za-z0-9\-_]{20,}"  # Bearer tokens
            r"|(?:sk-)[A-Za-z0-9]{20,}"           # OpenAI API keys (sk-...)
            r"|(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}"  # GitHub tokens
            r"|(?:xox[baprs]-)[A-Za-z0-9\-]{10,}"  # Slack tokens
            r"|(?:eyJ)[A-Za-z0-9._\-]{30,}"        # JWT tokens (base64 header eyJ...)
            r")",
            re.IGNORECASE,
        ),
        "[REDACTED_API_KEY]",
        0.99,
    ),
    (
        PIIType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
        1.00,
    ),
]


class PIIDetector:
    """
    Scans text for PII entities and returns match results and a redacted version.

    Usage:
        detector = PIIDetector()
        matches, clean_text = detector.scan("Email me at jane@example.com")
        # matches → [PIIMatch(pii_type=EMAIL, ...)]
        # clean_text → "Email me at [REDACTED_EMAIL]"
    """

    def scan(self, text: str) -> tuple[List[PIIMatch], str]:
        """
        Scan a string for all PII patterns.

        Args:
            text: The raw input text to inspect.

        Returns:
            Tuple of:
              - List[PIIMatch]: All PII entities found, in document order.
              - str: The sanitized text with all PII replaced by placeholders.
        """
        matches: List[PIIMatch] = []
        sanitized = text

        for pii_type, pattern, placeholder, weight in _PII_PATTERNS:
            for m in pattern.finditer(text):
                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        original=m.group(),
                        redacted=placeholder,
                        start=m.start(),
                        end=m.end(),
                        risk_weight=weight,
                    )
                )

        # Apply redactions from all patterns at once (replace in the sanitized copy).
        # Process patterns again on the copy so offsets don't drift.
        for _, pattern, placeholder, _ in _PII_PATTERNS:
            sanitized = pattern.sub(placeholder, sanitized)

        # Sort matches by start position for consistent output.
        matches.sort(key=lambda m: m.start)
        return matches, sanitized

    def has_pii(self, text: str) -> bool:
        """Quick boolean check — returns True if any PII was detected."""
        matches, _ = self.scan(text)
        return len(matches) > 0

    def max_risk_weight(self, text: str) -> float:
        """Returns the highest risk weight among all PII found (0.0 if none)."""
        matches, _ = self.scan(text)
        if not matches:
            return 0.0
        return max(m.risk_weight for m in matches)
