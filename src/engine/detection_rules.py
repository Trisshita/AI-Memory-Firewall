"""
AI Memory Firewall - Detection Rules Seed Data
===============================================
Defines all regex-based detection rules for the Week 3 Sensitivity Classifier.
Each DetectionRule contains a compiled pattern, redaction placeholder, risk weight,
and a human-readable description.

Entity Types Covered (12):
  1.  SSN              – US Social Security Numbers
  2.  CREDIT_CARD      – Visa, Mastercard, Amex, Discover card numbers
  3.  EMAIL            – Email addresses
  4.  PHONE_NUMBER     – US and international phone numbers
  5.  IP_ADDRESS       – IPv4 addresses
  6.  API_KEY          – OpenAI, GitHub, Slack, JWT Bearer tokens
  7.  AWS_KEY          – AWS access/secret keys (AKIA... prefix)
  8.  PRIVATE_KEY      – PEM-encoded RSA/EC/OpenSSH private key blocks
  9.  PASSPORT_NUMBER  – US and international passport numbers
  10. DRIVERS_LICENSE  – US driver's license numbers (multi-state patterns)
  11. IBAN             – International Bank Account Numbers
  12. VEHICLE_REG      – Vehicle registration plate numbers
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List


class SensitiveEntityType(str, Enum):
    """Enumeration of all sensitive entity types supported by the classifier."""
    SSN              = "SSN"
    CREDIT_CARD      = "CREDIT_CARD"
    EMAIL            = "EMAIL"
    PHONE_NUMBER     = "PHONE_NUMBER"
    IP_ADDRESS       = "IP_ADDRESS"
    API_KEY          = "API_KEY"
    AWS_KEY          = "AWS_KEY"
    PRIVATE_KEY      = "PRIVATE_KEY"
    PASSPORT_NUMBER  = "PASSPORT_NUMBER"
    DRIVERS_LICENSE  = "DRIVERS_LICENSE"
    IBAN             = "IBAN"
    VEHICLE_REG      = "VEHICLE_REG"
    # spaCy NER entity types (not regex-based, defined here for uniform naming)
    PERSON           = "PERSON"
    ORGANIZATION     = "ORGANIZATION"
    LOCATION         = "LOCATION"
    DATE             = "DATE"


@dataclass(frozen=True)
class DetectionRule:
    """
    Encapsulates a single regex-based detection rule.

    Attributes:
        entity_type:          The SensitiveEntityType this rule detects.
        pattern:              Pre-compiled regex pattern.
        redaction_placeholder: Safe replacement string when redacting.
        risk_weight:          Severity contribution (0.0 = harmless, 1.0 = critical).
        description:          Human-readable description of what this rule detects.
    """
    entity_type: SensitiveEntityType
    pattern: re.Pattern
    redaction_placeholder: str
    risk_weight: float
    description: str


# ---------------------------------------------------------------------------
# Rule Registry
# ---------------------------------------------------------------------------
DETECTION_RULES: List[DetectionRule] = [

    # 1. US Social Security Numbers
    DetectionRule(
        entity_type=SensitiveEntityType.SSN,
        pattern=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}"
            r"[-\s]\d{2}"
            r"[-\s]\d{4}\b"
        ),
        redaction_placeholder="[REDACTED_SSN]",
        risk_weight=0.90,
        description="US Social Security Numbers in XXX-XX-XXXX format",
    ),

    # 2. Credit / Debit Card Numbers
    DetectionRule(
        entity_type=SensitiveEntityType.CREDIT_CARD,
        pattern=re.compile(
            r"\b(?:"
            r"4\d{3}"
            r"|5[1-5]\d{2}"
            r"|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)"
            r"|3[47]\d{2}"
            r"|6(?:011|5\d{2})"
            r"|(?:30[0-5]|36|38)\d{2}"
            r")"
            r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
            r"(?:[-\s]?\d{3})?\b"
        ),
        redaction_placeholder="[REDACTED_CC]",
        risk_weight=0.95,
        description="Credit/debit card numbers (Visa, Mastercard, Amex, Discover, Diners)",
    ),

    # 3. Email Addresses
    DetectionRule(
        entity_type=SensitiveEntityType.EMAIL,
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        redaction_placeholder="[REDACTED_EMAIL]",
        risk_weight=0.70,
        description="Email addresses in standard RFC 5321 format",
    ),

    # 4. Phone Numbers (US + international)
    DetectionRule(
        entity_type=SensitiveEntityType.PHONE_NUMBER,
        pattern=re.compile(
            r"\b(?:\+?1[-.\s]?)?"
            r"(?:\(\d{3}\)|\d{3})"
            r"[-.\s]?\d{3}[-.\s]?\d{4}"
            r"(?:\s*(?:x|ext|extension)\.?\s*\d{1,6})?"
            r"\b",
            re.IGNORECASE,
        ),
        redaction_placeholder="[REDACTED_PHONE]",
        risk_weight=0.65,
        description="US and North American phone numbers in various formats",
    ),

    # 5. IPv4 Addresses
    DetectionRule(
        entity_type=SensitiveEntityType.IP_ADDRESS,
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        redaction_placeholder="[REDACTED_IP]",
        risk_weight=0.55,
        description="IPv4 addresses in dotted-decimal notation",
    ),

    # 6. AWS Access/Secret Keys
    DetectionRule(
        entity_type=SensitiveEntityType.AWS_KEY,
        pattern=re.compile(
            r"\b(?:AKIA|AIPA|AIDA|AROA|ASIA)[A-Z0-9]{16}\b"
        ),
        redaction_placeholder="[REDACTED_AWS_KEY]",
        risk_weight=0.98,
        description="AWS access key IDs starting with AKIA, AIPA, AIDA, AROA, or ASIA",
    ),

    # 7. API Keys & Bearer Tokens
    DetectionRule(
        entity_type=SensitiveEntityType.API_KEY,
        pattern=re.compile(
            r"(?:"
            r"(?:Bearer\s+)[A-Za-z0-9\-_]{20,}"
            r"|(?:sk-(?:proj-)?)[A-Za-z0-9]{20,}"
            r"|(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}"
            r"|(?:xox[baprs]-)[A-Za-z0-9\-]{10,}"
            r"|(?:eyJ)[A-Za-z0-9._\-]{30,}"
            r"|(?:amf_live_)[A-Za-z0-9\-_]{20,}"
            r")",
            re.IGNORECASE,
        ),
        redaction_placeholder="[REDACTED_API_KEY]",
        risk_weight=0.99,
        description="API keys and Bearer tokens (OpenAI, GitHub, Slack, JWT, AMF keys)",
    ),

    # 8. PEM Private Keys
    DetectionRule(
        entity_type=SensitiveEntityType.PRIVATE_KEY,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        redaction_placeholder="[REDACTED_PRIVATE_KEY]",
        risk_weight=1.00,
        description="PEM-encoded RSA, EC, OpenSSH, and DSA private key blocks",
    ),

    # 9. Passport Numbers
    DetectionRule(
        entity_type=SensitiveEntityType.PASSPORT_NUMBER,
        pattern=re.compile(
            r"\b(?:"
            r"[A-Z]{1,2}\d{6,9}"
            r"|[A-Z]\d{2}[A-Z]\d{5}"
            r"|\d{2}[A-Z]{2}\d{5}"
            r")\b"
        ),
        redaction_placeholder="[REDACTED_PASSPORT]",
        risk_weight=0.85,
        description="Passport numbers for US, UK, German, and French formats",
    ),

    # 10. Driver's License Numbers (US multi-state)
    DetectionRule(
        entity_type=SensitiveEntityType.DRIVERS_LICENSE,
        pattern=re.compile(
            r"\b(?:"
            r"[A-Z]\d{3}[-\s]?\d{4}[-\s]?\d{4}"
            r"|[A-Z]\d{7}"
            r"|[A-Z]{2}\d{6}"
            r")\b"
        ),
        redaction_placeholder="[REDACTED_DL]",
        risk_weight=0.80,
        description="US driver's license numbers in various state-specific formats",
    ),

    # 11. IBAN (International Bank Account Numbers)
    # Pattern: 2-letter country code + 2 check digits + 11-30 alphanumeric BBAN chars
    # Handles both space-grouped ("GB82 WEST 1234") and compact ("FR7630006000011234567890189").
    DetectionRule(
        entity_type=SensitiveEntityType.IBAN,
        pattern=re.compile(
            r"\b[A-Z]{2}\d{2}[ ]?[A-Z0-9]{1,4}(?:[ ]?[A-Z0-9]{1,4}){1,6}\b",
            re.IGNORECASE,
        ),
        redaction_placeholder="[REDACTED_IBAN]",
        risk_weight=0.85,
        description="International Bank Account Numbers (IBAN) for any country",
    ),

    # 12. Vehicle Registration Plates
    DetectionRule(
        entity_type=SensitiveEntityType.VEHICLE_REG,
        pattern=re.compile(
            r"\b(?:"
            r"[A-Z]{2,3}[-\s]?\d{1,4}[-\s]?[A-Z]{0,3}"
            r"|[A-Z]{1,3}[-]\d{3,4}"
            r"|\d{1,3}[-\s][A-Z]{3}"
            r")\b"
        ),
        redaction_placeholder="[REDACTED_VEHICLE_REG]",
        risk_weight=0.45,
        description="Vehicle registration/license plate numbers (UK, EU, US formats)",
    ),
]


# ---------------------------------------------------------------------------
# Convenience lookup maps
# ---------------------------------------------------------------------------

#: Risk weight by spaCy NER entity label
SPACY_ENTITY_RISK_MAP: dict[str, float] = {
    "PERSON":   0.35,
    "ORG":      0.30,
    "GPE":      0.25,
    "LOC":      0.20,
    "DATE":     0.20,
    "TIME":     0.15,
    "MONEY":    0.25,
    "CARDINAL": 0.10,
    "NORP":     0.20,
    "FAC":      0.20,
    "PRODUCT":  0.15,
    "EVENT":    0.15,
    "WORK_OF_ART": 0.10,
    "LAW":      0.25,
    "LANGUAGE": 0.10,
    "PERCENT":  0.15,
    "QUANTITY": 0.15,
    "ORDINAL":  0.10,
}

#: Map spaCy label -> SensitiveEntityType value
SPACY_LABEL_TO_ENTITY: dict[str, str] = {
    "PERSON": SensitiveEntityType.PERSON,
    "ORG":    SensitiveEntityType.ORGANIZATION,
    "GPE":    SensitiveEntityType.LOCATION,
    "LOC":    SensitiveEntityType.LOCATION,
}

#: Map Presidio entity type -> SensitiveEntityType value
PRESIDIO_TO_ENTITY: dict[str, str] = {
    "PERSON":               SensitiveEntityType.PERSON,
    "EMAIL_ADDRESS":        SensitiveEntityType.EMAIL,
    "PHONE_NUMBER":         SensitiveEntityType.PHONE_NUMBER,
    "CREDIT_CARD":          SensitiveEntityType.CREDIT_CARD,
    "US_SSN":               SensitiveEntityType.SSN,
    "US_PASSPORT":          SensitiveEntityType.PASSPORT_NUMBER,
    "US_DRIVER_LICENSE":    SensitiveEntityType.DRIVERS_LICENSE,
    "IBAN_CODE":            SensitiveEntityType.IBAN,
    "IP_ADDRESS":           SensitiveEntityType.IP_ADDRESS,
    "AWS_ACCESS_KEY":       SensitiveEntityType.AWS_KEY,
    "LOCATION":             SensitiveEntityType.LOCATION,
    "DATE_TIME":            SensitiveEntityType.DATE,
    "NRP":                  SensitiveEntityType.ORGANIZATION,
}

#: Maximum risk_weight for Presidio entity types.
PRESIDIO_ENTITY_RISK_MAP: dict[str, float] = {
    # Structured PII — keep Presidio confidence as-is (high risk)
    "US_SSN":            0.90,
    "CREDIT_CARD":       0.95,
    "EMAIL_ADDRESS":     0.70,
    "PHONE_NUMBER":      0.65,
    "IP_ADDRESS":        0.55,
    "IBAN_CODE":         0.85,
    "US_PASSPORT":       0.85,
    "US_DRIVER_LICENSE": 0.80,
    "AWS_ACCESS_KEY":    0.98,
    # NLP-derived entities — cap at the same weights used by spaCy
    "PERSON":            0.35,
    "LOCATION":          0.25,
    "DATE_TIME":         0.20,
    "NRP":               0.30,
    "ORGANIZATION":      0.30,
}
