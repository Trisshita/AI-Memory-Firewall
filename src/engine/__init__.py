"""
AI Memory Firewall - Security Evaluation Engine
================================================
Exports the core evaluation engine, PII detector, injection detector,
the Week 3 NLP Sensitivity Classifier, the Week 4 Policy Engine,
and the Week 5 Data Redaction Engine.
"""

from src.engine.classifier import ClassificationResult, EntityDetection, SensitivityClassifier
from src.engine.evaluator import EvaluationResult, FirewallEvaluator
from src.engine.injection import InjectionDetector, InjectionMatch
from src.engine.pii import PIIDetector, PIIMatch, PIIType
from src.engine.policy_engine import (
    PolicyEngine,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
    PolicyViolationDetail,
)
from src.engine.redactor import (  # Week 5
    DataRedactor,
    ENTITY_STRATEGY_MAP,
    RedactionEntry,
    RedactionMap,
    RedactionResult,
    RedactionStrategy,
)

__all__ = [
    # Evaluator
    "FirewallEvaluator",
    "EvaluationResult",
    # PII Detector (Week 1)
    "PIIDetector",
    "PIIMatch",
    "PIIType",
    # Injection Detector (Week 1)
    "InjectionDetector",
    "InjectionMatch",
    # Sensitivity Classifier (Week 3)
    "SensitivityClassifier",
    "ClassificationResult",
    "EntityDetection",
    # Policy Engine (Week 4)
    "PolicyEngine",
    "PolicyEvaluationContext",
    "PolicyEvaluationResult",
    "PolicyViolationDetail",
    # Data Redactor (Week 5)
    "DataRedactor",
    "RedactionStrategy",
    "RedactionEntry",
    "RedactionMap",
    "RedactionResult",
    "ENTITY_STRATEGY_MAP",
]

