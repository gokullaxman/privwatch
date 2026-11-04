"""
Tests for PrivWatch 3.1 Production Inference Pipeline & Explainability
"""

import pytest

from core.models import SecurityEvent, Severity
from ml.inference.model_runner import ModelRunner
from ml.inference.advisory_detector import AdvisoryMLDetector
from ml.explainability.explanation import CompositeRiskCalculator


def test_composite_risk_calculator_semantics():
    # Benign event with nominal anomaly score has minimal risk
    r_benign = CompositeRiskCalculator.calculate("BENIGN", anomaly_score=0.10, confidence=0.90)
    assert r_benign <= 10

    # Confirmed malicious with high anomaly has severe risk
    r_mal = CompositeRiskCalculator.calculate("CONFIRMED_MALICIOUS", anomaly_score=0.90, confidence=0.95)
    assert r_mal >= 80

    # Anomaly score alone without confirmed malicious label does NOT max out risk
    r_anom_only = CompositeRiskCalculator.calculate("SUSPICIOUS", anomaly_score=0.85, confidence=0.60)
    assert 40 <= r_anom_only <= 75


def test_model_runner_inference_and_attribution():
    runner = ModelRunner()
    ev = SecurityEvent(
        event_type="SUID_EXECUTION",
        uid=1001,
        euid=0,
        pid=5555,
        ppid=1000,
        process="bash",
        command="/tmp/pwn_bash",
        evidence={"exe": "/tmp/pwn_bash", "is_suid": True}
    )

    exp = runner.evaluate_event(ev)

    assert exp.event_id == ev.event_id
    assert exp.predicted_class in ["CONFIRMED_MALICIOUS", "PRIVILEGE_TRANSITION_ANOMALY"]
    assert exp.anomaly_score >= 0.0
    assert exp.confidence > 0.0
    assert exp.composite_risk_score > 50
    assert len(exp.contributing_features) > 0
    assert "process elevated effective UID to 0" in exp.detection_explanation or "writable directory" in exp.detection_explanation


def test_model_runner_fault_tolerance_on_malformed_event():
    runner = ModelRunner()
    # Malformed event with impossible types
    ev = SecurityEvent(event_id="malformed_test")
    # Manually poison internal field
    ev.timestamp = "not_a_datetime"  # type: ignore

    # Must NOT raise exception; returns safe baseline fallback
    exp = runner.evaluate_event(ev)
    assert exp.event_id == "malformed_test"
    assert exp.prediction_status == "INSUFFICIENT_EVIDENCE"


def test_advisory_ml_detector_generates_advisory_findings():
    detector = AdvisoryMLDetector()
    ev = SecurityEvent(
        event_type="SUID_EXECUTION",
        uid=1002,
        euid=0,
        pid=9999,
        ppid=1000,
        process="sh",
        command="/tmp/bad_sh",
        evidence={"exe": "/tmp/bad_sh", "is_suid": True}
    )

    findings = detector.evaluate_telemetry([ev])
    assert len(findings) == 1
    f = findings[0]
    assert f.vector == "AI_ML_DETECTION"
    assert f.evidence.get("is_advisory_ml") is True
    assert "explanation" in f.evidence
