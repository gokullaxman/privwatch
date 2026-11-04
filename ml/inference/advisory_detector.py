"""
PrivWatch 3.1 - Advisory ML Security Detector
Integrates non-blocking ML inference into Blue Team telemetry streams.
Generates advisory findings with transparent feature attribution without disrupting deterministic baselines.
"""

from typing import List, Optional, Dict, Any

from core.models import SecurityEvent, Finding, Severity, utc_now
from ml.inference.model_runner import ModelRunner
from ml.explainability.explanation import PredictionExplanation


class AdvisoryMLDetector:
    """
    Evaluates incoming telemetry events with the ML analytical tier.
    Produces advisory findings backed by calibrated confidence and feature attribution.
    """

    def __init__(self, runner: Optional[ModelRunner] = None):
        self.runner = runner or ModelRunner()
        self.advisory_findings: List[Finding] = []

    def evaluate_telemetry(
        self,
        events: List[SecurityEvent]
    ) -> List[Finding]:
        """
        Evaluate a sequence of security events and yield advisory findings
        for statistically anomalous or classified malicious activity.
        """
        findings: List[Finding] = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for i, ev in enumerate(sorted_events):
            history = sorted_events[:i]
            explanation: PredictionExplanation = self.runner.evaluate_event(ev, history)

            # Generate advisory finding if event is anomalous or classified threat
            if explanation.predicted_class != "BENIGN" or explanation.anomaly_score >= 0.65:
                # Map composite risk to severity
                if explanation.composite_risk_score >= 80:
                    sev = Severity.CRITICAL.value
                elif explanation.composite_risk_score >= 55:
                    sev = Severity.HIGH.value
                elif explanation.composite_risk_score >= 30:
                    sev = Severity.MEDIUM.value
                else:
                    sev = Severity.LOW.value

                f = Finding(
                    finding_id=f"fnd_ml_{ev.event_id[-8:]}",
                    vector="AI_ML_DETECTION",
                    severity=sev,
                    confidence=explanation.confidence,
                    title=f"ML Anomaly: {explanation.predicted_class} ({explanation.composite_risk_score}/100 Risk)",
                    description=explanation.detection_explanation,
                    affected_resource=f"{ev.source}:{ev.process or ev.event_type}",
                    evidence={
                        "is_advisory_ml": True,
                        "explanation": explanation.to_dict(),
                        "event_evidence": ev.evidence,
                        "contributing_features": explanation.contributing_features,
                        "anomaly_score": explanation.anomaly_score,
                        "composite_risk_score": explanation.composite_risk_score
                    },
                    detection_method="ml_advisory_ensemble",
                    risk_explanation=(
                        f"Machine learning model flagged statistical anomaly ({explanation.anomaly_score:.2f}) "
                        f"or threat classification '{explanation.predicted_class}' with composite risk score "
                        f"{explanation.composite_risk_score}/100."
                    ),
                    remediation="Inspect process lineage, UID transitions, and host audit logs to confirm legitimacy.",
                    references=["docs/ML_MODEL_ARCHITECTURE.md", "docs/ML_INFERENCE_GUIDE.md"],
                    timestamp=ev.timestamp
                )
                findings.append(f)

        self.advisory_findings.extend(findings)
        return findings
