"""
PrivWatch 3.1 - Prediction Explanation & Composite Risk Engine
Structures transparent evidence records, separating anomaly score, confidence, and composite risk.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from core.models import utc_now, format_iso, SecurityEvent
from ml.features.feature_schema import FeatureVector
from ml.explainability.attribution import FeatureAttributor


@dataclass
class PredictionExplanation:
    """
    Standardized explanation payload accompanying every model detection.
    Guarantees complete provenance, mathematical attribution, and auditability.
    """
    event_id: str
    predicted_class: str
    prediction_status: str
    anomaly_score: float               # [0.0, 1.0] Statistical distance from baseline
    confidence: float                  # [0.0, 1.0] Calibrated model certainty
    composite_risk_score: int          # [0 - 100] Multi-factor operational risk index
    contributing_features: List[Dict[str, Any]] = field(default_factory=list)
    detection_explanation: str = ""
    evidence_references: Dict[str, Any] = field(default_factory=dict)
    model_id: str = "privwatch_ml_v3_1"
    model_version: str = "3.1.0"
    dataset_version: str = "linux_baseline_v1"
    inference_timestamp_iso: str = field(default_factory=lambda: format_iso(utc_now()) or "")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CompositeRiskCalculator:
    """
    Computes calibrated composite risk score in [0, 100].
    Strictly prevents conflating anomaly score with attack probability.
    Formula:
      Risk = (0.35 * Anomaly_Score + 0.35 * Class_Severity_Weight + 0.20 * Confidence + 0.10 * Source_Reliability) * 100
    """

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "CONFIRMED_MALICIOUS": 1.0,
        "PRIVILEGE_TRANSITION_ANOMALY": 0.85,
        "PRIVILEGED_EXECUTION_ANOMALY": 0.80,
        "CONFIGURATION_TAMPERING": 0.75,
        "SUSPICIOUS": 0.50,
        "BENIGN": 0.05
    }

    @classmethod
    def calculate(
        cls,
        predicted_class: str,
        anomaly_score: float,
        confidence: float,
        source_reliability: float = 1.0
    ) -> int:
        sev_w = cls.SEVERITY_WEIGHTS.get(predicted_class, 0.20)
        norm_anom = min(1.0, max(0.0, float(anomaly_score)))
        norm_conf = min(1.0, max(0.0, float(confidence)))
        norm_src = min(1.0, max(0.0, float(source_reliability)))

        if predicted_class == "BENIGN" and norm_anom < 0.5:
            # Benign low-anomaly events have bounded minimal risk
            raw_risk = norm_anom * 10.0
        else:
            raw_risk = (
                (0.35 * norm_anom) +
                (0.35 * sev_w) +
                (0.20 * norm_conf) +
                (0.10 * norm_src)
            ) * 100.0

        return int(round(min(100.0, max(0.0, raw_risk))))


class ExplanationEngine:
    """Generates human-readable, evidence-supported security rationale"""

    @staticmethod
    def build_narrative(
        predicted_class: str,
        feature_vector: FeatureVector,
        contributions: List[Dict[str, Any]]
    ) -> str:
        v = feature_vector.values
        reasons = []

        if v.get("uid_euid_mismatch") == 1.0 and v.get("euid_is_root") == 1.0:
            reasons.append(f"process elevated effective UID to 0 (root) from real UID {int(v.get('uid', -1))}")

        if v.get("is_daemon_user") == 1.0 and v.get("is_interactive_shell") == 1.0:
            reasons.append("service daemon account executed interactive shell")

        if v.get("exe_in_writable_dir") == 1.0:
            reasons.append("executable is located in a world-writable directory (/tmp, /dev/shm, /var/tmp)")

        if v.get("auth_fails_last_300s", 0.0) >= 3.0:
            reasons.append(f"accumulated {int(v.get('auth_fails_last_300s'))} prior authentication failures in recent window")

        if v.get("modifies_sensitive_file") == 1.0:
            reasons.append("targeted a sensitive system authentication or scheduling configuration file")

        if not reasons:
            top_names = [c["feature"] for c in contributions[:2]]
            reasons.append(f"statistical divergence in features [{', '.join(top_names)}]")

        return f"Classification '{predicted_class}' driven by: {'; '.join(reasons)}."
