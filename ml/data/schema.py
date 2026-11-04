"""
PrivWatch 3.1 - Telemetry Dataset Schema & Label Definitions
Strictly enforces verified ground truth labels, host provenance, and leakage prevention.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import hashlib
import json

from core.models import SecurityEvent, utc_now, format_iso, parse_iso
from ml.features.feature_schema import FeatureVector


class DetectionLabel(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    PRIVILEGE_TRANSITION_ANOMALY = "PRIVILEGE_TRANSITION_ANOMALY"
    PRIVILEGED_EXECUTION_ANOMALY = "PRIVILEGED_EXECUTION_ANOMALY"
    CONFIGURATION_TAMPERING = "CONFIGURATION_TAMPERING"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"


class PredictionStatus(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    ANOMALOUS = "ANOMALOUS"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN = "UNKNOWN"


@dataclass
class LabeledTelemetryRecord:
    """
    Standard record format for Linux privilege escalation ML datasets.
    Includes full provenance, OS metadata, host/incident boundaries to prevent data leakage.
    """
    record_id: str
    host_id: str
    scenario_id: str
    kernel_release: str
    distribution: str
    event: SecurityEvent
    feature_vector: FeatureVector
    ground_truth_label: str = DetectionLabel.BENIGN.value
    label_provenance: str = "verified_lab_scenario"  # e.g., 'benign_baseline', 'cve_reproduction', 'sudo_audit'
    collector_version: str = "3.1.0"
    created_at_iso: str = field(default_factory=lambda: format_iso(utc_now()) or "")

    def record_hash(self) -> str:
        """Calculate SHA-256 integrity hash of this training record"""
        payload = {
            "record_id": self.record_id,
            "host_id": self.host_id,
            "scenario_id": self.scenario_id,
            "event_id": self.event.event_id,
            "label": self.ground_truth_label,
            "features": self.feature_vector.values
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "host_id": self.host_id,
            "scenario_id": self.scenario_id,
            "kernel_release": self.kernel_release,
            "distribution": self.distribution,
            "event": self.event.to_dict(),
            "feature_vector": self.feature_vector.to_dict(),
            "ground_truth_label": self.ground_truth_label,
            "label_provenance": self.label_provenance,
            "collector_version": self.collector_version,
            "created_at_iso": self.created_at_iso,
            "record_hash": self.record_hash()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LabeledTelemetryRecord":
        d = dict(data)
        d.pop("record_hash", None)
        ev = SecurityEvent.from_dict(d.pop("event"))
        fv = FeatureVector.from_dict(d.pop("feature_vector"))
        return cls(event=ev, feature_vector=fv, **d)
