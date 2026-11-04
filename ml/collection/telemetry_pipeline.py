"""
PrivWatch 3.1 - Linux Telemetry Collection & Laboratory Pipeline
Orchestrates genuine system event collection, normalization, feature extraction,
and provenance attribution for training and evaluation datasets.
"""

from datetime import datetime, timezone
import os
import platform
import uuid
from typing import List, Dict, Any, Optional

from core.models import SecurityEvent, utc_now, format_iso
from utils.system_info import get_system_info
from ml.features.feature_extractor import LinuxFeatureExtractor
from ml.features.feature_schema import FeatureVector
from ml.data.schema import LabeledTelemetryRecord, DetectionLabel


class LaboratoryTelemetryCollector:
    """
    Captures live system events produced during controlled benign workflows
    or authorized security assessment scenarios, packaging them into
    verified LabeledTelemetryRecord instances.
    """

    def __init__(self, scenario_id: Optional[str] = None, label_provenance: str = "benign_host_telemetry"):
        self.scenario_id = scenario_id or f"scen_{uuid.uuid4().hex[:12]}"
        self.label_provenance = label_provenance
        self.host_id = platform.node() or "linux_host"

        sys_info = get_system_info()
        self.kernel_release = sys_info.get("kernel", platform.release())
        self.distribution = sys_info.get("distribution", "Linux")

        self.extractor = LinuxFeatureExtractor()

    def process_raw_events(
        self,
        events: List[SecurityEvent],
        ground_truth_label: str = DetectionLabel.BENIGN.value
    ) -> List[LabeledTelemetryRecord]:
        """
        Convert observed SecurityEvent records into labeled training records with
        complete system provenance and extracted feature vectors.
        """
        records: List[LabeledTelemetryRecord] = []
        vectors = self.extractor.extract_matrix(events)

        for ev, fv in zip(events, vectors):
            rec = LabeledTelemetryRecord(
                record_id=f"rec_{uuid.uuid4().hex[:16]}",
                host_id=self.host_id,
                scenario_id=self.scenario_id,
                kernel_release=self.kernel_release,
                distribution=self.distribution,
                event=ev,
                feature_vector=fv,
                ground_truth_label=ground_truth_label,
                label_provenance=self.label_provenance,
                collector_version="3.1.0",
                created_at_iso=format_iso(utc_now()) or ""
            )
            records.append(rec)

        return records
