"""
Tests for PrivWatch 3.1 Model Drift & Telemetry Health Monitoring
"""

import numpy as np
import pytest

from ml.features.feature_schema import FEATURE_NAMES, FeatureVector
from ml.monitoring.drift_detector import ModelDriftMonitor


def test_drift_monitor_stable_distribution():
    rng = np.random.RandomState(42)
    # 100 baseline samples with mean 0, std 1
    baseline = rng.normal(loc=0.0, scale=1.0, size=(100, len(FEATURE_NAMES)))
    monitor = ModelDriftMonitor(baseline_matrix=baseline, window_size=100)

    # Ingest 60 similar events drawn from identical distribution
    for _ in range(60):
        vals = {name: float(rng.normal(0.0, 1.0)) for name in FEATURE_NAMES}
        fv = FeatureVector(event_id="test", timestamp_iso="2026-11-04T00:00:00Z", values=vals)
        monitor.record_inference(fv, "BENIGN", latency_ms=1.5)

    status = monitor.get_monitoring_status()
    assert status["monitored_events_count"] == 60
    assert status["drift_status"] == "STABLE"
    assert status["latency_compliant"] is True


def test_drift_monitor_detects_significant_distribution_shift():
    # Baseline with mean 0, std 1
    baseline = np.zeros((50, len(FEATURE_NAMES)), dtype=np.float64)
    monitor = ModelDriftMonitor(baseline_matrix=baseline, window_size=100)

    # Ingest 40 drastically shifted events (feature values shifted by 10 standard deviations)
    for _ in range(40):
        vals = {name: 50.0 for name in FEATURE_NAMES}
        fv = FeatureVector(event_id="test", timestamp_iso="2026-11-04T00:00:00Z", values=vals)
        monitor.record_inference(fv, "SUSPICIOUS", latency_ms=2.0)

    status = monitor.get_monitoring_status()
    assert status["drift_status"] in ["SIGNIFICANT_DRIFT", "MODERATE_DRIFT"]
    assert status["max_feature_psi"] > 0.10
