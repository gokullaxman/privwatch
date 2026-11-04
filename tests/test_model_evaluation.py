"""
Tests for PrivWatch 3.1 Model Evaluation Metrics
"""

import numpy as np
import pytest

from ml.evaluation.metrics import ModelEvaluator


def test_classification_metrics_computation():
    y_true = np.array(["BENIGN", "BENIGN", "SUSPICIOUS", "CONFIRMED_MALICIOUS"])
    y_pred = np.array(["BENIGN", "SUSPICIOUS", "SUSPICIOUS", "CONFIRMED_MALICIOUS"])

    metrics = ModelEvaluator.classification_metrics(y_true, y_pred)

    assert "macro_precision" in metrics
    assert "macro_recall" in metrics
    assert "macro_f1" in metrics
    assert "accuracy" in metrics
    assert metrics["accuracy"] == 0.75  # 3 out of 4 correct

    per_class = metrics["per_class"]
    assert "BENIGN" in per_class
    assert "CONFIRMED_MALICIOUS" in per_class
    assert per_class["CONFIRMED_MALICIOUS"]["precision"] == 1.0
    assert per_class["CONFIRMED_MALICIOUS"]["recall"] == 1.0


def test_latency_profile_percentiles():
    latencies = [1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 10.0, 20.0]
    profile = ModelEvaluator.latency_profile(latencies)

    assert "mean_ms" in profile
    assert "p50_ms" in profile
    assert "p95_ms" in profile
    assert "p99_ms" in profile
    assert profile["p50_ms"] > 0.0
    assert profile["p95_ms"] >= profile["p50_ms"]
    assert profile["max_ms"] == 20.0
