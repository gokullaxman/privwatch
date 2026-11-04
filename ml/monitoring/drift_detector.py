"""
PrivWatch 3.1 - Model Drift & Data Quality Monitor
Tracks feature distribution shifts, Population Stability Index (PSI), missing feature rates, and inference latency.
"""

from collections import deque
import threading
import time
from typing import List, Dict, Any, Optional
import numpy as np

from ml.features.feature_schema import FEATURE_NAMES, FeatureVector


class ModelDriftMonitor:
    """
    Monitors live inference telemetry for distribution drift, feature anomalies,
    and computational latency degradation.
    Bounded memory footprint (sliding FIFO window).
    """

    def __init__(self, baseline_matrix: Optional[np.ndarray] = None, window_size: int = 500):
        self.window_size = window_size
        self._lock = threading.Lock()
        self.inference_history: deque = deque(maxlen=window_size)
        self.latency_history: deque = deque(maxlen=window_size)
        self.predictions_history: deque = deque(maxlen=window_size)

        # Baseline feature statistics (mean and std)
        self.baseline_means: Optional[np.ndarray] = None
        self.baseline_stds: Optional[np.ndarray] = None
        if baseline_matrix is not None and baseline_matrix.shape[0] >= 5:
            self.baseline_means = np.mean(baseline_matrix, axis=0)
            stds = np.std(baseline_matrix, axis=0)
            self.baseline_stds = np.where(stds > 1e-6, stds, 1.0)

    def record_inference(
        self,
        feature_vector: FeatureVector,
        predicted_class: str,
        latency_ms: float
    ):
        """Record an inference event into sliding telemetry monitor"""
        with self._lock:
            self.inference_history.append(feature_vector.to_array())
            self.latency_history.append(latency_ms)
            self.predictions_history.append(predicted_class)

    def compute_psi(self, feature_idx: int) -> float:
        """
        Compute Population Stability Index (PSI) between baseline and recent sliding window.
        PSI < 0.1: No significant drift.
        0.1 <= PSI < 0.25: Moderate shift.
        PSI >= 0.25: Significant drift.
        """
        with self._lock:
            if self.baseline_means is None or len(self.inference_history) < 30:
                return 0.0

            recent = np.array(self.inference_history)[:, feature_idx]

        b_mean = self.baseline_means[feature_idx]
        b_std = self.baseline_stds[feature_idx]

        # 4-bin quantile approximation
        bins = [
            -np.inf,
            b_mean - b_std,
            b_mean,
            b_mean + b_std,
            np.inf
        ]

        # Target actual counts with Laplace smoothing for statistical stability
        actual_counts, _ = np.histogram(recent, bins=bins)
        actual_pcts = (actual_counts + 1.0) / (len(recent) + 4.0)

        # Expected baseline normal probabilities across bins: [0.158, 0.341, 0.341, 0.158]
        expected_pcts = np.array([0.16, 0.34, 0.34, 0.16])

        # PSI = sum((actual - expected) * ln(actual / expected))
        psi = np.sum((actual_pcts - expected_pcts) * np.log(actual_pcts / expected_pcts))
        return round(float(max(0.0, psi)), 4)

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Aggregate health metrics across feature stability, latency, and predictions"""
        with self._lock:
            n_events = len(self.inference_history)
            latencies = list(self.latency_history)
            preds = list(self.predictions_history)

        avg_latency = float(np.mean(latencies)) if latencies else 0.0
        p95_latency = float(np.percentile(latencies, 95)) if latencies else 0.0

        # Compute max PSI across core features (uid, euid, command_length, events_last_60s)
        max_psi = 0.0
        drifted_features = []
        if n_events >= 30 and self.baseline_means is not None:
            for idx in [0, 1, 21, 28]:
                psi_val = self.compute_psi(idx)
                if psi_val >= 0.25:
                    drifted_features.append(FEATURE_NAMES[idx])
                max_psi = max(max_psi, psi_val)

        # Prediction distribution
        pred_dist: Dict[str, int] = {}
        for p in preds:
            pred_dist[p] = pred_dist.get(p, 0) + 1

        drift_status = "STABLE"
        if max_psi >= 0.25:
            drift_status = "SIGNIFICANT_DRIFT"
        elif max_psi >= 0.20:
            drift_status = "MODERATE_DRIFT"

        return {
            "monitored_events_count": n_events,
            "drift_status": drift_status,
            "max_feature_psi": round(max_psi, 4),
            "drifted_features": drifted_features,
            "average_latency_ms": round(avg_latency, 3),
            "p95_latency_ms": round(p95_latency, 3),
            "latency_compliant": (avg_latency <= 5.0),
            "prediction_distribution": pred_dist
        }
