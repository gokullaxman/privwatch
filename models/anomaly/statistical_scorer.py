"""
PrivWatch 3.1 - Robust Statistical Anomaly Scorer
Computes non-parametric outlier scores using Median Absolute Deviation (MAD) and modified Z-scores.
Provides ultra-low-latency, dependency-light anomaly estimation on Linux telemetry.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np

from ml.features.feature_schema import FEATURE_NAMES, FeatureVector


class RobustStatisticalScorer:
    """
    Computes robust statistical anomaly scores on numerical feature vectors.
    Uses median and MAD instead of mean and standard deviation to resist outlier contamination.
    """

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.medians: Optional[np.ndarray] = None
        self.mads: Optional[np.ndarray] = None
        self.threshold: float = 3.5  # standard Boris Iglewicz / Hoaglin modified z-score threshold
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray):
        """Fit medians and MAD values on baseline training matrix X (n_samples, n_features)"""
        if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected feature matrix of shape (N, {len(FEATURE_NAMES)}), got {X.shape}")

        n_samples = X.shape[0]
        if n_samples < 5:
            raise ValueError(f"Insufficient samples to fit statistical scorer: {n_samples} (minimum 5)")

        self.medians = np.median(X, axis=0)
        diff = np.abs(X - self.medians)
        # Median Absolute Deviation with 0.6745 normal consistency factor
        raw_mad = np.median(diff, axis=0)
        # Prevent division by zero for invariant features
        self.mads = np.where(raw_mad > 1e-6, raw_mad, 1.0)
        self.is_fitted = True

    def score_vector(self, arr: np.ndarray) -> Tuple[float, Dict[str, float]]:
        """
        Compute anomaly score for single vector.
        Returns: (normalized_anomaly_score_0_to_1, top_contributing_feature_zscores)
        """
        if not self.is_fitted or self.medians is None or self.mads is None:
            # Fallback for un-fitted baseline: return default nominal score
            return 0.10, {}

        # Modified Z-score: 0.6745 * (x - median) / MAD
        mod_z = 0.6745 * np.abs(arr - self.medians) / self.mads
        max_z = np.max(mod_z)
        mean_top3_z = np.mean(np.sort(mod_z)[-3:])

        # Sigmoid transform to map to [0.0, 1.0] range
        # At threshold 3.5, score is ~0.60; at 5.0, score is ~0.80; at 8.0, score is ~0.95
        anomaly_score = float(1.0 / (1.0 + np.exp(-0.7 * (mean_top3_z - 3.0))))

        # Identify top 3 contributing features
        top_indices = np.argsort(mod_z)[-3:][::-1]
        top_features: Dict[str, float] = {}
        for idx in top_indices:
            if mod_z[idx] > 1.5:  # only include meaningfully elevated features
                top_features[FEATURE_NAMES[idx]] = round(float(mod_z[idx]), 2)

        return min(1.0, max(0.0, anomaly_score)), top_features

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomaly scores and binary outlier indicators for batch.
        Returns: (anomaly_scores [0..1], is_anomaly_bool [True/False])
        """
        if not self.is_fitted:
            raise RuntimeError("Scorer must be fitted before prediction")

        n = X.shape[0]
        scores = np.zeros(n, dtype=np.float64)
        is_anomaly = np.zeros(n, dtype=bool)

        for i in range(n):
            score, _ = self.score_vector(X[i])
            scores[i] = score
            is_anomaly[i] = (score >= 0.65)

        return scores, is_anomaly
