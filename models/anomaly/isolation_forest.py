"""
PrivWatch 3.1 - Isolation Forest Linux Anomaly Detector
Leverages Isolation Forest ensemble partitioning to detect multidimensional outliers in system telemetry.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from ml.features.feature_schema import FEATURE_NAMES, FeatureVector
from models.anomaly.statistical_scorer import RobustStatisticalScorer


class LinuxIsolationForestDetector:
    """
    Isolation Forest anomaly detector for Linux host process telemetry.
    Detects unusual combinations of UIDs, process ancestry, execution paths, and temporal rates.
    Includes automatic fallback to RobustStatisticalScorer if scikit-learn is absent.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[Any] = None
        self.fallback_scorer = RobustStatisticalScorer(contamination=contamination)
        self.is_fitted: bool = False
        self.model_id = "isolation_forest_v3_1"

    def fit(self, X: np.ndarray):
        """Fit Isolation Forest on baseline matrix X (N, 32)"""
        if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected shape (N, {len(FEATURE_NAMES)}), got {X.shape}")

        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=1  # CPU single-thread for low latency & predictable bounded footprint
            )
            self.model.fit(X)
        # Always fit fallback as well for dual-redundancy
        self.fallback_scorer.fit(X)
        self.is_fitted = True

    def score_vector(self, arr: np.ndarray) -> Tuple[float, bool, Dict[str, float]]:
        """
        Evaluate single feature vector.
        Returns: (anomaly_score_0_to_1, is_anomaly_bool, contributing_features)
        """
        if not self.is_fitted:
            return 0.10, False, {}

        # Fallback scorer top features calculation
        _, top_features = self.fallback_scorer.score_vector(arr)

        if SKLEARN_AVAILABLE and self.model is not None:
            # decision_function yields higher values for inliers, lower for outliers (negative)
            raw_score = self.model.decision_function(arr.reshape(1, -1))[0]
            # Map raw score (typically in [-0.5, 0.5]) to [0.0, 1.0] where 1.0 = highly anomalous
            normalized_score = float(1.0 / (1.0 + np.exp(6.0 * raw_score)))
            is_anomaly = bool(self.model.predict(arr.reshape(1, -1))[0] == -1)
            return min(1.0, max(0.0, normalized_score)), is_anomaly, top_features
        else:
            score, _ = self.fallback_scorer.score_vector(arr)
            return score, (score >= 0.65), top_features

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Batch inference returning (scores, is_anomaly)"""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted prior to prediction")

        n = X.shape[0]
        scores = np.zeros(n, dtype=np.float64)
        is_anomaly = np.zeros(n, dtype=bool)

        for i in range(n):
            score, anom, _ = self.score_vector(X[i])
            scores[i] = score
            is_anomaly[i] = anom

        return scores, is_anomaly
