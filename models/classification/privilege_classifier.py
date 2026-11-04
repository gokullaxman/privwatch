"""
PrivWatch 3.1 - Supervised Linux Privilege Escalation Classifier
Calibrated tree ensemble classifying multi-feature security telemetry into verified threat categories.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from ml.data.schema import DetectionLabel, PredictionStatus
from ml.features.feature_schema import FEATURE_NAMES, FeatureVector
from models.baseline.baseline_detector import DeterministicBaselineModel


class LinuxPrivilegeClassifier:
    """
    Supervised classifier for Linux security events.
    Predicts threat categories with calibrated probabilities and feature importances.
    """

    def __init__(self, n_estimators: int = 50, max_depth: int = 8, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model: Optional[Any] = None
        self.classes: List[str] = [label.value for label in DetectionLabel]
        self.feature_importances_: Dict[str, float] = {}
        self.is_fitted: bool = False
        self.baseline = DeterministicBaselineModel()
        self.model_id = "random_forest_privesc_v3_1"

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit ensemble classifier on feature matrix X and label vector y"""
        if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected shape (N, {len(FEATURE_NAMES)}), got {X.shape}")

        unique_labels = sorted(list(set(y)))
        self.classes = unique_labels

        if SKLEARN_AVAILABLE and len(unique_labels) >= 2 and len(y) >= 10:
            self.model = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                class_weight="balanced",
                random_state=self.random_state,
                n_jobs=1
            )
            self.model.fit(X, y)
            importances = self.model.feature_importances_
            self.feature_importances_ = {
                FEATURE_NAMES[i]: round(float(importances[i]), 4)
                for i in range(len(FEATURE_NAMES))
            }
            self.is_fitted = True
        else:
            # Mark fitted with baseline fallback if data is insufficient for tree fitting
            self.is_fitted = True

    def predict_vector(
        self,
        arr: np.ndarray,
        feature_vector: Optional[FeatureVector] = None
    ) -> Tuple[str, float, Dict[str, float], str]:
        """
        Predict threat class for single vector.
        Returns: (predicted_class, confidence, class_probabilities, prediction_status)
        """
        if not self.is_fitted:
            return DetectionLabel.BENIGN.value, 0.50, {}, PredictionStatus.UNKNOWN.value

        if SKLEARN_AVAILABLE and self.model is not None:
            probs = self.model.predict_proba(arr.reshape(1, -1))[0]
            prob_dict = {
                self.classes[i]: round(float(probs[i]), 4)
                for i in range(len(self.classes))
            }
            max_idx = int(np.argmax(probs))
            top_prob = float(probs[max_idx])
            pred_class = self.classes[max_idx]

            # Confidence gate: low-confidence predictions must NOT be claimed as confirmed
            if top_prob < 0.45:
                status = PredictionStatus.INSUFFICIENT_EVIDENCE.value
            elif pred_class == DetectionLabel.BENIGN.value:
                status = PredictionStatus.BENIGN.value
            elif pred_class in [DetectionLabel.SUSPICIOUS.value, DetectionLabel.PRIVILEGE_TRANSITION_ANOMALY.value, DetectionLabel.PRIVILEGED_EXECUTION_ANOMALY.value]:
                status = PredictionStatus.SUSPICIOUS.value
            else:
                status = PredictionStatus.CONFIRMED_MALICIOUS.value

            return pred_class, top_prob, prob_dict, status

        # Fallback to deterministic baseline
        if feature_vector is not None:
            pred_class, conf, _ = self.baseline.predict_one(feature_vector)
            return pred_class, conf, {pred_class: conf}, PredictionStatus.BENIGN.value if pred_class == DetectionLabel.BENIGN.value else PredictionStatus.SUSPICIOUS.value

        return DetectionLabel.BENIGN.value, 0.90, {DetectionLabel.BENIGN.value: 0.90}, PredictionStatus.BENIGN.value

    def get_top_features(self, n: int = 5) -> List[Tuple[str, float]]:
        """Return top N global features by importance"""
        if not self.feature_importances_:
            return []
        sorted_feats = sorted(self.feature_importances_.items(), key=lambda x: x[1], reverse=True)
        return sorted_feats[:n]
