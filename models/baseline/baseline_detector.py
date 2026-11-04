"""
PrivWatch 3.1 - Deterministic Rule-Based Baseline Engine
Encapsulates the trusted static security rules as a formal baseline classifier for empirical comparison.
"""

from typing import List, Dict, Any, Tuple
import numpy as np

from ml.data.schema import DetectionLabel, PredictionStatus
from ml.features.feature_schema import FEATURE_NAMES, FeatureVector


class DeterministicBaselineModel:
    """
    Standardized baseline model executing trusted POSIX deterministic detection rules.
    Provides the benchmark against which all ML and statistical models must be validated.
    """

    def __init__(self):
        self.model_id = "baseline_deterministic_v3_1"
        self.algorithm = "Deterministic POSIX & Heuristic Logic"

    def predict_one(self, feature_vector: FeatureVector) -> Tuple[str, float, Dict[str, Any]]:
        """
        Evaluate deterministic rules on feature vector.
        Returns: (predicted_label, confidence, explanation_dict)
        """
        v = feature_vector.values

        # Rule 1: Active EUID 0 elevation with unprivileged real UID
        if v.get("uid_euid_mismatch", 0.0) == 1.0 and v.get("euid_is_root", 0.0) == 1.0:
            if v.get("exe_in_writable_dir", 0.0) == 1.0:
                return (
                    DetectionLabel.CONFIRMED_MALICIOUS.value,
                    0.99,
                    {
                        "rule": "EUID_ROOT_IN_WRITABLE_DIR",
                        "reason": "Process running with effective UID 0 executing from world-writable path"
                    }
                )
            return (
                DetectionLabel.PRIVILEGE_TRANSITION_ANOMALY.value,
                0.95,
                {
                    "rule": "ACTIVE_EUID_ELEVATION",
                    "reason": "Process possesses effective root privileges differing from real UID"
                }
            )

        # Rule 2: Service daemon spawning interactive shell
        if v.get("is_daemon_user", 0.0) == 1.0 and v.get("is_interactive_shell", 0.0) == 1.0:
            return (
                DetectionLabel.PRIVILEGED_EXECUTION_ANOMALY.value,
                0.95,
                {
                    "rule": "DAEMON_SPAWNED_SHELL",
                    "reason": "Service daemon user spawned interactive shell interpreter"
                }
            )

        # Rule 3: Execution from world-writable directory
        if v.get("exe_in_writable_dir", 0.0) == 1.0 and (v.get("is_interactive_shell", 0.0) == 1.0 or v.get("is_network_tool", 0.0) == 1.0):
            return (
                DetectionLabel.SUSPICIOUS.value,
                0.90,
                {
                    "rule": "WRITABLE_DIR_PAYLOAD",
                    "reason": "Interactive tool or network binary executing from /tmp, /dev/shm, or /var/tmp"
                }
            )

        # Rule 4: Sudo brute force indicator
        if v.get("auth_fails_last_300s", 0.0) >= 3.0:
            return (
                DetectionLabel.SUSPICIOUS.value,
                0.88,
                {
                    "rule": "SUDO_BRUTE_FORCE_WINDOW",
                    "reason": f"Observed {int(v.get('auth_fails_last_300s', 0))} authentication failures in recent window"
                }
            )

        # Rule 5: Sensitive file modification
        if v.get("modifies_sensitive_file", 0.0) == 1.0 and v.get("uid_is_root", 0.0) == 0.0:
            return (
                DetectionLabel.CONFIGURATION_TAMPERING.value,
                0.92,
                {
                    "rule": "UNPRIVILEGED_SENSITIVE_WRITE",
                    "reason": "Non-root user attempted write to sensitive configuration file"
                }
            )

        # Default: Benign baseline execution
        return (
            DetectionLabel.BENIGN.value,
            0.90,
            {
                "rule": "DEFAULT_BENIGN",
                "reason": "No deterministic privilege escalation rules triggered"
            }
        )

    def predict(self, feature_vectors: List[FeatureVector]) -> Tuple[np.ndarray, np.ndarray]:
        """Predict labels and confidence across batch of feature vectors"""
        labels = []
        confidences = []
        for fv in feature_vectors:
            lbl, conf, _ = self.predict_one(fv)
            labels.append(lbl)
            confidences.append(conf)
        return np.array(labels), np.array(confidences)
