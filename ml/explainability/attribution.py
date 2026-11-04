"""
PrivWatch 3.1 - Feature Attribution & Explainability Engine
Calculates relative feature contributions and provides transparent mathematical reasoning for model predictions.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np

from ml.features.feature_schema import FEATURE_NAMES, FEATURE_DESCRIPTIONS, FeatureVector


class FeatureAttributor:
    """
    Computes local feature attribution for individual telemetry inferences.
    Combines tree feature importances and robust distance metrics into normalized contribution weights.
    """

    @staticmethod
    def attribute_prediction(
        feature_vector: FeatureVector,
        global_importances: Optional[Dict[str, float]] = None,
        outlier_zscores: Optional[Dict[str, float]] = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Derive top K feature contributions for a given prediction.
        Returns: List of dicts with feature name, description, value, and contribution percentage.
        """
        v = feature_vector.values
        importances = global_importances or {}
        zscores = outlier_zscores or {}

        # Combine local deviation (z-score) with global feature importance
        raw_weights: Dict[str, float] = {}

        for name in FEATURE_NAMES:
            val = float(v.get(name, 0.0))
            g_imp = importances.get(name, 1.0 / len(FEATURE_NAMES))
            z = zscores.get(name, 0.0)

            # Heuristic sensitivity for binary risk flags
            flag_boost = 2.0 if (name in [
                "uid_euid_mismatch", "euid_is_root", "exe_in_writable_dir",
                "is_daemon_user", "modifies_sensitive_file", "has_file_capabilities"
            ] and val == 1.0) else 1.0

            # Combined weight
            weight = (g_imp + 0.3 * abs(z)) * flag_boost * (1.0 if val != 0.0 else 0.1)
            raw_weights[name] = weight

        # Sort and select top K
        sorted_feats = sorted(raw_weights.items(), key=lambda x: x[1], reverse=True)[:top_k]
        total_weight = sum(w for _, w in sorted_feats) or 1.0

        contributions: List[Dict[str, Any]] = []
        for name, weight in sorted_feats:
            pct = round((weight / total_weight) * 100.0, 1)
            val = v.get(name, 0.0)
            contributions.append({
                "feature": name,
                "description": FEATURE_DESCRIPTIONS.get(name, ""),
                "value": round(val, 3) if isinstance(val, float) else val,
                "contribution_pct": pct,
                "z_score": zscores.get(name, 0.0)
            })

        return contributions
