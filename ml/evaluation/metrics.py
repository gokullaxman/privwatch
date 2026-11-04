"""
PrivWatch 3.1 - Scientific Model Evaluation Metrics
Computes precision, recall, F1, confusion matrices, false positive/negative rates, and latency profiles.
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional
import numpy as np


class ModelEvaluator:
    """Computes comprehensive classification and detection metrics across test partitions"""

    @staticmethod
    def classification_metrics(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        classes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Compute precision, recall, F1-score (per-class and macro-averaged),
        and confusion matrix.
        """
        all_classes = classes or sorted(list(set(list(y_true) + list(y_pred))))
        n_classes = len(all_classes)
        class_to_idx = {c: i for i, c in enumerate(all_classes)}

        # Confusion matrix: conf[true_idx, pred_idx]
        conf_matrix = np.zeros((n_classes, n_classes), dtype=int)
        for t, p in zip(y_true, y_pred):
            t_idx = class_to_idx.get(t)
            p_idx = class_to_idx.get(p)
            if t_idx is not None and p_idx is not None:
                conf_matrix[t_idx, p_idx] += 1

        per_class: Dict[str, Dict[str, float]] = {}
        macro_p = 0.0
        macro_r = 0.0
        macro_f1 = 0.0

        for c, i in class_to_idx.items():
            tp = conf_matrix[i, i]
            fp = conf_matrix[:, i].sum() - tp
            fn = conf_matrix[i, :].sum() - tp
            tn = conf_matrix.sum() - (tp + fp + fn)

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

            per_class[c] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "false_negative_rate": round(fnr, 4),
                "support": int(conf_matrix[i, :].sum())
            }

            macro_p += prec
            macro_r += rec
            macro_f1 += f1

        n = max(1, n_classes)
        return {
            "macro_precision": round(macro_p / n, 4),
            "macro_recall": round(macro_r / n, 4),
            "macro_f1": round(macro_f1 / n, 4),
            "accuracy": round(float(np.trace(conf_matrix) / max(1, conf_matrix.sum())), 4),
            "per_class": per_class,
            "classes": all_classes,
            "confusion_matrix": conf_matrix.tolist()
        }

    @staticmethod
    def latency_profile(latencies_ms: List[float]) -> Dict[str, float]:
        """Compute percentile and average latency profile from list of measurements"""
        if not latencies_ms:
            return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
        arr = np.array(latencies_ms)
        return {
            "mean_ms": round(float(np.mean(arr)), 3),
            "p50_ms": round(float(np.percentile(arr, 50)), 3),
            "p95_ms": round(float(np.percentile(arr, 95)), 3),
            "p99_ms": round(float(np.percentile(arr, 99)), 3),
            "max_ms": round(float(np.max(arr)), 3)
        }
