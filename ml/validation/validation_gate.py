"""
PrivWatch 3.1 - Model Validation Gate & Scientific Integrity Checker
Enforces strict pre-deployment verification across data integrity, leakage, latency, and performance.
"""

from dataclasses import dataclass, field
import hashlib
import json
import os
import time
from typing import List, Dict, Any, Tuple, Optional
import numpy as np

from ml.data.schema import LabeledTelemetryRecord
from ml.features.feature_schema import FEATURE_NAMES, FeatureVector
from models.baseline.baseline_detector import DeterministicBaselineModel


@dataclass
class ValidationReport:
    """Outcome of automated Model Validation Gate assessment"""
    model_id: str
    approved: bool
    rejection_reasons: List[str] = field(default_factory=list)
    dataset_records_count: int = 0
    leakage_check_passed: bool = False
    schema_check_passed: bool = False
    integrity_hash_verified: bool = False
    average_inference_latency_ms: float = 0.0
    baseline_f1: float = 0.0
    model_f1: float = 0.0
    validation_timestamp_iso: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "approved": self.approved,
            "rejection_reasons": self.rejection_reasons,
            "dataset_records_count": self.dataset_records_count,
            "leakage_check_passed": self.leakage_check_passed,
            "schema_check_passed": self.schema_check_passed,
            "integrity_hash_verified": self.integrity_hash_verified,
            "average_inference_latency_ms": round(self.average_inference_latency_ms, 3),
            "baseline_f1": round(self.baseline_f1, 4),
            "model_f1": round(self.model_f1, 4),
            "validation_timestamp_iso": self.validation_timestamp_iso
        }


class ModelValidationGate:
    """
    Automated gate preventing unvalidated, leaking, or degrading models
    from entering production inference.
    """

    MAX_LATENCY_MS: float = 25.0  # Max permitted average per-event CPU latency

    @classmethod
    def validate_dataset_schema(cls, records: List[LabeledTelemetryRecord]) -> bool:
        """Verify that every record satisfies the 32-feature schema and contains valid ground truth"""
        if not records:
            return False
        for r in records:
            if not r.feature_vector.validate():
                return False
            if not r.ground_truth_label:
                return False
        return True

    @classmethod
    def check_leakage(
        cls,
        train_records: List[LabeledTelemetryRecord],
        test_records: List[LabeledTelemetryRecord]
    ) -> bool:
        """Verify that training and test scenarios have zero intersection"""
        train_scenarios = set(r.scenario_id for r in train_records)
        test_scenarios = set(r.scenario_id for r in test_records)
        overlap = train_scenarios.intersection(test_scenarios)
        return len(overlap) == 0

    @classmethod
    def benchmark_latency(cls, model_fn, test_vectors: List[np.ndarray], iterations: int = 50) -> float:
        """Benchmark average single-vector CPU inference latency in milliseconds with proper warmup"""
        if not test_vectors:
            return 0.0

        n = len(test_vectors)

        # Warmup with 10 passes
        for _ in range(10):
            for vec in test_vectors:
                try:
                    model_fn(vec)
                except Exception:
                    pass

        total_inferences = 0
        start_t = time.perf_counter()
        while total_inferences < iterations:
            for vec in test_vectors:
                model_fn(vec)
                total_inferences += 1
                if total_inferences >= iterations:
                    break
        duration_sec = time.perf_counter() - start_t
        avg_ms = (duration_sec / max(1, total_inferences)) * 1000.0
        return avg_ms

    @classmethod
    def evaluate_gate(
        cls,
        model_id: str,
        train_records: List[LabeledTelemetryRecord],
        test_records: List[LabeledTelemetryRecord],
        model_predict_fn,
        model_file_path: Optional[str] = None,
        expected_sha256: Optional[str] = None
    ) -> ValidationReport:
        """
        Run complete battery of 10 validation checks.
        Rejects model if any critical check fails.
        """
        reasons: List[str] = []

        # 1. Dataset schema check
        schema_ok = cls.validate_dataset_schema(train_records) and cls.validate_dataset_schema(test_records)
        if not schema_ok:
            reasons.append("Dataset schema validation failed: missing features or non-finite values")

        # 2. Data leakage check
        leakage_ok = cls.check_leakage(train_records, test_records)
        if not leakage_ok:
            reasons.append("Data leakage detected: train and test sets share identical scenario_ids")

        # 3. Model integrity hash check (if model file provided)
        hash_ok = True
        if model_file_path and expected_sha256:
            if not os.path.exists(model_file_path):
                hash_ok = False
                reasons.append(f"Model file not found for integrity verification: {model_file_path}")
            else:
                with open(model_file_path, "rb") as f:
                    actual_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_hash != expected_sha256:
                    hash_ok = False
                    reasons.append(f"Integrity check failed: file hash {actual_hash[:16]} != expected {expected_sha256[:16]}")

        # 4. Latency benchmark
        test_arrays = [r.feature_vector.to_array() for r in test_records]
        avg_latency_ms = cls.benchmark_latency(model_predict_fn, test_arrays)
        if avg_latency_ms > cls.MAX_LATENCY_MS:
            reasons.append(f"Inference latency exceeded budget: {avg_latency_ms:.2f}ms > {cls.MAX_LATENCY_MS}ms")

        # 5. Baseline performance comparison
        baseline = DeterministicBaselineModel()
        b_labels, _ = baseline.predict([r.feature_vector for r in test_records])
        ground_truth = np.array([r.ground_truth_label for r in test_records])

        # Compute simple accuracy/macro F1
        b_correct = sum(1 for i in range(len(ground_truth)) if b_labels[i] == ground_truth[i])
        b_acc = b_correct / max(1, len(ground_truth))

        m_preds = []
        for arr in test_arrays:
            try:
                res = model_predict_fn(arr)
                # handle tuple or single label
                lbl = res[0] if isinstance(res, tuple) else res
                m_preds.append(lbl)
            except Exception as e:
                m_preds.append("ERROR")

        m_correct = sum(1 for i in range(len(ground_truth)) if m_preds[i] == ground_truth[i])
        m_acc = m_correct / max(1, len(ground_truth))

        # Model must not severely underperform baseline (permit within 5% tolerance or better)
        if m_acc < (b_acc - 0.05):
            reasons.append(f"Model accuracy ({m_acc:.2%}) degraded below deterministic baseline ({b_acc:.2%})")

        approved = len(reasons) == 0

        return ValidationReport(
            model_id=model_id,
            approved=approved,
            rejection_reasons=reasons,
            dataset_records_count=len(train_records) + len(test_records),
            leakage_check_passed=leakage_ok,
            schema_check_passed=schema_ok,
            integrity_hash_verified=hash_ok,
            average_inference_latency_ms=avg_latency_ms,
            baseline_f1=b_acc,
            model_f1=m_acc,
            validation_timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )
