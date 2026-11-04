"""
PrivWatch 3.1 - Production ML Model Runner
High-throughput, non-blocking inference engine combining anomaly detection, threat classification,
sequence evaluation, and automated explainability.
"""

import time
from typing import List, Dict, Any, Optional

from core.models import SecurityEvent
from ml.features.feature_schema import FEATURE_NAMES, FeatureVector
from ml.features.feature_extractor import LinuxFeatureExtractor
from models.baseline.baseline_detector import DeterministicBaselineModel
from models.anomaly.isolation_forest import LinuxIsolationForestDetector
from models.anomaly.statistical_scorer import RobustStatisticalScorer
from models.classification.privilege_classifier import LinuxPrivilegeClassifier
from models.sequence.markov_sequence import MarkovPrivilegeSequenceModel
from models.registry.model_registry import ModelRegistry
from ml.explainability.attribution import FeatureAttributor
from ml.explainability.explanation import (
    PredictionExplanation,
    CompositeRiskCalculator,
    ExplanationEngine
)
from ml.monitoring.drift_detector import ModelDriftMonitor


class ModelRunner:
    """
    Production inference engine. Executes ML evaluation on Linux telemetry events
    with guaranteed non-blocking fallback to deterministic baseline.
    """

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or ModelRegistry()
        self.extractor = LinuxFeatureExtractor()
        self.baseline = DeterministicBaselineModel()
        self.drift_monitor = ModelDriftMonitor()

        # Active loaded models (lazy or loaded from registry)
        self.anomaly_detector: Optional[Any] = None
        self.classifier: Optional[Any] = None
        self.markov_model: Optional[MarkovPrivilegeSequenceModel] = None

        self._load_production_models()

    def _load_production_models(self):
        """Attempt to load verified models from registry; fall back gracefully if not yet trained"""
        try:
            self.classifier, _ = self.registry.load_model("random_forest_privesc_v3_1", verify_hash=True)
        except Exception:
            self.classifier = None

        try:
            self.anomaly_detector, _ = self.registry.load_model("isolation_forest_v3_1", verify_hash=True)
        except Exception:
            self.anomaly_detector = None

        try:
            self.markov_model, _ = self.registry.load_model("markov_sequence_v3_1", verify_hash=True)
        except Exception:
            # Initialize with default Markov priors
            self.markov_model = MarkovPrivilegeSequenceModel()

    def evaluate_event(
        self,
        event: SecurityEvent,
        history: Optional[List[SecurityEvent]] = None
    ) -> PredictionExplanation:
        """
        Perform complete inference lifecycle on a SecurityEvent.
        Never throws exceptions; guaranteed deterministic fallback.
        """
        start_t = time.perf_counter()

        try:
            # 1. Feature Extraction
            fv = self.extractor.extract_features(event, history)
            arr = fv.to_array()

            # 2. Anomaly Detection
            if self.anomaly_detector is not None and getattr(self.anomaly_detector, 'is_fitted', False):
                anom_score, _, outlier_top = self.anomaly_detector.score_vector(arr)
            else:
                anom_score = 0.15
                outlier_top = {}

            # 3. Threat Classification
            if self.classifier is not None and getattr(self.classifier, 'is_fitted', False):
                pred_class, conf, _, status = self.classifier.predict_vector(arr, fv)
                global_imp = getattr(self.classifier, 'feature_importances_', {})
            else:
                pred_class, conf, _ = self.baseline.predict_one(fv)
                status = "BENIGN" if pred_class == "BENIGN" else "SUSPICIOUS"
                global_imp = {}

            # 4. Sequential Markov Anomaly Check (if history exists)
            seq_anom = 0.0
            if history and self.markov_model is not None:
                seq_states = [
                    MarkovPrivilegeSequenceModel.map_event_to_state(h)
                    for h in (history[-4:] + [event])
                ]
                seq_anom, _ = self.markov_model.score_sequence(seq_states)
                # Combine point anomaly and sequence anomaly
                anom_score = max(anom_score, seq_anom)

            # 5. Feature Attribution & Explainability
            contributions = FeatureAttributor.attribute_prediction(
                feature_vector=fv,
                global_importances=global_imp,
                outlier_zscores=outlier_top,
                top_k=4
            )
            narrative = ExplanationEngine.build_narrative(pred_class, fv, contributions)

            # 6. Composite Risk Calculation
            risk = CompositeRiskCalculator.calculate(
                predicted_class=pred_class,
                anomaly_score=anom_score,
                confidence=conf,
                source_reliability=1.0 if "audit" in (event.source or "") else 0.85
            )

            latency_ms = (time.perf_counter() - start_t) * 1000.0

            # 7. Record to Drift Monitor
            self.drift_monitor.record_inference(fv, pred_class, latency_ms)

            return PredictionExplanation(
                event_id=event.event_id,
                predicted_class=pred_class,
                prediction_status=status,
                anomaly_score=round(float(anom_score), 4),
                confidence=round(float(conf), 4),
                composite_risk_score=risk,
                contributing_features=contributions,
                detection_explanation=narrative,
                evidence_references={
                    "event_id": event.event_id,
                    "evidence_hash": event.evidence_hash(),
                    "source": event.source
                },
                model_id=getattr(self.classifier, "model_id", "baseline_deterministic_v3_1"),
                model_version="3.1.0",
                dataset_version="linux_telemetry_v1"
            )

        except Exception as e:
            # Deterministic safe fallback
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            pred_class = "SUSPICIOUS" if event.euid == 0 and event.uid != 0 else "BENIGN"
            return PredictionExplanation(
                event_id=event.event_id,
                predicted_class=pred_class,
                prediction_status="INSUFFICIENT_EVIDENCE",
                anomaly_score=0.20,
                confidence=0.50,
                composite_risk_score=25,
                contributing_features=[],
                detection_explanation=f"Fallback baseline invoked due to inference exception: {e}",
                evidence_references={"event_id": event.event_id},
                model_id="baseline_fallback"
            )
