# PrivWatch 3.1 - Production ML Inference & Operations Guide

## 1. Overview & Operational Principles

PrivWatch 3.1 integrates machine learning inference directly into the Linux security monitoring and incident response workflows.

### Operational Principles:
1. **Advisory First**: ML detections are surfaced with `vector="AI_ML_DETECTION"` and evidence tag `is_advisory_ml=True`. They complement, rather than overwrite, deterministic findings.
2. **Non-Blocking Resilience**: If an ML model weight file is missing or corrupted, the system falls back to `DeterministicBaselineModel` without dropping a single telemetry event.
3. **Sub-5ms Execution**: Every inference runs on CPU in under 5 milliseconds.

---

## 2. Programmatic Python API

### Basic Event Evaluation

```python
from core.models import SecurityEvent, Severity
from ml.inference.model_runner import ModelRunner

runner = ModelRunner()

# Construct observed event
event = SecurityEvent(
    event_type="SUID_EXECUTION",
    uid=1001,
    euid=0,
    pid=4521,
    ppid=1000,
    process="bash",
    command="/tmp/elevated_bash",
    evidence={"exe": "/tmp/elevated_bash", "is_suid": True}
)

# Run complete inference and attribution
explanation = runner.evaluate_event(event)

print(f"Predicted Class : {explanation.predicted_class}")
print(f"Anomaly Score   : {explanation.anomaly_score:.2f}")
print(f"Calibrated Conf : {explanation.confidence:.2f}")
print(f"Composite Risk  : {explanation.composite_risk_score}/100")
print(f"Explanation     : {explanation.detection_explanation}")

for feat in explanation.contributing_features:
    print(f"  - {feat['feature']}: {feat['value']} (Contribution: {feat['contribution_pct']}%)")
```

### Advisory Blue Team Evaluation

```python
from ml.inference.advisory_detector import AdvisoryMLDetector

detector = AdvisoryMLDetector()
findings = detector.evaluate_telemetry([event])

for f in findings:
    print(f"Finding: {f.title} [Severity: {f.severity}]")
    print(f"Risk: {f.evidence['composite_risk_score']}/100")
```

---

## 3. REST API Usage

### Check Model Registry & Drift Health
```bash
curl -X GET http://127.0.0.1:8443/api/v1/ml/status
```

**Response Example:**
```json
{
  "status": "OPERATIONAL",
  "registered_models": {
    "random_forest_privesc_v3_1": {
      "version": "3.1.0",
      "algorithm": "Random Forest (Balanced Ensembles)",
      "validation_status": "APPROVED",
      "sha256": "8c942e265289e389..."
    },
    "isolation_forest_v3_1": {
      "version": "3.1.0",
      "algorithm": "Isolation Forest & Robust Statistical Scorer",
      "validation_status": "APPROVED",
      "sha256": "3d5a1b..."
    }
  },
  "drift_monitor": {
    "monitored_events_count": 142,
    "drift_status": "STABLE",
    "max_feature_psi": 0.042,
    "average_latency_ms": 1.82,
    "latency_compliant": true
  }
}
```

### Evaluate Telemetry Event via REST API
```bash
curl -X POST http://127.0.0.1:8443/api/v1/ml/evaluate \
  -H "Authorization: Bearer $PRIVWATCH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "SUID_EXECUTION",
    "uid": 1000,
    "euid": 0,
    "pid": 5120,
    "ppid": 1000,
    "process": "sh",
    "command": "/tmp/root_sh",
    "evidence": {"exe": "/tmp/root_sh"}
  }'
```

---

## 4. Model Drift & Telemetry Health Operations

The `ModelDriftMonitor` tracks the Population Stability Index (PSI) over a sliding window of 500 inferences:

- **`STABLE` ($\text{PSI} < 0.20$)**: Normal operation. No drift detected.
- **`MODERATE_DRIFT` ($0.20 \le \text{PSI} < 0.25$)**: Mild distribution shift (e.g. new developer tools installed or increased cron frequency). Monitor closely.
- **`SIGNIFICANT_DRIFT` ($\text{PSI} \ge 0.25$)**: Severe feature divergence. Inspect `/api/v1/ml/status` for `drifted_features` and schedule an updated laboratory training run.
