# UATU Linux Edition — Machine Learning Governance & Model Trust

This document specifies the cryptographic model registry, manifest verification, trust states, evaluation metrics, and deterministic rule fallback architecture.

---

## 1. Machine Learning Governance Architecture

```
                    Model Weights File (.pkl)
                               │
                               ▼
                   Compute SHA-256 Checksum
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   Check Against Metadata Card         Check Against Authoritative
    models/metadata/<id>.json             models/manifest.json
            │                                     │
            └──────────────────┬──────────────────┘
                               │
                               ▼
                    Verify Trust Status:
            [APPROVED | UNVERIFIED | REVOKED]
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
    [APPROVED]           [UNVERIFIED]            [REVOKED]
  Permitted for         Evaluation Mode        Fatal Security
    Production              Only                Error Raised
    Inference                                  (Load Rejected)
                                                     │
                                                     ▼
                                            Deterministic Rule
                                             Engine Fallback
```

---

## 2. Authoritative Manifest & Integrity Gating

All production model weights must be cataloged in `models/manifest.json` before deployment:

```json
{
  "manifest_version": "1.0",
  "models": {
    "random_forest_privesc_v3_1": {
      "model_id": "random_forest_privesc_v3_1",
      "version": "3.1.0",
      "algorithm": "RandomForestClassifier",
      "sha256": "8c942e265289e389278c1b5c918c7fd24c7161c767f0eec836c2aaa87a4bc3a1",
      "status": "APPROVED",
      "feature_schema_version": "3.1"
    }
  }
}
```

### Loading Verification Invariants:
1. **Schema Check**: Feature names and order must exactly match `ml.features.feature_schema.FEATURE_NAMES`.
2. **Digest Verification**: SHA-256 of the pickle file on disk must match both the recorded card hash and the manifest entry. Mismatch raises `ValueError`.
3. **Trust Gating**:
   - `REVOKED`: Raises `PermissionError` immediately.
   - `UNVERIFIED` / `UNVALIDATED`: Rejected in production mode; allowed only if `evaluation_mode=True`.

---

## 3. Trust Lifecycle Management

Models transition through defined trust states:

- **`UNVERIFIED`**: Newly trained or imported model undergoing automated validation gating.
- **`VALIDATED`**: Passed data leakage tests, performance thresholds, and schema verification.
- **`APPROVED`**: Explicitly certified by authorized security administrator for live production inference.
- **`REVOKED`**: Flagged due to model drift, concept drift, or adversarial vulnerability. Permanently blocked from production execution.

---

## 4. Deterministic Fallback Architecture

If an ML model file is missing, corrupted, hash-mismatched, or revoked:
1. UATU marks the ML subsystem status as `DEGRADED` in `TelemetryHealth`.
2. Telemetry processing routes automatically and seamlessly through the deterministic rule-based `DetectionEngine`.
3. System posture and alerting remain 100% operational, guaranteeing high availability even under ML component failure.
