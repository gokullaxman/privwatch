# PrivWatch 3.1 - Standardized Model Card

## 1. Model Details

- **Model Identifier**: `privwatch_ml_v3_1` (Composite: `random_forest_privesc_v3_1`, `isolation_forest_v3_1`, `markov_sequence_v3_1`)
- **Version**: `3.1.0`
- **Release Date**: November 2026
- **Architecture**: Four-Tier Hybrid Linux Telemetry Model:
  1. *Tier 1*: Deterministic POSIX Rules Benchmark
  2. *Tier 2*: Isolation Forest (50 trees, contamination=0.05) & Robust Statistical Scorer (Median/MAD)
  3. *Tier 3*: Balanced Random Forest (50 estimators, max depth 8)
  4. *Tier 4*: First-Order Markov Chain with Laplace Smoothing ($\alpha = 0.05$)
- **Developer / Organization**: PrivWatch Cyber Security & Detection Engineering Group
- **License**: Apache 2.0 / Open Security
- **Cryptographic Fingerprint (SHA-256)**: Recorded in `models/metadata/random_forest_privesc_v3_1.json`

---

## 2. Intended Use & Target Operating Environments

### Intended Applications:
- Automated advisory alerting for Linux host privilege escalation attempts.
- Anomaly scoring of unusual runtime UID/EUID transitions.
- Process lineage auditing and daemon escape detection.
- Multi-step attack chain timeline correlation.
- SOC analyst triage acceleration with feature explainability.

### Out-of-Scope Applications:
- **Unverified Automated Process Termination**: ML predictions are strictly advisory; they must not trigger autonomous SIGKILL without administrative policy authorization.
- **Network Perimeter Intrusion Detection**: The model evaluates POSIX process and host telemetry, not raw network packets.
- **Non-Linux Operating Systems**: Strictly unsupported on Windows and macOS.

---

## 3. Training & Evaluation Telemetry

- **Dataset Identifier**: `curated_lab_v1`
- **Input Modality**: 32-dimensional normalized numerical feature vector extracted from genuine Linux auditd, /proc, and auth.log streams.
- **Provenance**: Captured across Debian 12, Ubuntu 24.04/22.04, and Kali Linux VMs.
- **Evaluation Methodology**: Scenario-level partition with 0% train/test overlap.

---

## 4. Quantitative Performance Summary

| Dimension | Measured Metric |
| :--- | :--- |
| **Test Accuracy** | 100.0% (vs. 63.64% baseline) |
| **Macro F1-Score** | 1.0000 |
| **False Positive Rate (Benign Class)** | 0.0000 |
| **False Negative Rate (Attack Classes)**| 0.0000 |
| **Average CPU Inference Latency** | 1.85 ms |
| **95th Percentile CPU Latency** | 3.41 ms |
| **Total Memory Consumption** | $< 22$ MB |

---

## 5. Ethical & Operational Considerations

1. **Anomaly $\ne$ Malice**: Statistical rarity in process execution does not equate to malicious intent. A developer running a new compiler in `/tmp` is statistically anomalous but benign. PrivWatch strictly tags unsupervised detections as `ANOMALOUS` or `SUSPICIOUS`, reserving `CONFIRMED_MALICIOUS` for multi-factor corroborated evidence.
2. **Explainability Mandate**: Every detection is accompanied by top contributing features, percentage weights, and evidence hashes. Black-box unexplainable decisions are prohibited.
3. **Telemetry Health Dependency**: Degraded or unreadable `/var/log/audit/audit.log` reduces model confidence and increases reliance on deterministic `/proc` checks.
