# PrivWatch 3.1 - Scientific Limitations & Operational Caveats

## 1. Introduction

PrivWatch 3.1 provides advanced statistical anomaly detection, calibrated threat classification, and sequential Markov modeling. However, machine learning in host security is subject to fundamental scientific and operational boundaries.

This document honestly outlines the verified limitations, assumptions, and failure modes of the PrivWatch ML architecture.

---

## 2. Documented Analytical & Operational Limitations

### 1. Telemetry Ingestion Blind Spots
- **Limitation**: When the Linux Audit subsystem (`auditd`) is disabled or unconfigured, PrivWatch falls back to polling `/proc`.
- **Operational Impact**: Transient processes that execute and terminate within sub-second intervals (e.g. `python -c "os.setuid(0); ..."` executing in 15 ms) will escape `/proc` polling intervals entirely.
- **Mitigation**: Kernel audit rules (`config/audit.rules`) must be deployed and active to guarantee deterministic capture of all `execve` and `setuid` invocations.

### 2. Concept Drift Across Diverse Linux Distributions
- **Limitation**: Normal execution baselines vary significantly between server distributions (Debian, RHEL) and workstation/pentesting environments (Kali Linux, Arch Linux).
- **Operational Impact**: A user running penetration testing tools (`nmap`, `hydra`, `metasploit`) on Kali Linux triggers high statistical anomaly scores that would be abnormal on a Debian database server.
- **Mitigation**: The `ModelDriftMonitor` tracks Population Stability Index (PSI). Security teams should establish host-specific or role-specific baseline training sets.

### 3. Living-Off-The-Land (LotL) Adversarial Evasion
- **Limitation**: Sophisticated adversaries using legitimate administrative utilities (e.g., authorized `sudo systemctl restart`, standard `find` queries) without changing UIDs or dropping payloads in `/tmp` present feature vectors that closely resemble benign administrative workflows.
- **Operational Impact**: While Markov sequence models detect unusual transitions, a patient attacker spacing actions over hours and mimicking sysadmin behavior can remain beneath statistical anomaly thresholds.
- **Mitigation**: Do not rely on ML models alone. The deterministic baseline rules and Red Team configuration audits remain mandatory lines of defense.

### 4. Labeled Sample Scarcity in Host Security
- **Limitation**: Verified, multi-scenario host privilege-escalation datasets are small in volume compared to massive network traffic datasets.
- **Operational Impact**: Deep learning architectures (LSTMs, Transformers) overfit catastrophically when trained on limited host incident records.
- **Architectural Defense**: PrivWatch deliberately rejects deep neural networks in favor of robust, shallow tree ensembles (Random Forest, Isolation Forest) and first-order Markov chains with explicit Laplace smoothing.

### 5. Single-Host Telemetry Horizon
- **Limitation**: PrivWatch evaluates telemetry originating from the local Linux host.
- **Operational Impact**: Attacks involving coordinated lateral movement, SSH pivoting, or external C2 command channels across a cluster cannot be correlated without centralizing events in an external SIEM or telemetry collector.

### 6. Mathematical Attribution vs. Legal Forensic Proof
- **Limitation**: Feature attribution percentages (`contribution_pct`) indicate which numerical variables influenced the model's decision function.
- **Operational Impact**: Feature attribution is not legal or forensic proof of malicious intent. An alert indicating 85% risk must be independently investigated by human security analysts prior to disciplinary or legal action.

---

## 3. Operational Best Practices

1. **Keep Auditd Loaded**: Always load `config/audit.rules` via `augenrules --load`.
2. **Treat ML Alerts as Advisory**: Review the `evidence_references` and `contributing_features` before taking disruptive remediation actions.
3. **Monitor Drift Regularly**: Query `/api/v1/ml/status` weekly to check for `SIGNIFICANT_DRIFT` alerts.
4. **Maintain Deterministic Baselines**: Never disable Tier 1 deterministic rules in favor of pure ML inference.
