# PrivWatch 3.1 - Machine Learning & Analytical Defect Register

This register documents all discovered analytical, scoring, classification, and statistical defects in the PrivWatch 3.0.1 platform, accompanied by technical root-cause analyses, reproduction steps, and required rectifications.

---

### ML-DEF-01: Hardcoded, Uncalibrated Confidence Values Across All Detections

- **File & Lines**:
  - `modules/blue_mode/sudo_detector.py:81` (`confidence=0.92`)
  - `modules/blue_mode/process_detector.py:37` (`confidence=0.95`)
  - `modules/blue_mode/suid_detector.py:45` (`confidence=0.98`)
  - `modules/timeline/event_correlator.py:108` (`confidence=0.94`)
- **Severity**: HIGH
- **Root Cause**: Confidence values were hardcoded float literals selected arbitrarily by developers without calibration or empirical validation against ground-truth datasets.
- **Observed Behavior**: Detections claim 94% - 98% confidence regardless of evidence quality, log source reliability, or telemetry completeness.
- **Expected Behavior**: Confidence must reflect empirical precision derived from calibrated validation datasets or statistical evidence weights, explicitly bounded by telemetry health.
- **Rectification**: Implement calibrated confidence calculation based on Platt scaling / isotonic calibration or evidence-weight scoring, separating anomaly scores from confidence metrics.

---

### ML-DEF-02: Conflation of Anomaly Score, Vulnerability Severity, and Attack Probability

- **File & Lines**: `core/models.py:72`, `modules/blue_mode/process_detector.py:29`
- **Severity**: HIGH
- **Root Cause**: The system uses a single categorical `Severity` enum (`HIGH`, `CRITICAL`) for both static vulnerabilities, statistical outliers, and active attacks.
- **Observed Behavior**: An unusual process execution (statistical anomaly) is treated as a confirmed `CRITICAL` or `HIGH` attack finding with identical semantics to a verified `NOPASSWD: ALL` root backdoor.
- **Expected Behavior**: Clear separation between:
  1. Static rule severity (inherent impact of a misconfiguration).
  2. Model anomaly score (statistical distance from baseline).
  3. Model confidence (probabilistic certainty).
  4. Telemetry evidence reliability.
  5. Overall composite incident risk score.
- **Rectification**: Create dedicated data structures: `AnomalyScore`, `CalibratedConfidence`, and `CompositeRiskScore`.

---

### ML-DEF-03: Total Absence of Statistical Anomaly Detection for Rare & Unseen Execution Paths

- **File & Lines**: `modules/blue_mode/process_collector.py:43-102`
- **Severity**: HIGH
- **Root Cause**: Process anomalies are detected only via static membership checks against hardcoded lists (`['www-data', 'apache', ...]`, `['sh', 'bash', ...]`).
- **Observed Behavior**: Novel privilege-escalation binaries, bespoke daemon accounts, or executions from unconventional paths (outside `/tmp`) are completely invisible.
- **Expected Behavior**: Unsupervised statistical anomaly detection (e.g., Isolation Forest, Robust Mahalanobis / Z-score) capable of flagging statistically rare process/UID/command triples.
- **Rectification**: Deploy an Isolation Forest and robust statistical outlier scoring engine trained on genuine Linux host process baselines.

---

### ML-DEF-04: Rigid Time-Window Count Thresholds Susceptible to Boundary Evasion

- **File & Lines**:
  - `modules/blue_mode/sudo_detector.py:65` (`window <= 600s`, `count >= 3`)
  - `modules/timeline/event_correlator.py:179` (`window <= 60s`, `count >= 4`)
- **Severity**: MEDIUM
- **Root Cause**: Hardcoded time intervals and count thresholds without exponential decay or statistical frequency analysis.
- **Observed Behavior**: An adversary pacing sudo password attempts at 605-second intervals bypasses brute-force detection completely.
- **Expected Behavior**: Continuous temporal decay modeling (e.g., half-life exponential weighting) that scores burst intensity and sustained low-frequency anomalies.
- **Rectification**: Implement temporal half-life feature engineering (`events_in_decay_window`, `inter_event_time_variance`) within the feature extraction pipeline.

---

### ML-DEF-05: Absence of Multi-Stage Sequence Modeling for Privilege Escalation Chains

- **File & Lines**: `modules/timeline/event_correlator.py:42-69`
- **Severity**: HIGH
- **Root Cause**: Event correlation is limited to three static hardcoded rules; cannot evaluate probabilistic transitions across multi-stage attack lifecycle steps.
- **Observed Behavior**: Complex multi-hop privilege escalation (e.g., non-login shell $\to$ capability grant $\to$ timer modification $\to$ root execution) is missed if it doesn't match the hardcoded templates.
- **Expected Behavior**: A sequence-based statistical transition model (First-Order Markov Chain / State-Transition Matrix) evaluating transition probability matrices of system events.
- **Rectification**: Implement a Markov Chain sequence analyzer modeling transition probabilities between normalized security event classes.

---

### ML-DEF-06: Inability to Adapt to Host-Specific Benign Baselines (High False-Positive Noise)

- **File & Lines**: `modules/blue_mode/suid_detector.py:34-46`
- **Severity**: MEDIUM
- **Root Cause**: Every execution of an SUID binary is flagged as `HIGH` severity without considering benign host execution history.
- **Observed Behavior**: Standard authorized administrative utilities (`sudo`, `passwd`, `su`, `chfn`, `ping`) trigger high-severity alerts on every invocation.
- **Expected Behavior**: The system must maintain a running baseline of normal SUID executions and flag deviations (new binary, unusual user, unusual parentage) rather than standard traffic.
- **Rectification**: Train anomaly detection models on host-specific execution telemetry to suppress habitual benign executions while highlighting rare deviations.

---

### ML-DEF-07: Static Keyword List Vulnerability to Command-Line Evasion

- **File & Lines**: `modules/blue_mode/sudo_detector.py:88`
- **Severity**: MEDIUM
- **Root Cause**: Regular expressions check command strings against a static `DANGEROUS_SUDO` wordlist.
- **Observed Behavior**: Executing `/bin/bash` via a symlink (e.g., `ln -s /bin/bash /opt/tool; sudo /opt/tool`) or via python inline execution bypasses detection.
- **Expected Behavior**: Multi-feature classification considering executable path, real vs effective UID/GID, child process spawns, and capability grants rather than raw command strings.
- **Rectification**: Combine lexical command features with process tree ancestry, ownership attributes, and binary capability markers in the supervised classifier.

---

### ML-DEF-08: Zero Model Integrity Verification, Versioning, or Validation Gates

- **File & Lines**: Non-existent in 3.0.1
- **Severity**: HIGH
- **Root Cause**: The repository lacked any model registry, serialization standards, or cryptographic provenance checks.
- **Observed Behavior**: No framework existed to verify model authenticity, prevent model tampering, or test for training/evaluation data leakage.
- **Expected Behavior**: Strict Model Validation Gate enforcing dataset schema compliance, feature drift monitoring, SHA-256 model weight hashing, and latency benchmarks prior to production inference.
- **Rectification**: Build `ml/validation/validation_gate.py` and `models/metadata/` with SHA-256 fingerprinting and strict validation gating.

---

### ML-DEF-09: Uncalibrated Posture Scoring Failing to Model Risk Compounding

- **File & Lines**: `core/models.py:276`
- **Severity**: LOW
- **Root Cause**: Linear additive penalty formula (`25*crit + 10*high + 3*med + 1*low`) lacks statistical or probabilistic justification.
- **Observed Behavior**: A system with 1 critical finding that cannot be exploited remotely receives score 75, while a system with 4 low findings receives score 96 despite an active chaining path.
- **Expected Behavior**: Composite risk model that computes risk density based on attack graph feasibility, vector diversity, and verified exploitation prerequisites.
- **Rectification**: Enhance posture calculation with vector diversity multipliers and verified anomaly coefficients.

---

### ML-DEF-10: Lack of Feature Explainability and Attribution for Security Alerts

- **File & Lines**: `modules/blue_mode/process_detector.py:30-38`
- **Severity**: MEDIUM
- **Root Cause**: Alerts output generic natural-language text templates without quantifying which specific attributes triggered the detection.
- **Observed Behavior**: Security analysts receiving an alert cannot inspect which underlying features (e.g., rare EUID, ancestry depth, directory entropy) contributed most to the anomaly score.
- **Expected Behavior**: Every prediction must deliver an explainability record including top contributing features, anomaly distance, and evidence links.
- **Rectification**: Implement `ml/explainability/feature_attribution.py` returning top contributing feature importances and human-interpretable rationale for every prediction.
