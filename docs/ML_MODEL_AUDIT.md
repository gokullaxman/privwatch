# PrivWatch 3.1 - Machine Learning & Statistical Detection Audit

## 1. Executive Summary

This document presents a rigorous technical audit of the analytical, scoring, classification, correlation, and detection mechanisms across the PrivWatch 3.0.1 codebase.

**Key Audit Finding:** Prior to PrivWatch 3.1, the repository contained **zero machine learning models, zero statistical anomaly detection algorithms, zero trained model weights, and zero predictive classification pipelines**. All security evaluations were driven exclusively by:
1. Deterministic POSIX filesystem inspection (Red Team mode).
2. Regular expression pattern matching on raw text log lines (Auth & Syslog collectors).
3. Hardcoded rule-based sliding-window aggregators (Sudo brute-force detector, SUID burst detector).
4. Heuristic penalty deductions for system posture calculation (`SystemPosture.calculate`).
5. Subjective, hardcoded confidence literals (`confidence = 0.90`, `0.95`, `0.98`) assigned statically in source code.

This audit details the exact behavior, mathematical properties, strengths, and failure modes of these existing heuristics, establishing the empirical baseline against which all PrivWatch 3.1 machine learning and statistical models are evaluated.

---

## 2. Inventory of Existing Detection & Scoring Mechanisms

| Component | File Path | Existing Methodology | Mathematical Formulation / Algorithm | Input Features | Limitations & Failure Modes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **System Posture Scoring** | `core/models.py:262` | Linear penalty arithmetic | `Score = max(0, 100 - (25*crit + 10*high + 3*med + 1*low))` | Counts of static findings by severity | Linear, uncalibrated; 4 critical findings yield score 0 regardless of system criticality or attack path feasibility. |
| **Sudo Brute Force Detector** | `modules/blue_mode/sudo_detector.py:51` | Sliding window count threshold | `Count(SUDO_AUTH_FAIL for user in window <= 600s) >= 3` | `timestamp`, `user`, `event_type` | Rigid threshold (fails on low-and-slow attacks at 601s; flags administrative typos; ignores process context). |
| **Dangerous Sudo Execution** | `modules/blue_mode/sudo_detector.py:84` | Static keyword regex | `regex.search(r'\b' + cmd + r'\b')` against `DANGEROUS_SUDO` | `command`, `user` | Easily bypassed by aliases, symlinks, wrapper scripts, or unusual flags; cannot detect novel utilities. |
| **SUID Execution Detector** | `modules/blue_mode/suid_detector.py:28` | Identity disparity check | `euid == 0 and uid != 0` via auditd/procfs | `uid`, `euid`, `process`, `command` | High noise on standard authorized setuid utilities (`sudo`, `passwd`, `su`, `ping`); lacks execution frequency baseline. |
| **Process Anomaly Detector** | `modules/blue_mode/process_detector.py:21` | Membership lookup & directory matching | `user in DAEMON_USERS and proc in SHELLS` OR `exe in /tmp` | `username`, `name`, `exe`, `ppid` | Fixed static set of daemon accounts; fails to detect web shells running under bespoke user accounts or non-standard paths. |
| **Event Correlator (Sudo)** | `modules/timeline/event_correlator.py:71` | Sequential rule matching | `Failures >= 2 followed by Success within 3600s by same user` | `user`, `timestamp`, `hostname` | Binary decision; no probabilistic scoring of command unusualness or user baseline; window of 1 hour is arbitrary. |
| **Event Correlator (Web Shell)** | `modules/timeline/event_correlator.py:125` | Ancestry / user temporal link | `SHELL_SPAWNED within 1800s where ppid==pid or user==user` | `pid`, `ppid`, `user`, `timestamp` | Fails when intermediate child processes break direct PID linkage; lacks process tree depth evaluation. |
| **Event Correlator (SUID Burst)** | `modules/timeline/event_correlator.py:166` | Window count threshold | `Count(SUID_EXECUTION in 60s) >= 4` | `timestamp`, `user`, `process` | Static threshold 4; fails on automated package manager updates executing suid tools; misses 3-binary reconnaissance. |
| **Confidence Scoring** | Across all modules | Static hardcoded literals | `confidence = 0.90 / 0.95 / 0.98` | None (hardcoded constant) | Completely uncalibrated; implies 95% empirical precision where no empirical validation was ever conducted. |

---

## 3. Detailed Component Analysis

### 3.1 System Posture Scoring Engine (`core/models.py`)
- **Algorithm**: Linear penalty deduction from 100.
- **Dataset Provenance**: None. Hardcoded arbitrary weights:
  - Critical finding: $-25$ points
  - High finding: $-10$ points
  - Medium finding: $-3$ points
  - Low finding: $-1$ point
- **Output**: Integer `0 - 100` categorized into `HEALTHY`, `ATTENTION_NEEDED`, `VULNERABLE`, or `CRITICAL_RISK`.
- **Known Weaknesses**:
  - Independent risk assumption: Assumes findings act independently without compounding impact.
  - No environment adaptation: A development sandbox is scored identically to a production bastion host.
  - Zero false-positive resistance: Any single unverified high-severity finding drops posture by 10 points.

### 3.2 Sudo Brute Force & Anomaly Logic (`modules/blue_mode/sudo_detector.py`)
- **Algorithm**: Sliding time-window grouping with count threshold $\ge 3$ within $600$ seconds.
- **Dataset Provenance**: None.
- **Input Features**: `e.timestamp`, `e.user`, `e.event_type`.
- **Known Weaknesses**:
  - Susceptible to boundary evasion: An attacker issuing attempts spaced at 605-second intervals bypasses detection entirely.
  - Ignorance of user baselines: A sysadmin who legitimately mistypes credentials on a new terminal is indistinguishable from an attacker.

### 3.3 Multi-Factor Forensic Event Correlation (`modules/timeline/event_correlator.py`)
- **Algorithm**: Deterministic rule chaining across three hardcoded scenarios:
  1. `_correlate_sudo_brute_to_success`
  2. `_correlate_webshell_to_privesc`
  3. `_correlate_suid_burst`
- **Output**: `Incident` objects with hardcoded `confidence=0.94`, `0.96`, `0.89`.
- **Known Weaknesses**:
  - Rigid sequences: Does not detect multi-stage attacks that diverge from the three predefined patterns.
  - Hardcoded confidence: Misrepresents confidence as empirical probabilities when they are subjective developer estimates.
  - Non-probabilistic state transitions: Cannot quantify the statistical likelihood of an observed sequence of system calls.

---

## 4. Root Causes for ML Model Absence in Prior Versions

1. **Heuristic Simplicity**: Prior versions prioritized rapid prototyping of Linux CLI utilities rather than statistical learning pipelines.
2. **Telemetry Standardization Gaps**: Until PrivWatch 3.0 normalized events into typed `SecurityEvent` schemas, structured features for tabular or sequential models were unavailable.
3. **Absence of Ground-Truth Pipelines**: No controlled methodology existed for collecting, labeling, and verifying Linux host privilege-escalation datasets without synthetic contamination.

---

## 5. Audit Conclusion & Baseline Preservation Mandate

The existing deterministic rules in `core/scanner.py`, `modules/red_mode/`, and `modules/blue_mode/` provide essential, high-confidence static security baselines. They detect definitive misconfigurations (e.g., `NOPASSWD: ALL` in `/etc/sudoers`, world-writable `/etc/passwd`).

**Mandate for PrivWatch 3.1:**
1. **Never discard or degrade the deterministic baseline.**
2. All new machine learning and statistical models must operate as an **advanced analytical layer** on top of the deterministic baseline.
3. Statistical anomalies must remain strictly distinguished from verified security violations.
4. Model predictions must be fully explainable, calibrated, and guarded by an automated validation gate.
