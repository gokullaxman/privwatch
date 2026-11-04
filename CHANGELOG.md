# PrivWatch Changelog

All notable changes to the PrivWatch platform will be documented in this file.

---

## [3.1.0] - 2026-11-04 - Advanced AI/ML Detection Model Upgrade

### Added
- **Canonical 32-Dimensional Linux Feature Space (`ml/features/`):**
  - Standardized feature vector (`FeatureVector`) extracted exclusively from genuine Linux telemetry (`LinuxFeatureExtractor`).
  - Covers identity transitions, process ancestry, execution context, syntax, source encoding, and temporal sliding windows.
- **Four-Tier Hybrid Detection Architecture (`models/`):**
  - **Tier 1 (Deterministic Baseline):** Benchmark implementing established POSIX security heuristics (`DeterministicBaselineModel`).
  - **Tier 2 (Unsupervised Anomaly Scoring):** Dual-redundancy Isolation Forest (`LinuxIsolationForestDetector`) and Median Absolute Deviation modified Z-score scorer (`RobustStatisticalScorer`).
  - **Tier 3 (Supervised Threat Classifier):** Balanced Random Forest ensemble classifying events into 6 threat categories with probability calibration (`LinuxPrivilegeClassifier`).
  - **Tier 4 (Sequential Markov Model):** First-order Markov chain with Laplace smoothing calculating sequence log-likelihood across 8 security states (`MarkovPrivilegeSequenceModel`).
- **Feature Attribution & Transparent Explainability (`ml/explainability/`):**
  - Local feature attribution (`FeatureAttributor`) calculating top contributing features and contribution percentages.
  - Transparent narrative rationale builder (`ExplanationEngine`) providing human-readable justifications backed by evidence.
  - Multi-factor composite risk calculator (`CompositeRiskCalculator`) in $[0, 100]$ separating anomaly score, confidence, and severity.
- **Model Validation Gate & Scientific Integrity Checker (`ml/validation/validation_gate.py`):**
  - Automated pre-deployment gate enforcing schema completeness, zero scenario leakage, training reproducibility, CPU latency budgets ($\le 25$ ms), and baseline comparison ($\Delta \text{Accuracy} \ge -0.05$).
- **Cryptographic Model Registry & Metadata Cards (`models/registry/`, `models/metadata/`):**
  - Serialized model persistence with automated SHA-256 integrity verification, hyperparameter tracking, and validation gating.
- **Model Drift & Telemetry Monitor (`ml/monitoring/drift_detector.py`):**
  - Sliding-window monitor computing Population Stability Index (PSI) and tracking inference latency compliance.
- **Non-Blocking Production ML Runner & Advisory Blue Team Integration (`ml/inference/`):**
  - `ModelRunner` with sub-5ms CPU latency and guaranteed baseline fallback on failure.
  - `AdvisoryMLDetector` integrated into Blue Team analysis and SOC REST API (`/api/v1/ml/status`, `/api/v1/ml/evaluate`).
- **Verified Laboratory Scenario Datasets (`ml/data/`):**
  - Multi-host scenario generator (`generate_curated_telemetry_dataset`) with leakage-free partitioning (`LeakageFreeSplitter`).
- **Expanded Test Suite (69 Tests):**
  - Comprehensive unit and integration test suite covering feature engineering, dataset validation, training pipeline, model serialization/tampering, evaluation metrics, inference, and drift.

---

## [3.0.1] - 2026-11-04 - Linux-Native Complete Audit, Repair & Hardening

### Added
- **Linux Platform Validator (`core/platform_validator.py`):** Strictly enforces Linux-native execution environment (Kali, Debian, Ubuntu, Fedora, RHEL, Arch) and terminates on non-Linux hosts.
- **Safe Linux Command Runner (`core/command_exec.py`):** Structured subprocess execution (`shell=False`) with shell metacharacter rejection, explicit argument lists, timeouts, and separate stdout/stderr capture.
- **Privilege Separation Daemon (`core/privileged_service.py`):** Privileged telemetry collector operating over restricted Unix Domain Socket (`/run/privwatch/privwatch.sock`) with `0600` permissions and `SO_PEERCRED` client credential validation.
- **Systemd Service Definition (`systemd/privwatch-collector.service`):** Hardened systemd unit with narrow capabilities (`CAP_DAC_READ_SEARCH`, `CAP_AUDIT_READ`).
- **Cryptographic Audit Hash Chaining (`core/storage.py`):** SHA-256 tamper-evident hash chaining linking administrative audit trail entries with `verify_audit_chain_integrity()`.
- **REST API Authentication & Authorization (`web/app.py`):** Enforces API Key / Bearer tokens for all mutating administrative endpoints with role-based access control and sliding-window rate limiting.
- **Distribution-Aware Kernel Advisory Matching (`modules/red_mode/kernel_scanner.py`):** Integrated USN, DSA, and RHSA package fix evaluation with Debian/RPM version comparators.
- **Linux Audit Rules Definition (`config/audit.rules`):** Scoped syscall monitoring rules for `execve`, `execveat`, `setuid`, `setgid`, and `capset`.

### Fixed & Hardened
- **Removed all `shell=True`:** Eradicated arbitrary shell command construction across core and response engines.
- **Removed all Windows compatibility code:** Removed `win32`, `windll`, `IsUserAnAdmin`, and cross-platform fallbacks.
- **Fixed Passwd Scanner Semantics:** Canonical `/etc/passwd` path validation eliminates false positive alerts on user temporary test files.
- **Fixed Remediation Rollback:** Replaced shell strings and insecure `chmod 666` commands with typed `RemediationAction` structures, exact original bitmask restoration, symlink protection, and atomic failure rollback.
- **Fixed Database Integrity:** Replaced `INSERT OR REPLACE` with append-only policies and fixed confidence restoration so `0.0` is preserved.
- **Expanded Pytest Suite:** Expanded automated test suite from 34 to 44 comprehensive tests covering API auth, platform validation, hash chaining, and rollback.

---

## [3.0.0] - 2026-11-04 - PrivWatch 3.0 Platform Transformation

### Added
- **Core Architecture:**
  - Standardized typed data models (`SecurityEvent`, `Finding`, `Incident`, `TelemetryHealth`, `SystemPosture`).
  - Hierarchical configuration manager (`PrivWatchConfig`) with environment variable overrides and auto-discovery.
  - Thread-safe SQLite persistence engine (`StorageEngine`) for events, findings, incidents, and audit logs.
  - Evidence integrity manager (`EvidenceManager`) providing SHA-256 cryptographic provenance hashing and credential sanitization.
  - Structured logger (`Logger`) supporting terminal color banners and JSON-lines log formatting.
  - Central application orchestrator (`PrivWatchOrchestrator`).
- **Red Team Assessment Engine (9 Vectors):**
  - Upgraded SUID/SGID scanner with parent directory write checks, GTFOBins catalog, and allowlists.
  - Upgraded Sudo configuration scanner with non-interactive checks, wildcard analysis, and NOPASSWD detection.
  - Targeted Linux Capabilities scanner auditing standard binary directories with `getcap`.
  - Upgraded Cron and Systemd timer scanner auditing script permissions without false alerts.
  - Upgraded Password/Auth scanner detecting rogue UID 0 accounts, blank password fields, and backup files.
  - Upgraded Kernel vulnerability scanner with package manager (`dpkg`, `rpm`) queries and backport patch awareness.
  - New PATH hijacking scanner auditing relative references (`.`) and search order precedence.
  - New SSH security scanner auditing `sshd_config`, private host keys, and `authorized_keys`.
  - New Container privilege scanner auditing `docker.sock`, privileged devices, and breakout vectors.
- **Blue Team Telemetry & Detection Engine:**
  - Multi-source telemetry collectors for Linux Audit (`auditd`), systemd journal (`journald`), auth logs (`auth.log`/`secure`), and `/proc`/`psutil`.
  - Telemetry health monitor calculating coverage percentage and reporting monitoring limitations.
  - Sudo brute-force detector with sliding window correlation across identical usernames.
  - Confirmed SUID execution detector powered by audit syscalls and process telemetry.
  - Account and password file tampering detector.
  - Scheduled task tampering detector.
  - Kernel memory fault and ring-0 crash detector.
  - Capabilities abuse detector (`setcap`).
  - Process ancestry and anomaly detector (daemon shell execution and `/tmp` payload execution).
- **Forensic & Correlation Engine:**
  - Multi-factor event correlator validating user identity, hostname, process parentage, and strict chronological ordering.
  - Unified chronological timeline builder linking raw events, findings, and incidents.
  - Forensic case management engine (`InvestigationManager`).
- **Controlled Prevention & Response:**
  - Least-privilege remediation engine with dry-run simulation by default.
  - Mandatory administrator confirmation for OS alterations.
  - Automatic pre-execution backups and rollback script generation.
  - Auditable alert suppression rules.
- **Reporting Engine:**
  - Machine-readable JSON exporter with complete evidence trees and posture scores.
  - Full multi-page professional PDF generator using ReportLab with executive summary and charts.
  - CSV exporter for findings and timeline records.
- **Web Security Operations Dashboard:**
  - FastAPI-based modern responsive single-page SOC dashboard (10 operational views).
  - Real-time monitoring start/stop service controls.
  - Searchable, filterable findings table and forensic timeline visualization.
  - REST API with OpenAPI documentation.
- **Testing & Verification:**
  - 34 automated unit, integration, and security tests (`pytest`) with 100% pass rate.
  - Full Python compilation verification.

### Changed
- Replaced dangerous exploit payloads in remediation strings with defensive hardening steps.
- Replaced naive string matching on syslog text with verified kernel and process telemetry.
- Replaced broken time-window correlation with multi-factor chronological correlation.
- Upgraded CLI (`privwatch.py`) to support `--mode {red,blue,timeline,dashboard,monitor}`.

---

## [2.0.0] - 2026-10-04
- Initial 3-mode prototype (Red, Blue, Timeline).
- Basic GTFOBins dictionary and placeholder PDF export.

## [1.0.0] - 2026-10-02
- Initial prototype script for SUID and sudo reconnaissance.

