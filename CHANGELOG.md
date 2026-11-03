# PrivWatch Changelog

All notable changes to the PrivWatch platform will be documented in this file.

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

