# PrivWatch 3.0

**Evidence-Driven Linux Privilege Escalation Detection, Telemetry Monitoring, Forensics & Prevention Platform**

[![Tests](https://img.shields.io/badge/tests-34%20passed-brightgreen.svg)](docs/TESTING.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Status: Production](https://img.shields.io/badge/status-production-success.svg)](CHANGELOG.md)

---

## 📋 Overview

**PrivWatch 3.0** is an enterprise-grade Linux security platform engineered to identify local privilege escalation vulnerabilities, monitor system telemetry in real time, detect adversary exploitation attempts, reconstruct forensic attack timelines, and execute controlled least-privilege remediation.

Operating under a strict **Real System Data Only** standard, PrivWatch never fabricates telemetry or simulates alerts. Every finding and incident is cryptographically fingerprinted and directly tied to operating system evidence.

```
╔═══════════════════════════════════════════════════════════╗
║                  PrivWatch v3.0.0                         ║
║        Privilege Escalation Detection & Forensics         ║
║                  Mode:              RED                   ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🚀 Key Capabilities

### 1. 🔴 Red Team Assessment Engine
Audits 9 distinct Linux privilege escalation vectors:
- **SUID/SGID Binaries:** Targeted enumeration across binary paths, parent directory write checks, GTFOBins catalog cross-referencing, and distribution allowlists.
- **Sudo Misconfigurations:** Non-interactive sudo rule auditing, NOPASSWD detection, wildcard analysis, and sudoers permission validation.
- **Linux Capabilities:** Evaluates dangerous capabilities (`CAP_SETUID`, `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`) using targeted `getcap` execution.
- **Cron & Systemd Timers:** Inspects system crontabs, cron directories, and systemd timers to identify writable scripts and binaries.
- **Password & Auth Databases:** Audits `/etc/passwd` and `/etc/shadow` for write access, rogue UID 0 accounts, blank password fields, and exposed backups.
- **Kernel Vulnerability Assessment:** Distribution-aware kernel evaluation querying local package managers (`dpkg`, `rpm`) to account for backported security patches.
- **PATH Hijacking:** Detects relative directory references (`.`) and writable directories preceding system binaries.
- **SSH Security:** Audits `/etc/ssh/sshd_config`, private host keys, and world-writable `authorized_keys`.
- **Container Boundaries:** Audits exposed `/var/run/docker.sock`, privileged devices, and container escape vectors.

### 2. 🔵 Blue Team Detection & Telemetry Engine
Continuous telemetry collection directly from Linux kernel and system interfaces:
- **Telemetry Sources:** Linux Audit (`auditd`), systemd journal (`journald`), authentication logs (`auth.log`/`secure`), and live process monitoring (`/proc`/`psutil`).
- **Telemetry Health Assessment:** Evaluates available vs missing sources, permission constraints, and monitoring coverage percentage.
- **Sudo Brute-Force Detection:** Sliding-window correlation identifying repeated password failures for the same user.
- **Verified SUID Execution:** Confirmed execution of elevated binaries via audit syscalls (`ruid != euid`) rather than naive text matching.
- **Process Lineage Anomaly Detection:** Identifies unprivileged daemons (`www-data`, `nobody`) spawning interactive shells or binaries executing from `/tmp`.
- **Tampering Detection:** Real-time detection of modifications to `/etc/passwd`, `/etc/shadow`, or crontabs.

### 3. ⏱️ Forensic & Correlation Engine
- **Multi-Factor Correlation:** Evaluates user identity, hostname, process parentage (PID/PPID), and chronological sequences.
- **Unified Forensic Timeline:** Reconstructs raw events, security findings, and correlated attack sequences in a single chronological stream.
- **Case Management:** Built-in investigation tracking with status updates and analyst notes.

### 4. 🛡️ Controlled Prevention & Remediation
- **Safe by Default:** Read-only operation during all scans.
- **Least-Privilege Playbooks:** Generates exact hardening commands and explains consequences.
- **Mandatory Safety Gates:** Requires explicit confirmation (`confirmed=True`, `dry_run=False`) for any OS alteration.
- **Rollback Assurance:** Generates pre-execution file backups and automated rollback commands.
- **Audit Logging:** Every administrative action and remediation execution is permanently logged to SQLite.

### 5. 📊 Reporting & Operations Dashboard
- **Executive PDF Reports:** Multi-page, professionally styled PDF reports built with ReportLab, featuring posture metrics, tables, and remediation playbooks.
- **Machine-Readable Exports:** Complete JSON reports with evidence hashes and CSV spreadsheet exports.
- **Web Operations Dashboard:** Modern responsive SOC interface (FastAPI + HTML5/Tailwind) featuring 10 operational views.

---

## 📂 Architecture

```
privwatch/
├── privwatch.py                 # Unified CLI entry point (Modes: red, blue, timeline, dashboard, monitor)
├── privwatch_v2.py              # Backward compatibility forwarder
├── config/
│   ├── settings.py              # Constants, allowlists, and vector paths
│   └── vectors.json             # Vector taxonomy and severity ratings
├── core/
│   ├── config.py                # Hierarchical configuration loader
│   ├── models.py                # SecurityEvent, Finding, Incident, TelemetryHealth, Posture
│   ├── storage.py               # SQLite persistence and audit engine
│   ├── evidence.py              # Cryptographic hashing & credential sanitization
│   ├── logger.py                # Structured console & JSON logger
│   ├── scanner.py               # Base Red Team scanner class
│   ├── log_parser.py            # Base Blue Team telemetry parser class
│   └── orchestrator.py          # Central coordinator & service lifecycle
├── modules/
│   ├── red_mode/                # 9 Privilege Escalation Scanners
│   │   ├── suid_scanner.py
│   │   ├── sudo_scanner.py
│   │   ├── capabilities_scanner.py
│   │   ├── cron_scanner.py
│   │   ├── passwd_scanner.py
│   │   ├── kernel_scanner.py
│   │   ├── path_scanner.py
│   │   ├── ssh_scanner.py
│   │   └── container_scanner.py
│   ├── blue_mode/               # Telemetry Collectors & Detectors
│   │   ├── telemetry/
│   │   │   ├── health_monitor.py
│   │   │   ├── auth_collector.py
│   │   │   ├── journal_collector.py
│   │   │   ├── audit_collector.py
│   │   │   └── process_collector.py
│   │   ├── sudo_detector.py
│   │   ├── suid_detector.py
│   │   ├── passwd_detector.py
│   │   ├── cron_detector.py
│   │   ├── kernel_detector.py
│   │   ├── capabilities_detector.py
│   │   └── process_detector.py
│   ├── timeline/                # Forensic Correlation & Timeline
│   │   ├── event_correlator.py
│   │   ├── timeline_builder.py
│   │   └── investigation.py
│   └── response/                # Prevention & Remediation
│       ├── remediation_engine.py
│       └── suppression.py
├── reports/
│   ├── json_exporter.py         # Full JSON serialization
│   ├── pdf_generator.py         # Professional PDF reports (ReportLab)
│   └── csv_exporter.py          # CSV spreadsheet exporter
├── web/
│   └── app.py                   # FastAPI REST API & Single-Page Dashboard
├── tests/                       # Automated Pytest Suite (34 Tests)
│   ├── conftest.py              # Isolated test fixtures
│   ├── test_scanners.py
│   ├── test_log_parsers.py
│   ├── test_event_normalization.py
│   ├── test_correlation.py
│   ├── test_remediation.py
│   ├── test_exporters.py
│   ├── test_api_integration.py
│   └── test_security_validation.py
├── docs/                        # Complete Technical Documentation
│   ├── PRIVWATCH_3_AUDIT.md
│   ├── PRIVWATCH_3_ARCHITECTURE.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   ├── DETECTION_RULES.md
│   ├── TELEMETRY_SOURCES.md
│   ├── SECURITY_MODEL.md
│   ├── API_REFERENCE.md
│   ├── TROUBLESHOOTING.md
│   └── TESTING.md
├── CHANGELOG.md                 # Detailed version history
├── requirements.txt             # Project dependencies
└── LICENSE                      # MIT License
```

---

## ⚡ Quick Start

### 1. Installation
```bash
git clone https://github.com/charith-Penugonda/privwatch.git
cd privwatch

# Install dependencies
pip install -r requirements.txt
```

### 2. Verify Installation
```bash
# Verify Python compilation
python3 -m compileall .

# Run automated test suite
python3 -m pytest -v
```

### 3. Usage Examples

```bash
# Red Team assessment (produces JSON, PDF, or CSV report)
python3 privwatch.py --mode red --format all

# Blue Team log forensics and telemetry analysis
python3 privwatch.py --mode blue --format pdf

# Forensic timeline reconstruction and attack correlation
python3 privwatch.py --mode timeline

# Continuous background telemetry monitoring
python3 privwatch.py --mode monitor

# Launch interactive Web Security Operations Dashboard
python3 privwatch.py --mode dashboard --port 8443
# Navigate to: http://127.0.0.1:8443
```

---

## 📖 Documentation Index

- [Comprehensive Audit & Gap Analysis](docs/PRIVWATCH_3_AUDIT.md)
- [System Architecture Blueprint](docs/PRIVWATCH_3_ARCHITECTURE.md)
- [Installation Guide](docs/INSTALLATION.md)
- [User Guide & Operations Manual](docs/USAGE.md)
- [Detection Rules & Heuristics](docs/DETECTION_RULES.md)
- [Telemetry Sources & Ingestion](docs/TELEMETRY_SOURCES.md)
- [Security Model & Safety Gates](docs/SECURITY_MODEL.md)
- [REST API Reference](docs/API_REFERENCE.md)
- [Troubleshooting & Diagnostics](docs/TROUBLESHOOTING.md)
- [Automated Testing Guide](docs/TESTING.md)

---

## 📄 License

PrivWatch is licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Charith Penugonda.
