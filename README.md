# UATU Linux Edition (v3.0.0)

**Intelligent Privilege Escalation Detection, Prevention, and Attack-Path Disruption**

[![Platform: 100% Linux Native](https://img.shields.io/badge/platform-Linux%20Only-blue.svg)](LIMITATIONS.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Audit Framework: auditd](https://img.shields.io/badge/telemetry-Linux%20Audit%20Netlink-orange.svg)](config/audit/uatu.rules)

---

## 📋 Overview

**UATU Linux Edition** is a production-grade, 100% Linux-native security platform engineered to identify exploitable privilege escalation pathways, monitor kernel and process telemetry in real time, correlate attack sequences with tamper-resistant evidence, and safely disrupt confirmed attack paths using reversible, least-privilege remediation.

Operating under a strict **Evidence-First Standard**, UATU never fabricates telemetry, simulates counters, or hardcodes posture scores. Everything displayed in reports and on the dashboard is backed by verified POSIX attributes, cryptographic evidence hashes, or real Linux Audit netlink / auth log events.

---

## ⚡ Quickstart on Kali Linux

### 1. Prerequisites Installation
Run the following commands on your Kali Linux VM to install required system utilities and Python dependencies:

```bash
# Update package repositories and install auditd and libcap tools
sudo apt-get update
sudo apt-get install -y auditd libcap2-bin python3 python3-pip python3-venv git

# Clone repository and navigate into project directory
cd /path/to/uatu-linux

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

### 2. Install Kernel Audit Rules
Deploy the UATU audit rules to monitor `execve`, credential transitions (`setuid` family), and sensitive configuration file watches:

```bash
# Install audit rules (requires root)
sudo bash scripts/install_audit_rules.sh
```

### 3. Run Privilege Escalation Scan & Attack Path Mapping
Enumerate local configuration defects (SUID/SGID, sudoers NOPASSWD/wildcards, capabilities, shadow/passwd permissions, writable scheduled scripts) and map multi-hop attack graphs:

```bash
# Run scan
./uatu.sh scan
```

### 4. Start Live Telemetry Watch & Real-Time Incident Detection
Monitor live process execution and authentication attempts in the background:

```bash
# Start watch in foreground (or run with sudo for full log visibility)
./uatu.sh watch
```

### 5. Launch Local Security Operations Dashboard
Start the local web dashboard bound strictly to `127.0.0.1:8443`:

```bash
# Start web dashboard
./uatu.sh serve
```
Open **http://127.0.0.1:8443/dashboard** in your browser. All requests are authenticated via the local security token stored at `./config/uatu_token` (mode 0600).

---

## 🛠️ CLI Command Reference

UATU provides a unified executable runner (`./uatu.sh`):

| Command | Description |
| :--- | :--- |
| `./uatu.sh doctor` | Run comprehensive system and environment diagnostics (10 categories). |
| `./uatu.sh status` | Display posture score, active findings count, and telemetry source health. |
| `./uatu.sh scan` | Enumerate 9 privilege escalation vectors and map attack paths (`[CONFIGURATION_ONLY]`). |
| `./uatu.sh watch [--verbose]` | Ingest live events from Linux auditd / auth log and correlate incidents in real time. |
| `./uatu.sh serve [--port=8443]` | Launch the FastAPI dark-theme dashboard and RBAC REST API on `127.0.0.1:8443`. |
| `./uatu.sh remediate <finding_id>` | Inspect and dry-run least-privilege permission correction for a finding. |
| `./uatu.sh remediate <finding_id> --apply` | Apply validated permission fix and record rollback snapshot. |
| `./uatu.sh rollback <finding_id>` | Exact atomic rollback to restore pre-remediation permissions. |
| `./uatu.sh report <item_id> --format=pdf` | Generate ReportLab PDF report for a finding or incident. |
| `./uatu.sh report <item_id> --format=json` | Export machine-readable JSON report with evidence hash. |
| `./uatu.sh test` | Execute automated test suite across all modules. |
| `./uatu.sh demo [--synthetic\|--live]` | Run structured demonstration (Scenario A synthetic or Scenario B live). |
| `./uatu.sh logs [--limit=N]` | Display immutable cryptographically hash-chained audit trail entries. |
| `./uatu.sh version` | Show UATU product version, architecture, and platform details. |
| `./uatu.sh install` | Deploy system auditd rules, secure directories, and systemd service (root). |
| `./uatu.sh uninstall` | Clean removal of services, audit rules, and state with confirmation (root). |

---

## 📚 Documentation Suite

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- [System Architecture](docs/ARCHITECTURE.md) — Subsystem specification and data flow
- [Installation Guide](docs/INSTALLATION.md) — Deployment instructions for Debian / Kali Linux
- [Configuration Reference](docs/CONFIGURATION.md) — Environment variables, directories, and policies
- [Telemetry Pipeline](docs/TELEMETRY.md) — Audit netlink, journald, and provenance invariants
- [Detection Engine](docs/DETECTION_ENGINE.md) — Correlation rules and incident state machine
- [Attack Path Engine](docs/ATTACK_PATH_ENGINE.md) — Directed graph modeling and bottleneck disruption
- [Response & Containment](docs/RESPONSE_ENGINE.md) — PID checks, cgroups v2 freeze, and nftables containment
- [Machine Learning Governance](docs/ML_GOVERNANCE.md) — Model registry, manifest checking, and trust states
- [API Security & RBAC](docs/API_SECURITY.md) — 5-tier access control, tokens, and browser headers
- [STRIDE Threat Model](docs/THREAT_MODEL.md) — System security boundaries and residual risk mitigations
- [Known Limitations](docs/KNOWN_LIMITATIONS.md) — Documented constraints and technical boundaries
- [Demonstration Guide](docs/DEMONSTRATION_GUIDE.md) — Step-by-step evaluator walkthrough
- [Demonstration Test Matrix](docs/DEMONSTRATION_TEST_MATRIX.md) — Capability mapping to demonstration steps
- [Expected Results](docs/DEMONSTRATION_EXPECTED_RESULTS.md) — Reference terminal logs and verification data
- [Final Engineering Audit](docs/FINAL_ENGINEERING_AUDIT.md) — Subsystem inventory and compliance review
- [Final Defect Register](docs/FINAL_DEFECT_REGISTER.md) — 10 cataloged defects and rectification log
- [Final Validation Report](docs/FINAL_VALIDATION_REPORT.md) — Verification matrix and gate sign-off

---

## 🧪 Live Prototype Demonstration (`demo.sh`)

To verify the complete vertical slice end-to-end on a Kali Linux machine:

```bash
# Run the automated end-to-end verification demo
chmod +x scripts/demo.sh
sudo bash scripts/demo.sh
```

The script demonstrates:
1. **D1:** Creating a writable script referenced by a scheduled service $\rightarrow$ running `./uatu.sh scan` $\rightarrow$ displaying the mapped attack path `[CONFIGURATION_ONLY]`.
2. **D2:** Generating 3 failed sudo authentication attempts in a test account $\rightarrow$ running detection evaluation $\rightarrow$ raising a correlated security incident (`Repeated Authentication Failures: sudo`).
3. **D3:** Running `./uatu.sh remediate <id>` (dry-run simulation) $\rightarrow$ applying the fix (`--apply`) $\rightarrow$ verifying permissions $\rightarrow$ executing `./uatu.sh rollback <id>` $\rightarrow$ verifying exact restoration.

---

## 🔒 Security Guarantees & Non-Negotiable Rules

1. **Linux-Native Only:** Windows and macOS execution paths are strictly rejected.
2. **Zero Fabrication:** Missing telemetry sources are explicitly labeled `UNAVAILABLE`. Counters never display synthetic or fake numbers.
3. **No Shell Injections:** All system operations use `core.command_runner.run_command()` with strict argument vector lists (`shell=False`).
4. **Configuration-Only Paths:** Attack graphs are strictly labeled `CONFIGURATION_ONLY` to avoid falsely claiming an active exploit has occurred.
5. **Least Privilege Remediation:** Remediation engines validate canonical paths, reject world-writable permissions (never `chmod 666`), enforce dry-run by default, and provide exact rollbacks.
6. **Local-Only API:** Dashboard and API bind to `127.0.0.1` only with token auth on all non-health routes.

For detailed limitations, see [LIMITATIONS.md](LIMITATIONS.md).
