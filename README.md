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
| `./uatu.sh scan` | Enumerate 9 privilege escalation vectors and map attack paths (`[CONFIGURATION_ONLY]`). |
| `./uatu.sh watch` | Ingest live events from Linux auditd / auth log and correlate incidents in real time. |
| `./uatu.sh serve` | Launch the FastAPI dark-theme dashboard on `127.0.0.1:8443`. |
| `./uatu.sh remediate <finding_id>` | Inspect and dry-run least-privilege permission correction for a finding. |
| `./uatu.sh remediate <finding_id> --apply` | Apply validated permission fix and record rollback snapshot. |
| `./uatu.sh rollback <finding_id>` | Exact atomic rollback to restore pre-remediation permissions. |
| `./uatu.sh report <item_id> --format=pdf` | Generate ReportLab PDF report for a finding or incident. |
| `./uatu.sh report <item_id> --format=json` | Export machine-readable JSON report with evidence hash. |

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
