# UATU Linux Edition — Demonstration Guide

This guide walks security evaluators, incident responders, and engineers through executing and verifying UATU's privilege escalation detection, attack-path disruption, and remediation capabilities.

---

## 1. Demonstration Architecture

UATU provides two distinct demonstration scenarios:

| Scenario | Target Environment | Requirements | Purpose |
| :--- | :--- | :--- | :--- |
| **Scenario A: Synthetic** | Any host / CI environment | Python 3, unprivileged | Evaluates pipeline, normalization, correlation, graph generation, and rollback without host modification |
| **Scenario B: Live Linux** | Kali Linux / Debian VM | Linux kernel >= 4.18, sudo | Live telemetry collection, ausearch/auditd ingestion, real privilege escalation detection, dry-run remediation, and rollback |

---

## 2. Scenario A — Synthetic Demonstration (Quick Evaluation)

Scenario A runs entirely in user-space using isolated temporary databases and clearly tagged synthetic testing fixtures (`data_origin=TEST_FIXTURE`).

### Execution:
```bash
./uatu.sh demo --synthetic
# or
bash scripts/demo.sh --scenario=a
```

### What Scenario A Verifies:
1. **Provenance & Invariant Enforcement**: Ingestion of test fixtures without schema violations.
2. **Deterministic Correlation**: 3 failed authentication events for user `attacker_test` within temporal window correlate into a `HIGH` severity Incident.
3. **Attack Path Mapping**: Detection of writable maintenance script references and construction of directed NetworkX graphs tagged `CONFIGURATION_ONLY`.
4. **Remediation Console**: Least-privilege plan generation, consequences evaluation, dry-run execution, and rollback calculation.
5. **Controlled Containment**: Execution of process containment in `OBSERVE_ONLY` mode, generating an immutable plan without killing live processes.
6. **Forensic Integrity**: Cryptographic SHA-256 hash chaining verification of the persistent audit log.

---

## 3. Scenario B — Live Linux Demonstration (Kali Linux VM)

Scenario B executes a controlled, non-destructive privilege escalation and detection workflow against native Linux kernel telemetry.

### Prerequisites:
1. Kali Linux 2024.x or Debian 12 (x86_64).
2. Python 3.10+ installed.
3. Auditd installed (`sudo apt install -y auditd`).

### Step-by-Step Walkthrough:

#### Step 1: System Diagnostics
Run the diagnostic gate to verify system compatibility:
```bash
./uatu.sh doctor
```
*Expected: Platform PASS, Kernel PASS, Audit Subsystem PASS, ML Manifest PASS.*

#### Step 2: Install System Components (Optional / Recommended)
Install auditd rules and systemd service:
```bash
sudo ./uatu.sh install
```

#### Step 3: Run Baseline Scan
Run a full static vulnerability scan:
```bash
./uatu.sh scan
```
*Expected: Posture score calculated (0-100), stock Kali allowlisted binaries ignored, zero false positives.*

#### Step 4: Execute Full Live Demonstration
Run the automated end-to-end live demonstration:
```bash
sudo ./uatu.sh demo --live
```
*The script automatically sets up a disposable directory in `/tmp/uatu_live_demo`, creates a world-writable test script, triggers telemetry, verifies correlation into an Incident, generates an attack path, executes a dry-run remediation, applies chmod 0755, rolls back to original state, cleans up all artifacts, and validates cryptographic audit trail integrity.*

#### Step 5: Start Operations Dashboard
Launch the web console and API:
```bash
./uatu.sh serve --port=8443
```
Open your browser to `http://127.0.0.1:8443` and authenticate using the token displayed in `config/uatu_token`.

---

## 4. Verification and Teardown

To verify host cleanliness after evaluation:
```bash
bash scripts/demo_cleanup.sh
bash scripts/demo_verify.sh
```
All demonstration files in `/tmp` and test rules in `/etc/cron.d` are eradicated.
