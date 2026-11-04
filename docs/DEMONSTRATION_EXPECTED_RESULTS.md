# UATU Linux Edition — Demonstration Expected Results

This document provides reference terminal logs, output structures, and data representations for validating UATU demonstration executions.

---

## 1. Scenario A: Synthetic Demonstration Reference Output

```text
========================================================================
  UATU LINUX EDITION — SCENARIO A: SYNTHETIC DEMONSTRATION
  [Mode: TEST FIXTURE SIMULATION — Zero Host Modification]
========================================================================
All data in this scenario is strictly tagged with data_origin=TEST_FIXTURE.

[*] Step 1: Normalizing and Ingesting Synthetic Security Events...
    Ingested 4 synthetic events into isolated evidence store.

[*] Step 2: Evaluating Detection Engine and Multi-Stage Correlation...
    Produced 1 correlated incident(s):
    - [CRITICAL] Multi-Stage Attack Sequence: attacker_test
      Attribution: {'user': 'attacker_test', 'pid': 5520, 'audit_serial': None, 'trigger_event': 'SUID_EXECUTION', 'failure_count': 3}
      Evidence Event IDs: ['evt_demo_fail_1', 'evt_demo_fail_2', 'evt_demo_fail_3', 'evt_demo_suid_exec']

[*] Step 3: Attack Path Intelligence Mapping (CONFIGURATION_ONLY)...
    Reconstructed 1 attack path(s):
    - Path: Transitive Root Escalation via Writable Scheduled Script (/opt/scripts/backup.sh)
      Level: CONFIGURATION_ONLY
      Chain: user:current -> script:/opt/scripts/backup.sh -> service:root_cron -> user:root
      Disruption: Remove write permissions on script: chmod 755 /opt/scripts/backup.sh

[*] Step 4: Remediation Plan Generation & Dry-Run Simulation...
    Target:            /opt/scripts/backup.sh
    Proposed Commands: ['chmod 755 /opt/scripts/backup.sh']
    Rollback Commands: ['chmod 0777 /opt/scripts/backup.sh']
    Simulation Status: SIMULATED (Dry Run)

[*] Step 5: Controlled Containment Plan (OBSERVE_ONLY Mode)...
    Action Type:   PROCESS_TERMINATION
    Status:        PLAN_GENERATED
    Mode Enforced: OBSERVE_ONLY

[*] Step 6: Verifying Immutable Cryptographic Audit Chain...
    Audit Chain Status: PASS (Intact & Chained)

[+] Scenario A: Synthetic Demonstration complete.
```

---

## 2. Diagnostics Gate (`./uatu.sh doctor`) Reference Output

```text
========================================================================
  UATU LINUX EDITION — SYSTEM DIAGNOSTICS (uatu doctor)
========================================================================
[PASS] Operating System Platform
       Category: ENVIRONMENT
       Message:  Linux native platform detected (Linux 6.8.0-kali1-amd64).

[PASS] Kernel Capabilities Support
       Category: ENVIRONMENT
       Message:  Kernel 6.8.0-kali1-amd64 supports required audit netlink, cgroups v2, and nftables features.

[PASS] Linux Audit Subsystem (auditd)
       Category: TELEMETRY
       Message:  Linux audit utilities (auditctl, ausearch) are installed and available in PATH.

[PASS] UATU Audit Rules
       Category: TELEMETRY
       Message:  System audit rules installed at /etc/audit/rules.d/uatu.rules.

[PASS] System Log Telemetry Accessibility
       Category: TELEMETRY
       Message:  Readable telemetry log sources found: /var/log/audit/audit.log, /var/log/auth.log

[PASS] SQLite Storage Permissions
       Category: STORAGE
       Message:  Database (/var/lib/uatu/uatu.db) mode 0600 and directory mode 0700 are secure.

[PASS] API Token Security
       Category: SECURITY
       Message:  API token found at /var/lib/uatu/token with strict 0600 permissions.

[PASS] cgroups v2 Process Containment
       Category: CONTAINMENT
       Message:  cgroups v2 hierarchy is mounted and active on the host.

[PASS] nftables Network Containment
       Category: CONTAINMENT
       Message:  nft binary is installed and available for packet filtering.

[PASS] ML Governance Manifest
       Category: ML_GOVERNANCE
       Message:  All 3 registered models verified against cryptographic manifest.

------------------------------------------------------------------------
Summary: 10 passed, 0 warnings, 0 failures.
[+] System meets operational requirements for UATU.
```

---

## 3. Web Dashboard Visual Verification

When accessing the web dashboard at `http://127.0.0.1:8443`:

1. **Overview Page**:
   - Posture Gauge: Calculates posture (0-100) from active scan findings.
   - Telemetry Source Status: Shows individual source health (GREEN = HEALTHY, YELLOW = DEGRADED, RED = UNAVAILABLE).
   - Real-time Incident Cards: Displays active correlated attacks.

2. **Attack Paths Page**:
   - Visualizes directed topological escalation paths.
   - Highlights the bottleneck node and recommended disruption action.
   - Banner prominently declares: `LEVEL: CONFIGURATION_ONLY (NEVER CLAIM EXPLOITED)`.

3. **Remediation Console**:
   - Allows selecting any finding.
   - Generates plan and consequence analysis.
   - Dry-run checkbox is checked by default.
   - Requires explicit confirmation to execute.
   - Offers 1-click rollback restoration.
