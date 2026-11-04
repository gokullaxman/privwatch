# UATU Linux Edition — Detection Engine & Correlation Specification

This document specifies the deterministic detection rules, temporal correlation algorithms, incident deduplication mechanics, and incident lifecycle state transitions.

---

## 1. Detection Engine Architecture

The Detection Engine evaluates normalized Linux telemetry against deterministic security rules and correlates multi-event sequences into unified Incidents.

```
       Normalized Telemetry Events (UatuEvent)
                          │
                          ▼
             Chronological Sorting (UTC)
                          │
                          ▼
            Partition Strictly by User
             (Never cross-correlate users)
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
User-Centric Correlation          Standalone Anomaly Rules
- Sudo/SSH Failures (>=3)         - SUID execution (euid != uid)
- Brute force to success          - Critical file edits (/etc/shadow)
- Multi-stage escalations         - Elevated world-writable execution
                                  - Syscall privilege transitions
         │                                 │
         └────────────────┬────────────────┘
                          ▼
         Candidate Incidents Generated
                          │
                          ▼
            Strict Deduplication Key:
            (rule_name, pid, audit_serial)
                          │
                          ▼
        Correlated Incidents (Persisted to DB)
```

---

## 2. Detection Rule Catalog

### Rule 1: Repeated Authentication Failures (`RULE_REPEATED_AUTH_FAILURES`)
- **Condition**: $\ge 3$ failed sudo or ssh attempts for the same user within 300 seconds.
- **Severity**: HIGH
- **Hypothesis**: Active password spraying or brute-force attack against local user account.

### Rule 2: Sudo Brute Force Followed by Root Elevation (`RULE_SUDO_BRUTE_FORCE_SUCCESS`)
- **Condition**: User accumulates authentication failures immediately followed by a successful `sudo` execution.
- **Severity**: CRITICAL
- **Hypothesis**: Attacker successfully compromised user credentials or bypassed authentication barrier to achieve root privileges.

### Rule 3: SUID Privilege Elevation (`RULE_SUID_EXECUTION`)
- **Condition**: Process executes where `euid == 0` and `uid != 0` (or `SUID_EXECUTION` audit tag).
- **Allowlist Filter**: Standard benign system binaries (`sudo`, `su`, `passwd`, `mount`, `ping`, `fusermount`) are suppressed unless executing from world-writable locations.
- **Severity**: HIGH (CRITICAL if executing from `/tmp`, `/var/tmp`, `/dev/shm`).

### Rule 4: Critical Authentication Database Modification (`RULE_WATCHED_FILE_EDIT`)
- **Condition**: Audit watch triggers on `/etc/sudoers`, `/etc/sudoers.d`, `/etc/passwd`, or `/etc/shadow`.
- **Severity**: CRITICAL
- **Confidence**: 1.0 (Direct kernel audit watch).

### Rule 5: Elevated World-Writable Directory Execution (`RULE_WORLD_WRITABLE_EXECUTION`)
- **Condition**: Process executable resides in `/tmp`, `/var/tmp`, or `/dev/shm` and runs with effective UID 0 or SUID bit set.
- **Severity**: CRITICAL
- **Hypothesis**: Execution of dropped compiler artifact, pre-compiled exploit, or trojan binary.

### Rule 6: Unexpected Syscall Privilege Transition (`RULE_UNEXPECTED_PRIVILEGE_TRANSITION`)
- **Condition**: Direct invocation of `setuid`, `setreuid`, or `setresuid` transitioning from non-root UID to 0 without preceding authorized PAM or sudo session.
- **Severity**: CRITICAL

### Rule 7: Multi-Stage Attack Sequence (`RULE_MULTI_STAGE_ESCALATION_SEQUENCE`)
- **Condition**: User conducts repeated authentication failures or reconnaissance probes, followed within window by an anomalous SUID execution or watched file modification.
- **Severity**: CRITICAL

---

## 3. Incident Lifecycle State Machine

Incidents adhere to a formal lifecycle:

$$\text{NEW} \longrightarrow \text{TRIAGED} \longrightarrow \text{INVESTIGATING} \longrightarrow \text{CONTAINMENT\_PENDING} \longrightarrow \text{CONTAINED} \longrightarrow \text{RESOLVED}$$
$$\text{Any State} \longrightarrow \text{FALSE\_POSITIVE}$$

### State Transition Invariant:
Every status change requires:
- `operator`: Identity of operator or policy engine authorizing the change.
- `rationale`: Non-empty technical justification.
- `timestamp`: UTC ISO timestamp recorded in `lifecycle_history` and cryptographically audited.
