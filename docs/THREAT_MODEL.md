# UATU Linux Edition — System Threat Model (STRIDE)

This document presents the STRIDE threat model, security boundaries, attacker assumptions, and residual risk mitigations for UATU Linux Edition.

---

## 1. System Security Boundary & Trust Assumptions

```
                    UNTRUSTED USER / PROCESS SPACE
      (Compromised accounts, malicious scripts, exploited binaries)
                                  │
══════════════════════════════════╪══════════════════════════════════
               SECURITY MONITORING BOUNDARY (UATU Core)
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
         Linux Kernel Telemetry            Local Storage & API
         - auditd Netlink / procfs         - SQLite 0600 (WAL)
         - Immutable append-only tables    - Localhost 127.0.0.1
         - Hash-chained audit logs         - Constant-time tokens
```

### Trust Assumptions:
1. **Linux Kernel Integrity**: The underlying Linux kernel and audit subsystem are not compromised by kernel rootkits (e.g. ring 0 compromises). UATU operates at the user-space/service boundary.
2. **Dedicated Storage Ownership**: `/var/lib/uatu` and `/var/log/uatu` are owned by `root:root` with mode `0700`.
3. **Execution Context**: The UATU background monitoring daemon runs as root (or dedicated service with capabilities `CAP_AUDIT_READ`, `CAP_AUDIT_CONTROL`, `CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`).

---

## 2. STRIDE Threat Analysis & Mitigations

### 2.1 Spoofing
- **Threat**: Attacker creates fake telemetry records or crafts synthetic events to misguide detection or trigger false alarms.
- **Mitigation**: Strict provenance validation (`UatuEvent.__post_init__`). Events marked synthetic cannot carry `LIVE_TELEMETRY` origins. Event payload is hashed with SHA-256 upon normalization.

### 2.2 Tampering
- **Threat**: Attacker tampers with historical incident records, evidence, or audit logs to conceal malicious activity.
- **Mitigation**:
  - SQLite tables enforce `ABORT` triggers preventing deletion or modification of evidence records.
  - Cryptographic hash chaining on `audit_trail` (`record_hash = SHA-256(prev_hash | payload)`), verifiable via `verify_audit_chain_integrity()`.
  - Machine learning models protected by SHA-256 manifest verification (`models/manifest.json`).

### 2.3 Repudiation
- **Threat**: Operator or attacker claims containment actions or remediation adjustments were executed without authorization.
- **Mitigation**: Every containment and remediation plan logs actor, timestamp, action type, pre-action state, and post-action verification to the immutable audit trail.

### 2.4 Information Disclosure
- **Threat**: Unprivileged local users inspect sensitive system telemetry, credentials, or API tokens.
- **Mitigation**:
  - API binds strictly to `127.0.0.1`.
  - Token files enforced with `0600` permissions.
  - SQLite database files enforced with `0600` permissions.
  - Tiered RBAC (`ADMIN`, `OPERATOR`, `ANALYST`, `AUDITOR`, `READ_ONLY`) prevents unprivileged inspection of administrative logs.

### 2.5 Denial of Service
- **Threat**: Attacker floods system with audit records to exhaust memory or triggers network containment against host loopback.
- **Mitigation**:
  - Rate limiting on API endpoints (120 requests/minute).
  - Network containment strictly rejects loopback (`127.0.0.1`, `::1`) and host default gateway.
  - Audit event deduplication merges redundant records per `(rule_name, pid, audit_serial)`.

### 2.6 Elevation of Privilege
- **Threat**: Attacker exploits UATU scripts or symlink targets during remediation to gain root access.
- **Mitigation**:
  - Zero `shell=True`, `os.system`, or shell strings across the entire codebase. Fixed safe PATH environment scrubbing.
  - Remediation strictly resolves canonical paths (`os.path.realpath`) and verifies ownership before chmod/chown operations.
  - Process containment verifies PID start times from `/proc/<pid>/stat` to eliminate PID-reuse attacks.
