# UATU Linux Edition — Telemetry Subsystem & Ingestion Architecture

This document details the telemetry ingestion pipeline, kernel audit subsystem integration, event schema normalization, and cryptographic provenance guarantees.

---

## 1. Telemetry Sources

```
+-----------------------------------------------------------------------------------+
|                            LINUX KERNEL & SYSTEMD                                 |
+-----------------------------------------------------------------------------------+
         │                                   │                           │
         ▼                                   ▼                           ▼
┌──────────────────┐               ┌──────────────────┐        ┌──────────────────┐
│   auditd Netlink │               │  /var/log/auth   │        │     Linux /proc  │
│   (auditctl rules)│              │  (/var/log/secure│        │  (comm, stat,    │
│                  │               │   systemd journal│        │   cmdline, caps) │
└──────────────────┘               └──────────────────┘        └──────────────────┘
         │                                   │                           │
         ▼                                   ▼                           ▼
┌──────────────────┐               ┌──────────────────┐        ┌──────────────────┐
│  AuditLogReader  │               │  AuthLogReader   │        │ ProcfsCollector  │
└──────────────────┘               └──────────────────┘        └──────────────────┘
         │                                   │                           │
         └───────────────────────────────────┼───────────────────────────┘
                                             │
                                             ▼
                                  ┌───────────────────────┐
                                  │   TelemetryEngine     │
                                  │   - Provenance Tagging│
                                  │   - SHA-256 Hashing   │
                                  │   - Event Bus Publish │
                                  └───────────────────────┘
                                             │
                                             ▼
                                  ┌───────────────────────┐
                                  │ SQLite Evidence Store │
                                  │ (Append-Only Tables)  │
                                  └───────────────────────┘
```

### 1.1 Linux Audit Subsystem (`auditd`)
- **Rules File**: `config/audit/uatu.rules` (deployed to `/etc/audit/rules.d/uatu.rules`).
- **Target Syscalls**:
  - `execve` (arch=b64, arch=b32) with key `uatu_exec`.
  - `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid` with key `uatu_priv_esc`.
- **Target File Watches**:
  - `-w /etc/sudoers -p wa -k uatu_sudoers`
  - `-w /etc/sudoers.d/ -p wa -k uatu_sudoers`
  - `-w /etc/passwd -p wa -k uatu_passwd`
  - `-w /etc/shadow -p wa -k uatu_shadow`
- **Ingestion Mode**:
  Reads via `ausearch -i -ts recent` or directly from `/var/log/audit/audit.log`. Merges multi-line audit records sharing `msg=audit(ts:serial)` into unified events with complete process context (PID, PPID, UID, EUID, EXE, CWD, COMMAND).

### 1.2 System Authentication Logs
- Monitors `/var/log/auth.log` (Debian/Ubuntu/Kali) and `/var/log/secure` (RHEL/CentOS).
- Extracts:
  - `SUDO_AUTH_FAILURE`
  - `SUDO_AUTH_SUCCESS`
  - `SSH_AUTH_FAILURE`
  - `SSH_AUTH_SUCCESS`
  - `PAM_SESSION_OPEN` / `PAM_SESSION_CLOSE`

---

## 2. Event Schema & Provenance Classification

Every telemetry record is normalized into `UatuEvent`:

```python
@dataclass
class UatuEvent:
    event_id: str
    timestamp: datetime
    hostname: str
    source: str
    collection_method: CollectionMethod
    event_type: str
    severity: EventSeverity
    uid: Optional[int]
    euid: Optional[int]
    pid: Optional[int]
    ppid: Optional[int]
    exe: Optional[str]
    command: Optional[str]
    user: Optional[str]
    evidence: Dict[str, Any]
    provenance_class: ProvenanceClass       # OBSERVED, DERIVED, CORRELATED, ML_INFERENCE
    data_origin: DataOrigin                 # LIVE_TELEMETRY, HISTORICAL_LOG, TEST_FIXTURE
    source_classification: SourceClassification # LIVE_AUDITD, LIVE_AUTH_LOG, SYNTHETIC_TEST
    integrity_hash: str                     # SHA-256 of canonical event representation
```

### Invariant Checks
1. If `data_origin == LIVE_TELEMETRY` or `source_classification == LIVE_AUDITD`, the event must not contain synthetic markers or test tags. Violation raises `ValueError("Provenance Violation")`.
2. All timestamps must be timezone-aware UTC. Naive datetimes are strictly rejected.
3. Event confidence scores must reside strictly in range `[0.0, 1.0]`. Preserves `0.0` as an explicit signal.
