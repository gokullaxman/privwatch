# UATU Linux Edition — Architectural Specification

```
+-----------------------------------------------------------------------------------+
|                            UATU LINUX EDITION (3.0.0)                             |
|        Intelligent Privilege Escalation Detection, Prevention & Attack-Path       |
|                                    Disruption                                     |
+-----------------------------------------------------------------------------------+
                                         │
     ┌───────────────────────────────────┼───────────────────────────────────┐
     │                                   │                                   │
     ▼                                   ▼                                   ▼
┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
│     EVIDENCE &        │   │    CORRELATION &      │   │    ATTACK-PATH &      │
│   TELEMETRY CORE      │   │   DETECTION ENGINE    │   │   DISRUPTION CORE     │
│                       │   │                       │   │                       │
│ - auditd Netlink      │   │ - Deduplication key   │   │ - NetworkX DiGraph    │
│ - /var/log/auth.log   │   │   (rule, pid, serial) │   │ - 12 Typed Node Types │
│ - Provenance Invariant│   │ - Multi-stage privesc │   │ - 15 Typed Edge Types │
│ - SHA-256 Event Hash  │   │ - State machine       │   │ - Bottleneck analysis │
│ - Zero Fake Telemetry │   │ - 7 Core Rule Vectors │   │ - CONFIGURATION_ONLY  │
└───────────────────────┘   └───────────────────────┘   └───────────────────────┘
     │                                   │                                   │
     └───────────────────────────────────┼───────────────────────────────────┘
                                         │
     ┌───────────────────────────────────┴───────────────────────────────────┐
     │                                   │                                   │
     ▼                                   ▼                                   ▼
┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
│   CONTAINMENT &       │   │     ML GOVERNANCE     │   │      PERSISTENCE      │
│   RESPONSE ENGINE     │   │     & TRUST GATES     │   │     & SECURITY API    │
│                       │   │                       │   │                       │
│ - PID-reuse guard     │   │ - manifest.json check │   │ - SQLite WAL Mode     │
│ - cgroups v2 freeze   │   │ - Trust States:       │   │ - SHA-256 Hash Chained│
│ - nftables containment│   │   APPROVED, REVOKED   │   │   Immutable Audit Log │
│ - Safe chmod rollback │   │ - Deterministic       │   │ - FastAPI 127.0.0.1   │
│ - OBSERVE_ONLY default│   │   rule fallback       │   │ - 5-Tier RBAC & CSP   │
└───────────────────────┘   └───────────────────────┘   └───────────────────────┘
```

---

## 1. Subsystem Architecture Overview

UATU is a strictly Linux-native security platform engineered for high-assurance privilege escalation detection, forensic reconstruction, and controlled disruption.

### 1.1 Core Principles
1. **Zero Fabrication**: All telemetry reflects verifiable operating system signals. Unavailable data sources are explicitly surfaced as `UNAVAILABLE`.
2. **Provenance Preservation**: Every event is immutable, cryptographically hashed, and tagged with its verified origin. Synthetic test data is strictly segregated.
3. **Safe Disruption**: Automated remediation enforces dry-run defaults, pre-execution backups, symlink validation, and verified inverse rollback actions.
4. **Non-Destructive Containment**: Process containment validates process start times against `/proc/<pid>/stat` to eliminate PID-reuse race conditions.

---

## 2. Telemetry and Provenance Invariants

### Ingestion Channels
- **Linux Audit Subsystem (`auditd`)**: Ingested via direct netlink socket or `ausearch -i` output parsing. Tracks `execve`, `setuid`, `setresuid`, `capset`, and watches on `/etc/sudoers`, `/etc/passwd`, `/etc/shadow`.
- **System Auth Logs (`auth.log` / `secure`)**: Continuous line parser extracting failed and successful authentication events for sudo, su, and ssh.
- **Process Filesystem (`/proc`)**: Direct POSIX inspection of process trees, capabilities (`getcap`), and user privileges.

### Provenance Guarantee
`UatuEvent` enforces cryptographic validation upon instantiation:
$$\text{integrity\_hash} = \text{SHA-256}(\text{canonical\_json}(\text{event\_fields}))$$
Attempting to create an event with `data_origin=LIVE_TELEMETRY` while marked as synthetic triggers a fatal `ValueError`.

---

## 3. Attack Graph Topological Modeling

Escalation pathways are modeled as directed multigraphs using NetworkX:
$$G = (V, E)$$
where $V$ represents typed security entities and $E$ represents typed relationships.

### Typed Node Vocabulary
`USER`, `GROUP`, `PROCESS`, `FILE`, `DIRECTORY`, `SERVICE`, `SYSTEMD_UNIT`, `CRON_JOB`, `SUDO_RULE`, `CAPABILITY`, `HOST`, `CONTAINER`.

### Typed Edge Vocabulary
`MEMBER_OF`, `OWNS`, `CAN_WRITE`, `CAN_EXECUTE`, `EXECUTED_BY`, `RUNS_AS`, `CAN_MODIFY`, `HAS_CAPABILITY`, `ESCALATES_TO`.

### Non-Exploited Guarantee
All generated paths carry level `CONFIGURATION_ONLY`. UATU never asserts an attack path has been traversed unless backed by chronological live telemetry events.

---

## 4. Response & Containment Architecture

The containment engine supports four operational modes:
1. `OBSERVE_ONLY` (Default): Evaluates and logs containment plans without host modification.
2. `ALERT_ONLY`: Broadcasts alerts to event bus; executes nothing.
3. `APPROVAL_REQUIRED`: Requires operator token and explicit confirmation.
4. `AUTHORIZED_AUTOMATIC`: Executes low-risk containment under pre-approved policies.

### Containment Mechanisms
- **Process Termination**: Validates PID > 2, verifies process start time from `/proc/<pid>/stat`, issues graceful `SIGTERM` followed by `SIGKILL` on timeout.
- **Process Freeze**: Freezes process via cgroups v2 (`cgroup.freeze = 1`), with fallback to `SIGSTOP`. Reversible via `thaw_process()`.
- **Network Containment**: Deploys temporary `nftables` drop rules with automatic timeout. Rejects loopback and default gateway targets.
