# UATU Linux Edition — Attack Path Intelligence Engine

This document details the directed graph modeling, topological escalation analysis, typed nodes and edges, bottleneck disruption calculation, and configuration-only constraints of the UATU Attack Path Engine.

---

## 1. Graph Modeling Architecture

The Attack Path Engine synthesizes findings from static scans and live configuration audits into directed multigraphs using NetworkX.

```
       [Unprivileged User (user:current)]
                      │
                      │ CAN_WRITE (CONFIGURATION_DERIVED)
                      ▼
       [Writable Script (/opt/scripts/backup.sh)]
                      │
                      │ EXECUTED_BY (CONFIGURATION_DERIVED)
                      ▼
       [Scheduled Service (service:root_cron)]
                      │
                      │ RUNS_AS (CONFIGURATION_DERIVED)
                      ▼
            [Root User (user:root)]
```

---

## 2. Graph Entity Vocabulary

### 2.1 Node Types (`NodeType`)
- `USER`: Local operating system user account (e.g. `user:current`, `user:root`).
- `GROUP`: System group (e.g. `group:sudo`, `group:shadow`).
- `PROCESS`: Running process instance with PID.
- `FILE`: Filesystem file object (scripts, binaries, configuration).
- `DIRECTORY`: Filesystem directory (e.g. PATH entries).
- `SERVICE`: System background service.
- `SYSTEMD_UNIT`: Systemd service or timer unit.
- `CRON_JOB`: Cron table entry or scheduled task.
- `SUDO_RULE`: Sudoers policy entry (NOPASSWD or wildcard).
- `CAPABILITY`: Linux file or process capability (e.g. `cap_setuid`).
- `HOST`: Endpoint host system.
- `CONTAINER`: Isolated container namespace.

### 2.2 Edge Types (`EdgeType`)
- `MEMBER_OF`: User membership in group.
- `OWNS`: User or group ownership of a filesystem resource.
- `CAN_WRITE`: User or group write permission to a file or directory.
- `CAN_EXECUTE`: Execution permission on a binary or script.
- `EXECUTED_BY`: Script invoked by a scheduled task or daemon.
- `RUNS_AS`: Execution context of a service or cron job.
- `CAN_MODIFY`: Ability to alter a service unit or configuration.
- `CAN_IMPERSONATE`: Transition from caller to target account.
- `HAS_CAPABILITY`: Binary granted elevated POSIX capabilities.
- `DEPENDS_ON`: Service or unit dependency relationship.
- `ESCALATES_TO`: Direct escalation from entity to root.

### 2.3 Edge Classifications (`EdgeClass`)
- `OBSERVED`: Edge established through direct, confirmed live kernel telemetry.
- `CONFIGURATION_DERIVED`: Edge established through verified static filesystem and policy parsing.
- `INFERRED`: Edge established through heuristic or correlation derivation.
- `HYPOTHETICAL`: Edge modeled for threat simulation and what-if analysis.

---

## 3. Disruption Bottleneck Analysis

For each valid escalation path leading to `user:root`, the engine calculates the **bottleneck node**:
- The single, highest-leverage entity whose removal or permission correction severs the escalation path with the lowest operational blast radius.
- Recommends an exact, typed disruption action (e.g., `chmod 755 /opt/scripts/backup.sh` or `setcap -r /usr/bin/python3`).

### Non-Negotiable Level Constraint
All generated paths carry level:
$$\text{level} = \text{"CONFIGURATION\_ONLY"}$$
UATU strictly prohibits claiming an attack path has been exploited without corresponding live telemetry evidence confirming the transition.
