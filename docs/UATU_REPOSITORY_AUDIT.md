# UATU Linux Edition - Comprehensive Repository Audit & Architectural Assessment

## 1. Executive Summary

This document establishes the formal Phase 0 engineering audit of the codebase (`https://github.com/gokullaxman/privwatch`) prior to its transformation into **UATU Linux Edition — Intelligent Privilege Escalation Detection, Prevention, and Attack-Path Disruption**.

The codebase currently stands at **PrivWatch 3.1.0**, featuring:
- A hardened, Linux-native execution baseline (Windows explicitly rejected via `LinuxPlatformValidator`).
- Deterministic Red Team audit scanners across 9 privilege escalation vectors.
- Blue Team telemetry ingestion from `auditd`, `/proc`, `/var/log/auth.log`, and `systemd journal`.
- A 4-tier Machine Learning pipeline (deterministic baseline, Isolation Forest/MAD anomaly scoring, Random Forest threat classification, and Markov sequential state transition modeling).
- An SQLite storage engine featuring SHA-256 tamper-evident administrative audit hash chaining.
- A REST API and Web Operations Dashboard protected by Bearer API Key authentication.
- A 69-test automated pytest verification suite.

### Core Architectural Gaps Identified for UATU:
While PrivWatch 3.1.0 excels at passive Red Team configuration auditing and advisory Blue Team log inspection, it fundamentally lacks:
1. **Attack-Path Intelligence**: Zero attack graph data structures, zero node/edge relation modeling, zero multi-hop exploitability analysis (e.g., Unprivileged User $\to$ Writable Privileged Script $\to$ Root Systemd Service).
2. **Policy-Driven Prevention**: No prevention policy engine, no enforcement mechanisms (AppArmor/SELinux integration, cgroups, namespaces, systemd security directives, seccomp filters), and no safe rollout modes (monitor-only vs. enforced).
3. **Attack Disruption & Active Containment**: No active disruption engine capable of terminating verified malicious processes, suspending suspect processes (`SIGSTOP`), isolating execution contexts into unshared namespaces, or applying network containment (`nftables`/`iptables` local drop) with anti-PID-reuse safeguards.
4. **Host Network Telemetry**: Zero socket-to-process correlation (no tracking of listening sockets, active outbound connections, or suspicious local binders).
5. **Multi-Dimensional Risk Assessment**: Existing system posture is calculated via a simplistic linear penalty formula ($100 - \sum \text{penalties}$), failing to decouple Privilege Impact, Exploitability, Exposure, Attack Path Length, and Evidence Quality.
6. **Unified UATU Security Dashboard**: The existing web UI contains only 4 basic tabs (Overview, Live Events, Findings, Reports) branded as PrivWatch, lacking Attack-Path Explorer, Prevention Center, Containment Operations, and Forensic Deep-Dive views.

---

## 2. Component-by-Component Inventory & Assessment

### 2.1 Core Subsystems (`core/`)

| File | Status | Technical Role | UATU Assessment & Gaps |
| :--- | :--- | :--- | :--- |
| `core/platform_validator.py` | Operational | Enforces Linux environment; terminates on non-Linux hosts (`UnsupportedPlatformError`). | Solid foundation. Must be extended to perform distribution-specific capability detection (eBPF availability, AppArmor vs SELinux presence, cgroups v2 mount status). |
| `core/command_exec.py` | Operational | Safe argument-array subprocess runner (`shell=False`, metacharacter rejection, timeouts). | Fully compliant with security directives. Reusable across all UATU containment and remediation modules. |
| `core/privileged_service.py` | Operational | Unix domain socket service (`/run/privwatch/privwatch.sock`, mode `0600`) with `SO_PEERCRED`. | Only supports 3 read-only RPC actions (`read_audit_log`, `read_auth_log`, `get_process_tree`). Lacks containment actions (`terminate_process`, `suspend_process`, `isolate_process`, `revoke_capability`). Needs transition to `/run/uatu/uatu.sock`. |
| `core/storage.py` | Operational | SQLite database engine with WAL mode, append-only policies, and SHA-256 audit hash chaining. | Contains tables for `events`, `findings`, `incidents`, `audit_trail`, `suppression_rules`. Missing tables for attack graph nodes/edges/paths, policies, containment operations, and network sockets. |
| `core/orchestrator.py` | Operational | Central coordinator for scans, telemetry collectors, and ML evaluators. | Currently tightly coupled to Red/Blue scan cycles. Must evolve into the UATU Engine coordinator managing continuous event routing, attack graph updating, and policy enforcement. |
| `core/models.py` | Operational | Typed dataclasses: `SecurityEvent`, `Finding`, `Incident`, `TelemetryHealth`, `SystemPosture`. | Missing data models for `AttackNode`, `AttackEdge`, `AttackPath`, `SecurityPolicy`, `ContainmentAction`, `RiskScoreCard`, and `NetworkSocketEvent`. `SystemPosture` scoring is uncalibrated. |
| `core/evidence.py` | Operational | Evidence provenance hashing (SHA-256) and credential sanitization regexes. | Functional. Will serve as the integrity backbone for the Forensic Investigation Engine. |
| `core/logger.py` | Operational | Colored ANSI terminal banners and structured logging. | Functional. Needs UATU branding and syslog/journald output routing. |

---

### 2.2 Telemetry Ingestion (`modules/blue_mode/telemetry/`)

| File | Status | Telemetry Source | UATU Assessment & Gaps |
| :--- | :--- | :--- | :--- |
| `audit_collector.py` | Operational | Linux Audit subsystem (`/var/log/audit/audit.log`). | Successfully parses `SYSCALL` and `EXECVE` records with EUID elevation checks. Lacks audit netlink direct socket stream (currently reads log file tail). |
| `auth_collector.py` | Operational | `/var/log/auth.log`, `/var/log/secure`. | Normalizes SSH, sudo, and PAM authentication events. Distribution discovery is partially hardcoded; needs dynamic systemd-journald fallback. |
| `journal_collector.py` | Operational | `journalctl` subprocess reader. | Reads recent priority logs. Needs structured JSON output parsing (`journalctl -o json`). |
| `process_collector.py` | Operational | `psutil` with `/proc` fallback. | Detects daemon shells, `/tmp` execution, and EUID mismatch. **Gap**: Misses sub-second transient executions when auditd is disabled; lacks cgroup and namespace extraction. |
| `health_monitor.py` | Operational | Evaluates readable status across system sources. | Reports coverage percentage. Warns on auditd absence. |
| **Network Telemetry** | **MISSING** | Host sockets, connections, listening ports. | **Completely absent**. No telemetry module exists to track open TCP/UDP sockets, listening daemons, or process-to-socket bindings. |

---

### 2.3 Privilege Escalation Scanners (`modules/red_mode/`)

| Scanner | Evaluated Vector | Current Status & Limitations |
| :--- | :--- | :--- |
| `suid_scanner.py` | SUID/SGID binaries, GTFOBins | Operational; verifies file ownership and parent directory permissions. |
| `sudo_scanner.py` | `/etc/sudoers`, NOPASSWD, wildcards | Operational; parses sudo rules without interactive password prompt. |
| `capabilities_scanner.py` | Linux file capabilities | Operational; inspects binary capabilities using `getcap`. |
| `cron_scanner.py` | Crontabs, cron directories, systemd timers | Operational; checks writable targets and script execution rights. |
| `passwd_scanner.py` | `/etc/passwd`, `/etc/shadow`, blank passwords | Operational; strictly evaluates canonical paths via `is_insecurely_writable()`. |
| `kernel_scanner.py` | Distribution CVEs (USN, DSA, RHSA) | Operational; queries package managers and backport patch advisories. |
| `path_scanner.py` | PATH environment relative directories | Operational; checks for `.` and writable PATH components. |
| `ssh_scanner.py` | `sshd_config`, private keys, `authorized_keys` | Operational; audits permissive file permissions and key exposure. |
| `container_scanner.py` | `docker.sock`, privileged container flags | Operational; detects container escape indicators. |

*Red Team scanners provide high-quality deterministic vulnerability identification. In UATU, their findings will serve as primary node and edge inputs into the Attack-Path Intelligence Engine.*

---

### 2.4 Machine Learning & Analytical Layer (`ml/` & `models/`)

| Subsystem | Components | Status & Integrity Assessment |
| :--- | :--- | :--- |
| `ml/features/` | `feature_schema.py`, `feature_extractor.py` | Operational. 32-dimensional canonical feature space covering identity, process ancestry, execution context, syntax, and temporal dynamics. |
| `ml/data/` | `schema.py`, `dataset_loader.py`, `curated_scenarios.py` | Operational. Scenario-based leakage-free partitioner (`LeakageFreeSplitter`), verified multi-host laboratory scenarios. |
| `models/` | `baseline_detector.py`, `isolation_forest.py`, `statistical_scorer.py`, `privilege_classifier.py`, `markov_sequence.py` | Operational. 4-tier model suite with deterministic baseline, Isolation Forest / MAD anomaly scorer, Random Forest classifier, and Markov sequence model. |
| `models/registry/` | `model_registry.py`, `.pkl` weights, `.json` metadata | Operational. Serializes models with SHA-256 fingerprinting and validation status checks. |
| `ml/validation/` | `validation_gate.py` | Operational. 10-point gate enforcing schema, zero leakage, CPU latency ($\le 25$ ms), and baseline accuracy parity. |
| `ml/explainability/`| `attribution.py`, `explanation.py` | Operational. Feature attribution (top-K % contributions), human-readable evidence narratives, composite risk calculator. |
| `ml/monitoring/` | `drift_detector.py` | Operational. Sliding-window Population Stability Index (PSI) and inference latency tracker. |

*Assessment: The ML layer is functional, tested, and scientifically defensible. For UATU, it requires signed model manifests (preventing local weight substitution) and integration with attack-path likelihood weights.*

---

### 2.5 Event Correlation & Forensics (`modules/timeline/`)

| File | Status | Technical Functionality | UATU Gaps |
| :--- | :--- | :--- | :--- |
| `event_correlator.py` | Partially Complete | Correlates 3 hardcoded scenarios: Sudo Brute Force, Web Shell to Privesc, SUID burst. | Lacks dynamic graph-based correlation; cannot correlate generalized multi-step sequences across arbitrary attack paths. |
| `timeline_builder.py` | Basic | Formats chronological timeline of events. | Output is primarily plain text and basic JSON; lacks forensic graph export and artifact chain-of-custody verification. |

---

### 2.6 Response & Remediation (`modules/response/`)

| File | Current Capabilities | UATU Requirements & Deficiencies |
| :--- | :--- | :--- |
| `remediation_engine.py` | Generates hardening plans for static findings (e.g. `chmod 0755` on writable scripts, `chmod u-s` on suid binaries). Captures exact bitmasks for atomic rollback. | **Passive only**. Does not contain active threat containment mechanisms: cannot kill/suspend rogue processes, isolate containers/cgroups, revoke live process capabilities, or block hostile network connections. |

---

### 2.7 Web Operations Dashboard & REST API (`web/app.py`)

- **Backend**: FastAPI with token-bucket rate limiting, Bearer API Key authentication (`PRIVWATCH_API_KEY`), administrative audit logging, and local binding (`127.0.0.1:8443`).
- **Dashboard UI**: Embedded Tailwind CSS / FontAwesome single-page HTML application.
- **Current Deficiencies**:
  - Branded as "PrivWatch 3.0".
  - Only contains 4 tabs: Overview, Live Monitoring, Findings, Reports.
  - Lacks pages for Attack-Path Explorer, Threat Detection, Incident Deep-Dive, Prevention Center, Containment Operations, and System Settings.
  - Interactive attack graph visualization (Cytoscape / vis.js or SVG canvas) is missing.

---

## 3. Comprehensive Defect & Gap Summary

1. **Absence of Attack-Path Intelligence Engine**: No graph representation of identities, permissions, assets, and transitive privilege transitions.
2. **Absence of Policy-Driven Prevention Engine**: No rule-based or LSM-integrated proactive enforcement to block unauthorized privilege elevation.
3. **Absence of Attack Disruption & Containment Engine**: No ability to terminate or freeze actively exploiting processes, isolate execution contexts, or apply network drops.
4. **Missing Network Telemetry**: Zero visibility into socket bindings, listening ports, and network-spawning binaries.
5. **Rigid Event Correlation**: Correlation is restricted to 3 pre-baked templates rather than dynamic graph and sequence traversal.
6. **Incomplete Privileged Service Capabilities**: Daemon only provides read-only log reading, lacking authorized containment operations.
7. **Dashboard Functional Scope Deficit**: UI lacks 7 of the 11 required enterprise operational views.
8. **Legacy Branding & Identity**: Naming, banners, service units, and paths still reference PrivWatch rather than UATU Linux Edition.
