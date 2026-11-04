# UATU Linux Edition - Architectural & Functional Defect Register

This register documents all discovered architectural, functional, security, and integrity defects identified during the Phase 0 audit of the codebase, detailing their technical descriptions, security impacts, severity levels, reproduction procedures, required corrections, and verification test strategies.

---

### DEF-UATU-01: Total Absence of Attack-Path Intelligence and Transitive Privilege Graph

- **Component**: Core / Analytics (Missing subsystem `attack_path/`)
- **Severity**: CRITICAL
- **Technical Description**: The system identifies static misconfigurations independently (e.g. finding A: script is writable, finding B: sudo rule exists) but lacks an attack graph modeling relationships between Users, Groups, Binaries, Files, Services, and Capabilities. It cannot compute transitive attack paths (e.g., `developer` $\to$ write `backup.sh` $\to$ executed by root cron $\to$ root shell).
- **Security Impact**: High-risk privilege escalation chains remain invisible if each individual node appears below critical severity thresholds. Security teams cannot prioritize root causes that disrupt multiple attack paths.
- **Reproduction Procedure**:
  1. Create user `alice`.
  2. Create a script `/opt/backup.sh` owned by `alice` but executed by a root systemd service.
  3. Run PrivWatch scan.
  4. *Observed*: Finding reports `/opt/backup.sh` is writable. No attack path linking user `alice` to root privilege acquisition is discovered.
- **Required Correction**: Implement `attack_path/graph.py`, `nodes.py`, `edges.py`, `traversal.py`, and `prioritization.py` constructing a directed acyclic attack graph with shortest-path traversal, cycle handling, exploitability scoring, and graph snapshot change detection.
- **Verification Test**: `tests/test_attack_path_engine.py::test_transitive_script_to_root_attack_path`
- **Status**: PLANNED (Phase 4)

---

### DEF-UATU-02: Total Absence of Active Threat Disruption and Containment Engine

- **Component**: Response Engine (`modules/response/`, Missing `response/containment.py`)
- **Severity**: CRITICAL
- **Technical Description**: The platform only contains a passive `RemediationEngine` that modifies static file permissions. It completely lacks runtime containment capabilities: it cannot terminate confirmed malicious processes, suspend suspicious processes via `SIGSTOP`, isolate processes into unshared namespaces or restricted cgroups, revoke capabilities via `setcap`, or apply network drops.
- **Security Impact**: When an active privilege-escalation exploit is detected (e.g. a webshell spawning a root shell), the platform generates alerts but cannot stop the adversary from executing secondary payloads, stealing credentials, or destroying evidence.
- **Reproduction Procedure**:
  1. Ingest an event representing confirmed malicious execution (`CONFIRMED_MALICIOUS`, PID 9999).
  2. Inspect available response actions in `remediation_engine.py`.
  3. *Observed*: Only file permission hardening commands (`chmod`) are supported. Zero process containment or active attack disruption capabilities exist.
- **Required Correction**: Implement `response/containment.py` providing verified process termination (`SIGTERM`/`SIGKILL` with independent verification), process suspension (`SIGSTOP`), process namespace isolation (`unshare`/cgroups), network containment (`nftables`/`iptables` drop rules), and anti-PID-reuse safeguards.
- **Verification Test**: `tests/test_containment_engine.py::test_safe_process_suspension_and_termination`
- **Status**: PLANNED (Phase 9)

---

### DEF-UATU-03: Absence of Policy-Driven Prevention Framework

- **Component**: Core / Security (Missing subsystem `prevention/`)
- **Severity**: HIGH
- **Technical Description**: PrivWatch operates purely reactively (detection and post-exploitation reporting). It possesses no policy engine defining restricted privilege transitions, protected filesystem resources, allowed administrative operations, or proactive enforcement mechanisms.
- **Security Impact**: Organizations cannot enforce security baselines or proactively block known privilege escalation transitions before exploitation occurs.
- **Reproduction Procedure**:
  1. Review system configuration for policy definitions.
  2. *Observed*: No policy files, schema, evaluator, or enforcement hooks exist.
- **Required Correction**: Implement `prevention/policy.py`, `evaluator.py`, and `enforcement/` supporting declarative policies (e.g., blocking service accounts from spawning shells, restricting capability inheritance, locking sensitive configs) with 4-phase safe rollout (monitor-only, policy evaluation, approval-required, enforced).
- **Verification Test**: `tests/test_prevention_engine.py::test_policy_evaluation_and_enforcement_gate`
- **Status**: PLANNED (Phase 8)

---

### DEF-UATU-04: Lack of Host Network Socket Telemetry

- **Component**: Telemetry Ingestion (`modules/blue_mode/telemetry/`)
- **Severity**: HIGH
- **Technical Description**: Telemetry collectors gather process, audit, and authentication events, but collect zero host network information. There is no tracking of listening sockets, active inbound/outbound connections, or socket-to-process PID mappings.
- **Security Impact**: Privileged backdoors binding to local ports (e.g. netcat listeners), reverse shells connecting to external C2 IP addresses, and rogue administrative services are entirely invisible to detection and correlation engines.
- **Reproduction Procedure**:
  1. Inspect `modules/blue_mode/telemetry/`.
  2. *Observed*: Modules exist for `audit`, `auth`, `journal`, and `process`. Zero network telemetry module exists.
- **Required Correction**: Implement `telemetry/network/socket_collector.py` reading `/proc/net/tcp`, `/proc/net/udp`, and `ss` outputs to map sockets to PIDs, inode references, remote IPs, and local listening ports.
- **Verification Test**: `tests/test_network_telemetry.py::test_socket_to_process_correlation`
- **Status**: PLANNED (Phase 2)

---

### DEF-UATU-05: Rigid, Non-Generalizable Event Correlation Logic

- **Component**: Timeline / Correlation (`modules/timeline/event_correlator.py`)
- **Severity**: MEDIUM
- **Technical Description**: `EventCorrelator` contains only three hardcoded, rigid correlation rules (`_correlate_sudo_brute_to_success`, `_correlate_webshell_to_privesc`, `_correlate_suid_burst`). Any multi-stage attack sequence diverging from these three static templates is completely ignored.
- **Security Impact**: Attack sequences involving novel steps (e.g., failed SSH login $\to$ cron edit $\to$ capability grant $\to$ root spawn) fail to correlate into unified incidents, leaving SOC analysts with fragmented, unlinked alerts.
- **Reproduction Procedure**:
  1. Feed events: `SSH_AUTH_FAIL` $\to$ `SSH_LOGIN` $\to$ `CRON_MODIFIED` $\to$ `ACTIVE_EUID_ELEVATION`.
  2. Execute `EventCorrelator.detect_attack_patterns()`.
  3. *Observed*: Zero incidents generated because the pattern does not match the 3 hardcoded rules.
- **Required Correction**: Implement a generalized, graph-driven `correlation/engine.py` using process tree ancestry (PPID-to-PID chaining), session token tracking, and temporal proximity windows to reconstruct arbitrary attack chains.
- **Verification Test**: `tests/test_correlation_engine.py::test_generalized_multistage_incident_reconstruction`
- **Status**: PLANNED (Phase 6)

---

### DEF-UATU-06: Uncalibrated, Arbitrary System Posture Scoring

- **Component**: Core Models (`core/models.py: SystemPosture.calculate`)
- **Severity**: MEDIUM
- **Technical Description**: Posture score uses a crude linear deduction formula: `100 - (25*crit + 10*high + 3*med + 1*low)`. It does not evaluate Privilege Impact, Exploitability, Attack Path Reachability, Exposure, or Evidence Reliability as distinct orthogonal dimensions.
- **Security Impact**: Scores do not reflect actual system risk. A system with 4 low findings receives a 96 score even if they form a complete exploitable privilege escalation chain, while a system with 4 isolated critical findings receives a 0 score regardless of actual feasibility.
- **Reproduction Procedure**:
  1. Calculate score with 4 critical findings: score is 0.
  2. Calculate score with a 3-step exploitable attack path of medium findings: score is 91.
- **Required Correction**: Implement `risk/scoring.py` and `risk/prioritization.py` computing decoupled metrics: Severity, Confidence, Exploitability, Impact, Attack-Path Proximity, and Composite Risk Index $[0, 100]$.
- **Verification Test**: `tests/test_risk_engine.py::test_multidimensional_risk_scoring`
- **Status**: PLANNED (Phase 7)

---

### DEF-UATU-07: Incomplete Privileged Service RPC Capabilities

- **Component**: Privileged Service (`core/privileged_service.py`)
- **Severity**: HIGH
- **Technical Description**: The daemon listening on `/run/privwatch/privwatch.sock` allowlists only 3 read-only RPC actions (`read_audit_log`, `read_auth_log`, `get_process_tree`). It lacks RPC commands for executing authorized containment operations, applying firewall drops, or managing prevention policies.
- **Security Impact**: In a true least-privilege architecture, the web dashboard and CLI cannot execute containment without either running the entire application as root or implementing secure privileged RPC methods.
- **Reproduction Procedure**:
  1. Send RPC request `{"action": "terminate_process", "params": {"pid": 1234}}` to privileged socket.
  2. *Observed*: Request rejected: `Action 'terminate_process' not in allowlist`.
- **Required Correction**: Rename and upgrade service to `privileged_service/server.py` (`/run/uatu/uatu.sock`), expanding allowlisted actions to include `terminate_process`, `suspend_process`, `isolate_process`, `apply_firewall_containment`, and `enforce_policy`, guarded by peer PID verification and administrative authentication.
- **Verification Test**: `tests/test_privileged_service.py::test_privileged_containment_rpc_lifecycle`
- **Status**: PLANNED (Phase 10)

---

### DEF-UATU-08: Dashboard UI Scope Deficit & Legacy Naming

- **Component**: Web Interface (`web/app.py`)
- **Severity**: MEDIUM
- **Technical Description**: The web dashboard is branded as "PrivWatch 3.0" and features only 4 tabs (Overview, Live Events, Findings, Reports). It lacks pages for Attack-Path Explorer, Threat Detection, Incident Investigation, Prevention Center, Containment Center, ML Intelligence, and System Settings.
- **Security Impact**: Security operators cannot visualize discovered attack graphs, review pending prevention approvals, trigger verified containment, or inspect forensic process trees from the UI.
- **Reproduction Procedure**:
  1. Open dashboard in browser (`http://127.0.0.1:8443`).
  2. *Observed*: Title is "PrivWatch", only 4 tabs are present, no attack graph canvas exists.
- **Required Correction**: Transform dashboard into the **UATU Centralized Security Operations Dashboard** with all 11 required tabs, interactive attack-path visualization, and real-time backend API integration.
- **Verification Test**: `tests/test_api_integration.py::test_uatu_dashboard_endpoints`
- **Status**: PLANNED (Phase 11)

---

### DEF-UATU-09: Database Schema Missing UATU Entities

- **Component**: Storage Engine (`core/storage.py`)
- **Severity**: HIGH
- **Technical Description**: SQLite database schema only defines `events`, `findings`, `incidents`, `audit_trail`, and `suppression_rules`. Tables for attack graph nodes, edges, attack paths, security policies, policy evaluations, and containment actions do not exist.
- **Security Impact**: Attack paths, prevention policies, and containment audit trails cannot be persisted across restarts, breaking incident forensics and compliance auditing.
- **Reproduction Procedure**:
  1. Inspect `core/storage.py: init_db()`.
  2. *Observed*: No schema definitions for graph nodes, edges, paths, policies, or containment history.
- **Required Correction**: Update schema with migration routines adding `attack_nodes`, `attack_edges`, `attack_paths`, `policies`, `policy_evaluations`, `containment_records`, and `network_sockets`.
- **Verification Test**: `tests/test_storage_evidence_store.py::test_storage_initializes_all_tables`
- **Status**: CLOSED (Phase 1)
- **Resolution Summary**: `core/storage.py` was fully upgraded with 23 entity tables, forward migration logic, append-only triggers, and zero-confidence preservation. Verified with `test_storage_evidence_store.py`.

---

### DEF-UATU-13: Inconsistent Event Schema Across Telemetry Subsystems (D1)

- **Component**: Core Models & Telemetry Ingestion (`core/models.py`, `core/event_schema.py`)
- **Severity**: HIGH
- **Technical Description**: Security telemetry lacked a unified, versioned, cryptographic schema with provenance classes, data origins, and collection method enums.
- **Verification Test**: `tests/test_event_schema.py`
- **Status**: CLOSED (Phase 1)
- **Resolution Summary**: Implemented `core/event_schema.py` with `UatuEvent`, monotonic IDs, UTC timezone-aware validation, explicit enums (`ProvenanceClass`, `DataOrigin`, `CollectionStatus`, `CollectionMethod`), confidence range enforcement, and canonical SHA-256 integrity hashing.

---

### DEF-UATU-14: Insecure External Command Execution Safety (D2)

- **Component**: Command Execution (`core/command_exec.py`, `core/command_runner.py`)
- **Severity**: HIGH
- **Technical Description**: Potential exposure to command injection, shell metacharacters, unvalidated timeouts, or shell=True invocations across modules.
- **Verification Test**: `tests/test_command_runner_guard.py`, `tests/test_platform_and_command_runner.py`
- **Status**: CLOSED (Phase 1)
- **Resolution Summary**: Implemented `core/command_runner.py` with `CommandRunner`, strict `shell=False`, NUL byte rejection, fixed safe `PATH`, `LC_ALL=C`, mandatory timeouts, and frozen `CommandResult`. Enforced by AST guard test `test_command_runner_guard.py` verifying 0 shell=True or os.system/popen usages.

---

### DEF-UATU-15: Loss of Zero-Confidence Telemetry Values (D7)

- **Component**: Storage Engine (`core/storage.py`)
- **Severity**: MEDIUM
- **Technical Description**: `get_events` previously evaluated `if r['confidence']:` which coerced `confidence=0.0` to default `1.0`, corrupting unverified anomaly telemetry.
- **Verification Test**: `tests/test_storage_evidence_store.py::test_storage_confidence_zero_preservation`
- **Status**: CLOSED (Phase 1)
- **Resolution Summary**: Fixed confidence checks in `core/storage.py` to `if r['confidence'] is not None`, preserving 0.0 accurately.

---

### DEF-UATU-16: Database Tamper-Resistance & Audit Integrity (D6)

- **Component**: Storage Engine (`core/storage.py`)
- **Severity**: HIGH
- **Technical Description**: Evidence tables lacked immutable database triggers to prevent UPDATE/DELETE modifications, and audit log lacked cryptographic verify_chain() reporting the exact tampered row.
- **Verification Test**: `tests/test_storage_evidence_store.py::test_storage_event_immutability_triggers`, `test_storage_audit_hash_chain_verification_and_tamper_detection`
- **Status**: CLOSED (Phase 1)
- **Resolution Summary**: Added SQLite triggers raising ABORT on UPDATE/DELETE on `events` and `evidence_objects`. Added SHA-256 hash chaining with `verify_chain()` detecting tampering and identifying the exact broken row index.

---

### DEF-UATU-10: ML Models Lack Signed Manifests Against Hostile Replacement

- **Component**: Model Governance (`models/registry/model_registry.py`)
- **Severity**: MEDIUM
- **Technical Description**: Model weights are verified against a SHA-256 hash stored in an adjacent plain-text JSON metadata file. An attacker with local write access to `/models/metadata/` could replace both the `.pkl` weight file and the `.json` hash simultaneously without detection.
- **Security Impact**: Integrity verification can be bypassed if an adversary tampers with both the artifact and its adjacent unsigned metadata.
- **Reproduction Procedure**:
  1. Replace `isolation_forest_v3_1.pkl` with arbitrary model.
  2. Compute SHA-256 of new file and update `isolation_forest_v3_1.json`.
  3. Load model via `ModelRegistry.load_model()`.
  4. *Observed*: Model loads successfully because the hash matches the tampered metadata.
- **Required Correction**: Implement HMAC-SHA256 or cryptographic signature verification on model manifests using a local service secret key or root-owned trust store (`/etc/uatu/trust_store.pem`).
- **Verification Test**: `tests/test_model_governance.py::test_signed_model_manifest_verification`
- **Status**: PLANNED (Phase 5)

---

### DEF-UATU-11: Transient Process Telemetry Blind Spot When Auditd Is Inactive

- **Component**: Process Telemetry (`modules/blue_mode/telemetry/process_collector.py`)
- **Severity**: MEDIUM
- **Technical Description**: When kernel `auditd` is disabled, the system falls back to polling `/proc` via `psutil`. Short-lived processes executing and terminating in under 50 milliseconds (e.g. `suid` helper scripts or rapid command exploits) completely escape detection.
- **Security Impact**: Attackers can execute sub-second privilege transitions during polling intervals without generating process telemetry.
- **Reproduction Procedure**:
  1. Stop `auditd`.
  2. Execute a 10ms python command that switches UID and exits.
  3. *Observed*: Process collector polling interval misses the event.
- **Required Correction**: Provide explicit capability detection and degraded-mode warnings; integrate Linux netlink audit socket (`audit_collector.py`) and Linux process connector (`PROC_CN_MCAST` / eBPF where available) to capture process lifecycles event-driven rather than purely polling.
- **Verification Test**: `tests/test_process_telemetry.py::test_degraded_telemetry_reporting`
- **Status**: PLANNED (Phase 2)

---

### DEF-UATU-12: Legacy Project Identity, Service Units, and Branding

- **Component**: Root / CLI / Packaging (`privwatch.py`, `systemd/`, `README.md`)
- **Severity**: LOW
- **Technical Description**: CLI entry point is `privwatch.py`, service unit is `privwatch-collector.service`, runtime socket is `/run/privwatch/`, and documentation exclusively refers to PrivWatch 3.0/3.1.
- **Security Impact**: Inconsistent naming causes administrative confusion, conflicts with existing systemd service namespaces, and misrepresents the platform's transformed scope.
- **Reproduction Procedure**:
  1. Inspect root entry point and systemd definitions.
  2. *Observed*: All binaries and configuration files use `privwatch` prefix.
- **Required Correction**: Implement unified `uatu.py` CLI (preserving `privwatch.py` as a backwards-compatible alias), update systemd service unit to `systemd/uatu.service`, update socket to `/run/uatu/uatu.sock`, and update documentation suite.
- **Verification Test**: `tests/test_cli_and_service.py::test_uatu_cli_and_service_definitions`
- **Status**: PLANNED (Phase 13)

