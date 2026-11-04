# UATU Linux Edition — Final Defect Register & Rectification Log

This register catalogs all architectural, security, reliability, and conformance defects identified during the engineering audit, documenting their root cause, security impact, rectification details, and verification tests.

---

## Catalog of Rectified Defects

### DEF-01: Synthetic Test Fixtures Masquerading as Live Telemetry
- **Severity**: HIGH
- **Affected Subsystem**: `core/event_schema.py`
- **Root Cause**: Events instantiated with `DataOrigin.TEST_FIXTURE` could be processed identically to live events, creating the risk of synthetic test data appearing in live security views.
- **Security Impact**: Threat of false detections, synthetic tampering, and reporting distortion.
- **Rectification**: Implemented `SourceClassification` enum (`LIVE_AUDITD`, `LIVE_AUTH_LOG`, `LIVE_PROCESS_OBSERVATION`, `SYNTHETIC_TEST`, `REPLAYED_EVENT`, `IMPORTED_EVENT`). Added invariant enforcement in `UatuEvent.__post_init__` that raises `ValueError("Provenance Violation")` if synthetic events attempt to register under live origins or classifications.
- **Verification Test**: `tests/test_event_schema.py::test_synthetic_provenance_invariant_rejects_live_masquerade`

### DEF-02: Health State Oscillation & Flapping
- **Severity**: MEDIUM
- **Affected Subsystem**: `core/health.py`
- **Root Cause**: Binary transitions between `HEALTHY` and `UNAVAILABLE` caused telemetry state flapping during transient network or netlink latency.
- **Security Impact**: Misleading monitoring metrics, unnecessary alerts, and operator fatigue.
- **Rectification**: Added `RECOVERING` state and recovery hysteresis (`recovery_successes` counter with `recovery_threshold = 3`) before promoting degraded/unavailable sources to healthy.
- **Verification Test**: `tests/test_configuration_and_health.py::test_health_recovery_hysteresis`

### DEF-03: Attack Path Graph Lacked Node & Edge Type Granularity
- **Severity**: MEDIUM
- **Affected Subsystem**: `core/models.py`, `attack_path/graph_builder.py`
- **Root Cause**: Graph nodes and edges used informal strings instead of strictly typed domain models.
- **Security Impact**: Graph traversal ambiguities, incomplete attack path reconstruction, and improper disruption bottleneck identification.
- **Rectification**: Implemented 12 typed `NodeType` enums, 15 typed `EdgeType` enums, and `EdgeClass` (`OBSERVED`, `CONFIGURATION_DERIVED`, `INFERRED`, `HYPOTHETICAL`). Extended `AttackPathEngine` to model 6 distinct escalation topologies.
- **Verification Test**: `tests/test_attack_path_engine.py` (all tests pass)

### DEF-04: Incident Deduplication Flaw in Audit Syscall Sequences
- **Severity**: HIGH
- **Affected Subsystem**: `detection/engine.py`
- **Root Cause**: Linux audit generates multiple distinct records (SYSCALL, CWD, PATH, PROCTITLE) sharing the same timestamp and serial number for a single execution, triggering duplicate incident alerts.
- **Security Impact**: Alert flooding and operator distraction during active attacks.
- **Rectification**: Implemented strict deduplication key `(rule_name, pid, audit_serial)`. Events sharing the same key are merged into a single incident preserving ordered event references.
- **Verification Test**: `tests/test_detection_engine.py::test_detection_dedupe_20_records_one_pid_one_incident`

### DEF-05: Missing Elevated World-Writable Execution Detection
- **Severity**: HIGH
- **Affected Subsystem**: `detection/engine.py`
- **Root Cause**: Rule engine did not explicitly evaluate execution of elevated binaries originating from world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`).
- **Security Impact**: Missed detection of dropped privilege escalation exploits and trojans.
- **Rectification**: Added `RULE_WORLD_WRITABLE_EXECUTION` triggering critical incident when elevated process or SUID binary executes from world-writable paths.
- **Verification Test**: `tests/test_detection_engine.py::test_world_writable_elevated_execution_detection`

### DEF-06: Potential PID-Reuse Vulnerability in Process Containment
- **Severity**: CRITICAL
- **Affected Subsystem**: `modules/response/containment_engine.py`
- **Root Cause**: Terminating target PID without verifying its process start time allowed race conditions where a killed target was replaced by an innocent recycled PID.
- **Security Impact**: Inadvertent termination of legitimate user or system processes under rapid PID churn.
- **Rectification**: Added inspection of `/proc/<pid>/stat` field 22 (`starttime` clock ticks). Target process start time is verified against the recorded start time before sending signals; mismatch aborts immediately. Protected PID <= 2 and kernel threads.
- **Verification Test**: `tests/test_containment_engine.py::test_pid_reuse_prevention`, `test_process_termination_pid_guards`

### DEF-07: Unchecked Network Containment Targeting Critical Interfaces
- **Severity**: HIGH
- **Affected Subsystem**: `modules/response/containment_engine.py`
- **Root Cause**: Network isolation lacked checks preventing containment of loopback or default gateway IPs.
- **Security Impact**: Potential denial-of-service against the host itself or management connection loss.
- **Rectification**: Added strict IP validation via `ipaddress`. Prohibited containment of loopback (`127.0.0.1`, `::1`), multicast, host interfaces, and default gateway extracted from `/proc/net/route`.
- **Verification Test**: `tests/test_containment_engine.py::test_network_containment_guards`

### DEF-08: Missing Model Manifest Integrity Verification
- **Severity**: HIGH
- **Affected Subsystem**: `models/registry/model_registry.py`
- **Root Cause**: Model deserialization checked individual metadata JSON files but lacked validation against an authoritative master manifest.
- **Security Impact**: Threat of unauthorized model substitution or adversarial weight tampering.
- **Rectification**: Generated `models/manifest.json`. Implemented manifest cross-checking on `load_model`, rejecting any model whose hash does not match the manifest. Added trust state enforcement (`REVOKED` models rejected).
- **Verification Test**: `tests/test_model_loading.py::test_model_registry_manifest_verification`, `test_model_registry_rejects_revoked_model`

### DEF-09: Unbounded API Roles & Non-Constant-Time Token Comparison
- **Severity**: HIGH
- **Affected Subsystem**: `web/app.py`
- **Root Cause**: Standard string comparison (`==`) was susceptible to timing side-channels; API lacked tiered Role-Based Access Control (RBAC).
- **Security Impact**: Timing attacks against API tokens; unprivileged users could trigger destructive containment operations.
- **Rectification**: Enforced constant-time token comparison with `secrets.compare_digest`. Implemented 5-tier RBAC (`ADMIN`, `OPERATOR`, `ANALYST`, `AUDITOR`, `READ_ONLY`). Injected browser security headers (CSP, X-Frame-Options, X-Content-Type-Options).
- **Verification Test**: `tests/test_api_integration.py::test_security_headers_injected_on_responses`, `test_rbac_privilege_enforcement`

### DEF-10: Lack of System Diagnostics & Doctor Subcommand
- **Severity**: MEDIUM
- **Affected Subsystem**: `uatu_cli.py`, `core/diagnostics.py`
- **Root Cause**: Administrators had no automated way to pre-verify system prerequisites, kernel features, auditd status, and database permissions.
- **Security Impact**: Operational failures when running UATU in degraded or unconfigured environments.
- **Rectification**: Created `core/diagnostics.py` with 10 diagnostic categories. Exposed via `uatu.sh doctor` and `uatu_cli.py doctor` with structured PASS/WARN/FAIL output.
- **Verification Test**: `tests/test_diagnostics.py` (all tests pass)
