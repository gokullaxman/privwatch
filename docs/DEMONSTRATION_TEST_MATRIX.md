# UATU Linux Edition — Demonstration Test Matrix

This matrix maps each step in the UATU demonstration scenarios to the underlying security engineering requirement, implementation module, inputs, and expected outcomes.

---

| Step ID | Demonstration Step | Scenario | Module Under Test | Input Vector | Expected Outcome | Security Guarantee |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TM-01** | Diagnostic Gate | A & B | `core.diagnostics.SystemDiagnostics` | Host OS, Kernel, auditd, permissions | PASS on Linux; FAIL on Windows; WARN if optional tools missing | Non-Linux systems rejected |
| **TM-02** | Telemetry Ingestion | A | `core.event_schema.UatuEvent` | 4 Synthetic events (`TEST_FIXTURE`) | Stored in SQLite with provenance hash | Provenance invariants enforced |
| **TM-03** | Auth Failure Correlation | A & B | `detection.engine.DetectionEngine` | 3 failed sudo events within 300s window | 1 Incident generated: `Repeated Authentication Failures` | Strictly partitioned by user |
| **TM-04** | World-Writable Script | A & B | `modules.red_mode.cron_scanner` | Script chmod 0777 referenced by cron | 1 Finding generated: `Writable Script Referenced in Cron` | Resource ownership and mode captured |
| **TM-05** | Attack Path Mapping | A & B | `attack_path.graph_builder` | Finding `CRON` writable script | 1 Attack Path constructed: `user:current -> script -> service:root_cron -> user:root` | Marked `CONFIGURATION_ONLY` |
| **TM-06** | Remediation Plan | A & B | `modules.response.remediation_engine` | Target finding ID | Plan generated: `chmod 755 <target>`, backup taken | Original permissions captured |
| **TM-07** | Remediation Dry-Run | A & B | `modules.response.remediation_engine` | Plan execution with `dry_run=True` | Status `SIMULATED`, filesystem untouched | Read-only default enforced |
| **TM-08** | Remediation Execution | B | `modules.response.remediation_engine` | Plan execution with `confirmed=True` | Status `EXECUTED`, target chmod 0755 | Verification check verifies change |
| **TM-09** | Remediation Rollback | B | `modules.response.remediation_engine` | Rollback request for finding ID | Target restored to exact original mode 0777 | Zero residual permission drift |
| **TM-10** | Stock SUID Allowlist | B | `detection.engine.DetectionEngine` | Execution of `/usr/bin/sudo` | 0 Incidents generated | Zero false alarms on benign binaries |
| **TM-11** | Process Containment Guard | A & B | `modules.response.containment_engine` | Termination request for PID 1 | `ValueError: Safety violation: Refusing to target protected PID 1 <= 2` | Critical system stability protected |
| **TM-12** | PID Reuse Prevention | A & B | `modules.response.containment_engine` | Target PID with mismatched starttime | `RuntimeError: PID-reuse attack detected` | Recycled PIDs cannot be killed |
| **TM-13** | Network Containment Guard | A & B | `modules.response.containment_engine` | Containment request for `127.0.0.1` | `ValueError: Safety violation: Refusing network containment against loopback` | Host connectivity preserved |
| **TM-14** | Audit Trail Hash Chain | A & B | `core.storage.StorageEngine` | Sequential admin actions | `verify_audit_chain_integrity() == (True, None)` | Cryptographic non-repudiation |
| **TM-15** | Demonstration Cleanup | B | `scripts/demo_cleanup.sh` | Execution on demo directory | Host returned to 100% clean baseline | Zero test artifacts left on disk |
