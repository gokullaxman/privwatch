# UATU Linux Edition — Known Limitations & Operational Boundaries

This document records the exact technical limitations, platform boundaries, and environmental constraints of UATU Linux Edition.

---

## 1. Operating System & Platform Boundaries

- **Linux Only**: UATU is engineered exclusively for Linux systems (specifically Debian-based distributions, Kali Linux 2024.x, and Ubuntu 22.04/24.04). Windows and macOS are strictly unsupported. Execution on non-Linux platforms immediately exits with an explicit error.
- **Kernel Version Requirement**: Linux kernel >= 4.18 is required for standard audit netlink, POSIX capabilities, and modern namespace support. Kernels >= 5.x are recommended for cgroups v2 unified hierarchies.

---

## 2. Telemetry and Audit Subsystem Constraints

- **Single Audit Dispatcher**: The Linux kernel supports only one active audit daemon at a time. If an existing EDR agent or daemon holds exclusive netlink locks, UATU operates in file ingestion mode (`/var/log/audit/audit.log` or `ausearch`) or systemd journal mode.
- **Audit Rule Buffering**: Under extreme burst activity (e.g. rapid process forks exceeding 10,000 execve/sec), the kernel audit backlog buffer (`-b 8192`) may drop records if backpressure occurs.

---

## 3. Containment & Remediation Boundaries

- **Irreversibility of Process Termination**: Terminating a process (`SIGKILL` / `SIGTERM`) terminates the process execution context irreversibly. Rollback of process termination is technically impossible in POSIX systems; UATU explicitly marks termination operations as irreversible.
- **cgroups v2 Hierarchy**: Process freezing requires cgroups v2 (`cgroup.freeze`). On older legacy systems using cgroups v1, UATU automatically falls back to `SIGSTOP` / `SIGCONT`, which pauses the target process but does not freeze kernel workqueues.
- **Root Filesystem Remediation**: Remediation operations that alter file permissions or ownership require root privileges. In user-space execution, remediation plans can only be simulated (dry-run mode).

---

## 4. Machine Learning & Behavioral Inference

- **Anomaly != Malicious**: Machine learning inference scores represent statistical deviation from baseline distributions, not confirmed maliciousness. UATU never executes automated destructive containment based solely on ML anomaly scores; high-impact containment requires deterministic rule confirmation or explicit administrative authorization.
- **Concept Drift**: Behavioral models require periodic baseline updates to adapt to legitimate system updates and software installations.
