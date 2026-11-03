# PrivWatch 3.0 — Telemetry Sources & Ingestion Specification

PrivWatch 3.0 enforces a strict **Real System Data Only** standard. Telemetry is collected directly from supported Linux kernel and operating system interfaces. When a telemetry source is absent or inaccessible, the platform explicitly reports the monitoring limitation rather than fabricating data.

---

## 1. Supported Telemetry Sources

| Source | Default Path / Interface | Target Artifacts | Fallback Behavior |
|--------|--------------------------|------------------|-------------------|
| **Authentication Subsystem** | `/var/log/auth.log` (Debian/Ubuntu)<br>`/var/log/secure` (RHEL/Fedora) | Sudo commands, auth failures, su switching, user account modifications. | Automatically discovers active distribution path; reports permission warning if unreadable. |
| **systemd Journal** | `journalctl -o json` | Structured system events, service unit executions, system priority alerts. | Gracefully disabled if journald is absent (e.g. containers, non-systemd distros). |
| **Linux Audit (auditd)** | `/var/log/audit/audit.log` or `ausearch` | High-fidelity syscall executions (`execve`, `capset`, `setuid`), file access watches on `/etc/shadow`. | Reports limitation: SUID execution detection falls back to live process inspection. |
| **Process Subsystem** | `/proc` & `psutil` | Live process tree, PID/PPID hierarchy, real vs effective UID discrepancies, executables in `/tmp`. | Fully operational on all Linux kernels; cross-platform fallback via psutil. |
| **Kernel Diagnostics** | `dmesg -T` or `/var/log/kern.log` | Ring-0 memory faults, kernel oops, refcount underflows, page table corruption. | Disabled if dmesg requires root/CAP_SYSLOG privileges. |
| **Filesystem & Metadata** | POSIX `stat`, `getcap`, `/etc/sudoers` | File permissions, SUID/SGID bits, POSIX file capabilities, sudoers rules. | Standard POSIX filesystem operations supported natively. |

---

## 2. Telemetry Health Assessment

The `TelemetryHealthMonitor` assesses system coverage by testing availability and read access for every telemetry interface:

- **Available & Readable:** Telemetry actively ingested.
- **Available but Permission Denied:** Host possesses the source, but current execution user lacks read permissions (e.g. unprivileged user reading `/var/log/audit/audit.log`).
- **Unavailable:** Source not present on this distribution.

The telemetry health report is exposed via `GET /api/v1/health` and rendered on the Web Dashboard.

