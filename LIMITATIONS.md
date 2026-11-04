# UATU Linux Edition — Architectural Scope & Limitations

This document explicitly defines the operational boundaries, threat coverage, and technical limitations of the **UATU Prototype Slice (v3.0.0)**.

---

## 1. Operating System & Architectural Boundaries

1. **Linux-Native Only**:
   - UATU relies directly on Linux kernel subsystems (`/proc`, netlink, capabilities, credentials, POSIX file permissions).
   - Windows, macOS, BSD, and WSL are strictly unsupported. Execution will abort upon platform inspection.

2. **Discretionary Access Control (DAC) Scope**:
   - The current prototype slice focuses on Linux Discretionary Access Control (DAC) vulnerabilities:
     - SUID/SGID executable flags.
     - Sudo configuration rules (`/etc/sudoers`, `/etc/sudoers.d/*`, `NOPASSWD`, wildcards).
     - Linux POSIX capabilities (`cap_setuid`, `cap_dac_override`, etc.).
     - Writable root scheduled tasks (`/etc/crontab`, `/etc/cron.*`, systemd service unit `ExecStart` binaries).
     - User database permissions (`/etc/passwd`, `/etc/shadow` ownership and group/other write permissions).
   - Mandatory Access Control (MAC) systems like SELinux policies, AppArmor profiles, and Smack rules are not fully modeled in this slice.

---

## 2. Telemetry & Ingestion Dependencies

1. **Linux Audit Netlink (`auditd`) Requirement**:
   - Process execution (`execve`, `execveat`) and credential transition (`setuid`, `setgid`, `setresuid`, `setresgid`) monitoring relies on the Linux Audit Framework.
   - If `auditd` or the kernel audit subsystem is unavailable, disabled, or unconfigured, execution monitoring is recorded as `UNAVAILABLE` in Telemetry Health. UATU does not synthesize or fabricate missing audit logs.

2. **Transient Process Visibility**:
   - If auditd rules (`uatu.rules`) are not loaded in the kernel, polling-based process tracking cannot capture transient short-lived processes (executing under 50ms).

3. **Authentication Log Formats**:
   - Ingestion supports standard Debian/Ubuntu/Kali `/var/log/auth.log`, systemd-journald, and RHEL `/var/log/secure`. Custom syslog formats without standard PAM tags may not trigger authentication failure heuristics.

---

## 3. Attack Graph Modeling Boundaries

1. **Strictly Configuration-Only**:
   - All attack pathways mapped by the graph engine are labeled strictly with `level: CONFIGURATION_ONLY`.
   - Mapped paths illustrate transitive escalation topology based on file permissions and service references. They do **not** claim that an exploit was successfully triggered or executed.

2. **Static Choke Points**:
   - Choke point identification calculates bottleneck nodes where least-privilege permission disruption stops the path. It does not predict dynamic in-memory privilege transitions (e.g. heap exploitation, ptrace injection).

---

## 4. Threat Detection & Response Limits

1. **No Kernel-Level Rootkit Detection**:
   - UATU is an endpoint privilege escalation detection and attack-path disruption platform, not a kernel memory integrity monitor.
   - Kernel rootkits modifying kernel function pointers (e.g., hooking `sys_call_table` or hiding processes via `task_struct` unlinking) are beyond the scope of this slice.

2. **Safe Disruption & Containment**:
   - All automated remediation actions are strictly reversible, typed `chmod` and `chown` operations targeting validated, canonical filesystem paths.
   - Destructive operations (killing arbitrary PIDs, network blackholing, unmounting filesystems) are strictly disabled in this slice to prevent denial of service.

