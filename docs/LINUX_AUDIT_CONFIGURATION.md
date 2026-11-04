# PrivWatch 3.0 — Linux Audit Configuration & Policy Guide

## 1. Overview

The Linux Audit subsystem (`auditd` / `kauditd`) provides kernel-level telemetry for system call execution, privilege transitions, and file system accesses. PrivWatch 3.0 relies on Linux Audit to detect transient process execution and credential switches that evade standard `/proc` polling.

---

## 2. Kernel Syscalls Monitored by PrivWatch

PrivWatch 3.0 defines a dedicated audit policy in `config/audit.rules` covering the following critical security operations:

| Syscall | Architecture | Security Significance | ATT&CK Technique |
|---|---|---|---|
| `execve`, `execveat` | `x86_64`, `b32` | Captures every executed process with absolute binary path, arguments, and calling UID/EUID. | T1059 (Command Execution) |
| `setuid`, `setreuid`, `setresuid` | `x86_64`, `b32` | Monitors user ID transitions from unprivileged to root (UID 0). | T1548 (Abuse Elevation Control) |
| `setgid`, `setregid`, `setresgid` | `x86_64`, `b32` | Monitors group ID transitions to privileged groups (`shadow`, `sudo`, `wheel`). | T1548 (Abuse Elevation Control) |
| `capset` | `x86_64`, `b32` | Detects runtime manipulation of process Linux capability sets (`cap_setuid`, `cap_dac_override`). | T1548.001 (Setuid/Setgid) |
| `init_module`, `finit_module` | `x86_64`, `b32` | Detects ring-0 kernel module insertion (rootkits, driver abuse). | T1547.006 (Kernel Modules) |

---

## 3. Filesystem Watch Rules

PrivWatch monitors critical authentication, sudoers, and scheduled task paths for unauthorized writes and reads:

```bash
# Monitor changes to user databases
-w /etc/passwd -p wa -k privwatch_passwd_changes
-w /etc/shadow -p rwa -k privwatch_shadow_access
-w /etc/gshadow -p rwa -k privwatch_shadow_access
-w /etc/security/ -p wa -k privwatch_pam_changes

# Monitor sudoers configuration
-w /etc/sudoers -p wa -k privwatch_sudoers_changes
-w /etc/sudoers.d/ -p wa -k privwatch_sudoers_changes

# Monitor scheduled tasks (cron and timers)
-w /etc/crontab -p wa -k privwatch_cron_changes
-w /etc/cron.d/ -p wa -k privwatch_cron_changes
-w /etc/cron.daily/ -p wa -k privwatch_cron_changes
-w /var/spool/cron/ -p wa -k privwatch_cron_changes
-w /etc/systemd/system/ -p wa -k privwatch_systemd_changes
```

---

## 4. Installation and Deployment Procedure

PrivWatch 3.0 requires administrator approval to deploy audit rules. The application **never silently alters audit policy at startup**.

### Step 1: Install auditd Package
```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y auditd audispd-plugins

# Fedora / RHEL / CentOS
sudo dnf install -y audit
```

### Step 2: Deploy PrivWatch Rules
```bash
# Copy rules to system audit directory
sudo cp config/audit.rules /etc/audit/rules.d/privwatch.rules

# Load rules into active kernel audit subsystem
sudo augenrules --load

# Verify rules are loaded in kernel
sudo auditctl -l
```

### Step 3: Check Audit Health and Backlog
```bash
sudo auditctl -s
```
Output should indicate `enabled 1` and `flag 1`.

---

## 5. Telemetry Ingestion Without Auditd

If `auditd` is disabled or `/var/log/audit/audit.log` is unreadable, PrivWatch 3.0 operates in degraded telemetry mode:
- Live process execution monitoring falls back to periodic `/proc` sampling.
- **Telemetry Health Report explicitly warns:**
  > `Reliable kernel process execution monitoring is unavailable (auditd not readable or inactive). /proc polling alone cannot guarantee detection of transient execution.`
- Attackers executing transient commands (`whoami`, `cat /etc/shadow`) between polling intervals may evade detection.
