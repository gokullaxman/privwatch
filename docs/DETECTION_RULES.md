# PrivWatch 3.0 — Detection Rules & Heuristics Specification

PrivWatch 3.0 replaces naive text string matching with multi-factor, evidence-driven detection rules.

---

## 1. Red Team Audit Vectors

### SUID/SGID Privilege Escalation (`VECTOR_SUID`)
- **Detection Method:** Filesystem stat audit on standard binary directories (`/usr/bin`, `/bin`, `/sbin`, `/opt`).
- **Heuristic:**
  - `st_mode & S_ISUID` or `S_ISGID` on executables.
  - Evaluation of owner UID (UID 0 vs non-root).
  - Validation of write permissions on the binary itself (CRITICAL) and parent directory (HIGH).
  - Matching against the GTFOBins catalog for command execution escapes.
  - Filtering against distribution allowlists (`passwd`, `mount`, `sudo`, `su`) to highlight unusual utilities.

### Sudoers Misconfigurations (`VECTOR_SUDO`)
- **Detection Method:** Non-interactive `sudo -n -l` audit and static parsing of `/etc/sudoers` and `/etc/sudoers.d/*`.
- **Heuristic:**
  - NOPASSWD combined with wildcard `ALL` commands (CRITICAL).
  - NOPASSWD on shell escape utilities (`vim`, `find`, `python`, `less`, `bash`, `awk`) (HIGH).
  - Sudoers file permissions: owned by non-root or writable by unprivileged users (CRITICAL).

### Linux Capabilities Abuse (`VECTOR_CAPABILITIES`)
- **Detection Method:** Targeted `getcap` execution against system executable paths.
- **Heuristic:**
  - Detection of hazardous capabilities: `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_CHOWN`, `CAP_FOWNER`.
  - Explains technical exploitation mechanism without executing any exploit.

### Cron & Systemd Timer Abuse (`VECTOR_CRON`)
- **Detection Method:** Directory write auditing and script reference parsing.
- **Heuristic:**
  - Writable system cron directories (`/etc/cron.*`) (CRITICAL).
  - Writable `/etc/crontab` or systemd service units (CRITICAL).
  - Root scheduled jobs executing scripts writable by unprivileged users (CRITICAL).
  - Avoids false alarms on ordinary user crontabs.

### Password & Account Database Weaknesses (`VECTOR_PASSWD`)
- **Detection Method:** Stat inspection and account parsing of `/etc/passwd` and `/etc/shadow`.
- **Heuristic:**
  - Writable `/etc/passwd` or `/etc/shadow` by unprivileged users (CRITICAL).
  - Non-root accounts configured with UID 0 (CRITICAL).
  - Accounts with blank/empty password fields (CRITICAL).
  - Readable `/etc/shadow` or unshadowed backup files (HIGH).

### Kernel Vulnerability Assessment (`VECTOR_KERNEL`)
- **Detection Method:** Kernel release evaluation cross-referenced with native package manager metadata.
- **Heuristic:**
  - Evaluates running release against validated minimum/maximum advisory boundaries.
  - Queries local package manager (`dpkg`, `rpm`) to account for backported patches.
  - Never infers confirmed vulnerabilities solely from upstream version prefixes.

### PATH Hijacking (`VECTOR_PATH_HIJACKING`)
- **Detection Method:** Tokenized analysis of `$PATH` and system profile scripts.
- **Heuristic:**
  - Relative entries (`.` or empty components) in execution PATH (HIGH).
  - Writable directories appearing before standard system binaries (`/usr/bin`, `/bin`) in PATH (CRITICAL).

### SSH Configuration Security (`VECTOR_SSH_SECURITY`)
- **Detection Method:** Static inspection of `/etc/ssh/sshd_config`, host keys, and `authorized_keys`.
- **Heuristic:**
  - `PermitRootLogin yes` (HIGH).
  - `PermitEmptyPasswords yes` (CRITICAL).
  - Readable private host keys (CRITICAL).
  - World-writable user `authorized_keys` (CRITICAL).

### Container Privilege Boundaries (`VECTOR_CONTAINER_PRIVILEGE`)
- **Detection Method:** Container environment detection and device exposure audit.
- **Heuristic:**
  - Accessible `/var/run/docker.sock` with write permissions (CRITICAL).
  - Host block devices (`/dev/sda`, `/dev/vda`) exposed in container namespace (CRITICAL).
  - Accessible `/proc/kcore` within container (HIGH).

---

## 2. Blue Team Telemetry Rules

### Sudo Brute Force & Password Guessing
- **Rule:** `sliding_window_threshold_correlation`
- **Heuristic:** Ingests `SUDO_AUTH_FAIL` events from authentication telemetry. Accumulating 3 or more failed password attempts for the same username within a 10-minute window raises a HIGH severity alert.

### SUID Binary Execution
- **Rule:** `linux_audit_syscall_analysis`
- **Heuristic:** Analyzes `auditd` `EXECVE` or `SYSCALL` records where effective UID (`euid`) is 0 and real UID (`ruid`) is non-zero. Confirms true elevation rather than naive text matching.

### Daemon Shell Spawning (Web Shell Indicator)
- **Rule:** `process_tree_ancestry_audit`
- **Heuristic:** Monitors `/proc` and process telemetry for service accounts (`www-data`, `nobody`, `apache`, `nginx`) spawning interactive shells (`/bin/sh`, `/bin/bash`, `python`, `perl`).

### Executable Running from Temporary Directories
- **Rule:** `process_exe_path_audit`
- **Heuristic:** Identifies active processes whose executable path resides in world-writable temporary directories (`/tmp`, `/dev/shm`, `/var/tmp`).

---

## 3. Forensic Event Correlation Rules

### Sudo Brute Force -> Successful Root Execution
- **Correlation Logic:**
  1. Identifies a sequence of failed sudo events: `fail1.user == fail2.user == U`.
  2. Identifies a subsequent successful sudo command `succ.user == U` on the same hostname.
  3. Enforces chronological order: `fail_last.timestamp < succ.timestamp <= fail_last.timestamp + window`.
  4. Generates a CRITICAL severity `Incident`.

### Web Shell -> Privileged Binary Execution
- **Correlation Logic:**
  1. Identifies `SUSPICIOUS_SHELL_SPAWNED` event by daemon user with PID P1.
  2. Identifies subsequent `SUID_EXECUTION` or `ACTIVE_EUID_ELEVATION` by child process (`ppid == P1`) or same user within 30 minutes.
  3. Synthesizes a CRITICAL incident linking initial web compromise to local privilege escalation.

