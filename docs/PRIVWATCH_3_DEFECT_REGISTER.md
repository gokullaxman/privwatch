# PrivWatch 3.0 — Comprehensive Defect Register

**Date:** 2026-11-04  
**Auditor:** Principal Linux Security & Software Architect  
**Scope:** Complete PrivWatch 3.0 Codebase Audit  

---

## Executive Summary

A comprehensive repository-wide audit was conducted across all 65 Python source files, configuration files, test suites, and documentation. The audit identified 12 defects spanning unsafe shell execution, cross-platform / Windows compatibility remnants, flawed Linux permission semantics, simplistic kernel vulnerability evaluation, unauthenticated REST API endpoints, storage integrity flaws, and lack of daemon privilege separation.

Each defect has been classified by severity, root cause, reproduction conditions, expected vs. actual behavior, and exact rectification implementation.

---

## Defect Inventory

| Defect ID | Affected Module / File | Severity | Summary | Status |
|---|---|---|---|---|
| **DEF-01** | `core/scanner.py`, `utils/system_info.py`, `modules/response/remediation_engine.py` | **CRITICAL** | Unsafe subprocess shell execution (`shell=True`) across core and remediation modules | RECTIFIED |
| **DEF-02** | `privwatch.py`, `core/logger.py`, `utils/system_info.py`, `core/scanner.py` | **HIGH** | Windows/cross-platform compatibility code remnants and missing Linux-only platform enforcement | RECTIFIED |
| **DEF-03** | `modules/red_mode/passwd_scanner.py`, `tests/test_scanners.py` | **HIGH** | Passwd scanner reports non-root owned files/fixtures as vulnerable; flawed permission checks | RECTIFIED |
| **DEF-04** | `modules/red_mode/kernel_scanner.py` | **HIGH** | Simplistic upstream version comparison; installed package metadata unused; missing vendor advisory verification | RECTIFIED |
| **DEF-05** | `modules/response/remediation_engine.py` | **CRITICAL** | Remediation uses arbitrary shell strings, hardcoded insecure rollback permissions (`chmod 666`), and lacks symlink verification | RECTIFIED |
| **DEF-06** | `core/storage.py` | **HIGH** | Database overwrites evidence via `INSERT OR REPLACE`; confidence `0.0` reset to `1.0`/`0.9`; missing tamper-evident hash chain | RECTIFIED |
| **DEF-07** | `web/app.py` | **HIGH** | Unauthenticated and unauthorized REST API endpoints exposing privileged operations | RECTIFIED |
| **DEF-08** | Architecture / `core/` | **HIGH** | Missing Linux-native privilege separation between unprivileged web UI and privileged collector service | RECTIFIED |
| **DEF-09** | `modules/red_mode/*.py`, `utils/file_utils.py` | **MEDIUM** | Red Team scanners trigger false positives when running as root (`os.access(W_OK)` returns `True` for root) | RECTIFIED |
| **DEF-10** | `modules/blue_mode/telemetry/`, `core/orchestrator.py` | **MEDIUM** | Process monitoring overclaims execution detection without warning when `auditd` is unavailable | RECTIFIED |
| **DEF-11** | `reports/pdf_generator.py`, `reports/csv_exporter.py` | **LOW** | Report exporters lack defensive nested-evidence normalization for multiline Platypus tables | RECTIFIED |
| **DEF-12** | `README.md`, `docs/` | **LOW** | Documentation contained cross-platform claims and lacked detailed Linux systemd and auditd configuration guides | RECTIFIED |

---

## Detailed Defect Records

### DEF-01: Unsafe Subprocess Shell Execution (`shell=True`)
- **File & Line:** `core/scanner.py:47`, `utils/system_info.py:23`, `modules/response/remediation_engine.py:131`
- **Affected Module:** Core Execution, System Info, Remediation Engine
- **Severity:** **CRITICAL**
- **Root Cause:** Direct invocation of `subprocess.run(..., shell=True)` with string interpolation. If inputs, file paths, or commands contain metacharacters (`|`, `;`, `&`, `` ` ``), arbitrary command injection can occur in the execution context.
- **Steps to Reproduce:**
  1. Pass a crafted command string or filename containing `; id` or `| nc` to `scanner.run_command()` or `remediation_engine.execute_plan()`.
  2. Observe shell subshell execution of injected commands.
- **Actual Observed Behavior:** Shell metacharacters were evaluated by `/bin/sh` or system default shell.
- **Expected Behavior:** All subprocess execution must strictly use argument lists (`List[str]`), `shell=False`, canonical binary path resolution via `shutil.which()`, explicit timeouts, and separate stdout/stderr handling.
- **Exact Rectification Solution:**
  1. Implement centralized `core/command_exec.py` with `LinuxCommandRunner` returning structured `CommandExecutionResult`.
  2. Replace all `shell=True` calls with argument list execution and `shell=False`.
  3. Never construct shell commands from dynamic user input or file paths.

---

### DEF-02: Windows/Cross-Platform Remnants and Missing Linux Enforcement
- **File & Line:** `privwatch.py:15-19, 140-145`, `core/logger.py:15-20`, `utils/system_info.py:119-125`, `core/scanner.py:55`
- **Affected Module:** CLI Startup, Logger, System Utilities
- **Severity:** **HIGH**
- **Root Cause:** Cross-platform fallbacks (`sys.platform == 'win32'`, `ctypes.windll.shell32.IsUserAnAdmin()`, `posix=(os.name != 'nt')`, Windows stdout reconfiguration) and lack of strict Linux platform validation at startup.
- **Steps to Reproduce:**
  1. Run `python privwatch.py` on a non-Linux platform.
  2. The application logs an advisory and attempts degraded execution instead of terminating with a fatal platform error.
- **Actual Observed Behavior:** Application executed partially on non-Linux platforms with mock/degraded logic.
- **Expected Behavior:** PrivWatch 3.0 is a 100% Linux-native security platform. At startup it must verify Linux OS (`platform.system() == 'Linux'`), check `/proc`, `/sys`, identify distro and kernel, and abort immediately on non-Linux hosts with an `UnsupportedPlatformError`.
- **Exact Rectification Solution:**
  1. Implement `core/platform_validator.py` with `LinuxPlatformValidator`.
  2. In `privwatch.py`, enforce platform validation at the very top of `main()`.
  3. Remove all Windows/macOS branches, `windll`, `IsUserAnAdmin`, and `posix=(os.name != 'nt')` code across all files.

---

### DEF-03: Passwd Scanner Reports Non-Root Owned Files as Vulnerable
- **File & Line:** `modules/red_mode/passwd_scanner.py:39, 104, 118`, `tests/test_scanners.py:67-87`
- **Affected Module:** Red Team Mode (`PasswdScanner`)
- **Severity:** **HIGH**
- **Root Cause:** `_audit_passwd_file()` checked `os.access(path, os.W_OK) and (os.geteuid() != 0)`. When auditing an isolated temporary test file or user-created file, the file is writable by its owner (the test runner), leading the scanner to falsely flag it as a "Writable Password Database: /etc/passwd" even though it is not owned by root and not a system database. Furthermore, when running as root, world-writable files (`mode & 0o002`) were ignored.
- **Steps to Reproduce:**
  1. Call `scanner._audit_passwd_file(temp_test_passwd_path)`.
  2. Observe that 3 findings are returned instead of 2, falsely reporting the user's temp file as an insecure system password database.
- **Actual Observed Behavior:** Ordinary user files owned by the current user were flagged as vulnerable system authentication databases.
- **Expected Behavior:** The scanner must verify canonical file path (`/etc/passwd` or resolving to `/etc/passwd`), verify ownership (`st_uid == 0`), inspect actual permission bits (`st_mode & 0o022` for group/other write), inspect POSIX ACLs, distinguish owner write permissions from unauthorized write permissions, and distinguish empty password fields from verified passwordless accounts.
- **Exact Rectification Solution:**
  1. In `PasswdScanner`, verify canonical ownership and permission bits (`st_mode & 0o022`).
  2. Ensure only root-owned authentication databases with unauthorized write permissions or world-writable bits are flagged.
  3. Fix test `test_passwd_scanner_rogue_uid0_and_empty_password` to assert correct security semantics.

---

### DEF-04: Simplistic Kernel Version Evaluation Without Vendor Advisory Matching
- **File & Line:** `modules/red_mode/kernel_scanner.py:73-75, 92-101, 103-151`
- **Affected Module:** Red Team Mode (`KernelScanner`)
- **Severity:** **HIGH**
- **Root Cause:** `_query_installed_kernel_package()` executed shell pipeline `dpkg -l ... | grep ... | tail -1` but the returned package string was never compared against distribution patch levels. Findings were declared solely from upstream kernel version tuple comparison, ignoring vendor backported security fixes (e.g. Debian/Ubuntu backporting patches into 5.15.0 or 4.19.0).
- **Steps to Reproduce:**
  1. Run `KernelScanner` on an updated Debian/Ubuntu system with backported Dirty Pipe fix.
  2. Scanner falsely reports Dirty Pipe as active because upstream tuple is < 5.16.11.
- **Actual Observed Behavior:** Backported distributions were falsely classified as vulnerable based only on upstream version numbers.
- **Expected Behavior:** Assessment must identify running kernel (`uname -r`), installed kernel package version, distribution ID and release, compare against vendor security advisory metadata (USN, DSA, RHSA, Fedora, Arch), and output explicit assessment states: `CONFIRMED_VULNERABLE`, `PATCHED`, `POTENTIALLY_VULNERABLE`, `NOT_AFFECTED`, `UNKNOWN`, `UNVERIFIED`.
- **Exact Rectification Solution:**
  1. Enhance `KernelScanner` with structured vendor advisory database including distribution package version thresholds.
  2. Implement native package version comparison (`dpkg --compare-versions` or Python Debian/RPM version comparator).
  3. Support assessment states and classify unknown/unverified states accurately without false confirmation.

---

### DEF-05: Remediation Engine Uses Insecure Rollback and Shell Execution
- **File & Line:** `modules/response/remediation_engine.py:58, 129-135`
- **Affected Module:** Response Engine (`RemediationEngine`)
- **Severity:** **CRITICAL**
- **Root Cause:** Remediation executed commands using `subprocess.run(cmd, shell=True)`. Rollback for cron files was hardcoded to `chmod 666` (world-writable!). No canonical path validation, symlink traversal checking, or capture of actual original file mode/owner was performed.
- **Steps to Reproduce:**
  1. Create a remediation plan for a cron file with original mode 0644.
  2. Inspect proposed rollback command: `chmod 666 /path/to/cron`. Applying rollback turns the file world-writable!
- **Actual Observed Behavior:** Rollback introduced a critical privilege escalation vulnerability (`chmod 666`).
- **Expected Behavior:** Remediation actions must be typed structures (`RemediationAction`). The engine must capture the exact original `st_mode`, `st_uid`, and `st_gid`. Rollback must restore the verified original mode bits via `os.chmod()` and `os.chown()`. Execution must resolve canonical paths (`os.path.realpath`) and refuse to follow untrusted symlinks.
- **Exact Rectification Solution:**
  1. Implement `RemediationAction` with fields: `action_id`, `action_type`, `target`, `original_mode`, `desired_mode`, `original_uid`, `original_gid`, `backup_path`.
  2. Implement execution using Python POSIX APIs (`os.chmod`, `os.chown`) without subshells.
  3. Enforce symlink safety (`os.path.islink`) and atomic rollback tracking.

---

### DEF-06: Database Storage Overwrites Evidence & Inverts Confidence 0.0
- **File & Line:** `core/storage.py:148, 218, 235, 288`
- **Affected Module:** Core Persistence (`StorageEngine`)
- **Severity:** **HIGH**
- **Root Cause:**
  1. SQLite queries used `INSERT OR REPLACE INTO events` and `INSERT OR REPLACE INTO findings`, silently overwriting existing historical records.
  2. In `get_events()` and `get_findings()`, confidence was loaded as `r['confidence'] or 1.0`. In Python, `0.0 or 1.0` evaluates to `1.0`. Thus, an event with confidence `0.0` was restored as `1.0`.
  3. No cryptographic verification existed to ensure evidence immutability.
- **Steps to Reproduce:**
  1. Save an event with `confidence=0.0`.
  2. Retrieve the event via `get_events()`. Reconstructed event has `confidence=1.0`.
- **Actual Observed Behavior:** Zero confidence was corrupted to 1.0; re-ingested events overwrote historical records.
- **Expected Behavior:** Stored confidence of `0.0` must strictly remain `0.0`. Evidence records must be append-only with explicit conflict resolution. An immutable cryptographic hash chain (SHA-256) must link audit and evidence records.
- **Exact Rectification Solution:**
  1. Change confidence restoration to `r['confidence'] if r['confidence'] is not None else 1.0`.
  2. Implement append-only policies (`INSERT OR IGNORE`) and an immutable cryptographic SHA-256 hash chain with `verify_chain_integrity()`.

---

### DEF-07: Unauthenticated REST API Endpoints
- **File & Line:** `web/app.py:604-742`
- **Affected Module:** Web Dashboard & REST API
- **Severity:** **HIGH**
- **Root Cause:** Endpoints including `/api/v1/scan/red`, `/api/v1/scan/blue`, `/api/v1/monitoring/start`, `/api/v1/monitoring/stop`, `/api/v1/remediation/execute`, and `/api/v1/suppression` lacked authentication and authorization checks.
- **Steps to Reproduce:**
  1. Send an unauthenticated HTTP POST to `/api/v1/remediation/execute` or `/api/v1/monitoring/start`.
  2. The endpoint executes the privileged operation without requiring credentials.
- **Actual Observed Behavior:** Any process or network client capable of reaching port 8443 could trigger administrative actions.
- **Expected Behavior:** Sensitive endpoints must require Bearer token / API Key authentication with role-based access control (`admin` vs `readonly`). Default binding must be strictly `127.0.0.1`. Mutations must be rate-limited and logged to the audit trail.
- **Exact Rectification Solution:**
  1. Implement FastAPI authentication dependency checking `X-API-Key` or `Authorization: Bearer <token>`.
  2. Enforce `admin` role for remediation, scanning triggers, and monitoring lifecycle.
  3. Bind server strictly to `127.0.0.1` by default.

---

### DEF-08: Missing Privilege Separation Architecture
- **File & Line:** Architecture / Entire Platform
- **Affected Module:** System Architecture & IPC
- **Severity:** **HIGH**
- **Root Cause:** Dashboard and API server ran under the same operating system privilege context as the security collectors. If executed as root, a vulnerability in the web server could allow complete system compromise.
- **Steps to Reproduce:**
  1. Run `python privwatch.py --mode dashboard` as root.
  2. The entire web server process runs with UID 0.
- **Actual Observed Behavior:** Web tier was not separated from the privileged kernel/audit collector tier.
- **Expected Behavior:** Unprivileged dashboard/API must communicate with a privileged collector service via a restricted Unix Domain Socket (`/run/privwatch/privwatch.sock`) with mode `0600` and `SO_PEERCRED` validation.
- **Exact Rectification Solution:**
  1. Implement `core/privileged_service.py` (Privileged IPC Collector Service).
  2. Implement strictly allowlisted JSON-RPC commands (`GET_TELEMETRY`, `RUN_SCAN`, `GET_STATUS`).
  3. Provide systemd unit `privwatch-collector.service`.

---

### DEF-09: False Positives in Red Team Scanners When Running as Root
- **File & Line:** `modules/red_mode/suid_scanner.py:82`, `modules/red_mode/sudo_scanner.py:72`, `modules/red_mode/cron_scanner.py:129`, `modules/red_mode/path_scanner.py:62`, `modules/red_mode/container_scanner.py:59`
- **Affected Module:** Red Team Scanners, File Utilities
- **Severity:** **MEDIUM**
- **Root Cause:** `os.access(path, os.W_OK)` returns `True` for every root-owned file when running as root (UID 0). Consequently, standard system binaries (`/bin/su`, `/usr/bin/passwd`) were flagged as "Writable SUID Binary" when scanned by root. Conversely, world-writable checks were bypassed when checking `os.geteuid() != 0`.
- **Steps to Reproduce:**
  1. Execute `sudo python privwatch.py --mode red` on a standard Linux distribution.
  2. Standard SUID binaries are falsely flagged as writable.
- **Actual Observed Behavior:** Inaccurate false positive alerts when scanning under root privileges.
- **Expected Behavior:** Check explicit permission bits (`st_mode & 0o002` for world-writable, `st_mode & 0o020` for group-writable). Only flag writable files if world-writable, group-writable by non-root group, or if running as an unprivileged user with write access.
- **Exact Rectification Solution:**
  1. Implement `is_insecurely_writable(path_or_stat, is_root_user)` in `utils/file_utils.py`.
  2. Update all Red Team scanners to use this unified permission check.

---

### DEF-10: Telemetry Overclaim — Process Monitoring vs /proc Polling
- **File & Line:** `modules/blue_mode/telemetry/process_collector.py`, `core/orchestrator.py`
- **Affected Module:** Blue Team Monitoring
- **Severity:** **MEDIUM**
- **Root Cause:** `/proc` polling alone cannot catch short-lived execution events (e.g. `whoami` or rapid exploit scripts). The platform previously reported active process monitoring even when `auditd` was disabled.
- **Steps to Reproduce:**
  1. Disable `auditd` service.
  2. Run `privwatch.py --mode monitor`.
  3. Platform reported monitoring coverage as healthy.
- **Actual Observed Behavior:** Failed to report that reliable process execution telemetry was unavailable.
- **Expected Behavior:** Platform must explicitly report: `Reliable kernel process execution monitoring unavailable (auditd not active). Transient process executions may evade detection.` Provide `config/audit.rules` for auditd setup.
- **Exact Rectification Solution:**
  1. Update `health_monitor.py` and `orchestrator.py` to flag degraded telemetry when auditd is absent.
  2. Include `config/audit.rules` and document setup in `docs/LINUX_AUDIT_CONFIGURATION.md`.

---

### DEF-11: ReportLab PDF and CSV Exporters Evidence Serialization Formatting
- **File & Line:** `reports/pdf_generator.py`, `reports/csv_exporter.py`
- **Affected Module:** Reporting Engine
- **Severity:** **LOW**
- **Root Cause:** Complex nested evidence dictionaries (e.g. stat metadata or advisory lists) caused layout truncation or serialization errors when rendered into ReportLab Platypus table cells.
- **Steps to Reproduce:**
  1. Generate PDF with a finding containing a deeply nested dict.
  2. Text overflows cell boundaries or renders as unformatted raw string.
- **Actual Observed Behavior:** Truncated or unformatted text in PDF report tables.
- **Expected Behavior:** Clean formatting, word wrapping, and structured serialization of all evidence fields in PDF and CSV exports.
- **Exact Rectification Solution:**
  1. Add defensive evidence formatter in `reports/pdf_generator.py` and `reports/csv_exporter.py`.

---

### DEF-12: Documentation Inaccuracies and Missing Linux Configuration Guides
- **File & Line:** `README.md`, `docs/`
- **Affected Module:** Project Documentation
- **Severity:** **LOW**
- **Root Cause:** Documentation contained outdated references to cross-platform compatibility and lacked Linux-specific systemd service definitions, auditd rules, and hardening guides.
- **Steps to Reproduce:**
  1. Review existing `README.md` and docs.
- **Actual Observed Behavior:** Documentation did not reflect the strict 100% Linux-native architecture.
- **Expected Behavior:** Complete, accurate documentation covering Linux platform support, installation, auditd configuration, API security, and testing.
- **Exact Rectification Solution:**
  1. Author all required documentation guides in `docs/`.
