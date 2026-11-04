# PrivWatch 3.0 — Controlled Remediation & Rollback Architecture

## 1. Safety-First Remediation Model

PrivWatch 3.0 provides automated, controlled remediation for identified privilege escalation vulnerabilities. Unlike traditional scripts that execute arbitrary shell commands with `shell=True`, PrivWatch enforces strict safety guarantees:

```
[Red Team Finding]
        │
        ▼
[RemediationEngine.generate_plan()]
        │
        ├── Validate Canonical Path (os.path.realpath)
        ├── Inspect Symlink Handling (os.path.islink -> Reject if untrusted)
        ├── Capture Original Mode (st_mode)
        ├── Capture Original UID/GID (st_uid, st_gid)
        └── Generate Typed RemediationAction Objects
        │
        ▼
[Safety Gate 1: Default to Dry-Run] (read_only=True / dry_run=True)
        │
        ▼
[Safety Gate 2: Explicit Confirmation Gate] (confirmed=True required)
        │
        ▼
[Pre-Execution Backup] (shutil.copy2 -> .privwatch_<action_id>.bak)
        │
        ▼
[Safe POSIX System Calls] (os.chmod / os.chown) (shell=False)
        │
        ├── [Execution Succeeded] ──► Log to Immutable Audit Trail
        │
        └── [Execution Failed] ─────► Trigger Atomic Reverse Rollback
                                       ├── Restore Exact Original Mode
                                       ├── Restore Exact Original UID/GID
                                       └── Log Failure & Rollback Event
```

---

## 2. Typed Remediation Actions

Every proposed operation is encapsulated in a strongly-typed `RemediationAction` structure:

| Field | Type | Description |
|---|---|---|
| `action_id` | `str` | Unique operation identifier (e.g. `act_a1b2c3`). |
| `action_type` | `str` | Strictly defined operation (`STRIP_SUID`, `CHMOD`, `CHOWN`, `REMOVE_LINE`). |
| `target` | `str` | Input path string. |
| `canonical_target` | `str` | Verified realpath on the filesystem. |
| `expected_original_mode` | `int` | Exact permission bitmask before remediation (e.g. `0o104755`). |
| `desired_mode` | `int` | Exact hardened bitmask to apply (e.g. `0o100755`). |
| `expected_original_uid` | `int` | Existing owner UID. |
| `desired_uid` | `int` | Target owner UID (typically 0 for root). |
| `backup_required` | `bool` | Whether pre-modification backup must be generated. |
| `backup_path` | `str` | Location of generated backup file. |

---

## 3. Rollback Guarantees

### Prohibition of Generic Permissions
PrivWatch **never** restores files using generic permissions such as `chmod 666` or `chmod 777`. Rollback commands and system call restorations strictly apply the exact original bitmask (`expected_original_mode`) captured during pre-execution analysis.

### Atomic Failure Rollback
If a multi-step remediation plan partially fails (e.g. action 1 succeeds, action 2 fails due to permission denial or filesystem read-only status):
1. Execution immediately halts.
2. The engine iterates completed actions in reverse order (`reversed(executed_actions)`).
3. `os.chmod()` and `os.chown()` restore the recorded original state.
4. If a backup was created, the original file is preserved.
5. The partial failure and rollback actions are recorded in the SHA-256 chained audit log.

---

## 4. Symlink Traversal Protection

PrivWatch refuses to modify targets that are symlinks (`os.path.islink(target) == True`). This prevents attackers from exploiting time-of-check to time-of-use (TOCTOU) symlink races to trick the privileged remediation engine into chmodding `/etc/shadow` or other arbitrary system files.

