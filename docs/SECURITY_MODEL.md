# PrivWatch 3.0 — Platform Security Model

PrivWatch 3.0 is designed from first principles as an auditable, defense-in-depth security tool. It strictly prevents unauthorized actions, input tampering, command injection, and data leakage.

---

## 1. Safety Principles & Execution Boundaries

### A. Read-Only Default Mode
All assessment scans (Red Team) and forensic analyses (Blue Team) operate in strictly read-only mode:
- No system files are created or altered during scans.
- No processes are killed automatically.
- No network traffic or exploit payloads are transmitted.

### B. Controlled Remediation Gates
Any remediation action that alters operating system state must pass through mandatory safety controls:
1. **Dry-Run by Default:** Remediation plans are simulated first (`dry_run=True`), showing proposed commands and consequences without altering the system.
2. **Explicit Confirmation Required:** Setting `confirmed=True` and `dry_run=False` is strictly enforced.
3. **Automatic Pre-Execution Backup:** Before any configuration file is modified, a timestamped backup copy is created.
4. **Automated Rollback Scripts:** Rollback commands are generated and presented alongside proposed changes.
5. **Immutable Audit Trail:** All administrative actions and remediation executions are permanently logged to SQLite.

---

## 2. Secure Software Architecture

### A. Subprocess Safety
- Subprocess execution strictly uses argument lists (`['/usr/bin/find', ...]`) without `shell=True` wherever possible.
- Strict command execution timeouts (default 25s) prevent denial-of-service hangs.
- When shell pipelines are required, executions are sandboxed and restricted.

### B. Path Traversal Prevention
- All file download and report access endpoints validate requested paths using `safe_resolve_path`.
- Paths attempting directory traversal (`../`) outside the configured report directory are rejected with HTTP 403.

### C. Sensitive Credential Sanitization
- Passwords and password hashes (SHA-512 crypt, yescrypt, bcrypt) in `/etc/shadow` are automatically redacted by `EvidenceManager.sanitize` before terminal output or API transmission.
- Private SSH host keys are redacted to prevent leakage.

### D. Web API & Dashboard Security
- The web server binds strictly to `127.0.0.1` by default, preventing unintended network exposure.
- CORS is restricted to localhost origins.
- Input models are strictly validated using Pydantic.

