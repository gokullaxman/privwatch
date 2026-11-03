# PrivWatch 3.0 — Troubleshooting & Diagnostic Guide

This guide addresses common operational questions, permission warnings, and environmental edge cases.

---

## 1. Common Warning Messages

### `[!] Not executing as root (UID 0) - some checks may be limited`
- **Cause:** PrivWatch was started from a standard unprivileged user shell.
- **Resolution:**
  - This is expected and normal for non-root audits. PrivWatch will safely evaluate all readable files and user-level privileges.
  - For full audits of `/etc/shadow`, restricted auditd logs, or full systemd service units, run with elevated privileges:
    ```bash
    sudo python3 privwatch.py --mode red
    ```

### `Telemetry health report shows /var/log/audit/audit.log UNAVAILABLE`
- **Cause:** The Linux Audit daemon (`auditd`) is either not installed or not running on this host (common on minimal containers or default Debian installations).
- **Resolution:**
  - On Debian/Ubuntu: `sudo apt-get install auditd && sudo systemctl enable --now auditd`
  - On Fedora/RHEL: `sudo dnf install audit && sudo systemctl enable --now auditd`
  - PrivWatch will automatically detect and ingest audit logs once the service is started.

### `getcap tool not available`
- **Cause:** The `libcap2-bin` package is missing.
- **Resolution:** Install the capability utility:
  ```bash
  sudo apt-get install libcap2-bin  # Debian/Ubuntu
  sudo dnf install libcap           # Fedora/RHEL
  ```

---

## 2. Dashboard & API Issues

### Dashboard fails to bind to port 8443 (`[Errno 98] Address already in use`)
- **Cause:** Another process is utilizing port 8443.
- **Resolution:** Pass an alternative port:
  ```bash
  python3 privwatch.py --mode dashboard --port 8080
  ```

### PDF report export falls back to `.txt`
- **Cause:** The ReportLab package is not installed in the active Python environment.
- **Resolution:**
  ```bash
  pip install reportlab
  ```
  Once installed, PrivWatch 3.0 automatically generates full multi-page PDF documents.

---

## 3. Running Diagnostic Self-Tests

If you suspect a module is misbehaving or environment dependencies are corrupted, run the comprehensive test suite:

```bash
python3 -m pytest -v
```

This runs 34 automated unit, integration, and security checks verifying scanners, collectors, correlators, and exporters.

