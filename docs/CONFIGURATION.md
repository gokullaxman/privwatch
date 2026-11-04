# UATU Linux Edition — Configuration Reference

This guide details configuration parameters, environment variables, default paths, and policy controls across the UATU platform.

---

## 1. Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `UATU_CONFIG_FILE` | `./config/config.yaml` | Path to primary YAML configuration file |
| `UATU_DB_PATH` | `/var/lib/uatu/uatu.db` (root) or `./uatu.db` | Path to persistent SQLite evidence database |
| `UATU_API_KEY` | Auto-generated random 32-byte token | Administrative API authentication key |
| `UATU_TOKEN_FILE` | `/var/lib/uatu/token` or `./config/uatu_token` | Secure 0600 file containing generated API key |
| `UATU_LOG_LEVEL` | `INFO` | Console and structured logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `UATU_JSON_LOG` | `/var/log/uatu/uatu.jsonl` | Output path for structured JSON-lines telemetry |
| `UATU_READ_ONLY` | `true` | Enforces global read-only safety mode across remediation engines |

---

## 2. Directory Layout and File Permissions

UATU enforces strict POSIX filesystem permissions to prevent local privilege escalation against the security monitoring service itself:

| Path | Purpose | Recommended Mode | Owner |
| :--- | :--- | :--- | :--- |
| `/etc/uatu` | Configuration files & tokens | `0755` | `root:root` |
| `/etc/uatu/token` | Administrative API bearer token | `0600` | `root:root` |
| `/var/lib/uatu` | SQLite database directory | `0700` | `root:root` |
| `/var/lib/uatu/uatu.db` | Primary forensic evidence database | `0600` | `root:root` |
| `/var/log/uatu` | Structured audit and telemetry logs | `0700` | `root:root` |
| `/etc/audit/rules.d/uatu.rules` | Kernel audit subsystem configuration | `0640` | `root:root` |
| `/etc/systemd/system/uatu.service` | Systemd service definition | `0644` | `root:root` |

---

## 3. Correlation & Detection Tuning

Configured in `config/config.yaml` or passed to `DetectionEngine`:

```yaml
detection:
  correlation_window_seconds: 300       # Time window for grouping related events
  failed_auth_threshold: 3              # Number of failures before triggering brute-force incident
  deduplication_mode: "strict"          # Deduplicate by (rule_name, pid, audit_serial)
  suid_allowlist:
    - "/usr/bin/sudo"
    - "/bin/su"
    - "/usr/bin/passwd"
    - "/bin/mount"
    - "/bin/umount"
    - "/bin/ping"
    - "/usr/bin/fusermount"
    - "/usr/bin/fusermount3"

containment:
  default_mode: "OBSERVE_ONLY"          # OBSERVE_ONLY, ALERT_ONLY, APPROVAL_REQUIRED, AUTHORIZED_AUTOMATIC
  termination_timeout_sec: 2.0          # SIGTERM to SIGKILL deadline
  network_containment_timeout_sec: 1800 # nftables temporary rule timeout (30 min)
```

---

## 4. API & Role-Based Access Control (RBAC)

Tokens can be assigned explicit roles via `/etc/uatu/api_tokens.json`:

```json
{
  "tokens": [
    {
      "token": "admin-super-secret-token",
      "user": "secops_admin",
      "role": "admin"
    },
    {
      "token": "operator-token",
      "user": "shift_operator",
      "role": "operator"
    },
    {
      "token": "analyst-token",
      "user": "soc_analyst",
      "role": "analyst"
    },
    {
      "token": "readonly-token",
      "user": "auditor_guest",
      "role": "readonly"
    }
  ]
}
```
