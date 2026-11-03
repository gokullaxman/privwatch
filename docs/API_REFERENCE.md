# PrivWatch 3.0 — REST API Reference

The PrivWatch 3.0 Web Operations Platform exposes a full REST API for security orchestration, telemetry queries, and programmatic reporting.

---

## Base URL
```
http://127.0.0.1:8443
```

---

## Endpoints

### 1. Operations & Overview
- **`GET /api/v1/overview`**
  - **Description:** Retrieve overall security posture score (0 - 100), severity counts, telemetry source health, and active incidents.
  - **Response:**
    ```json
    {
      "posture": {
        "score": 75,
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "status": "ATTENTION_NEEDED"
      },
      "telemetry_health": {
        "overall_coverage_pct": 60.0
      },
      "monitoring": { "active": false }
    }
    ```

- **`GET /api/v1/health`**
  - **Description:** Get status and accessibility of individual system telemetry sources.

- **`GET /api/v1/system`**
  - **Description:** Host identity, kernel version, OS distribution, execution user, and root privilege status.

---

### 2. Security Findings
- **`GET /api/v1/findings`**
  - **Parameters:**
    - `vector` (optional): Filter by vector (e.g., `SUID/SGID`, `SUDO`, `CRON`, `KERNEL`)
    - `severity` (optional): Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - **Response:** Array of Finding objects with evidence hashes and remediation guidance.

---

### 3. Telemetry & Forensics
- **`GET /api/v1/events`**
  - **Parameters:** `limit` (default 100), `event_type` (optional)
  - **Response:** Array of normalized SecurityEvent objects.

- **`GET /api/v1/incidents`**
  - **Parameters:** `status` (`NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`)
  - **Response:** Array of correlated Incident objects.

- **`POST /api/v1/incidents/{incident_id}/status`**
  - **Body:** `{ "status": "INVESTIGATING", "note": "Analyst assigned" }`

- **`GET /api/v1/timeline`**
  - **Description:** Unified chronological sequence combining raw events and detected incidents.

---

### 4. Scanners & Monitoring Service
- **`POST /api/v1/scan/red`**
  - **Description:** Trigger full Red Team privilege escalation audit.

- **`POST /api/v1/scan/blue`**
  - **Description:** Trigger Blue Team log forensics and telemetry analysis.

- **`POST /api/v1/monitoring/start`**
  - **Description:** Start live background telemetry monitoring service.

- **`POST /api/v1/monitoring/stop`**
  - **Description:** Stop live background telemetry monitoring service.

- **`GET /api/v1/monitoring/status`**
  - **Description:** Query active state of monitoring service (`{"monitoring": true/false}`).

---

### 5. Controlled Remediation
- **`POST /api/v1/remediation/plan`**
  - **Body:** `{ "finding_id": "fnd_..." }`
  - **Response:** Returns proposed least-privilege commands, consequences, and rollback commands.

- **`POST /api/v1/remediation/execute`**
  - **Body:** `{ "finding_id": "fnd_...", "confirmed": true, "dry_run": false }`
  - **Response:** Execution status and backup file path.

---

### 6. Reports & Export
- **`POST /api/v1/reports/generate`**
  - **Body:** `{ "format": "json|pdf|csv", "mode": "red|blue" }`
  - **Response:** `{ "status": "SUCCESS", "output_file": "/path/to/report" }`

- **`GET /api/v1/reports/download?path=/path/to/report`**
  - **Description:** Safe download of generated report files with path traversal protection.

