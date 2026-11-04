# PrivWatch 3.0 — REST API & SOC Operations Security Model

## 1. Network Binding & Perimeter Isolation

PrivWatch 3.0 REST API and dashboard server strictly bind to `127.0.0.1` by default. External network binding (`0.0.0.0`) is prohibited unless explicitly configured by an administrator.

```bash
# Default safe localhost invocation
python privwatch.py --mode dashboard --host 127.0.0.1 --port 8443
```

---

## 2. Authentication & Authorization Framework

### Authentication Tokens
PrivWatch requires API authentication for all administrative and mutating endpoints via:
1. HTTP Header: `X-API-Key: <token>`
2. HTTP Header: `Authorization: Bearer <token>`

The authentication token can be set via the `PRIVWATCH_API_KEY` environment variable:
```bash
export PRIVWATCH_API_KEY="custom-secure-secret-token"
python privwatch.py --mode dashboard
```
If not specified, PrivWatch automatically initializes with a secure default local token (`privwatch-secure-local-admin-token`), transparently injected into the web dashboard HTML template for localhost browser interactions.

### Role-Based Access Control (RBAC)

| Role | Permissions | Accessible Endpoints |
|---|---|---|
| `admin` | Full read, write, scan, monitor, remediate | All endpoints (`/api/v1/*`) |
| `readonly` | Read findings, events, timeline, export reports | `/api/v1/overview`, `/api/v1/findings`, `/api/v1/events`, `/api/v1/reports/download` |
| `anonymous` | Unauthenticated | `/`, `/dashboard` (HTML UI only) |

---

## 3. Protected Endpoint Inventory

The following sensitive routes require `admin` authorization:

| Endpoint | HTTP Method | Required Role | Audit Log Action |
|---|---|---|---|
| `/api/v1/scan/red` | `POST` | `admin` | `TRIGGER_RED_SCAN` |
| `/api/v1/scan/blue` | `POST` | `admin` | `TRIGGER_BLUE_SCAN` |
| `/api/v1/monitoring/start` | `POST` | `admin` | `START_MONITORING` |
| `/api/v1/monitoring/stop` | `POST` | `admin` | `STOP_MONITORING` |
| `/api/v1/remediation/execute` | `POST` | `admin` | `REMEDIATION_EXECUTE` |
| `/api/v1/suppression` | `POST` | `admin` | `ADD_SUPPRESSION_RULE` |
| `/api/v1/incidents/{id}/status` | `POST` | `admin` | `UPDATE_INCIDENT_STATUS` |

Unauthenticated requests to protected endpoints receive HTTP `401 Unauthorized`. Requests with insufficient roles receive HTTP `403 Forbidden`.

---

## 4. Rate Limiting & Defense-in-Depth

- **Sliding-Window Rate Limiting:** All API routes enforce an in-memory sliding window limit of 120 requests per minute per client IP. Excessive requests are rejected with HTTP `429 Too Many Requests`.
- **Path Traversal Prevention:** The `/api/v1/reports/download` endpoint strictly resolves file paths using `safe_resolve_path()`, ensuring requested files remain within the designated `reports/` output directory. Directory traversals (`../`) return HTTP `403 Access Denied`.
- **Cryptographic Audit Trail:** Every administrative operation is recorded to `privwatch.db` with a SHA-256 hash chaining record linked to the previous transaction hash.
