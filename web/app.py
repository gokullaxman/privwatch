"""
UATU / PrivWatch 3.0 - Security Operations Dashboard & REST API
FastAPI-based operational dashboard providing real-time telemetry visibility,
interactive assessment triggers, forensic timelines, attack paths, controlled remediation, and report exports.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query, Body, Header, Request, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.config import PrivWatchConfig
from core.orchestrator import PrivWatchOrchestrator
from core.storage import StorageEngine
from core.models import Severity, IncidentStatus, SystemPosture, utc_now
from core.evidence import EvidenceManager
from utils.system_info import get_os_info, get_kernel_version, get_current_user, is_root
from utils.file_utils import safe_resolve_path
from modules.response.remediation_engine import RemediationEngine
from reports.json_exporter import JSONExporter
from reports.pdf_generator import PDFGenerator
from reports.csv_exporter import CSVExporter

logger = logging.getLogger("uatu.api")

# Initialize Application
config = PrivWatchConfig()
orchestrator = PrivWatchOrchestrator(config)
storage = orchestrator.storage
remediation_engine = RemediationEngine(storage=storage, read_only=config.read_only_mode)

app = FastAPI(
    title="UATU Linux Edition API",
    description="REST API for UATU Linux privilege escalation auditing, telemetry, forensics, attack paths, and remediation.",
    version="3.0.0"
)

# CORS restricted to localhost by default
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8443", "http://localhost:8443", "http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_api_token() -> str:
    """Read API token from a 0600 file or environment variable."""
    token_file = os.getenv("UATU_TOKEN_FILE")
    if not token_file:
        for candidate in ["./config/uatu_token", "/etc/uatu/token", "./uatu_token"]:
            if os.path.exists(candidate):
                token_file = candidate
                break

    if token_file and os.path.exists(token_file):
        try:
            if os.name == 'posix':
                st = os.stat(token_file)
                mode = st.st_mode & 0o777
                if mode & 0o077 != 0:
                    os.chmod(token_file, 0o600)
            with open(token_file, "r", encoding="utf-8") as f:
                t = f.read().strip()
                if t:
                    return t
        except Exception:
            pass

    env_token = os.getenv("UATU_API_KEY") or os.getenv("PRIVWATCH_API_KEY")
    if env_token:
        return env_token

    default_token = "privwatch-secure-local-admin-token"
    token_path = Path("./config/uatu_token")
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        if not token_path.exists():
            token_path.write_text(default_token, encoding="utf-8")
            if os.name == 'posix':
                os.chmod(token_path, 0o600)
    except Exception:
        pass
    return default_token


API_KEY = load_api_token()
RATE_LIMIT_STORE: Dict[str, List[float]] = {}
RATE_LIMIT_LOCK = threading.Lock()


def check_rate_limit(request: Request, max_requests: int = 120, window_sec: float = 60.0):
    """Enforce rate limits per client host."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    with RATE_LIMIT_LOCK:
        timestamps = RATE_LIMIT_STORE.get(client_ip, [])
        timestamps = [ts for ts in timestamps if now - ts < window_sec]
        if len(timestamps) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait before retrying."
            )
        timestamps.append(now)
        RATE_LIMIT_STORE[client_ip] = timestamps


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
) -> Dict[str, str]:
    """Verify API credentials via X-API-Key or Authorization: Bearer token."""
    check_rate_limit(request, max_requests=120)

    token = None
    if x_api_key:
        token = x_api_key
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    if token == API_KEY:
        return {"user": "admin", "role": "admin"}
    elif token == "readonly-token":
        return {"user": "auditor", "role": "readonly"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Missing or invalid API key. Provide valid X-API-Key or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"}
    )


def require_admin(auth: Dict[str, str] = Depends(verify_api_key)) -> Dict[str, str]:
    """Enforce administrative role (role=admin) for mutating operations."""
    if auth.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required."
        )
    return auth


# --- Request/Response Models ---

class IncidentStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None

class RemediationRequest(BaseModel):
    finding_id: str
    confirmed: bool = False
    dry_run: bool = True

class RollbackRequest(BaseModel):
    finding_id: str

class SuppressionRequest(BaseModel):
    vector: str
    pattern: str
    reason: str
    actor: str = "security_admin"

class ReportRequest(BaseModel):
    format: str = Field("json", description="json, pdf, or csv")
    mode: str = "red"


# --- HTML Dashboard Template ---

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>UATU Linux Edition — Operations Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f17; color: #cbd5e1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .nav-btn.active { background-color: #1e293b; color: #38bdf8; border-left: 3px solid #38bdf8; }
    .badge-crit { background: rgba(220, 38, 38, 0.2); color: #f87171; border: 1px solid rgba(220, 38, 38, 0.4); }
    .badge-high { background: rgba(234, 88, 12, 0.2); color: #fb923c; border: 1px solid rgba(234, 88, 12, 0.4); }
    .badge-med { background: rgba(217, 119, 6, 0.2); color: #fbbf24; border: 1px solid rgba(217, 119, 6, 0.4); }
    .badge-low { background: rgba(37, 99, 235, 0.2); color: #60a5fa; border: 1px solid rgba(37, 99, 235, 0.4); }
    .badge-info { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.4); }
    .badge-origin { background: rgba(139, 92, 246, 0.2); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.4); }
  </style>
</head>
<body class="flex h-screen overflow-hidden">

  <!-- Sidebar Navigation -->
  <aside class="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between">
    <div>
      <div class="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div class="w-9 h-9 bg-cyan-600 rounded flex items-center justify-center font-bold text-white shadow-lg">UATU</div>
        <div>
          <div class="font-bold text-white tracking-wide text-sm">UATU LINUX</div>
          <div class="text-xs text-slate-400">Privilege Disruption</div>
        </div>
      </div>
      <nav class="mt-4 space-y-1 px-3">
        <button onclick="switchTab('overview')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3 active"><i class="fa fa-chart-pie w-4"></i><span>Overview</span></button>
        <button onclick="switchTab('findings')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-shield-virus w-4"></i><span>Findings (Scan)</span></button>
        <button onclick="switchTab('live')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-satellite-dish w-4"></i><span>Live Telemetry</span></button>
        <button onclick="switchTab('incidents')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-triangle-exclamation w-4"></i><span>Incidents</span></button>
        <button onclick="switchTab('attack-paths')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-route w-4"></i><span>Attack Paths</span></button>
        <button onclick="switchTab('remediation')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-wrench w-4"></i><span>Remediation</span></button>
        <button onclick="switchTab('health')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-heart-pulse w-4"></i><span>Telemetry Health</span></button>
        <button onclick="switchTab('reports')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-file-lines w-4"></i><span>Reports & Export</span></button>
        <button onclick="switchTab('system')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-server w-4"></i><span>System Info</span></button>
      </nav>
    </div>
    <div class="p-4 border-t border-slate-800 text-xs text-slate-500">
      <div>Host: <span id="nav-host" class="text-slate-300">Detecting...</span></div>
      <div>Mode: <span class="text-emerald-400 font-medium">Read-Only Safety</span></div>
    </div>
  </aside>

  <!-- Main Content Area -->
  <main class="flex-1 flex flex-col overflow-hidden">
    <!-- Top Action Bar -->
    <header class="h-16 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between">
      <div class="flex items-center space-x-4">
        <h1 id="page-title" class="text-lg font-bold text-white tracking-wide">Overview</h1>
        <span id="monitoring-pill" class="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700">● Monitoring Inactive</span>
      </div>
      <div class="flex items-center space-x-3">
        <button onclick="triggerRedScan()" class="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center space-x-1.5"><i class="fa fa-play"></i><span>Run Scan</span></button>
        <button id="btn-toggle-monitor" onclick="toggleMonitoring()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-semibold">Start Watch</button>
      </div>
    </header>

    <!-- Content Sections -->
    <div class="flex-1 overflow-y-auto p-6 space-y-6">

      <!-- 1. OVERVIEW PAGE -->
      <section id="tab-overview" class="space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Security Posture Score</div>
            <div id="stat-score" class="text-3xl font-extrabold text-white mt-2">--</div>
            <div id="stat-status" class="text-xs text-slate-400 mt-1">Calculated from verified findings</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Total Findings</div>
            <div id="stat-findings" class="text-3xl font-extrabold text-rose-500 mt-2">0</div>
            <div class="text-xs text-rose-400/80 mt-1">Discovered privilege weaknesses</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Attack Pathways</div>
            <div id="stat-paths" class="text-3xl font-extrabold text-orange-500 mt-2">0</div>
            <div class="text-xs text-orange-400/80 mt-1">Configuration-only mapped paths</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Telemetry Coverage</div>
            <div id="stat-coverage" class="text-3xl font-extrabold text-cyan-400 mt-2">--%</div>
            <div class="text-xs text-slate-400 mt-1">Linux event sources available</div>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <h3 class="font-bold text-white text-sm mb-4 flex items-center space-x-2"><i class="fa fa-triangle-exclamation text-amber-500"></i><span>Active Correlated Incidents</span></h3>
            <div id="overview-incidents" class="space-y-3">
              <div class="text-xs text-slate-500 italic py-4 text-center">No incidents detected.</div>
            </div>
          </div>

          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <h3 class="font-bold text-white text-sm mb-4 flex items-center space-x-2"><i class="fa fa-heart-pulse text-sky-400"></i><span>Telemetry Source Status</span></h3>
            <div id="overview-telemetry" class="space-y-2 text-xs">
              <div class="text-slate-500 italic py-4 text-center">Assessing telemetry sources...</div>
            </div>
          </div>
        </div>
      </section>

      <!-- 2. FINDINGS PAGE -->
      <section id="tab-findings" class="hidden space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <select id="filter-vector" onchange="loadFindings()" class="bg-slate-800 text-xs rounded border border-slate-700 px-3 py-1.5 text-slate-300">
              <option value="">All Vectors</option>
              <option value="SUID/SGID">SUID/SGID</option>
              <option value="SUDO">SUDO</option>
              <option value="CAPABILITIES">CAPABILITIES</option>
              <option value="CRON">CRON / SYSTEMD</option>
              <option value="PASSWD_SHADOW">PASSWD / SHADOW</option>
            </select>
            <select id="filter-severity" onchange="loadFindings()" class="bg-slate-800 text-xs rounded border border-slate-700 px-3 py-1.5 text-slate-300">
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
          <button onclick="loadFindings()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700"><i class="fa fa-rotate-right mr-1"></i>Refresh</button>
        </div>
        <div id="findings-container" class="space-y-3">
          <div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No findings matching query.</div>
        </div>
      </section>

      <!-- 3. LIVE TELEMETRY PAGE -->
      <section id="tab-live" class="hidden space-y-4">
        <div class="flex items-center justify-between">
          <div class="text-sm text-slate-400">Stream of live ingested events from Linux Audit, journald, and /proc</div>
          <button onclick="refreshEvents()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700"><i class="fa fa-rotate-right mr-1"></i>Refresh</button>
        </div>
        <div class="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-800/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th class="p-3">Timestamp</th>
                <th class="p-3">Severity</th>
                <th class="p-3">Source</th>
                <th class="p-3">Origin</th>
                <th class="p-3">Event Type</th>
                <th class="p-3">User / PID</th>
                <th class="p-3">Process / Command</th>
              </tr>
            </thead>
            <tbody id="live-events-tbody" class="divide-y divide-slate-800">
              <tr><td colspan="7" class="p-8 text-center text-slate-500 italic">No telemetry events recorded yet.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- 4. INCIDENTS PAGE -->
      <section id="tab-incidents" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div class="text-xs text-slate-400">Correlated security incidents with ordered evidence timeline</div>
          <button onclick="loadIncidents()" class="px-3 py-1 bg-slate-800 text-xs rounded border border-slate-700"><i class="fa fa-rotate-right mr-1"></i>Refresh</button>
        </div>
        <div id="incidents-container" class="space-y-4">
          <div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No incidents detected.</div>
        </div>
      </section>

      <!-- 5. ATTACK PATHS PAGE -->
      <section id="tab-attack-paths" class="hidden space-y-4">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <div class="flex justify-between items-center mb-3">
            <div>
              <h2 class="text-base font-bold text-white flex items-center space-x-2">
                <i class="fa fa-route text-orange-400"></i>
                <span>Attack Pathway Analysis</span>
              </h2>
              <p class="text-xs text-slate-400 mt-1">Multi-hop graph paths leading from unprivileged user to root UID 0.</p>
            </div>
            <button onclick="loadAttackPaths()" class="px-3 py-1.5 bg-slate-800 text-xs rounded border border-slate-700"><i class="fa fa-rotate-right mr-1"></i>Refresh</button>
          </div>
          <div class="p-3 bg-amber-950/30 border border-amber-800/50 rounded text-xs text-amber-300">
            <i class="fa fa-circle-info mr-1"></i>
            All paths are labeled <strong>CONFIGURATION_ONLY</strong>. They reflect theoretical exploitability derived from static permissions, not confirmed execution.
          </div>
        </div>
        <div id="attack-paths-container" class="space-y-4">
          <div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No exploitable attack paths mapped.</div>
        </div>
      </section>

      <!-- 6. REMEDIATION PAGE -->
      <section id="tab-remediation" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800 space-y-4">
          <h2 class="text-base font-bold text-white flex items-center space-x-2">
            <i class="fa fa-wrench text-cyan-400"></i>
            <span>Defensive Remediation Console</span>
          </h2>
          <p class="text-xs text-slate-400">Generate, dry-run, apply, and rollback safe permission corrections.</p>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div class="md:col-span-2">
              <label class="block text-xs font-medium text-slate-400 mb-1">Select Finding to Remediate</label>
              <select id="remediation-finding-select" class="w-full bg-slate-800 text-xs rounded border border-slate-700 px-3 py-2 text-slate-200">
                <option value="">Select a finding...</option>
              </select>
            </div>
            <div class="flex items-end space-x-2">
              <button onclick="planSelectedRemediation()" class="w-full px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold">Generate Plan</button>
            </div>
          </div>

          <!-- Plan Card -->
          <div id="remediation-plan-card" class="hidden bg-slate-950 p-4 rounded border border-slate-800 space-y-3 text-xs">
            <div class="flex justify-between items-center">
              <span class="font-bold text-white" id="rem-plan-title">Plan Details</span>
              <span class="font-mono text-slate-400" id="rem-plan-resource">/path/to/target</span>
            </div>
            <div>
              <span class="text-slate-500 block mb-1">Proposed Command:</span>
              <div class="bg-slate-900 p-2 rounded font-mono text-emerald-400" id="rem-plan-command">chmod 755 ...</div>
            </div>
            <div>
              <span class="text-slate-500 block mb-1">Rollback Command:</span>
              <div class="bg-slate-900 p-2 rounded font-mono text-amber-400" id="rem-plan-rollback">chmod ...</div>
            </div>
            <div>
              <span class="text-slate-500 block mb-1">Consequences:</span>
              <div class="text-slate-300" id="rem-plan-consequences">...</div>
            </div>

            <div class="pt-3 border-t border-slate-800 flex items-center justify-between">
              <div class="flex items-center space-x-4">
                <label class="flex items-center space-x-1.5 cursor-pointer">
                  <input type="checkbox" id="rem-chk-dryrun" checked class="rounded border-slate-700 bg-slate-800">
                  <span class="text-slate-300">Dry-run simulation</span>
                </label>
                <label class="flex items-center space-x-1.5 cursor-pointer">
                  <input type="checkbox" id="rem-chk-confirm" class="rounded border-slate-700 bg-slate-800">
                  <span class="text-slate-300">Explicit confirmation</span>
                </label>
              </div>
              <div class="flex items-center space-x-2">
                <button onclick="executeSelectedRemediation()" class="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded font-semibold">Apply Fix</button>
                <button onclick="rollbackSelectedRemediation()" class="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-semibold">Rollback</button>
              </div>
            </div>
          </div>

          <!-- Execution Result Output -->
          <div id="remediation-result-card" class="hidden bg-slate-950 p-4 rounded border border-slate-800 font-mono text-xs">
            <div class="text-slate-400 mb-1 font-sans font-semibold">Execution Output:</div>
            <pre id="rem-result-text" class="text-slate-300 whitespace-pre-wrap"></pre>
          </div>
        </div>
      </section>

      <!-- 7. TELEMETRY HEALTH PAGE -->
      <section id="tab-health" class="hidden space-y-4">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800 flex justify-between items-center">
          <div>
            <h2 class="text-base font-bold text-white">Telemetry Subsystem Health</h2>
            <p class="text-xs text-slate-400 mt-1">Status of Linux Audit Netlink, systemd-journald, /proc, and kernel probes.</p>
          </div>
          <button onclick="loadHealth()" class="px-3 py-1.5 bg-slate-800 text-xs rounded border border-slate-700"><i class="fa fa-rotate-right mr-1"></i>Refresh Health</button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4" id="health-grid">
          <div class="text-xs text-slate-500 italic p-6 text-center">Loading telemetry health...</div>
        </div>
      </section>

      <!-- 8. REPORTS PAGE -->
      <section id="tab-reports" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <h2 class="text-base font-bold text-white mb-2">Export Assessment Reports</h2>
          <p class="text-xs text-slate-400 mb-6">Produce machine-readable JSON or executive ReportLab PDF reports with evidence hashes and limitations.</p>
          <div class="flex items-center space-x-3">
            <button onclick="generateReport('pdf')" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-pdf"></i><span>Generate Complete PDF Report</span></button>
            <button onclick="generateReport('json')" class="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-code"></i><span>Generate Complete JSON Report</span></button>
            <button onclick="generateReport('csv')" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-csv"></i><span>Generate CSV Export</span></button>
          </div>
          <div id="report-download-link" class="mt-4 text-xs"></div>
        </div>
      </section>

      <!-- 9. SYSTEM INFORMATION PAGE -->
      <section id="tab-system" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <h2 class="text-base font-bold text-white mb-4">Target Operating System & Runtime</h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs" id="system-info-grid">
            <div><span class="text-slate-500">Hostname:</span> <span id="sys-host" class="text-white block font-mono">--</span></div>
            <div><span class="text-slate-500">OS / Distro:</span> <span id="sys-distro" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Kernel Release:</span> <span id="sys-kernel" class="text-white block font-mono">--</span></div>
            <div><span class="text-slate-500">Architecture:</span> <span id="sys-arch" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Execution User:</span> <span id="sys-user" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Root Privileges:</span> <span id="sys-root" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Package Manager:</span> <span id="sys-pm" class="text-white block">--</span></div>
            <div><span class="text-slate-500">UATU Edition:</span> <span class="text-cyan-400 block font-bold">Linux Native 3.0</span></div>
          </div>
        </div>
      </section>

    </div>
  </main>

  <script>
    const API_KEY = "%%API_KEY%%";

    // Authenticated Fetch wrapper
    async function authFetch(url, options = {}) {
      options.headers = options.headers || {};
      if (options.headers instanceof Headers) {
        options.headers.set('X-API-Key', API_KEY);
      } else {
        options.headers['X-API-Key'] = API_KEY;
      }
      return fetch(url, options);
    }

    // Tab switching
    function switchTab(tabId) {
      document.querySelectorAll('main > div > section').forEach(el => el.classList.add('hidden'));
      const activeSec = document.getElementById('tab-' + tabId);
      if (activeSec) activeSec.classList.remove('hidden');
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
        document.getElementById('page-title').innerText = event.currentTarget.innerText.trim();
      }

      if (tabId === 'overview') loadOverview();
      else if (tabId === 'findings') loadFindings();
      else if (tabId === 'live') refreshEvents();
      else if (tabId === 'incidents') loadIncidents();
      else if (tabId === 'attack-paths') loadAttackPaths();
      else if (tabId === 'remediation') loadRemediationOptions();
      else if (tabId === 'health') loadHealth();
      else if (tabId === 'system') loadSystem();
    }

    // Load Overview Data
    async function loadOverview() {
      try {
        const res = await authFetch('/api/v1/overview');
        const data = await res.json();
        document.getElementById('stat-score').innerText = data.posture.score + '/100';
        document.getElementById('stat-status').innerText = data.posture.status;
        document.getElementById('stat-coverage').innerText = data.telemetry_health.overall_coverage_pct + '%';
        document.getElementById('nav-host').innerText = data.system.hostname;

        // Findings count
        const fRes = await authFetch('/api/v1/findings');
        const findings = await fRes.json();
        document.getElementById('stat-findings').innerText = findings.length;

        // Paths count
        const pRes = await authFetch('/api/v1/attack-paths');
        const paths = await pRes.json();
        document.getElementById('stat-paths').innerText = paths.length;

        // Telemetry health list
        const telList = document.getElementById('overview-telemetry');
        telList.innerHTML = '';
        for (const [k, s] of Object.entries(data.telemetry_health.sources)) {
          const isHealthy = s.available && s.readable;
          telList.innerHTML += `
            <div class="flex items-center justify-between p-2 rounded bg-slate-800/40 border border-slate-800">
              <span class="text-slate-300 font-medium">${s.name}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isHealthy ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">
                ${isHealthy ? 'HEALTHY' : (s.available ? 'PERM_DENIED' : 'UNAVAILABLE')}
              </span>
            </div>`;
        }

        // Incidents summary
        const incList = document.getElementById('overview-incidents');
        if (data.incidents && data.incidents.length > 0) {
          incList.innerHTML = data.incidents.map(inc => `
            <div class="p-3 bg-slate-800/60 rounded border border-slate-700 flex justify-between items-center">
              <div>
                <span class="text-xs font-bold text-white">${inc.title}</span>
                <span class="text-[10px] text-slate-400 block">${inc.hypothesis}</span>
              </div>
              <span class="text-[10px] font-bold px-2 py-0.5 rounded badge-crit">${inc.severity}</span>
            </div>
          `).join('');
        } else {
          incList.innerHTML = '<div class="text-xs text-slate-500 italic py-4 text-center">No incidents detected.</div>';
        }

        // Monitoring toggle pill
        const pill = document.getElementById('monitoring-pill');
        if (data.monitoring.active) {
          pill.className = "text-xs px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800";
          pill.innerText = "● Monitoring Active";
          document.getElementById('btn-toggle-monitor').innerText = "Stop Watch";
        } else {
          pill.className = "text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700";
          pill.innerText = "● Monitoring Inactive";
          document.getElementById('btn-toggle-monitor').innerText = "Start Watch";
        }
      } catch (err) {
        console.error("Overview error:", err);
      }
    }

    // Toggle Monitoring
    async function toggleMonitoring() {
      const btn = document.getElementById('btn-toggle-monitor');
      const isStart = btn.innerText.includes("Start");
      const endpoint = isStart ? '/api/v1/monitoring/start' : '/api/v1/monitoring/stop';
      await authFetch(endpoint, { method: 'POST' });
      loadOverview();
    }

    // Trigger Red Scan
    async function triggerRedScan() {
      const btn = event.currentTarget;
      btn.disabled = true;
      btn.innerText = "Scanning...";
      try {
        const res = await authFetch('/api/v1/scan/red', { method: 'POST' });
        const data = await res.json();
        alert(`Assessment scan complete! Discovered ${data.findings_count} findings.`);
        loadOverview();
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa fa-play mr-1"></i>Run Scan';
      }
    }

    // Load Findings
    async function loadFindings() {
      const v = document.getElementById('filter-vector').value;
      const s = document.getElementById('filter-severity').value;
      const res = await authFetch(`/api/v1/findings?vector=${v}&severity=${s}`);
      const findings = await res.json();
      const container = document.getElementById('findings-container');

      if (!findings.length) {
        container.innerHTML = '<div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No findings matching query.</div>';
        return;
      }

      container.innerHTML = findings.map(f => `
        <div class="bg-slate-900 p-4 rounded-lg border border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="text-xs px-2 py-0.5 rounded font-bold badge-${f.severity.toLowerCase().slice(0,4)}">${f.severity}</span>
              <span class="text-xs text-slate-400 uppercase font-mono">[${f.vector}]</span>
              <span class="text-xs px-2 py-0.5 rounded font-mono badge-origin">DATA_ORIGIN: STATIC_SCAN</span>
              <span class="text-sm font-semibold text-white">${f.title}</span>
            </div>
            <div class="flex items-center space-x-2">
              <a href="/api/v1/reports/export/json?item_type=finding&item_id=${f.finding_id}" target="_blank" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-amber-400 text-[10px] rounded border border-slate-700"><i class="fa fa-code mr-1"></i>JSON</a>
              <a href="/api/v1/reports/export/pdf?item_type=finding&item_id=${f.finding_id}" target="_blank" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-rose-400 text-[10px] rounded border border-slate-700"><i class="fa fa-file-pdf mr-1"></i>PDF</a>
              <span class="text-[10px] text-slate-500 font-mono">${f.affected_resource || ''}</span>
            </div>
          </div>
          <p class="text-xs text-slate-300">${f.description}</p>
          <div class="text-xs text-slate-400 italic">Risk: ${f.risk_explanation || 'Privilege escalation pathway'}</div>
          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs font-mono text-slate-300">
            <span class="text-slate-500 block text-[10px] uppercase font-sans">Defensive Remediation:</span>
            ${f.remediation}
          </div>
        </div>
      `).join('');
    }

    // Refresh Live Events
    async function refreshEvents() {
      const res = await authFetch('/api/v1/events?limit=100');
      const events = await res.json();
      const tbody = document.getElementById('live-events-tbody');

      if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-slate-500 italic">No telemetry events recorded yet.</td></tr>';
        return;
      }

      tbody.innerHTML = events.map(e => `
        <tr class="hover:bg-slate-800/40">
          <td class="p-3 font-mono text-slate-400">${e.timestamp ? e.timestamp.replace('T', ' ').slice(0,19) : ''}</td>
          <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold badge-${e.severity ? e.severity.toLowerCase().slice(0,4) : 'info'}">${e.severity}</span></td>
          <td class="p-3 text-slate-300">${e.source}</td>
          <td class="p-3"><span class="px-1.5 py-0.5 rounded text-[10px] font-mono badge-origin">${e.data_origin || 'LIVE_TELEMETRY'}</span></td>
          <td class="p-3 font-mono text-cyan-400">${e.event_type}</td>
          <td class="p-3 text-slate-300">${e.user || 'uid:' + e.uid} / ${e.pid || '-'}</td>
          <td class="p-3 font-mono text-slate-300 max-w-xs truncate">${e.command || e.process || '-'}</td>
        </tr>
      `).join('');
    }

    // Load Incidents
    async function loadIncidents() {
      const res = await authFetch('/api/v1/incidents');
      const incidents = await res.json();
      const container = document.getElementById('incidents-container');

      if (!incidents.length) {
        container.innerHTML = '<div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No incidents detected.</div>';
        return;
      }

      container.innerHTML = incidents.map(inc => `
        <div class="bg-slate-900 p-5 rounded-lg border border-slate-800 space-y-3">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="text-xs px-2 py-0.5 rounded font-bold badge-${inc.severity.toLowerCase().slice(0,4)}">${inc.severity}</span>
              <span class="text-sm font-bold text-white">${inc.title}</span>
              <span class="text-xs text-slate-400">Status: <strong class="text-cyan-400">${inc.status}</strong></span>
            </div>
            <div class="flex items-center space-x-2">
              <a href="/api/v1/reports/export/json?item_type=incident&item_id=${inc.incident_id}" target="_blank" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-amber-400 text-[10px] rounded border border-slate-700"><i class="fa fa-code mr-1"></i>JSON</a>
              <a href="/api/v1/reports/export/pdf?item_type=incident&item_id=${inc.incident_id}" target="_blank" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-rose-400 text-[10px] rounded border border-slate-700"><i class="fa fa-file-pdf mr-1"></i>PDF</a>
              <span class="text-[10px] text-slate-500 font-mono">${inc.incident_id}</span>
            </div>
          </div>
          <p class="text-xs text-slate-300">${inc.hypothesis}</p>
          <div class="bg-slate-950 p-3 rounded border border-slate-800 text-xs">
            <span class="text-slate-500 block text-[10px] uppercase font-sans mb-1">Ordered Constituent Evidence (${inc.event_ids.length} Events):</span>
            <div class="font-mono text-slate-300 space-y-1">
              ${inc.event_ids.map(eid => `<div>• Event Ref: <span class="text-cyan-400">${eid}</span></div>`).join('')}
            </div>
          </div>
        </div>
      `).join('');
    }

    // Load Attack Paths
    async function loadAttackPaths() {
      const res = await authFetch('/api/v1/attack-paths');
      const paths = await res.json();
      const container = document.getElementById('attack-paths-container');

      if (!paths.length) {
        container.innerHTML = '<div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No exploitable attack paths mapped.</div>';
        return;
      }

      container.innerHTML = paths.map(p => `
        <div class="bg-slate-900 p-5 rounded-lg border border-slate-800 space-y-3">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="text-xs px-2 py-0.5 rounded font-bold bg-amber-950 text-amber-400 border border-amber-800">CONFIGURATION_ONLY</span>
              <span class="text-sm font-bold text-white">Path ${p.path_id}</span>
              <span class="text-xs text-slate-400">Risk Score: <strong class="text-rose-400">${p.total_risk_score}</strong></span>
            </div>
            <span class="text-[10px] text-slate-500 font-mono">Confidence: ${p.confidence}</span>
          </div>
          <div class="p-3 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-cyan-300 flex items-center space-x-2 overflow-x-auto">
            ${p.node_ids.map((n, i) => `
              <span class="px-2 py-1 bg-slate-900 rounded border border-slate-700">${n}</span>
              ${i < p.node_ids.length - 1 ? '<i class="fa fa-arrow-right text-slate-500 text-[10px]"></i>' : ''}
            `).join('')}
          </div>
          <div class="text-xs text-slate-300">
            <strong>Bottleneck Node:</strong> <span class="font-mono text-amber-400">${p.bottleneck_node_id || 'N/A'}</span>
          </div>
          <div class="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs text-emerald-400 font-mono">
            <strong>Recommended Disruption:</strong> ${p.recommended_disruption || 'None specified'}
          </div>
        </div>
      `).join('');
    }

    // Load Remediation Finding Options
    async function loadRemediationOptions() {
      const res = await authFetch('/api/v1/findings');
      const findings = await res.json();
      const select = document.getElementById('remediation-finding-select');
      select.innerHTML = '<option value="">Select a finding...</option>';
      findings.forEach(f => {
        select.innerHTML += `<option value="${f.finding_id}">[${f.severity}] ${f.title} (${f.affected_resource})</option>`;
      });
    }

    // Plan Remediation
    async function planSelectedRemediation() {
      const fId = document.getElementById('remediation-finding-select').value;
      if (!fId) { alert("Please select a finding first."); return; }
      const res = await authFetch('/api/v1/remediation/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: fId })
      });
      if (!res.ok) { alert("Error generating plan"); return; }
      const plan = await res.json();

      document.getElementById('rem-plan-title').innerText = plan.title;
      document.getElementById('rem-plan-resource').innerText = plan.target_resource;
      document.getElementById('rem-plan-command').innerText = plan.proposed_commands.join(' && ');
      document.getElementById('rem-plan-rollback').innerText = plan.rollback_commands.join(' && ');
      document.getElementById('rem-plan-consequences').innerText = plan.consequences;
      document.getElementById('remediation-plan-card').classList.remove('hidden');
    }

    // Execute Remediation
    async function executeSelectedRemediation() {
      const fId = document.getElementById('remediation-finding-select').value;
      const dryRun = document.getElementById('rem-chk-dryrun').checked;
      const confirmed = document.getElementById('rem-chk-confirm').checked;

      if (!dryRun && !confirmed) {
        alert("You must check 'Explicit confirmation' to apply real changes!");
        return;
      }

      const res = await authFetch('/api/v1/remediation/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: fId, dry_run: dryRun, confirmed: confirmed })
      });
      const data = await res.json();
      document.getElementById('remediation-result-card').classList.remove('hidden');
      document.getElementById('rem-result-text').innerText = JSON.stringify(data, null, 2);
    }

    // Rollback Remediation
    async function rollbackSelectedRemediation() {
      const fId = document.getElementById('remediation-finding-select').value;
      if (!fId) { alert("Please select a finding to rollback."); return; }

      const res = await authFetch('/api/v1/remediation/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: fId })
      });
      const data = await res.json();
      document.getElementById('remediation-result-card').classList.remove('hidden');
      document.getElementById('rem-result-text').innerText = JSON.stringify(data, null, 2);
    }

    // Load Health
    async function loadHealth() {
      const res = await fetch('/api/v1/health');
      const data = await res.json();
      const grid = document.getElementById('health-grid');
      grid.innerHTML = '';
      for (const [k, s] of Object.entries(data.sources)) {
        const isHealthy = s.available && s.readable;
        grid.innerHTML += `
          <div class="bg-slate-900 p-4 rounded-lg border border-slate-800 space-y-2">
            <div class="flex justify-between items-center">
              <span class="font-bold text-white text-sm">${s.name}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isHealthy ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">
                ${isHealthy ? 'HEALTHY' : (s.available ? 'PERM_DENIED' : 'UNAVAILABLE')}
              </span>
            </div>
            <div class="text-xs text-slate-400 space-y-1">
              <div>Available: <strong class="text-white">${s.available}</strong></div>
              <div>Readable: <strong class="text-white">${s.readable}</strong></div>
              <div>Collection Method: <span class="font-mono text-cyan-400">${s.collection_method}</span></div>
            </div>
          </div>
        `;
      }
    }

    // Generate Reports
    async function generateReport(fmt) {
      const res = await authFetch('/api/v1/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: fmt, mode: 'red' })
      });
      const data = await res.json();
      const linkDiv = document.getElementById('report-download-link');
      linkDiv.innerHTML = `<a href="/api/v1/reports/download?path=${encodeURIComponent(data.output_file)}" class="text-cyan-400 underline font-semibold"><i class="fa fa-download mr-1"></i>Download Generated ${fmt.toUpperCase()} Report</a>`;
    }

    // Load System Info
    async function loadSystem() {
      const res = await authFetch('/api/v1/system');
      const data = await res.json();
      document.getElementById('sys-host').innerText = data.hostname;
      document.getElementById('sys-distro').innerText = `${data.os_info.distro_name} ${data.os_info.distro_version}`;
      document.getElementById('sys-kernel').innerText = data.kernel;
      document.getElementById('sys-arch').innerText = data.os_info.machine;
      document.getElementById('sys-user').innerText = data.user;
      document.getElementById('sys-root').innerText = data.is_root ? "YES (Privileged)" : "NO (Unprivileged)";
      document.getElementById('sys-pm').innerText = data.os_info.package_manager;
    }

    // Initialize on load
    window.onload = () => {
      loadOverview();
      loadSystem();
    };
  </script>
</body>
</html>
"""


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serve the single-page UATU operations dashboard with injected auth token"""
    html = DASHBOARD_HTML.replace("%%API_KEY%%", API_KEY)
    return HTMLResponse(content=html, status_code=200)


@app.get("/health")
@app.get("/api/v1/health")
def get_health():
    """Telemetry health status endpoint (unauthenticated)"""
    return orchestrator.get_telemetry_health().to_dict()


@app.get("/api/v1/overview")
def get_overview(auth: Dict[str, str] = Depends(verify_api_key)):
    """Retrieve top-level operational health, posture, and active incidents"""
    posture = orchestrator.get_posture()
    telemetry_health = orchestrator.get_telemetry_health()
    incidents = storage.get_incidents(status=IncidentStatus.NEW.value)

    return {
        'posture': posture.to_dict(),
        'telemetry_health': telemetry_health.to_dict(),
        'monitoring': {
            'active': orchestrator.is_monitoring()
        },
        'incidents': [i.to_dict() for i in incidents],
        'system': {
            'hostname': telemetry_health.hostname
        }
    }


@app.get("/api/v1/findings")
def get_findings(
    vector: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Retrieve security findings from persistent storage with filters"""
    findings = storage.get_findings(vector=vector, severity=severity)
    return [f.to_dict() for f in findings]


@app.get("/api/v1/events")
def get_events(
    limit: int = 100,
    event_type: Optional[str] = Query(None),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Retrieve normalized security events with explicit data_origin"""
    events = storage.get_events(limit=limit, event_type=event_type)
    return [e.to_dict() for e in events]


@app.get("/api/v1/incidents")
def get_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Retrieve correlated security incidents"""
    incidents = storage.get_incidents(status=status_filter)
    return [i.to_dict() for i in incidents]


@app.post("/api/v1/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    auth: Dict[str, str] = Depends(require_admin)
):
    """Update workflow status of an incident with admin authorization"""
    storage.update_incident_status(incident_id, update.status, update.note)
    storage.log_admin_action(
        action="UPDATE_INCIDENT_STATUS",
        target=incident_id,
        actor=auth["user"],
        details={'status': update.status, 'note': update.note},
        result="SUCCESS"
    )
    return {'status': 'SUCCESS', 'incident_id': incident_id, 'new_status': update.status}


@app.get("/api/v1/attack-paths")
def get_attack_paths(auth: Dict[str, str] = Depends(verify_api_key)):
    """Retrieve mapped attack paths strictly labeled with CONFIGURATION_ONLY level"""
    return storage.get_attack_paths()


@app.get("/api/v1/timeline")
def get_timeline(auth: Dict[str, str] = Depends(verify_api_key)):
    """Build and return unified chronological timeline"""
    from modules.timeline.timeline_builder import TimelineBuilder
    from modules.timeline.event_correlator import EventCorrelator

    correlator = EventCorrelator(window_seconds=config.timeline_window_sec)
    events = storage.get_events(limit=1000)
    correlator.add_events(events)

    builder = TimelineBuilder(correlator)
    timeline = builder.build_timeline()

    for entry in timeline:
        if isinstance(entry.get('timestamp'), datetime):
            entry['timestamp'] = entry['timestamp'].isoformat()

    return timeline


@app.get("/api/v1/system")
def get_system_info(auth: Dict[str, str] = Depends(verify_api_key)):
    """Retrieve target system platform details"""
    return {
        'hostname': orchestrator.get_telemetry_health().hostname,
        'kernel': get_kernel_version(),
        'os_info': get_os_info(),
        'user': get_current_user(),
        'is_root': is_root()
    }


@app.post("/api/v1/scan/red")
def trigger_red_scan(auth: Dict[str, str] = Depends(require_admin)):
    """Trigger complete privilege escalation scan (Admin only)"""
    storage.log_admin_action(
        action="TRIGGER_RED_SCAN",
        target="system",
        actor=auth["user"],
        details={},
        result="STARTED"
    )
    findings = orchestrator.run_red_team_scan()
    return {
        'status': 'COMPLETED',
        'findings_count': len(findings),
        'findings': [f.to_dict() for f in findings]
    }


@app.post("/api/v1/scan/blue")
def trigger_blue_scan(auth: Dict[str, str] = Depends(require_admin)):
    """Trigger Blue Team telemetry log analysis (Admin only)"""
    storage.log_admin_action(
        action="TRIGGER_BLUE_SCAN",
        target="telemetry_logs",
        actor=auth["user"],
        details={},
        result="STARTED"
    )
    findings = orchestrator.run_blue_team_analysis()
    return {
        'status': 'COMPLETED',
        'detections_count': len(findings),
        'findings': [f.to_dict() for f in findings]
    }


@app.post("/api/v1/monitoring/start")
def start_monitoring(auth: Dict[str, str] = Depends(require_admin)):
    """Start live background telemetry monitoring (Admin only)"""
    orchestrator.start_monitoring(poll_interval_sec=5)
    storage.log_admin_action(
        action="START_MONITORING",
        target="system_telemetry",
        actor=auth["user"],
        details={'interval_sec': 5},
        result="SUCCESS"
    )
    return {'status': 'STARTED', 'monitoring': True}


@app.post("/api/v1/monitoring/stop")
def stop_monitoring(auth: Dict[str, str] = Depends(require_admin)):
    """Stop live background telemetry monitoring (Admin only)"""
    orchestrator.stop_monitoring()
    storage.log_admin_action(
        action="STOP_MONITORING",
        target="system_telemetry",
        actor=auth["user"],
        details={},
        result="SUCCESS"
    )
    return {'status': 'STOPPED', 'monitoring': False}


@app.get("/api/v1/monitoring/status")
def get_monitoring_status(auth: Dict[str, str] = Depends(verify_api_key)):
    """Check live monitoring status"""
    return {'monitoring': orchestrator.is_monitoring()}


@app.post("/api/v1/remediation/plan")
def get_remediation_plan(
    finding_id: str = Body(..., embed=True),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Generate a least-privilege remediation plan for a finding"""
    findings = storage.get_findings()
    matching = [f for f in findings if f.finding_id == finding_id]
    if not matching:
        raise HTTPException(status_code=404, detail="Finding ID not found")

    plan = remediation_engine.generate_plan(matching[0])
    return {
        'finding_id': plan.finding_id,
        'title': plan.title,
        'target_resource': plan.target_resource,
        'proposed_commands': plan.proposed_commands,
        'consequences': plan.consequences,
        'rollback_commands': plan.rollback_commands
    }


@app.post("/api/v1/remediation/execute")
def execute_remediation(
    req: RemediationRequest,
    auth: Dict[str, str] = Depends(require_admin)
):
    """Execute or simulate remediation plan (Admin only)"""
    findings = storage.get_findings()
    matching = [f for f in findings if f.finding_id == req.finding_id]
    if not matching:
        raise HTTPException(status_code=404, detail="Finding ID not found")

    plan = remediation_engine.generate_plan(matching[0])
    result = remediation_engine.execute_plan(
        plan=plan,
        actor=auth["user"],
        confirmed=req.confirmed,
        dry_run=req.dry_run
    )
    return result


@app.post("/api/v1/remediation/rollback")
def rollback_remediation(
    req: RollbackRequest,
    auth: Dict[str, str] = Depends(require_admin)
):
    """Rollback previous remediation action for a finding (Admin only)"""
    result = remediation_engine.rollback_plan(
        finding_id=req.finding_id,
        actor=auth["user"]
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Rollback failed"))
    return result


@app.post("/api/v1/reports/generate")
def generate_report(
    req: ReportRequest,
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Generate JSON, PDF, or CSV report"""
    findings = storage.get_findings()
    posture = orchestrator.get_posture()
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = Path(config.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    fmt = req.format.lower()
    if fmt == "json":
        out_file = str(out_dir / f"privwatch_report_{timestamp_str}.json")
        path = JSONExporter.export_findings(findings, out_file, mode=req.mode, posture=posture)
    elif fmt == "pdf":
        out_file = str(out_dir / f"privwatch_report_{timestamp_str}.pdf")
        path = PDFGenerator.generate_report(findings, out_file, mode=req.mode, posture=posture)
    elif fmt == "csv":
        out_file = str(out_dir / f"privwatch_report_{timestamp_str}.csv")
        path = CSVExporter.export_findings(findings, out_file)
    else:
        raise HTTPException(status_code=400, detail="Unsupported report format")

    return {
        'status': 'SUCCESS',
        'format': fmt,
        'output_file': path
    }


@app.get("/api/v1/reports/download")
def download_report(
    path: str = Query(...),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Download generated report with path traversal validation"""
    safe_path = safe_resolve_path(path, base_dir=config.output_dir)
    if not safe_path or not os.path.exists(safe_path):
        raise HTTPException(status_code=403, detail="Access denied or file does not exist")

    filename = os.path.basename(safe_path)
    return FileResponse(safe_path, filename=filename)


@app.get("/api/v1/reports/export/json")
def export_item_json_route(
    item_type: str = Query(...),
    item_id: str = Query(...),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Export single finding or incident to JSON with evidence hash and limitations."""
    item = None
    related_events = []
    if item_type.lower() == "finding":
        findings = storage.get_findings()
        match = [f for f in findings if f.finding_id == item_id]
        if not match:
            raise HTTPException(status_code=404, detail="Finding not found")
        item = match[0]
    elif item_type.lower() == "incident":
        incidents = storage.get_incidents()
        match = [i for i in incidents if i.incident_id == item_id]
        if not match:
            raise HTTPException(status_code=404, detail="Incident not found")
        item = match[0]
        for eid in item.event_ids:
            ev = storage.get_event_by_id(eid)
            if ev:
                related_events.append(ev)
    else:
        raise HTTPException(status_code=400, detail="Invalid item_type, must be 'finding' or 'incident'")

    out_dir = Path(config.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = str(out_dir / f"export_{item_type}_{item_id}.json")
    path = JSONExporter.export_item_json(item, out_file, related_events)
    return FileResponse(path, filename=os.path.basename(path))


@app.get("/api/v1/reports/export/pdf")
def export_item_pdf_route(
    item_type: str = Query(...),
    item_id: str = Query(...),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Export single finding or incident to ReportLab PDF with evidence hash and limitations."""
    item = None
    related_events = []
    if item_type.lower() == "finding":
        findings = storage.get_findings()
        match = [f for f in findings if f.finding_id == item_id]
        if not match:
            raise HTTPException(status_code=404, detail="Finding not found")
        item = match[0]
    elif item_type.lower() == "incident":
        incidents = storage.get_incidents()
        match = [i for i in incidents if i.incident_id == item_id]
        if not match:
            raise HTTPException(status_code=404, detail="Incident not found")
        item = match[0]
        for eid in item.event_ids:
            ev = storage.get_event_by_id(eid)
            if ev:
                related_events.append(ev)
    else:
        raise HTTPException(status_code=400, detail="Invalid item_type, must be 'finding' or 'incident'")

    out_dir = Path(config.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = str(out_dir / f"export_{item_type}_{item_id}.pdf")
    path = PDFGenerator.generate_item_report(item, out_file, related_events)
    return FileResponse(path, filename=os.path.basename(path))


@app.get("/api/v1/audit")
def get_audit_trail(
    limit: int = 100,
    auth: Dict[str, str] = Depends(require_admin)
):
    """Retrieve administrative action audit log"""
    return storage.get_audit_logs(limit=limit)


@app.post("/api/v1/suppression")
def add_suppression_rule(
    req: SuppressionRequest,
    auth: Dict[str, str] = Depends(require_admin)
):
    """Add an alert suppression rule (Admin only)"""
    import uuid
    rule_id = f"rule_{uuid.uuid4().hex[:8]}"
    storage.add_suppression(
        rule_id=rule_id,
        vector=req.vector,
        pattern=req.pattern,
        reason=req.reason,
        actor=auth["user"]
    )
    return {'status': 'SUCCESS', 'rule_id': rule_id}


# --- PrivWatch 3.1 ML Compatibility Endpoints ---

@app.get("/api/v1/ml/status")
def get_ml_status(auth: Dict[str, str] = Depends(verify_api_key)):
    """Retrieve ML model registry status"""
    from models.registry.model_registry import ModelRegistry
    from ml.inference.model_runner import ModelRunner

    registry = ModelRegistry()
    runner = ModelRunner(registry)
    drift_status = runner.drift_monitor.get_monitoring_status()

    meta_dir = registry.metadata_dir
    models = {}
    if os.path.exists(meta_dir):
        for f in os.listdir(meta_dir):
            if f.endswith(".json"):
                m_path = os.path.join(meta_dir, f)
                try:
                    with open(m_path, "r", encoding="utf-8") as mfile:
                        card = json.load(mfile)
                        models[card.get("model_id")] = {
                            "version": card.get("version"),
                            "algorithm": card.get("algorithm"),
                            "validation_status": card.get("validation_status"),
                            "sha256": card.get("sha256_hash", "")[:16] + "..."
                        }
                except Exception:
                    pass

    return {
        "status": "OPERATIONAL",
        "registered_models": models,
        "drift_monitor": drift_status
    }


@app.post("/api/v1/ml/evaluate")
def evaluate_ml_event(
    payload: Dict[str, Any] = Body(...),
    auth: Dict[str, str] = Depends(verify_api_key)
):
    """Evaluate event through ML model runner"""
    from core.models import SecurityEvent
    from ml.inference.model_runner import ModelRunner

    runner = ModelRunner()
    ev = SecurityEvent.from_dict(payload)
    explanation = runner.evaluate_event(ev)
    return explanation.to_dict()
