"""
PrivWatch 3.0 - Security Operations Dashboard & REST API
FastAPI-based modern operational dashboard providing real-time telemetry visibility,
interactive assessment triggers, forensic timelines, controlled remediation, and report exports.
"""

from datetime import datetime, timezone
import json
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

# Initialize Application
config = PrivWatchConfig()
orchestrator = PrivWatchOrchestrator(config)
storage = orchestrator.storage
remediation_engine = RemediationEngine(storage=storage, read_only=config.read_only_mode)

app = FastAPI(
    title="PrivWatch 3.0 Platform API",
    description="REST API for PrivWatch privilege escalation auditing, telemetry, forensics, and remediation.",
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


# API Security, Role-Based Access Control & Rate Limiting
API_KEY = os.getenv("PRIVWATCH_API_KEY", "privwatch-secure-local-admin-token")
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
  <title>PrivWatch 3.0 — Security Operations Platform</title>
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
  </style>
</head>
<body class="flex h-screen overflow-hidden">

  <!-- Sidebar Navigation -->
  <aside class="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between">
    <div>
      <div class="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div class="w-9 h-9 bg-cyan-600 rounded flex items-center justify-center font-bold text-white shadow-lg">PW</div>
        <div>
          <div class="font-bold text-white tracking-wide text-sm">PRIVWATCH 3.0</div>
          <div class="text-xs text-slate-400">Security Operations</div>
        </div>
      </div>
      <nav class="mt-4 space-y-1 px-3">
        <button onclick="switchTab('overview')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3 active"><i class="fa fa-chart-pie w-4"></i><span>Overview</span></button>
        <button onclick="switchTab('live')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-satellite-dish w-4"></i><span>Live Monitoring</span></button>
        <button onclick="switchTab('findings')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-shield-virus w-4"></i><span>Security Findings</span></button>
        <button onclick="switchTab('assessment')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-crosshairs w-4"></i><span>Assessment (Red)</span></button>
        <button onclick="switchTab('threats')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-bell w-4"></i><span>Threat Detection</span></button>
        <button onclick="switchTab('timeline')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-clock-rotate-left w-4"></i><span>Forensic Timeline</span></button>
        <button onclick="switchTab('investigations')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-folder-open w-4"></i><span>Investigations</span></button>
        <button onclick="switchTab('reports')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-file-lines w-4"></i><span>Reports & Export</span></button>
        <button onclick="switchTab('system')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-server w-4"></i><span>System Information</span></button>
        <button onclick="switchTab('settings')" class="nav-btn w-full text-left px-3 py-2 rounded text-sm flex items-center space-x-3"><i class="fa fa-sliders w-4"></i><span>Settings & Audit</span></button>
      </nav>
    </div>
    <div class="p-4 border-t border-slate-800 text-xs text-slate-500">
      <div>Host: <span id="nav-host" class="text-slate-300">Checking...</span></div>
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
        <button onclick="triggerRedScan()" class="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center space-x-1.5"><i class="fa fa-play"></i><span>Run Red Scan</span></button>
        <button onclick="triggerBlueAnalysis()" class="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center space-x-1.5"><i class="fa fa-search"></i><span>Analyze Logs</span></button>
        <button id="btn-toggle-monitor" onclick="toggleMonitoring()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-semibold">Start Monitor</button>
      </div>
    </header>

    <!-- Content Sections -->
    <div class="flex-1 overflow-y-auto p-6 space-y-6">

      <!-- 1. OVERVIEW PAGE -->
      <section id="tab-overview" class="space-y-6">
        <!-- Posture Metrics Banner -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Security Posture Score</div>
            <div id="stat-score" class="text-3xl font-extrabold text-white mt-2">--</div>
            <div id="stat-status" class="text-xs text-slate-400 mt-1">Calculated from verified findings</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Critical Findings</div>
            <div id="stat-crit" class="text-3xl font-extrabold text-red-500 mt-2">0</div>
            <div class="text-xs text-red-400/80 mt-1">Requires immediate remediation</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">High Severity Issues</div>
            <div id="stat-high" class="text-3xl font-extrabold text-orange-500 mt-2">0</div>
            <div class="text-xs text-orange-400/80 mt-1">Elevated attack vectors</div>
          </div>
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400 font-medium">Telemetry Coverage</div>
            <div id="stat-coverage" class="text-3xl font-extrabold text-cyan-400 mt-2">--%</div>
            <div class="text-xs text-slate-400 mt-1">Supported log sources active</div>
          </div>
        </div>

        <!-- Recent Incidents & Health -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <h3 class="font-bold text-white text-sm mb-4 flex items-center space-x-2"><i class="fa fa-triangle-exclamation text-amber-500"></i><span>Correlated Incidents</span></h3>
            <div id="overview-incidents" class="space-y-3">
              <div class="text-xs text-slate-500 italic py-4 text-center">No active correlated incidents.</div>
            </div>
          </div>

          <div class="bg-slate-900 p-5 rounded-lg border border-slate-800">
            <h3 class="font-bold text-white text-sm mb-4 flex items-center space-x-2"><i class="fa fa-heart-pulse text-sky-400"></i><span>Telemetry Source Health</span></h3>
            <div id="overview-telemetry" class="space-y-2 text-xs">
              <div class="text-slate-500 italic py-4 text-center">Assessing telemetry sources...</div>
            </div>
          </div>
        </div>
      </section>

      <!-- 2. LIVE MONITORING PAGE -->
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
                <th class="p-3">Event Type</th>
                <th class="p-3">User / PID</th>
                <th class="p-3">Process / Command</th>
              </tr>
            </thead>
            <tbody id="live-events-tbody" class="divide-y divide-slate-800">
              <tr><td colspan="6" class="p-8 text-center text-slate-500 italic">No telemetry events recorded yet. Start monitoring or run log analysis.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- 3. FINDINGS PAGE -->
      <section id="tab-findings" class="hidden space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <select id="filter-vector" onchange="loadFindings()" class="bg-slate-800 text-xs rounded border border-slate-700 px-3 py-1.5 text-slate-300">
              <option value="">All Vectors</option>
              <option value="SUID/SGID">SUID/SGID</option>
              <option value="SUDO">SUDO</option>
              <option value="CAPABILITIES">CAPABILITIES</option>
              <option value="CRON">CRON</option>
              <option value="KERNEL">KERNEL</option>
              <option value="PATH_HIJACKING">PATH HIJACKING</option>
              <option value="SSH_SECURITY">SSH SECURITY</option>
              <option value="CONTAINER_PRIVILEGE">CONTAINER</option>
            </select>
            <select id="filter-severity" onchange="loadFindings()" class="bg-slate-800 text-xs rounded border border-slate-700 px-3 py-1.5 text-slate-300">
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
          <button onclick="loadFindings()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700">Refresh Findings</button>
        </div>
        <div id="findings-container" class="space-y-3">
          <div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No findings matching query.</div>
        </div>
      </section>

      <!-- 4. ASSESSMENT (RED TEAM) PAGE -->
      <section id="tab-assessment" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800 flex justify-between items-center">
          <div>
            <h2 class="text-base font-bold text-white">Privilege Escalation Reconnaissance</h2>
            <p class="text-xs text-slate-400 mt-1">Evaluates all 9 Red Team attack vectors against current operating system permissions.</p>
          </div>
          <button onclick="triggerRedScan()" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-play"></i><span>Trigger Complete Scan</span></button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4" id="assessment-vectors-grid">
          <!-- Populated dynamically -->
        </div>
      </section>

      <!-- 5. THREAT DETECTION (BLUE TEAM) PAGE -->
      <section id="tab-threats" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800 flex justify-between items-center">
          <div>
            <h2 class="text-base font-bold text-white">Log Forensics & Detection</h2>
            <p class="text-xs text-slate-400 mt-1">Scans Linux authentication logs, auditd, and kernel diagnostics for live or historic exploitation attempts.</p>
          </div>
          <button onclick="triggerBlueAnalysis()" class="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-search"></i><span>Run Detection Engine</span></button>
        </div>
        <div class="bg-slate-900 rounded-lg border border-slate-800 p-5">
          <h3 class="font-bold text-white text-sm mb-4">Active Blue Team Detections</h3>
          <div id="threat-detections-list" class="space-y-3">
            <div class="text-xs text-slate-500 italic p-4 text-center">No active threat detections found.</div>
          </div>
        </div>
      </section>

      <!-- 6. FORENSIC TIMELINE PAGE -->
      <section id="tab-timeline" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div class="text-xs text-slate-400">Chronological reconstruction of correlated security events and incidents</div>
          <button onclick="loadTimeline()" class="px-3 py-1 bg-slate-800 text-xs rounded border border-slate-700">Refresh Timeline</button>
        </div>
        <div id="timeline-container" class="space-y-4 border-l-2 border-slate-800 pl-6 ml-4">
          <div class="text-xs text-slate-500 italic py-6">No timeline events available.</div>
        </div>
      </section>

      <!-- 7. INVESTIGATIONS PAGE -->
      <section id="tab-investigations" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div class="text-xs text-slate-400">Case files and incident investigation tracker</div>
          <button onclick="loadIncidents()" class="px-3 py-1 bg-slate-800 text-xs rounded border border-slate-700">Refresh Incidents</button>
        </div>
        <div id="incidents-container" class="space-y-4">
          <div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No active investigation cases.</div>
        </div>
      </section>

      <!-- 8. REPORTS PAGE -->
      <section id="tab-reports" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <h2 class="text-base font-bold text-white mb-2">Generate Assessment Report</h2>
          <p class="text-xs text-slate-400 mb-6">Export findings and timeline into professional machine-readable or executive PDF formats.</p>
          <div class="flex items-center space-x-3">
            <button onclick="generateReport('pdf')" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-pdf"></i><span>Generate PDF Report</span></button>
            <button onclick="generateReport('json')" class="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-code"></i><span>Generate JSON Report</span></button>
            <button onclick="generateReport('csv')" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center space-x-2"><i class="fa fa-file-csv"></i><span>Generate CSV Export</span></button>
          </div>
          <div id="report-download-link" class="mt-4 text-xs"></div>
        </div>
      </section>

      <!-- 9. SYSTEM INFORMATION PAGE -->
      <section id="tab-system" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <h2 class="text-base font-bold text-white mb-4">Host & Environment Details</h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs" id="system-info-grid">
            <div><span class="text-slate-500">Hostname:</span> <span id="sys-host" class="text-white block font-mono">--</span></div>
            <div><span class="text-slate-500">OS / Distro:</span> <span id="sys-distro" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Kernel Release:</span> <span id="sys-kernel" class="text-white block font-mono">--</span></div>
            <div><span class="text-slate-500">Architecture:</span> <span id="sys-arch" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Execution User:</span> <span id="sys-user" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Root Privileges:</span> <span id="sys-root" class="text-white block">--</span></div>
            <div><span class="text-slate-500">Package Manager:</span> <span id="sys-pm" class="text-white block">--</span></div>
            <div><span class="text-slate-500">PrivWatch Version:</span> <span class="text-cyan-400 block font-bold">3.0.0</span></div>
          </div>
        </div>
      </section>

      <!-- 10. SETTINGS & AUDIT PAGE -->
      <section id="tab-settings" class="hidden space-y-6">
        <div class="bg-slate-900 p-6 rounded-lg border border-slate-800">
          <h2 class="text-base font-bold text-white mb-2">Administrative Audit Trail</h2>
          <p class="text-xs text-slate-400 mb-4">Immutable audit log of all scans, alert acknowledgments, and remediation actions.</p>
          <div id="audit-trail-list" class="space-y-2 text-xs">
            <div class="text-slate-500 italic py-4">No audit entries recorded.</div>
          </div>
        </div>
      </section>

    </div>
  </main>

  <script>
    // Tab switching
    function switchTab(tabId) {
      document.querySelectorAll('main > div > section').forEach(el => el.classList.add('hidden'));
      document.getElementById('tab-' + tabId).classList.remove('hidden');
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      event.currentTarget.classList.add('active');
      document.getElementById('page-title').innerText = event.currentTarget.innerText.trim();

      if (tabId === 'overview') loadOverview();
      else if (tabId === 'live') refreshEvents();
      else if (tabId === 'findings') loadFindings();
      else if (tabId === 'timeline') loadTimeline();
      else if (tabId === 'investigations') loadIncidents();
      else if (tabId === 'system') loadSystem();
      else if (tabId === 'settings') loadAudit();
    }

    // Load Overview Data
    async function loadOverview() {
      try {
        const res = await fetch('/api/v1/overview');
        const data = await res.json();
        document.getElementById('stat-score').innerText = data.posture.score + '/100';
        document.getElementById('stat-status').innerText = data.posture.status;
        document.getElementById('stat-crit').innerText = data.posture.critical_count;
        document.getElementById('stat-high').innerText = data.posture.high_count;
        document.getElementById('stat-coverage').innerText = data.telemetry_health.overall_coverage_pct + '%';
        document.getElementById('nav-host').innerText = data.system.hostname;

        // Telemetry health list
        const telList = document.getElementById('overview-telemetry');
        telList.innerHTML = '';
        for (const [k, s] of Object.entries(data.telemetry_health.sources)) {
          telList.innerHTML += `
            <div class="flex items-center justify-between p-2 rounded bg-slate-800/40 border border-slate-800">
              <span class="text-slate-300 font-medium">${s.name}</span>
              <span class="px-2 py-0.5 rounded text-[10px] ${s.available && s.readable ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">
                ${s.available && s.readable ? 'HEALTHY' : (s.available ? 'PERM_DENIED' : 'UNAVAILABLE')}
              </span>
            </div>`;
        }

        // Monitoring status pill
        const pill = document.getElementById('monitoring-pill');
        if (data.monitoring.active) {
          pill.className = "text-xs px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800";
          pill.innerText = "● Monitoring Active";
          document.getElementById('btn-toggle-monitor').innerText = "Stop Monitor";
        } else {
          pill.className = "text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700";
          pill.innerText = "● Monitoring Inactive";
          document.getElementById('btn-toggle-monitor').innerText = "Start Monitor";
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
      await fetch(endpoint, { method: 'POST' });
      loadOverview();
    }

    // Trigger Red Team Scan
    async function triggerRedScan() {
      const btn = event.currentTarget;
      btn.disabled = true;
      btn.innerText = "Scanning...";
      try {
        const res = await fetch('/api/v1/scan/red', { method: 'POST' });
        const data = await res.json();
        alert(`Red Team scan complete! Discovered ${data.findings_count} findings.`);
        loadOverview();
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa fa-play mr-1"></i>Run Red Scan';
      }
    }

    // Trigger Blue Team Analysis
    async function triggerBlueAnalysis() {
      const btn = event.currentTarget;
      btn.disabled = true;
      btn.innerText = "Analyzing...";
      try {
        const res = await fetch('/api/v1/scan/blue', { method: 'POST' });
        const data = await res.json();
        alert(`Blue Team analysis complete! ${data.detections_count} events analyzed.`);
        loadOverview();
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa fa-search mr-1"></i>Analyze Logs';
      }
    }

    // Load Findings
    async function loadFindings() {
      const v = document.getElementById('filter-vector').value;
      const s = document.getElementById('filter-severity').value;
      const res = await fetch(`/api/v1/findings?vector=${v}&severity=${s}`);
      const findings = await res.json();
      const container = document.getElementById('findings-container');

      if (!findings.length) {
        container.innerHTML = '<div class="text-xs text-slate-500 italic p-8 text-center bg-slate-900 rounded border border-slate-800">No findings matching query.</div>';
        return;
      }

      container.innerHTML = findings.map((f, i) => `
        <div class="bg-slate-900 p-4 rounded-lg border border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="text-xs px-2 py-0.5 rounded font-bold badge-${f.severity.toLowerCase().slice(0,4)}">${f.severity}</span>
              <span class="text-xs text-slate-400 uppercase font-mono">[${f.vector}]</span>
              <span class="text-sm font-semibold text-white">${f.title}</span>
            </div>
            <span class="text-[10px] text-slate-500 font-mono">${f.affected_resource || ''}</span>
          </div>
          <p class="text-xs text-slate-300">${f.description}</p>
          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs font-mono text-slate-300">
            <span class="text-slate-500 block text-[10px] uppercase font-sans">Remediation:</span>
            ${f.remediation}
          </div>
        </div>
      `).join('');
    }

    // Generate Reports
    async function generateReport(fmt) {
      const res = await fetch('/api/v1/reports/generate', {
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
      const res = await fetch('/api/v1/system');
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
    """Serve the single-page PrivWatch 3.0 operations dashboard with injected auth token"""
    html = DASHBOARD_HTML.replace("%%API_KEY%%", API_KEY)
    return HTMLResponse(content=html, status_code=200)


@app.get("/api/v1/overview")
def get_overview():
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
def get_findings(vector: Optional[str] = Query(None), severity: Optional[str] = Query(None)):
    """Retrieve security findings from persistent storage with filters"""
    findings = storage.get_findings(vector=vector, severity=severity)
    return [f.to_dict() for f in findings]


@app.get("/api/v1/events")
def get_events(limit: int = 100, event_type: Optional[str] = Query(None)):
    """Retrieve normalized security events"""
    events = storage.get_events(limit=limit, event_type=event_type)
    return [e.to_dict() for e in events]


@app.get("/api/v1/incidents")
def get_incidents(status_filter: Optional[str] = Query(None, alias="status")):
    """Retrieve correlated security incidents"""
    incidents = storage.get_incidents(status=status_filter)
    return [i.to_dict() for i in incidents]


@app.post("/api/v1/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, update: IncidentStatusUpdate, auth: Dict[str, str] = Depends(require_admin)):
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


@app.get("/api/v1/timeline")
def get_timeline():
    """Build and return unified chronological timeline"""
    from modules.timeline.timeline_builder import TimelineBuilder
    from modules.timeline.event_correlator import EventCorrelator

    correlator = EventCorrelator(window_seconds=config.timeline_window_sec)
    events = storage.get_events(limit=1000)
    correlator.add_events(events)

    builder = TimelineBuilder(correlator)
    timeline = builder.build_timeline()

    # Format datetimes
    for entry in timeline:
        if isinstance(entry.get('timestamp'), datetime):
            entry['timestamp'] = entry['timestamp'].isoformat()

    return timeline


@app.get("/api/v1/health")
def get_health():
    """Retrieve telemetry health status"""
    return orchestrator.get_telemetry_health().to_dict()


@app.get("/api/v1/system")
def get_system_info():
    """Retrieve system information"""
    return {
        'hostname': orchestrator.get_telemetry_health().hostname,
        'kernel': get_kernel_version(),
        'os_info': get_os_info(),
        'user': get_current_user(),
        'is_root': is_root()
    }


@app.post("/api/v1/scan/red")
def trigger_red_scan(auth: Dict[str, str] = Depends(require_admin)):
    """Trigger full Red Team privilege escalation assessment (Admin only)"""
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
def get_monitoring_status():
    """Check live monitoring status"""
    return {'monitoring': orchestrator.is_monitoring()}


@app.post("/api/v1/remediation/plan")
def get_remediation_plan(finding_id: str = Body(..., embed=True)):
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
def execute_remediation(req: RemediationRequest, auth: Dict[str, str] = Depends(require_admin)):
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


@app.post("/api/v1/reports/generate")
def generate_report(req: ReportRequest):
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
def download_report(path: str = Query(...)):
    """Download generated report with path traversal validation"""
    safe_path = safe_resolve_path(path, base_dir=config.output_dir)
    if not safe_path or not os.path.exists(safe_path):
        raise HTTPException(status_code=403, detail="Access denied or file does not exist")

    filename = os.path.basename(safe_path)
    return FileResponse(safe_path, filename=filename)


@app.get("/api/v1/audit")
def get_audit_trail(limit: int = 100):
    """Retrieve administrative action audit log"""
    return storage.get_audit_logs(limit=limit)


@app.post("/api/v1/suppression")
def add_suppression_rule(req: SuppressionRequest, auth: Dict[str, str] = Depends(require_admin)):
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


# -------------------------------------------------------------------------
# Machine Learning & Analytical Endpoints (PrivWatch 3.1)
# -------------------------------------------------------------------------

@app.get("/api/v1/ml/status")
def get_ml_status():
    """Retrieve ML model registry status, drift metrics, and inference latency profile"""
    from models.registry.model_registry import ModelRegistry
    from ml.inference.model_runner import ModelRunner

    registry = ModelRegistry()
    runner = ModelRunner(registry)
    drift_status = runner.drift_monitor.get_monitoring_status()

    # Query registered metadata
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
def evaluate_ml_event(payload: Dict[str, Any] = Body(...), auth: Dict[str, str] = Depends(verify_api_key)):
    """
    Evaluate an arbitrary security event payload through the ML inference engine.
    Returns anomaly score, calibrated confidence, risk score, and feature attribution.
    """
    from core.models import SecurityEvent
    from ml.inference.model_runner import ModelRunner

    runner = ModelRunner()
    ev = SecurityEvent.from_dict(payload)
    explanation = runner.evaluate_event(ev)
    return explanation.to_dict()


