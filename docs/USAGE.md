# PrivWatch 3.0 — User Guide & Operations Manual

PrivWatch 3.0 provides a single unified CLI (`privwatch.py`) and a modern web operations dashboard.

---

## 1. CLI Execution Modes

### A. Red Team Mode (Privilege Escalation Reconnaissance)
Scans the local host across 9 distinct privilege escalation vectors:
```bash
python3 privwatch.py --mode red
```
Options:
- `--format {json,pdf,csv,all}`: Export findings to specified report formats.
- `--output ./custom_reports`: Specify destination directory.

### B. Blue Team Mode (Log Forensics & Detection)
Inspects Linux authentication logs, audit subsystem records, and live process trees:
```bash
python3 privwatch.py --mode blue --format pdf
```

### C. Forensic Timeline Mode (Attack Reconstruction)
Correlates security events into unified chronological sequences and incident cases:
```bash
python3 privwatch.py --mode timeline
```

### D. Live Telemetry Monitoring Mode
Runs continuous background monitoring of process parentage and security events:
```bash
python3 privwatch.py --mode monitor
```

### E. Web Operations Dashboard Mode
Launches the interactive Web Security Operations Dashboard:
```bash
python3 privwatch.py --mode dashboard --host 127.0.0.1 --port 8443
```
Open your browser to: `http://127.0.0.1:8443`

---

## 2. Web Dashboard Features

The PrivWatch 3.0 dashboard provides 10 operational views:
1. **Overview:** Real-time security posture score (0 - 100), severity breakdown, active incident alerts, and telemetry source health.
2. **Live Monitoring:** Real-time stream of ingested process and log events with pause, refresh, and start/stop controls.
3. **Security Findings:** Comprehensive searchable and filterable database of identified vulnerabilities with complete evidence bundles.
4. **Assessment (Red):** Direct interface to trigger and review targeted privilege escalation audits.
5. **Threat Detection (Blue):** Active detections, alert acknowledgment, and anomaly reviews.
6. **Forensic Timeline:** Interactive chronological attack reconstruction.
7. **Investigations:** Case management interface with analyst notes and status tracking.
8. **Reports & Export:** On-demand generation and downloading of PDF, JSON, and CSV reports.
9. **System Information:** Host details, OS distribution, kernel release, and package manager telemetry.
10. **Settings & Audit:** Administrative audit log and false-positive alert suppression rules.

