#!/usr/bin/env python3
"""
UATU Linux Edition - Command Line Interface (CLI)
Implements all core operations:
  scan       - Enumerate privilege escalation weaknesses and construct attack paths
  watch      - Live telemetry ingestion and rule-based incident detection
  serve      - Start operational dashboard on 127.0.0.1:8443
  remediate  - Inspect, dry-run, or apply permission corrections
  rollback   - Restore verified pre-remediation permissions
  report     - Export single finding or incident to JSON or ReportLab PDF
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import List, Optional

from core.config import PrivWatchConfig
from core.orchestrator import PrivWatchOrchestrator
from core.storage import StorageEngine
from core.models import Finding, Incident, Severity, SystemPosture, format_iso, utc_now
from core.platform import LinuxPlatform
from attack_path.graph_builder import AttackPathEngine
from modules.response.remediation_engine import RemediationEngine
from reports.json_exporter import JSONExporter
from reports.pdf_generator import PDFGenerator
from telemetry.reader import TelemetryEngine
from detection.engine import DetectionEngine


def cmd_scan(args, orchestrator: PrivWatchOrchestrator):
    print("=" * 72)
    print("  UATU LINUX EDITION — PRIVILEGE ESCALATION ASSESSMENT SCAN")
    print("=" * 72)

    findings = orchestrator.run_red_team_scan()
    posture = orchestrator.get_posture()

    print(f"\nDiscovered Findings: {len(findings)}")
    print(f"Posture Score:       {posture.score}/100 ({posture.status})\n")

    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] [{f.severity}] {f.title}")
        print(f"    ID:       {f.finding_id}")
        print(f"    Vector:   {f.vector}")
        print(f"    Resource: {f.affected_resource or 'N/A'}")
        if f.evidence:
            print(f"    Evidence: owner={f.evidence.get('owner')} mode={f.evidence.get('mode')}")
        print(f"    Fix:      {f.remediation.replace(chr(10), ' ')}")
        print()

    # Build and evaluate attack paths
    ap_engine = AttackPathEngine(orchestrator.storage)
    paths = ap_engine.build_graph_from_findings(findings)

    print("-" * 72)
    print(f"  ATTACK PATH ANALYSIS [CONFIGURATION_ONLY]: {len(paths)} PATH(S) IDENTIFIED")
    print("  Note: Paths represent theoretical escalation based on permissions only.")
    print("-" * 72)

    for idx, p in enumerate(paths, 1):
        print(f"Path #{idx}: {p.title}")
        print(f"    Path ID:     {p.path_id}")
        print(f"    Chain:       {' -> '.join([n['id'] for n in p.nodes])}")
        print(f"    Bottleneck:  {p.bottleneck_node}")
        print(f"    Disruption:  {p.recommended_disruption}\n")


def cmd_watch(args, orchestrator: PrivWatchOrchestrator):
    print("=" * 72)
    print("  UATU LINUX EDITION — LIVE TELEMETRY WATCH & INCIDENT DETECTION")
    print("  Ingesting from Linux Audit netlink / ausearch and /var/log/auth.log")
    print("  Press Ctrl+C to stop.")
    print("=" * 72)

    is_verbose = getattr(args, "verbose", False)
    storage = orchestrator.storage
    bus = orchestrator.event_bus
    tel_engine = TelemetryEngine(storage=storage, event_bus=bus)
    det_engine = DetectionEngine(storage=storage, event_bus=bus)

    try:
        while True:
            # Poll live logs
            events = tel_engine.poll_once()
            if is_verbose and events:
                for ev in events:
                    print(f"[{format_iso(ev.timestamp)}] TELEMETRY: [{ev.severity}] {ev.event_type} user={ev.user} exe={ev.exe or ev.command}")

            # Run detection evaluation
            incidents = det_engine.evaluate_recent_events(window_sec=300)
            if incidents:
                for inc in incidents:
                    print(f"\n*** INCIDENT DETECTED ***")
                    print(f"  ID:         {inc.incident_id}")
                    print(f"  Title:      {inc.title}")
                    print(f"  Severity:   {inc.severity}")
                    print(f"  Hypothesis: {inc.hypothesis}")
                    print(f"  Events:     {', '.join(inc.event_ids)}\n")

            time.sleep(2)
    except KeyboardInterrupt:
        print("\nTelemetry watch stopped by user.")


def cmd_serve(args, orchestrator: PrivWatchOrchestrator):
    import uvicorn
    from web.app import app

    host = "127.0.0.1"
    port = getattr(args, "port", 8443) or 8443

    print("=" * 72)
    print("  UATU LINUX EDITION — SECURITY OPERATIONS DASHBOARD")
    print("=" * 72)
    print(f"Dashboard URL: http://{host}:{port}/dashboard")
    print("Auth Token:    Loaded from config/uatu_token (mode 0600)")
    print("Listening on 127.0.0.1 (localhost only). Press Ctrl+C to terminate.\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")


def cmd_remediate(args, orchestrator: PrivWatchOrchestrator):
    f_id = args.finding_id
    apply_mode = getattr(args, "apply", False)

    storage = orchestrator.storage
    findings = storage.get_findings()
    matching = [f for f in findings if f.finding_id == f_id]
    if not matching:
        print(f"Error: Finding '{f_id}' not found in evidence store.", file=sys.stderr)
        sys.exit(1)

    finding = matching[0]
    rem_engine = RemediationEngine(storage=storage, read_only=False)
    plan = rem_engine.generate_plan(finding)

    print("=" * 72)
    print(f"  REMEDIATION PLAN FOR FINDING {f_id}")
    print("=" * 72)
    print(f"Target Resource:    {plan.target_resource}")
    print(f"Proposed Commands:  {'; '.join(plan.proposed_commands)}")
    print(f"Rollback Commands:  {'; '.join(plan.rollback_commands)}")
    print(f"Consequences:       {plan.consequences}\n")

    if apply_mode:
        print("Applying remediation...")
        res = rem_engine.execute_plan(plan, actor="admin", confirmed=True, dry_run=False)
        print(f"Status:             {res.get('status')}")
        print(f"Executed Commands:  {res.get('executed_commands')}")
        print(f"Verification:       {res.get('verification')}")
        print(f"Output:             {res.get('output', '').strip()}")
        print("\nRemediation applied and state captured for rollback.")
    else:
        print("[DRY RUN SIMULATION]")
        res = rem_engine.execute_plan(plan, actor="admin", confirmed=False, dry_run=True)
        print(f"Status:             {res.get('status')}")
        print(f"Proposed Execution: {res.get('proposed_commands')}")
        print("\nTo apply this fix, run:\n  ./uatu.sh remediate " + f_id + " --apply\n")


def cmd_rollback(args, orchestrator: PrivWatchOrchestrator):
    f_id = args.finding_id
    storage = orchestrator.storage
    rem_engine = RemediationEngine(storage=storage, read_only=False)

    print("=" * 72)
    print(f"  ROLLING BACK REMEDIATION FOR FINDING {f_id}")
    print("=" * 72)

    res = rem_engine.rollback_plan(finding_id=f_id, actor="admin")
    if res.get("success"):
        print("Rollback successful!")
        print(f"Target:      {res.get('target')}")
        print(f"Commands:    {res.get('rollback_commands')}")
        print(f"Permissions: Mode={oct(res.get('restored_mode', 0))} Owner={res.get('restored_uid')}:{res.get('restored_gid')}")
    else:
        print(f"Rollback failed: {res.get('error')}", file=sys.stderr)
        sys.exit(1)


def cmd_report(args, orchestrator: PrivWatchOrchestrator):
    item_id = args.item_id
    fmt = getattr(args, "format", "json") or "json"
    storage = orchestrator.storage

    # Check if finding or incident
    findings = storage.get_findings()
    matching_f = [f for f in findings if f.finding_id == item_id]

    item = None
    related_events = []
    if matching_f:
        item = matching_f[0]
    else:
        incidents = storage.get_incidents()
        matching_i = [i for i in incidents if i.incident_id == item_id]
        if matching_i:
            item = matching_i[0]
            for eid in item.event_ids:
                ev = storage.get_event_by_id(eid)
                if ev:
                    related_events.append(ev)
        else:
            print(f"Error: Item '{item_id}' not found as Finding or Incident.", file=sys.stderr)
            sys.exit(1)

    out_dir = Path("./reports").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt.lower() == "pdf":
        out_file = str(out_dir / f"uatu_{item_id}_{ts}.pdf")
        path = PDFGenerator.generate_item_report(item, out_file, related_events)
        print(f"PDF Report generated: {path}")
    else:
        out_file = str(out_dir / f"uatu_{item_id}_{ts}.json")
        path = JSONExporter.export_item_json(item, out_file, related_events)
        print(f"JSON Report exported:  {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="uatu",
        description="UATU Linux Edition — Intelligent Privilege Escalation Detection & Disruption",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    subparsers.add_parser("scan", help="Run full privilege escalation scan and build attack paths")

    # watch
    watch_parser = subparsers.add_parser("watch", help="Live telemetry collection and real-time detection")
    watch_parser.add_argument("--verbose", "-v", action="store_true", help="Print raw telemetry stream in addition to detections")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start operations dashboard on 127.0.0.1:8443")
    serve_parser.add_argument("--port", type=int, default=8443, help="Dashboard port (default: 8443)")

    # remediate
    rem_parser = subparsers.add_parser("remediate", help="Plan or apply least-privilege permission fix")
    rem_parser.add_argument("finding_id", help="Target finding ID")
    rem_parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")

    # rollback
    rb_parser = subparsers.add_parser("rollback", help="Restore pre-remediation permissions")
    rb_parser.add_argument("finding_id", help="Target finding ID to rollback")

    # report
    rep_parser = subparsers.add_parser("report", help="Generate single finding/incident report")
    rep_parser.add_argument("item_id", help="Finding or Incident ID")
    rep_parser.add_argument("--format", choices=["json", "pdf"], default="json", help="Report format (default: json)")

    args = parser.parse_args()

    config = PrivWatchConfig()
    orchestrator = PrivWatchOrchestrator(config)

    commands = {
        "scan": cmd_scan,
        "watch": cmd_watch,
        "serve": cmd_serve,
        "remediate": cmd_remediate,
        "rollback": cmd_rollback,
        "report": cmd_report
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args, orchestrator)


if __name__ == "__main__":
    main()

