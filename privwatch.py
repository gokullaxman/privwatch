#!/usr/bin/env python3
"""
PrivWatch 3.0 - Privilege Escalation Detection, Forensics & Prevention Platform
Unified CLI entry point supporting Red Team assessment, Blue Team forensics,
attack timeline correlation, background monitoring, and web operations dashboard.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

from core.config import PrivWatchConfig
from core.orchestrator import PrivWatchOrchestrator
from core.platform_validator import LinuxPlatformValidator, UnsupportedPlatformError
from core.logger import Logger
from core.models import Severity, SystemPosture, format_iso, utc_now
from utils.system_info import is_root, get_os_info, get_kernel_version, get_current_user
from reports.json_exporter import JSONExporter
from reports.pdf_generator import PDFGenerator
from reports.csv_exporter import CSVExporter


VERSION = "3.0.0"


def print_summary(findings, posture):
    """Print clean terminal summary box"""
    Logger.header("ASSESSMENT SUMMARY")
    print(f"  Security Posture Score : {posture.score} / 100 ({posture.status})")
    print(f"  Critical Findings      : {posture.critical_count}")
    print(f"  High Severity Findings : {posture.high_count}")
    print(f"  Medium Severity Issues : {posture.medium_count}")
    print(f"  Low / Info Findings    : {posture.low_count + posture.info_count}")
    print(f"  Total Findings         : {len(findings)}\n")


def generate_reports(findings, orchestrator, output_dir, report_formats, mode):
    """Generate requested report formats"""
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    posture = orchestrator.get_posture()
    telemetry_health = orchestrator.get_telemetry_health()

    formats = ['json', 'pdf', 'csv'] if report_formats in ['both', 'all'] else [report_formats]

    for fmt in formats:
        if fmt == 'json':
            json_file = str(out_dir / f"privwatch_{mode}_{ts}.json")
            JSONExporter.export_findings(findings, json_file, mode=mode, posture=posture, telemetry_health=telemetry_health)
            Logger.success(f"JSON Report exported: {json_file}")
        elif fmt == 'pdf':
            pdf_file = str(out_dir / f"privwatch_{mode}_{ts}.pdf")
            res_file = PDFGenerator.generate_report(findings, pdf_file, mode=mode, posture=posture)
            Logger.success(f"PDF Report exported: {res_file}")
        elif fmt == 'csv':
            csv_file = str(out_dir / f"privwatch_{mode}_{ts}.csv")
            CSVExporter.export_findings(findings, csv_file)
            Logger.success(f"CSV Report exported: {csv_file}")


def main():
    # Enforce 100% Linux-native execution environment
    try:
        sys_report = LinuxPlatformValidator.validate_platform(strict=True)
    except UnsupportedPlatformError as e:
        sys.stderr.write(f"\n{str(e)}\n\n")
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description="PrivWatch 3.0 - Linux Privilege Escalation Detection, Forensics & Prevention",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  red        - Enumerate privilege escalation weaknesses (9 attack vectors)
  blue       - Analyze system logs, auditd, and process telemetry for active attacks
  timeline   - Reconstruct chronological attack timeline and correlate incidents
  dashboard  - Launch interactive web security operations dashboard
  monitor    - Run continuous background telemetry monitoring

Examples:
  python privwatch.py --mode red
  python privwatch.py --mode blue --format pdf
  python privwatch.py --mode timeline
  python privwatch.py --mode dashboard --port 8443
        """
    )

    parser.add_argument(
        '--mode',
        choices=['red', 'blue', 'timeline', 'dashboard', 'monitor'],
        default='red',
        help='Operation mode (default: red)'
    )
    parser.add_argument(
        '--output',
        default='./reports',
        help='Output directory for generated reports (default: ./reports)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'pdf', 'csv', 'all', 'both'],
        default='json',
        help='Report export format (default: json)'
    )
    parser.add_argument(
        '--db',
        default='./privwatch.db',
        help='SQLite database path (default: ./privwatch.db)'
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Dashboard bind host (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8443,
        help='Dashboard bind port (default: 8443)'
    )

    args = parser.parse_args()

    # Load configuration
    cfg = PrivWatchConfig(
        mode=args.mode,
        output_dir=args.output,
        db_path=args.db,
        dashboard_host=args.host,
        dashboard_port=args.port
    )

    orchestrator = PrivWatchOrchestrator(cfg)

    Logger.banner(args.mode, VERSION)

    # Permission advisory
    if not is_root():
        Logger.warning(f"Executing with unprivileged UID {os.geteuid() if hasattr(os, 'geteuid') else 'unknown'}.")
        Logger.warning("Comprehensive assessment of /etc/shadow, /etc/sudoers, and audit logs requires root (UID 0).")
        print()

    # Mode: Dashboard
    if args.mode == 'dashboard':
        import uvicorn
        from web.app import app
        Logger.info(f"Starting PrivWatch 3.0 Dashboard at http://{args.host}:{args.port}")
        Logger.info("Press Ctrl+C to terminate.")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return

    # Mode: Monitor
    if args.mode == 'monitor':
        orchestrator.start_monitoring(poll_interval_sec=5)
        Logger.info("Continuous telemetry monitoring active. Press Ctrl+C to exit.")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            orchestrator.stop_monitoring()
            Logger.info("Monitoring terminated.")
        return

    start_time = datetime.now()
    findings = []

    # Mode: Red Team Scan
    if args.mode == 'red':
        findings = orchestrator.run_red_team_scan()
        posture = orchestrator.get_posture()
        print_summary(findings, posture)
        generate_reports(findings, orchestrator, args.output, args.format, "red")

    # Mode: Blue Team Log Analysis
    elif args.mode == 'blue':
        findings = orchestrator.run_blue_team_analysis()
        posture = orchestrator.get_posture()
        print_summary(findings, posture)
        generate_reports(findings, orchestrator, args.output, args.format, "blue")

    # Mode: Forensic Timeline
    elif args.mode == 'timeline':
        incidents = orchestrator.run_timeline_correlation()
        Logger.success(f"Forensic timeline reconstructed with {len(incidents)} correlated incidents.")

    elapsed = (datetime.now() - start_time).total_seconds()
    Logger.success(f"Operation completed in {elapsed:.2f} seconds\n")


if __name__ == '__main__':
    main()
