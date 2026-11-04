"""
PrivWatch 3.0 - Central Application Orchestrator
Coordinates scanners, telemetry collectors, event correlation, persistence, and live monitoring services.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import threading
import time
from typing import Dict, List, Optional, Any, Callable

from core.config import PrivWatchConfig
from core.models import (
    SecurityEvent, Finding, Incident, TelemetryHealth, SystemPosture,
    Severity, utc_now
)
from core.storage import StorageEngine
from core.logger import Logger


class PrivWatchOrchestrator:
    """Master orchestrator for the PrivWatch 3.0 security platform"""

    def __init__(self, config: Optional[PrivWatchConfig] = None):
        self.config = config or PrivWatchConfig()
        self.storage = StorageEngine(self.config.db_path)
        self.findings: List[Finding] = []
        self.events: List[SecurityEvent] = []
        self.incidents: List[Incident] = []

        # Background monitoring thread management
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_telemetry_health: Optional[TelemetryHealth] = None

    def run_red_team_scan(self) -> List[Finding]:
        """Execute full Red Team privilege escalation assessment"""
        from modules.red_mode.suid_scanner import SuidScanner
        from modules.red_mode.sudo_scanner import SudoScanner
        from modules.red_mode.capabilities_scanner import CapabilitiesScanner
        from modules.red_mode.cron_scanner import CronScanner
        from modules.red_mode.passwd_scanner import PasswdScanner
        from modules.red_mode.kernel_scanner import KernelScanner
        from modules.red_mode.path_scanner import PathScanner
        from modules.red_mode.ssh_scanner import SshScanner
        from modules.red_mode.container_scanner import ContainerScanner

        scanners = [
            ("SUID/SGID Binaries", SuidScanner(self.config)),
            ("Sudo Configuration", SudoScanner(self.config)),
            ("Linux Capabilities", CapabilitiesScanner(self.config)),
            ("Cron & Systemd Timers", CronScanner(self.config)),
            ("Password & Auth Files", PasswdScanner(self.config)),
            ("Kernel Vulnerabilities", KernelScanner(self.config)),
            ("PATH Hijacking Vectors", PathScanner(self.config)),
            ("SSH Configurations", SshScanner(self.config)),
            ("Container Privileges", ContainerScanner(self.config))
        ]

        Logger.header("PRIVWATCH 3.0 — RED TEAM ASSESSMENT SCAN")
        all_findings: List[Finding] = []

        for name, scanner in scanners:
            Logger.info(f"Scanning vector: {name}...")
            try:
                results = scanner.scan()
                all_findings.extend(results)
                if results:
                    crit = sum(1 for f in results if f.severity == Severity.CRITICAL.value)
                    high = sum(1 for f in results if f.severity == Severity.HIGH.value)
                    Logger.warning(f"  → Found {len(results)} issues ({crit} CRITICAL, {high} HIGH)")
                else:
                    Logger.success(f"  → {name}: No vulnerabilities identified")
            except Exception as e:
                Logger.error(f"  → Scanner error on {name}: {str(e)}")

        # Filter against active suppression rules
        filtered = [f for f in all_findings if not self.storage.is_suppressed(f.vector, f.title)]

        self.findings = filtered
        self.storage.save_findings(filtered)
        return filtered

    def run_blue_team_analysis(self) -> List[Finding]:
        """Execute Blue Team telemetry and log forensics analysis"""
        from modules.blue_mode.sudo_detector import SudoDetector
        from modules.blue_mode.suid_detector import SuidDetector
        from modules.blue_mode.passwd_detector import PasswdDetector
        from modules.blue_mode.cron_detector import CronDetector
        from modules.blue_mode.kernel_detector import KernelDetector
        from modules.blue_mode.capabilities_detector import CapabilitiesDetector
        from modules.blue_mode.process_detector import ProcessAnomalyDetector

        detectors = [
            ("Sudo Activity", SudoDetector(self.config)),
            ("SUID Executions", SuidDetector(self.config)),
            ("Password File Access", PasswdDetector(self.config)),
            ("Scheduled Task Changes", CronDetector(self.config)),
            ("Kernel Attack Indicators", KernelDetector(self.config)),
            ("Capabilities Usage", CapabilitiesDetector(self.config)),
            ("Process Anomalies", ProcessAnomalyDetector(self.config))
        ]

        Logger.header("PRIVWATCH 3.0 — BLUE TEAM TELEMETRY ANALYSIS")
        all_findings: List[Finding] = []
        collected_events: List[SecurityEvent] = []

        for name, detector in detectors:
            Logger.info(f"Analyzing: {name}...")
            try:
                findings = detector.parse()
                events = detector.get_events()
                all_findings.extend(findings)
                collected_events.extend(events)

                if findings:
                    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL.value)
                    high = sum(1 for f in findings if f.severity == Severity.HIGH.value)
                    Logger.critical(f"  → Detected {len(findings)} events ({crit} CRITICAL, {high} HIGH)")
                else:
                    Logger.success(f"  → {name}: No anomalies detected")
            except Exception as e:
                Logger.error(f"  → Detector error on {name}: {str(e)}")

        # PrivWatch 3.1: Non-blocking Advisory ML Evaluation
        if collected_events:
            try:
                from ml.inference.advisory_detector import AdvisoryMLDetector
                ml_detector = AdvisoryMLDetector()
                ml_findings = ml_detector.evaluate_telemetry(collected_events)
                if ml_findings:
                    Logger.info(f"  → ML Advisory: Generated {len(ml_findings)} explainable anomaly finding(s)")
                    all_findings.extend(ml_findings)
            except Exception as e:
                Logger.warning(f"  → ML Advisory evaluation skipped: {e}")

        self.findings.extend(all_findings)
        self.events.extend(collected_events)

        self.storage.save_findings(all_findings)
        self.storage.save_events(collected_events)
        return all_findings

    def run_timeline_correlation(self) -> List[Incident]:
        """Correlate collected events into attack sequences and forensic timeline"""
        from modules.timeline.event_correlator import EventCorrelator
        from modules.timeline.timeline_builder import TimelineBuilder

        correlator = EventCorrelator(window_seconds=self.config.timeline_window_sec)
        # Fetch events from memory or storage
        stored_events = self.storage.get_events(limit=5000)
        correlator.add_events(stored_events)

        incidents = correlator.detect_attack_patterns()
        self.incidents = incidents
        for inc in incidents:
            self.storage.save_incident(inc)

        builder = TimelineBuilder(correlator)
        builder.print_timeline()
        return incidents

    def get_posture(self) -> SystemPosture:
        """Compute system posture strictly from stored or active findings"""
        findings = self.findings if self.findings else self.storage.get_findings()
        return SystemPosture.calculate(findings)

    def get_telemetry_health(self) -> TelemetryHealth:
        """Evaluate real health of all system telemetry sources"""
        from modules.blue_mode.telemetry.health_monitor import TelemetryHealthMonitor
        monitor = TelemetryHealthMonitor(self.config)
        health = monitor.assess()
        self._last_telemetry_health = health
        return health

    # --- Live Monitoring Service Lifecycle ---

    def start_monitoring(self, poll_interval_sec: int = 5):
        """Start background live telemetry monitoring service"""
        if self._monitoring_active:
            Logger.warning("Monitoring service is already running")
            return

        self._monitoring_active = True
        self._stop_event.clear()

        def _monitor_loop():
            Logger.info("PrivWatch Live Monitoring background service started")
            while not self._stop_event.is_set():
                try:
                    # Ingest live processes and journal/audit increments
                    self._collect_live_telemetry_cycle()
                except Exception as e:
                    Logger.error(f"Live telemetry cycle encountered error: {str(e)}")
                self._stop_event.wait(poll_interval_sec)

        self._monitoring_thread = threading.Thread(target=_monitor_loop, daemon=True)
        self._monitoring_thread.start()
        self.storage.log_admin_action(
            action="START_MONITORING",
            target="telemetry_service",
            actor="SYSTEM",
            details={'poll_interval': poll_interval_sec},
            result="STARTED"
        )

    def stop_monitoring(self):
        """Gracefully terminate background monitoring service"""
        if not self._monitoring_active:
            return

        self._stop_event.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=4.0)
        self._monitoring_active = False
        Logger.info("PrivWatch Live Monitoring service stopped")
        self.storage.log_admin_action(
            action="STOP_MONITORING",
            target="telemetry_service",
            actor="SYSTEM",
            details={},
            result="STOPPED"
        )

    def is_monitoring(self) -> bool:
        """Check if background telemetry monitor is actively running"""
        return self._monitoring_active

    def _collect_live_telemetry_cycle(self):
        """Internal worker checking live processes and telemetry sources"""
        from modules.blue_mode.telemetry.process_collector import ProcessCollector
        collector = ProcessCollector()
        events = collector.collect()
        if events:
            self.storage.save_events(events)
            self.events.extend(events)
