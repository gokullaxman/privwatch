"""
PrivWatch 3.0 - Process Ancestry & Anomaly Detector (Blue Team Mode)
Detects suspicious process parentage, daemon users spawning interactive shells,
and execution of binaries from world-writable directories (/tmp, /dev/shm).
"""

from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import Severity
from modules.blue_mode.telemetry.process_collector import ProcessCollector


class ProcessAnomalyDetector(LogParser):
    """Detects live process execution anomalies and suspicious ancestry"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__("PROCESS_ANOMALY", config)
        self.collector = ProcessCollector()

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Inspect running processes for ancestry and permission anomalies"""
        events = self.collector.collect()
        self.events = events

        for e in events:
            if e.event_type == "SUSPICIOUS_SHELL_SPAWNED":
                self.add_finding(
                    severity=Severity.HIGH.value,
                    title=f"Suspicious Shell Spawned by Service Account: {e.user}",
                    description=f"Service user '{e.user}' (PID {e.pid}) spawned interactive interpreter '{e.process}': {e.command}",
                    affected_resource=f"pid:{e.pid}:{e.user}",
                    evidence=e.evidence,
                    detection_method="process_tree_ancestry_audit",
                    risk_explanation="Daemon accounts like www-data or nobody should never execute interactive shells; strongly indicative of remote command injection / web shell.",
                    remediation=f"Inspect parent process PID {e.ppid} and isolate service container or terminate malicious process: kill -9 {e.pid}",
                    confidence=0.95
                )

            elif e.event_type == "PROCESS_RUNNING_FROM_TMP":
                self.add_finding(
                    severity=Severity.HIGH.value,
                    title=f"Binary Executing from World-Writable Path: {e.process}",
                    description=f"Process PID {e.pid} ({e.process}) is executing from a temporary directory: {e.command}",
                    affected_resource=f"pid:{e.pid}",
                    evidence=e.evidence,
                    detection_method="process_exe_path_audit",
                    risk_explanation="Dropping and executing payloads in /tmp or /dev/shm is a common adversary technique to bypass directory restrictions.",
                    remediation=f"Mount /tmp and /dev/shm with 'noexec' in /etc/fstab; terminate suspicious process PID {e.pid}.",
                    confidence=0.90
                )

        return self.findings

