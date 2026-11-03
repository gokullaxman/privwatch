"""
PrivWatch 3.0 - SUID Execution Detector (Blue Team Mode)
Detects verified execution of SUID/SGID binaries using Linux Audit and runtime process inspection.
Strictly avoids naive syslog keyword matching.
"""

from datetime import datetime, timezone
import os
from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_SUID
from modules.blue_mode.telemetry.audit_collector import AuditCollector
from modules.blue_mode.telemetry.process_collector import ProcessCollector


class SuidDetector(LogParser):
    """Detects confirmed executions of binaries with elevated effective UID"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_SUID, config)
        self.audit_collector = AuditCollector(
            getattr(config, 'audit_log_path', None) if config else None
        )
        self.process_collector = ProcessCollector()

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Collect and analyze execution telemetry for elevated privilege executions"""
        # 1. Collect from Linux Audit Subsystem if available
        audit_events = self.audit_collector.collect_events()
        self.events.extend(audit_events)

        suid_audit = [e for e in audit_events if e.event_type == "SUID_EXECUTION"]
        for e in suid_audit:
            self.add_finding(
                severity=Severity.HIGH.value,
                title=f"Verified SUID Execution: {e.process or 'Unknown Process'}",
                description=f"User UID {e.uid} executed binary '{e.command or e.process}' with elevated EUID {e.euid}.",
                affected_resource=e.command or e.process or "unknown",
                evidence=e.evidence,
                detection_method="linux_audit_syscall_analysis",
                risk_explanation="Elevated SUID execution confirmed via kernel audit subsystem.",
                remediation="Verify if this execution was authorized by system administration.",
                confidence=0.98
            )

        # 2. Collect from live process telemetry
        proc_events = self.process_collector.collect()
        self.events.extend(proc_events)

        suid_procs = [e for e in proc_events if e.event_type == "ACTIVE_EUID_ELEVATION"]
        for e in suid_procs:
            self.add_finding(
                severity=Severity.HIGH.value,
                title=f"Active EUID Elevation in Running Process: {e.process}",
                description=f"Process PID {e.pid} ({e.process}) is running with effective UID {e.euid} different from real UID {e.uid}.",
                affected_resource=f"pid:{e.pid}",
                evidence=e.evidence,
                detection_method="live_proc_euid_stat_inspection",
                risk_explanation="Process is actively utilizing elevated privileges.",
                remediation="Inspect process parentage and open sockets.",
                confidence=0.95
            )

        return self.findings
