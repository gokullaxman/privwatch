"""
PrivWatch 3.0 - Linux Capabilities Abuse Detector (Blue Team Mode)
Analyzes telemetry to detect setcap invocations, capset syscall abuse, and capability modification events.
"""

from datetime import datetime, timezone
import os
import re
from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_CAPABILITIES
from modules.blue_mode.telemetry.audit_collector import AuditCollector


class CapabilitiesDetector(LogParser):
    """Detects capability abuse and setcap invocations in system telemetry"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_CAPABILITIES, config)
        self.audit_collector = AuditCollector(
            getattr(config, 'audit_log_path', None) if config else None
        )

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Parse audit logs for setcap command executions or capset syscalls"""
        audit_events = self.audit_collector.collect_events()
        self.events.extend(audit_events)

        for e in audit_events:
            raw = (e.evidence.get('raw_line') or '').lower()

            # Detect setcap execution
            if "setcap" in raw or e.process == "setcap":
                self.add_finding(
                    severity=Severity.HIGH.value,
                    title="setcap Invocation Detected",
                    description=f"Process executed setcap utility to assign Linux capabilities: {raw[:200]}",
                    affected_resource=e.command or "setcap",
                    evidence=e.evidence,
                    detection_method="audit_syscall_log_parse",
                    risk_explanation="Adversaries use setcap to grant dangerous capabilities (e.g. cap_setuid) to local binaries for backdoor persistence.",
                    remediation="Verify whether capability assignment was legitimate: getcap -r /path/to/binary",
                    confidence=0.92
                )

        return self.findings
