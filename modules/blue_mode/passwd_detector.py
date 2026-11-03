"""
PrivWatch 3.0 - Password File & Account Tampering Detector (Blue Team Mode)
Detects unauthorized account modifications, password alterations, and /etc/shadow access events.
"""

from datetime import datetime, timezone
import os
from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_PASSWD
from modules.blue_mode.telemetry.auth_collector import AuthLogCollector
from modules.blue_mode.telemetry.audit_collector import AuditCollector


class PasswdDetector(LogParser):
    """Detects account modification and password database tampering"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_PASSWD, config)
        self.auth_collector = AuthLogCollector(
            getattr(config, 'auth_log_path', None) if config else None
        )
        self.audit_collector = AuditCollector(
            getattr(config, 'audit_log_path', None) if config else None
        )

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Detect account creation and modification events"""
        auth_events = self.auth_collector.collect_events()
        self.events.extend(auth_events)

        acct_events = [e for e in auth_events if e.event_type == "ACCOUNT_MODIFICATION"]
        for e in acct_events:
            self.add_finding(
                severity=Severity.HIGH.value,
                title=f"Account Modification Event: {e.process}",
                description=f"Account modification utility '{e.process}' executed: {e.evidence.get('raw_message')}",
                affected_resource=e.process or "account_subsystem",
                evidence=e.evidence,
                detection_method="auth_log_process_parse",
                risk_explanation="Unauthorized user or group modifications can establish persistent backdoors.",
                remediation="Verify whether account modifications were authorized by system change requests.",
                confidence=0.92
            )

        # Audit daemon watch on /etc/shadow or /etc/passwd
        audit_events = self.audit_collector.collect_events()
        self.events.extend(audit_events)

        for e in audit_events:
            raw = e.evidence.get('raw_line', '')
            if any(target in raw for target in ["/etc/shadow", "/etc/passwd", "/etc/sudoers"]):
                if "success=yes" in raw and any(op in raw for op in ["openat", "unlink", "rename", "write"]):
                    self.add_finding(
                        severity=Severity.CRITICAL.value,
                        title="Auditd Alert: Modification of System Authentication Database",
                        description=f"Process {e.process} (PID {e.pid}) accessed critical security file: {raw}",
                        affected_resource="/etc/shadow",
                        evidence=e.evidence,
                        detection_method="auditd_file_watch_trigger",
                        risk_explanation="Direct alteration of system credential files.",
                        remediation="Investigate PID and user credentials responsible for this change.",
                        confidence=0.98
                    )

        return self.findings
