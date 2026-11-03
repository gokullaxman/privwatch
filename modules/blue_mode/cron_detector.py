"""
PrivWatch 3.0 - Cron & Scheduled Task Tampering Detector (Blue Team Mode)
Detects modifications to crontabs, creation of new scheduled tasks, and cron directory tampering.
"""

from datetime import datetime, timezone
import os
import re
from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_CRON
from modules.blue_mode.telemetry.auth_collector import AuthLogCollector


class CronDetector(LogParser):
    """Detects unauthorized modification of cron jobs and scheduled tasks"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_CRON, config)
        self.auth_collector = AuthLogCollector(
            getattr(config, 'auth_log_path', None) if config else None
        )

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Parse authentication and audit logs for crontab modifications"""
        auth_events = self.auth_collector.collect_events()
        self.events.extend(auth_events)

        for e in auth_events:
            raw = (e.evidence.get('raw_message') or '').lower()
            # Detect crontab edits: e.g. "crontab[123]: (root) REPLACE (root)" or "crontab[123]: (user) EDIT (user)"
            if "crontab" in e.process.lower() or "crontab" in raw:
                if any(action in raw for action in ["replace", "edit", "delete"]):
                    self.add_finding(
                        severity=Severity.MEDIUM.value,
                        title="Crontab Modification Detected",
                        description=f"Crontab utility executed action: {e.evidence.get('raw_message')}",
                        affected_resource="crontab",
                        evidence=e.evidence,
                        detection_method="crontab_auth_log_inspection",
                        risk_explanation="Adversaries frequently install cron jobs to maintain persistence and execute root scripts.",
                        remediation="Inspect current crontabs (crontab -l) to ensure scheduled scripts are recognized and approved.",
                        confidence=0.88
                    )

        return self.findings
