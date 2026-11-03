"""
PrivWatch 3.0 - Sudo Activity & Brute Force Detector (Blue Team Mode)
Analyzes authentication logs and telemetry to detect repeated sudo authentication failures,
unauthorized sudo attempts, and suspicious elevated command executions.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import os
import re
from typing import List, Optional, Any, Dict

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_SUDO, DANGEROUS_SUDO
from modules.blue_mode.telemetry.auth_collector import AuthLogCollector


class SudoDetector(LogParser):
    """Detects suspicious sudo activity, password brute-forcing, and privilege abuse"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_SUDO, config)
        self.auth_collector = AuthLogCollector(
            getattr(config, 'auth_log_path', None) if config else None
        )

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Parse authentication logs and identify verified sudo abuse patterns"""
        if log_file:
            self.auth_collector.log_path = log_file

        events = self.auth_collector.collect_events()
        self.events = events

        if not events:
            return self.findings

        sudo_events = [e for e in events if e.process == "sudo"]
        failed_attempts = [e for e in sudo_events if e.event_type == "SUDO_AUTH_FAIL"]
        command_executions = [e for e in sudo_events if e.event_type == "SUDO_COMMAND"]

        # 1. Detect password guessing / brute-force by user
        self._detect_brute_force(failed_attempts)

        # 2. Detect dangerous command executions
        self._detect_dangerous_commands(command_executions)

        return self.findings

    def _detect_brute_force(self, failed_events: List[SecurityEvent]):
        """Group failed attempts by user within a 10-minute sliding window"""
        by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for e in failed_events:
            username = e.user or "unknown"
            by_user[username].append(e)

        for user, user_events in by_user.items():
            if len(user_events) >= 3:
                # Sort chronologically
                sorted_events = sorted(user_events, key=lambda x: x.timestamp)
                first_ts = sorted_events[0].timestamp
                last_ts = sorted_events[-1].timestamp

                if (last_ts - first_ts).total_seconds() <= 600:  # Within 10 minutes
                    self.add_finding(
                        severity=Severity.HIGH.value,
                        title=f"Repeated Sudo Authentication Failures: {user}",
                        description=f"User '{user}' accumulated {len(sorted_events)} failed sudo authentication attempts within 10 minutes.",
                        affected_resource=f"user:{user}",
                        evidence={
                            'user': user,
                            'attempt_count': len(sorted_events),
                            'first_attempt': first_ts.isoformat(),
                            'last_attempt': last_ts.isoformat(),
                            'event_ids': [e.event_id for e in sorted_events]
                        },
                        detection_method="sliding_window_threshold_correlation",
                        risk_explanation="Indicates either an unauthorized attacker attempting to guess passwords or credential brute-forcing.",
                        remediation=f"Lock account temporarily if compromised: usermod -L {user}; verify authentication source in logs.",
                        confidence=0.92
                    )

    def _detect_dangerous_commands(self, cmd_events: List[SecurityEvent]):
        """Detect execution of dangerous shell escape utilities via sudo"""
        for e in cmd_events:
            cmd = e.command or ""
            for dangerous in DANGEROUS_SUDO:
                if re.search(r'\b' + re.escape(dangerous) + r'\b', cmd, re.IGNORECASE):
                    self.add_finding(
                        severity=Severity.HIGH.value,
                        title=f"Suspicious Sudo Command Execution: {dangerous}",
                        description=f"User '{e.user}' executed dangerous utility '{dangerous}' with elevated privileges: {cmd}",
                        affected_resource=dangerous,
                        evidence={
                            'user': e.user,
                            'command': cmd,
                            'event_id': e.event_id,
                            'timestamp': e.timestamp.isoformat()
                        },
                        detection_method="sudo_command_pattern_match",
                        risk_explanation=f"Execution of {dangerous} via sudo provides interactive shell escape vectors.",
                        remediation="Review necessity of sudo access for this command; audit user activity during this session.",
                        confidence=0.88
                    )
                    break
