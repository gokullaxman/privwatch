"""
PrivWatch 3.0 - Authentication Telemetry Collector
Ingests and normalizes /var/log/auth.log and /var/log/secure events into structured SecurityEvent records.
"""

from datetime import datetime, timezone
import os
import platform
import re
from typing import List, Optional, Dict, Any

from core.models import SecurityEvent, Severity, utc_now
from core.log_parser import LogParser


class AuthLogCollector(LogParser):
    """Collects and normalizes authentication subsystem logs"""

    def __init__(self, log_path: Optional[str] = None):
        super().__init__("AUTH_TELEMETRY")
        self.log_path = log_path or ("/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure")
        self.hostname = platform.node() or "localhost"

    def parse(self, log_file: Optional[str] = None) -> List[Any]:
        """Base compatibility method returning empty findings; events are collected via collect_events()"""
        return []

    def collect_events(self, max_lines: int = 15000) -> List[SecurityEvent]:
        """Read and parse authentication log entries into normalized SecurityEvent objects"""
        if not self.log_path or not os.path.exists(self.log_path) or not os.access(self.log_path, os.R_OK):
            return []

        events: List[SecurityEvent] = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-max_lines:]
        except Exception:
            return []

        for line in lines:
            evt = self._normalize_line(line.strip())
            if evt:
                events.append(evt)

        self.events = events
        return events

    def _normalize_line(self, line: str) -> Optional[SecurityEvent]:
        """Parse raw syslog authentication line into SecurityEvent"""
        if not line:
            return None

        timestamp = self.parse_syslog_timestamp(line) or utc_now()

        # Strip standard BSD timestamp (Month Day HH:MM:SS) or ISO timestamp and hostname
        content = re.sub(r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(?:[^\s]+\s+)?', '', line)
        content = re.sub(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?:[^\s]+\s+)?', '', content)

        # Extract process and PID: sudo[1234]: or sshd[5678]:
        proc_match = re.match(r'^([a-zA-Z0-9_\.\-]+)(?:\[(\d+)\])?\s*:\s*(.+)$', content)
        if not proc_match:
            return None

        process = proc_match.group(1)
        pid = int(proc_match.group(2)) if proc_match.group(2) else None
        message = proc_match.group(3).strip()

        event_type = "AUTH_EVENT"
        severity = Severity.INFO.value
        user = None
        command = None
        evidence = {'raw_message': message, 'log_line': line}

        # 1. Sudo command execution
        if process == "sudo" and "COMMAND=" in message:
            event_type = "SUDO_COMMAND"
            # Extract user: e.g. "operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/bin/bash"
            user_m = re.match(r'^([a-zA-Z0-9_\.\-]+)\s*:', message)
            if user_m:
                user = user_m.group(1)
            cmd_m = re.search(r'COMMAND=(.+)$', message)
            if cmd_m:
                command = cmd_m.group(1).strip()
            severity = Severity.INFO.value

        # 2. Sudo authentication failure
        elif process == "sudo" and any(term in message.lower() for term in ["authentication failure", "incorrect password", "3 incorrect password attempts"]):
            event_type = "SUDO_AUTH_FAIL"
            user_m = re.search(r'user=([a-zA-Z0-9_\.\-]+)', message) or re.match(r'^([a-zA-Z0-9_\.\-]+)\s*:', message)
            if user_m:
                user = user_m.group(1)
            severity = Severity.HIGH.value

        # 3. User switching (su)
        elif process == "su":
            if "Successful su" in message or "session opened" in message:
                event_type = "SU_SUCCESS"
                u_match = re.search(r'for ([a-zA-Z0-9_\.\-]+) by ([a-zA-Z0-9_\.\-]+)', message)
                if u_match:
                    user = u_match.group(1)
                    evidence['switch_from'] = u_match.group(2)
            elif "FAILED SU" in message or "authentication failure" in message:
                event_type = "SU_FAIL"
                severity = Severity.MEDIUM.value

        # 4. User account modifications
        elif process in ["useradd", "usermod", "chage", "passwd"]:
            event_type = "ACCOUNT_MODIFICATION"
            severity = Severity.HIGH.value

        # 5. SSH authentication events
        elif process == "sshd":
            if "Failed password" in message or "Invalid user" in message:
                event_type = "SSH_AUTH_FAIL"
                u_match = re.search(r'for (?:invalid user )?([a-zA-Z0-9_\.\-]+) from', message)
                if u_match:
                    user = u_match.group(1)
                severity = Severity.MEDIUM.value
            elif "Accepted" in message:
                event_type = "SSH_AUTH_SUCCESS"
                u_match = re.search(r'for ([a-zA-Z0-9_\.\-]+) from', message)
                if u_match:
                    user = u_match.group(1)

        return SecurityEvent(
            timestamp=timestamp,
            hostname=self.hostname,
            source=self.log_path,
            event_type=event_type,
            severity=severity,
            user=user,
            pid=pid,
            process=process,
            command=command,
            evidence=evidence,
            confidence=0.95
        )
