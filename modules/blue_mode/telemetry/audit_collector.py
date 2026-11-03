"""
PrivWatch 3.0 - Linux Audit Telemetry Collector (auditd)
Parses Linux Audit subsystem logs (audit.log / ausearch) to extract verified syscall executions,
credential switches (ruid != euid), capset events, and process execution records.
"""

from datetime import datetime, timezone
import os
import platform
import re
from typing import List, Optional, Dict, Any

from core.models import SecurityEvent, Severity, utc_now


class AuditCollector:
    """Collects and parses telemetry records from the Linux Audit subsystem"""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or "/var/log/audit/audit.log"
        self.hostname = platform.node() or "localhost"

    def is_available(self) -> bool:
        """Check if audit log exists and is readable"""
        return os.path.exists(self.log_path) and os.access(self.log_path, os.R_OK)

    def collect_events(self, max_records: int = 5000) -> List[SecurityEvent]:
        """Read and parse raw audit.log into normalized SecurityEvent objects"""
        if not self.is_available():
            return []

        events: List[SecurityEvent] = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-max_records:]
        except Exception:
            return []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            evt = self._parse_audit_line(line)
            if evt:
                events.append(evt)

        return events

    def _parse_audit_line(self, line: str) -> Optional[SecurityEvent]:
        """Parse audit message line: type=SYSCALL msg=audit(1730657730.123:452): ..."""
        type_m = re.search(r'type=([A-Z_]+)', line)
        if not type_m:
            return None

        record_type = type_m.group(1)

        # Parse epoch timestamp: msg=audit(1730657730.123:452)
        ts_m = re.search(r'msg=audit\((\d+(?:\.\d+)?):(\d+)\)', line)
        if ts_m:
            try:
                epoch = float(ts_m.group(1))
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            except Exception:
                dt = utc_now()
        else:
            dt = utc_now()

        # Parse key-value pairs
        fields: Dict[str, str] = {}
        for match in re.finditer(r'([a-zA-Z0-9_\.\-]+)=("[^"]*"|\'[^\']*\'|[^\s]+)', line):
            k = match.group(1)
            v = match.group(2).strip('"\'')
            fields[k] = v

        pid = int(fields.get("pid")) if fields.get("pid", "").isdigit() else None
        ppid = int(fields.get("ppid")) if fields.get("ppid", "").isdigit() else None
        uid = int(fields.get("uid")) if fields.get("uid", "").isdigit() else None
        euid = int(fields.get("euid")) if fields.get("euid", "").isdigit() else None
        comm = fields.get("comm")
        exe = fields.get("exe")

        event_type = f"AUDIT_{record_type}"
        severity = Severity.INFO.value

        # Identify SUID execution: euid != uid in SYSCALL or EXECVE
        is_suid_exec = False
        if euid is not None and uid is not None and euid == 0 and uid != 0:
            is_suid_exec = True
            event_type = "SUID_EXECUTION"
            severity = Severity.HIGH.value

        return SecurityEvent(
            timestamp=dt,
            hostname=self.hostname,
            source="auditd",
            event_type=event_type,
            severity=severity,
            uid=uid,
            euid=euid,
            pid=pid,
            ppid=ppid,
            process=comm or (os.path.basename(exe) if exe else None),
            command=exe,
            evidence={
                'record_type': record_type,
                'fields': fields,
                'is_suid_elevation': is_suid_exec,
                'raw_line': line
            },
            confidence=0.98
        )
