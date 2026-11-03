"""
PrivWatch 3.0 - systemd Journal Telemetry Collector
Collects structured events from journald using journalctl JSON output.
"""

from datetime import datetime, timezone
import json
import os
import platform
import shutil
import subprocess
from typing import List, Optional, Any

from core.models import SecurityEvent, Severity, utc_now


class JournalCollector:
    """Collects structured telemetry records from systemd journald"""

    def __init__(self):
        self.hostname = platform.node() or "localhost"
        self.journalctl_bin = shutil.which("journalctl")

    def is_available(self) -> bool:
        """Check if journalctl is available and operational"""
        return bool(self.journalctl_bin)

    def collect_events(self, max_records: int = 500) -> List[SecurityEvent]:
        """Collect recent journal entries formatted as JSON"""
        if not self.is_available():
            return []

        events: List[SecurityEvent] = []
        try:
            cmd = [self.journalctl_bin, "-o", "json", "-n", str(max_records), "--no-pager"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode != 0 or not res.stdout:
                return []

            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    evt = self._normalize_record(record)
                    if evt:
                        events.append(evt)
                except Exception:
                    continue
        except Exception:
            pass

        return events

    def _normalize_record(self, record: dict) -> Optional[SecurityEvent]:
        """Convert journald JSON record into normalized SecurityEvent"""
        # Timestamp is in microseconds epoch
        ts_raw = record.get("__REALTIME_TIMESTAMP")
        if ts_raw:
            try:
                epoch_sec = float(ts_raw) / 1000000.0
                dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
            except Exception:
                dt = utc_now()
        else:
            dt = utc_now()

        message = record.get("MESSAGE", "")
        if isinstance(message, list):
            message = "".join([chr(c) if isinstance(c, int) else str(c) for c in message])

        comm = record.get("_COMM")
        pid_raw = record.get("_PID")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None
        uid_raw = record.get("_UID")
        uid = int(uid_raw) if uid_raw and str(uid_raw).isdigit() else None

        unit = record.get("_SYSTEMD_UNIT")

        event_type = "JOURNAL_ENTRY"
        severity = Severity.INFO.value

        # Classify priority
        priority_raw = record.get("PRIORITY")
        if priority_raw in ["0", "1", "2", "3"]:
            severity = Severity.HIGH.value

        return SecurityEvent(
            timestamp=dt,
            hostname=self.hostname,
            source="systemd_journal",
            event_type=event_type,
            severity=severity,
            uid=uid,
            pid=pid,
            process=comm,
            evidence={
                'message': message,
                'unit': unit,
                'priority': priority_raw
            },
            confidence=0.90
        )
