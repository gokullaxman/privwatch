"""
PrivWatch 3.0 - Live Process Telemetry Collector
Inspects active operating system processes via psutil and /proc, detecting suspicious parent-child
lineage, unprivileged daemons spawning root shells, and binaries executing from temporary directories.
"""

from datetime import datetime, timezone
import os
import platform
from typing import List, Optional, Dict, Any

from core.models import SecurityEvent, Severity, utc_now


class ProcessCollector:
    """Inspects live system processes and extracts security anomalies into normalized events"""

    def __init__(self):
        self.hostname = platform.node() or "localhost"

    def is_available(self) -> bool:
        """Check if process enumeration is supported on this host"""
        return os.path.exists("/proc") or self._has_psutil()

    def _has_psutil(self) -> bool:
        try:
            import psutil
            return True
        except ImportError:
            return False

    def collect(self) -> List[SecurityEvent]:
        """Enumerate active processes and detect runtime privilege anomalies"""
        try:
            import psutil
            return self._collect_with_psutil(psutil)
        except ImportError:
            return self._collect_with_procfs()

    def _collect_with_psutil(self, psutil_mod) -> List[SecurityEvent]:
        """Enumerate processes using psutil library"""
        events: List[SecurityEvent] = []
        suspicious_daemon_users = {'www-data', 'apache', 'nginx', 'nobody', 'daemon', 'httpd'}

        for proc in psutil_mod.process_iter(['pid', 'ppid', 'name', 'username', 'uids', 'cmdline', 'exe']):
            try:
                pinfo = proc.info
                name = (pinfo.get('name') or '').lower()
                cmdline_list = pinfo.get('cmdline') or []
                cmdline = " ".join(cmdline_list)
                username = pinfo.get('username') or ''
                exe = pinfo.get('exe') or ''
                uids = pinfo.get('uids')
                pid = pinfo.get('pid')
                ppid = pinfo.get('ppid')

                # Anomaly 1: Web server daemon spawning an interactive shell
                if username.lower() in suspicious_daemon_users:
                    if name in ['sh', 'bash', 'dash', 'zsh', 'python', 'python3', 'perl', 'nc', 'ncat']:
                        events.append(SecurityEvent(
                            timestamp=utc_now(),
                            hostname=self.hostname,
                            source="process_inspection",
                            event_type="SUSPICIOUS_SHELL_SPAWNED",
                            severity=Severity.HIGH.value,
                            user=username,
                            pid=pid,
                            ppid=ppid,
                            process=name,
                            command=cmdline or exe,
                            evidence={
                                'anomaly': 'Daemon user executing interactive shell/interpreter',
                                'username': username,
                                'process': name,
                                'cmdline': cmdline,
                                'exe': exe
                            },
                            confidence=0.92
                        ))

                # Anomaly 2: Binary running from /tmp or /dev/shm
                if exe:
                    exe_lower = exe.lower()
                    if any(temp_dir in exe_lower for temp_dir in ['/tmp/', '/dev/shm/', '/var/tmp/']):
                        events.append(SecurityEvent(
                            timestamp=utc_now(),
                            hostname=self.hostname,
                            source="process_inspection",
                            event_type="PROCESS_RUNNING_FROM_TMP",
                            severity=Severity.HIGH.value,
                            user=username,
                            pid=pid,
                            ppid=ppid,
                            process=name,
                            command=cmdline or exe,
                            evidence={
                                'anomaly': 'Process executing from temporary world-writable directory',
                                'exe_path': exe,
                                'pid': pid
                            },
                            confidence=0.88
                        ))

                # Anomaly 3: Real UID != Effective UID (Active privilege elevation)
                if uids and hasattr(uids, 'real') and hasattr(uids, 'effective'):
                    if uids.real != uids.effective and uids.effective == 0:
                        events.append(SecurityEvent(
                            timestamp=utc_now(),
                            hostname=self.hostname,
                            source="process_inspection",
                            event_type="ACTIVE_EUID_ELEVATION",
                            severity=Severity.HIGH.value,
                            user=username,
                            uid=uids.real,
                            euid=uids.effective,
                            pid=pid,
                            ppid=ppid,
                            process=name,
                            command=cmdline or exe,
                            evidence={
                                'real_uid': uids.real,
                                'effective_uid': uids.effective,
                                'exe': exe
                            },
                            confidence=0.95
                        ))

            except (psutil_mod.NoSuchProcess, psutil_mod.AccessDenied):
                continue
            except Exception:
                continue

        return events

    def _collect_with_procfs(self) -> List[SecurityEvent]:
        """Fallback process inspection via Linux /proc filesystem"""
        events: List[SecurityEvent] = []
        if not os.path.exists("/proc"):
            return events

        try:
            for entry in os.scandir("/proc"):
                if entry.is_dir() and entry.name.isdigit():
                    pid = int(entry.name)
                    status_path = os.path.join(entry.path, "status")
                    if os.path.exists(status_path):
                        # Simple read of Uid line
                        try:
                            with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                                for line in f:
                                    if line.startswith("Uid:"):
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            ruid = int(parts[1])
                                            euid = int(parts[2])
                                            if ruid != euid and euid == 0:
                                                events.append(SecurityEvent(
                                                    timestamp=utc_now(),
                                                    hostname=self.hostname,
                                                    source="procfs",
                                                    event_type="ACTIVE_EUID_ELEVATION",
                                                    severity=Severity.HIGH.value,
                                                    uid=ruid,
                                                    euid=euid,
                                                    pid=pid,
                                                    evidence={'ruid': ruid, 'euid': euid},
                                                    confidence=0.95
                                                ))
                        except Exception:
                            continue
        except Exception:
            pass
        return events
