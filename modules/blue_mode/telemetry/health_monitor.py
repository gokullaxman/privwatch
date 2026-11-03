"""
PrivWatch 3.0 - Telemetry Health & Coverage Monitor
Assesses availability, accessibility, permission boundaries, and collection health
for all supported Linux telemetry sources without fabricating operational status.
"""

from datetime import datetime, timezone
import os
import platform
import shutil
from typing import Dict, Optional, Any

from core.models import TelemetryHealth, TelemetrySourceStatus, utc_now
from core.config import PrivWatchConfig


class TelemetryHealthMonitor:
    """Monitors and evaluates system telemetry ingestion status"""

    def __init__(self, config: Optional[PrivWatchConfig] = None):
        self.config = config or PrivWatchConfig()
        self.hostname = platform.node() or "localhost"

    def assess(self) -> TelemetryHealth:
        """Execute comprehensive health evaluation of all potential telemetry sources"""
        sources: Dict[str, TelemetrySourceStatus] = {}

        # 1. Authentication Log (/var/log/auth.log or /var/log/secure)
        auth_path = self.config.auth_log_path or "/var/log/auth.log"
        sources['auth_log'] = self._check_file_source("Authentication Log", auth_path)

        # 2. Linux Audit Subsystem (auditd)
        audit_path = self.config.audit_log_path or "/var/log/audit/audit.log"
        sources['auditd'] = self._check_file_source("Linux Audit Subsystem (auditd)", audit_path)

        # 3. Systemd Journal (journalctl)
        sources['systemd_journal'] = self._check_command_source("systemd Journal", "journalctl")

        # 4. Linux Process Subsystem (/proc)
        sources['procfs'] = self._check_directory_source("Process Telemetry (/proc)", "/proc")

        # 5. Kernel Diagnostics (dmesg)
        sources['dmesg'] = self._check_command_source("Kernel Diagnostic Buffer", "dmesg")

        # Calculate coverage percentage
        total_sources = len(sources)
        healthy_sources = sum(1 for s in sources.values() if s.available and s.readable)
        coverage_pct = (healthy_sources / total_sources * 100.0) if total_sources > 0 else 0.0

        return TelemetryHealth(
            hostname=self.hostname,
            timestamp=utc_now(),
            sources=sources,
            overall_coverage_pct=coverage_pct,
            ingestion_rate_eps=0.0
        )

    def _check_file_source(self, name: str, path: str) -> TelemetrySourceStatus:
        """Check availability and read permissions of a log file source"""
        exists = os.path.exists(path)
        readable = os.access(path, os.R_OK) if exists else False
        error_msg = None

        if not exists:
            error_msg = f"File not found: {path} (standard on this distribution?)"
        elif not readable:
            error_msg = f"Permission denied reading {path} (requires elevated privileges/audit group)"

        return TelemetrySourceStatus(
            name=name,
            path_or_cmd=path,
            available=exists,
            readable=readable,
            error_message=error_msg,
            event_count=0,
            last_collected_at=utc_now() if (exists and readable) else None
        )

    def _check_command_source(self, name: str, command: str) -> TelemetrySourceStatus:
        """Check if command-line telemetry tool is installed and executable"""
        cmd_path = shutil.which(command)
        exists = bool(cmd_path)
        readable = os.access(cmd_path, os.X_OK) if cmd_path else False
        error_msg = None

        if not exists:
            error_msg = f"Utility '{command}' not found in system PATH"

        return TelemetrySourceStatus(
            name=name,
            path_or_cmd=cmd_path or command,
            available=exists,
            readable=readable,
            error_message=error_msg,
            event_count=0,
            last_collected_at=utc_now() if (exists and readable) else None
        )

    def _check_directory_source(self, name: str, path: str) -> TelemetrySourceStatus:
        """Check if virtual filesystem directory is mounted and accessible"""
        exists = os.path.exists(path) and os.path.isdir(path)
        readable = os.access(path, os.R_OK) if exists else False
        error_msg = None

        if not exists:
            error_msg = f"Filesystem directory {path} not mounted"
        elif not readable:
            error_msg = f"Permission denied accessing {path}"

        return TelemetrySourceStatus(
            name=name,
            path_or_cmd=path,
            available=exists,
            readable=readable,
            error_message=error_msg,
            event_count=0,
            last_collected_at=utc_now() if (exists and readable) else None
        )
