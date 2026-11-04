"""
UATU Linux Edition - Live Telemetry Ingestion Engine
Collects and normalizes live Linux endpoint telemetry from:
1. Linux Audit Framework (ausearch -i / audit.log)
2. Systemd Journal & Auth logs (journalctl / /var/log/auth.log / /var/log/secure)
Routes all normalized events through the EventBus into the Evidence Store with data_origin=LIVE_TELEMETRY.
Updates HealthRegistry states, reporting UNAVAILABLE when collectors are missing or inaccessible.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import time
from typing import List, Optional, Dict, Any, Generator

from core.command_runner import CommandRunner
from core.event_schema import (
    UatuEvent, ProvenanceClass, DataOrigin, CollectionStatus,
    CollectionMethod, EventSeverity
)
from core.event_bus import EventBus
from core.storage import StorageEngine
from core.health import HealthRegistry, default_health_registry


class AuditLogReader:
    """Parses ausearch -i output or /var/log/audit/audit.log into UatuEvent records."""

    def __init__(self, log_path: str = "/var/log/audit/audit.log", health_reg: Optional[HealthRegistry] = None):
        self.log_path = log_path
        self.health_reg = health_reg or default_health_registry
        self.hostname = platform.node() or "localhost"

    def is_available(self) -> bool:
        """Check if audit subsystem tools or logs are available."""
        has_bin = bool(shutil.which("ausearch") or shutil.which("auditctl"))
        has_log = os.path.exists(self.log_path) and os.access(self.log_path, os.R_OK)
        return has_bin or has_log

    def check_health(self):
        """Update health registry for exec monitoring and audit telemetry."""
        if not self.is_available():
            self.health_reg.record_error(
                "auditd_exec_monitoring",
                "auditd / ausearch is not installed or /var/log/audit/audit.log is inaccessible",
                is_fatal=True
            )
        else:
            self.health_reg.record_success("auditd_exec_monitoring", "auditd telemetry available")

    def read_events_from_ausearch(self, checkpoint_time: Optional[str] = None) -> List[UatuEvent]:
        """Query ausearch -i for interpreted audit records."""
        if not shutil.which("ausearch"):
            self.check_health()
            return []

        cmd = ["ausearch", "-i"]
        if checkpoint_time:
            cmd.extend(["-ts", checkpoint_time])
        else:
            cmd.extend(["-ts", "recent"])

        result = CommandRunner.run(cmd, timeout=15.0)
        if not result.success and result.return_code != 0:
            # ausearch returns 1 if no matching events found
            return []

        return self.parse_audit_text(result.stdout)

    def read_events_from_log_file(self, max_lines: int = 5000) -> List[UatuEvent]:
        """Read and parse trailing lines from audit.log."""
        if not os.path.exists(self.log_path):
            self.check_health()
            return []

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-max_lines:]
            self.health_reg.record_success("auditd_exec_monitoring")
            return self.parse_audit_lines(lines)
        except PermissionError:
            self.health_reg.record_error(
                "auditd_exec_monitoring",
                f"Permission denied reading {self.log_path}. Requires root or audit group permissions.",
                is_fatal=True
            )
            return []
        except Exception as e:
            self.health_reg.record_error("auditd_exec_monitoring", str(e))
            return []

    def parse_audit_text(self, text: str) -> List[UatuEvent]:
        """Parse raw text blocks from ausearch into events."""
        return self.parse_audit_lines(text.splitlines())

    def parse_audit_lines(self, lines: List[str]) -> List[UatuEvent]:
        """Parse raw or interpreted audit lines into structured UatuEvent objects."""
        events: List[UatuEvent] = []

        for line in lines:
            line = line.strip()
            if not line or not ("type=" in line and "msg=audit" in line):
                continue

            evt = self._parse_single_line(line)
            if evt:
                events.append(evt)

        return events

    def _parse_single_line(self, line: str) -> Optional[UatuEvent]:
        # Extract record type
        type_m = re.search(r'type=([A-Z0-9_]+)', line)
        if not type_m:
            return None
        record_type = type_m.group(1)

        # Extract timestamp: msg=audit(1730657730.123:452) or msg=audit(MM/DD/YYYY HH:MM:SS.mmm:nnn)
        ts = self._extract_timestamp(line)

        # Parse key=value fields
        fields: Dict[str, str] = {}
        for match in re.finditer(r'([a-zA-Z0-9_\.\-]+)=("[^"]*"|\'[^\']*\'|[^\s]+)', line):
            k = match.group(1)
            v = match.group(2).strip('"\'')
            fields[k] = v

        uid = int(fields["uid"]) if fields.get("uid", "").isdigit() else None
        euid = int(fields["euid"]) if fields.get("euid", "").isdigit() else None
        suid = int(fields["suid"]) if fields.get("suid", "").isdigit() else None
        gid = int(fields["gid"]) if fields.get("gid", "").isdigit() else None
        egid = int(fields["egid"]) if fields.get("egid", "").isdigit() else None
        pid = int(fields["pid"]) if fields.get("pid", "").isdigit() else None
        ppid = int(fields["ppid"]) if fields.get("ppid", "").isdigit() else None
        comm = fields.get("comm")
        exe = fields.get("exe")
        key = fields.get("key", "").strip('"\'')

        event_type = f"AUDIT_{record_type}"
        severity = EventSeverity.INFO

        # 1. Monitored file modifications: /etc/sudoers, /etc/passwd, /etc/shadow
        if key in ("uatu_sudoers", "uatu_passwd", "uatu_shadow") or record_type in ("PATH", "CONFIG_CHANGE"):
            name = fields.get("name", "")
            if "sudoers" in key or "sudoers" in name:
                event_type = "WATCHED_FILE_EDIT_SUDOERS"
                severity = EventSeverity.HIGH
            elif "passwd" in key or "passwd" in name:
                event_type = "WATCHED_FILE_EDIT_PASSWD"
                severity = EventSeverity.CRITICAL
            elif "shadow" in key or "shadow" in name:
                event_type = "WATCHED_FILE_EDIT_SHADOW"
                severity = EventSeverity.CRITICAL

        # 2. SUID execution: euid == 0 and uid != 0
        if euid is not None and uid is not None and euid == 0 and uid != 0:
            event_type = "SUID_EXECUTION"
            severity = EventSeverity.HIGH

        # 3. Privilege escalation syscalls
        if key == "uatu_priv_esc" or record_type in ("SETUID", "SETREUID", "SETRESUID"):
            event_type = "PRIVILEGE_TRANSITION_SYSCALL"
            severity = EventSeverity.HIGH

        # 4. Standard process executions
        if record_type in ("EXECVE", "SYSCALL") and event_type == f"AUDIT_{record_type}":
            event_type = "PROCESS_EXECUTION"

        return UatuEvent(
            timestamp=ts,
            host_id="localhost",
            hostname=self.hostname,
            source="auditd",
            collection_method=CollectionMethod.AUDITD_LOG,
            event_type=event_type,
            severity=severity,
            uid=uid,
            euid=euid,
            suid=suid,
            gid=gid,
            egid=egid,
            pid=pid,
            ppid=ppid,
            exe=exe or comm,
            command=comm or exe,
            user=fields.get("AUID") or fields.get("auid") or str(uid),
            evidence={
                "record_type": record_type,
                "key": key,
                "fields": fields,
                "raw_line": line
            },
            provenance_class=ProvenanceClass.OBSERVED,
            data_origin=DataOrigin.LIVE_TELEMETRY,
            confidence=0.98,
            collection_status=CollectionStatus.SUCCESS
        )

    def _extract_timestamp(self, line: str) -> datetime:
        # Epoch format: msg=audit(1730657730.123:452)
        epoch_m = re.search(r'msg=audit\((\d+(?:\.\d+)?):', line)
        if epoch_m:
            try:
                epoch = float(epoch_m.group(1))
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            except Exception:
                pass

        # Interpreted format: msg=audit(11/04/2026 12:30:15.123:452)
        int_m = re.search(r'msg=audit\((\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?):', line)
        if int_m:
            try:
                dt = datetime.strptime(int_m.group(1).split(".")[0], "%m/%d/%Y %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        return datetime.now(timezone.utc)


class AuthLogReader:
    """Reads journald or /var/log/auth.log to detect sudo and ssh authentication failures and successes."""

    def __init__(self, auth_log_path: Optional[str] = None, health_reg: Optional[HealthRegistry] = None):
        self.auth_log_path = auth_log_path
        self.health_reg = health_reg or default_health_registry
        self.hostname = platform.node() or "localhost"

    def is_available(self) -> bool:
        """Check if journalctl or auth.log exists."""
        if shutil.which("journalctl"):
            return True
        candidates = ["/var/log/auth.log", "/var/log/secure"]
        if self.auth_log_path:
            candidates.insert(0, self.auth_log_path)
        return any(os.path.exists(p) and os.access(p, os.R_OK) for p in candidates)

    def collect_events(self, max_lines: int = 2000) -> List[UatuEvent]:
        """Collect events using journalctl (preferred) or auth log file."""
        events: List[UatuEvent] = []

        if shutil.which("journalctl"):
            events.extend(self._collect_from_journal(lines_count=max_lines))
        else:
            events.extend(self._collect_from_file(lines_count=max_lines))

        return events

    def _collect_from_journal(self, lines_count: int = 1000) -> List[UatuEvent]:
        """Query journalctl for sudo and ssh authentication messages."""
        cmd = ["journalctl", "-n", str(lines_count), "--no-pager", "-u", "sudo", "-u", "ssh", "-u", "sshd"]
        result = CommandRunner.run(cmd, timeout=15.0)
        if result.success and result.stdout:
            self.health_reg.record_success("journald_auth_telemetry")
            return self.parse_auth_lines(result.stdout.splitlines())
        else:
            return self._collect_from_file(lines_count=lines_count)

    def _collect_from_file(self, lines_count: int = 1000) -> List[UatuEvent]:
        """Read fallback auth.log or /var/log/secure."""
        candidates = ["/var/log/auth.log", "/var/log/secure"]
        if self.auth_log_path:
            candidates.insert(0, self.auth_log_path)

        for p in candidates:
            if os.path.exists(p) and os.access(p, os.R_OK):
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()[-lines_count:]
                    self.health_reg.record_success("journald_auth_telemetry")
                    return self.parse_auth_lines(lines)
                except Exception:
                    continue

        self.health_reg.record_degraded(
            "journald_auth_telemetry",
            "journalctl returned no output and /var/log/auth.log is inaccessible"
        )
        return []

    def parse_auth_lines(self, lines: List[str]) -> List[UatuEvent]:
        """Parse raw authentication syslog lines into UatuEvent objects."""
        events: List[UatuEvent] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            evt = self._parse_auth_line(line)
            if evt:
                events.append(evt)

        return events

    def _parse_auth_line(self, line: str) -> Optional[UatuEvent]:
        ts = self._extract_timestamp(line)

        # 1. Sudo authentication failures
        if "sudo:" in line and any(k in line.lower() for k in ("incorrect password", "authentication failure", "failed")):
            user_match = re.search(r'([a-zA-Z0-9_\.\-]+)\s*:\s*(?:\d+\s+incorrect password|authentication failure)', line)
            user = user_match.group(1) if user_match else "unknown"
            return UatuEvent(
                timestamp=ts,
                hostname=self.hostname,
                source="journald:sudo",
                collection_method=CollectionMethod.SYSTEMD_JOURNAL,
                event_type="SUDO_AUTH_FAILURE",
                severity=EventSeverity.MEDIUM,
                user=user,
                command="sudo",
                evidence={"raw_line": line, "action": "AUTH_FAILURE"},
                provenance_class=ProvenanceClass.OBSERVED,
                data_origin=DataOrigin.LIVE_TELEMETRY,
                confidence=1.0
            )

        # 2. Sudo successful execution
        if "sudo:" in line and "COMMAND=" in line:
            user_match = re.search(r'sudo:\s+([a-zA-Z0-9_\.\-]+)\s+:', line)
            user = user_match.group(1) if user_match else "unknown"
            cmd_match = re.search(r'COMMAND=(.+)$', line)
            cmd = cmd_match.group(1).strip() if cmd_match else "unknown"

            return UatuEvent(
                timestamp=ts,
                hostname=self.hostname,
                source="journald:sudo",
                collection_method=CollectionMethod.SYSTEMD_JOURNAL,
                event_type="SUDO_AUTH_SUCCESS",
                severity=EventSeverity.INFO,
                user=user,
                euid=0,
                command=cmd,
                evidence={"raw_line": line, "command": cmd, "target_user": "root"},
                provenance_class=ProvenanceClass.OBSERVED,
                data_origin=DataOrigin.LIVE_TELEMETRY,
                confidence=1.0
            )

        # 3. SSH authentication failures
        if "sshd" in line and ("Failed password" in line or "authentication failure" in line):
            user_match = re.search(r'Failed password for (?:invalid user )?([a-zA-Z0-9_\.\-]+)', line)
            user = user_match.group(1) if user_match else "unknown"
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            r_ip = ip_match.group(1) if ip_match else "unknown"

            return UatuEvent(
                timestamp=ts,
                hostname=self.hostname,
                source="journald:sshd",
                collection_method=CollectionMethod.SYSTEMD_JOURNAL,
                event_type="SSH_AUTH_FAILURE",
                severity=EventSeverity.MEDIUM,
                user=user,
                evidence={"raw_line": line, "remote_ip": r_ip},
                provenance_class=ProvenanceClass.OBSERVED,
                data_origin=DataOrigin.LIVE_TELEMETRY,
                confidence=1.0
            )

        return None

    def _extract_timestamp(self, line: str) -> datetime:
        # Standard syslog RFC3164: "Nov  4 12:30:15"
        m = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
        if m:
            try:
                current_year = datetime.now(timezone.utc).year
                dt_str = f"{m.group(1)} {current_year}"
                dt = datetime.strptime(dt_str, "%b %d %H:%M:%S %Y")
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        # ISO format: "2026-11-04T12:30:15"
        iso_m = re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if iso_m:
            try:
                dt = datetime.fromisoformat(iso_m.group(1).replace(" ", "T"))
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        return datetime.now(timezone.utc)


class TelemetryEngine:
    """Master telemetry coordinator: reads auditd & journald, passes events to EventBus and Storage."""

    def __init__(
        self,
        storage: Optional[StorageEngine] = None,
        event_bus: Optional[EventBus] = None,
        health_reg: Optional[HealthRegistry] = None
    ):
        self.storage = storage or StorageEngine()
        self.event_bus = event_bus or EventBus()
        self.health_reg = health_reg or default_health_registry

        self.audit_reader = AuditLogReader(health_reg=self.health_reg)
        self.auth_reader = AuthLogReader(health_reg=self.health_reg)

        # Register health check components
        self.health_reg.register("auditd_exec_monitoring", critical=True)
        self.health_reg.register("journald_auth_telemetry", critical=False)

    def poll_once(self) -> List[UatuEvent]:
        """Poll telemetry from available collectors, publish to event bus, and persist to evidence store."""
        collected: List[UatuEvent] = []

        # 1. Audit collector
        self.audit_reader.check_health()
        if self.audit_reader.is_available():
            audit_events = self.audit_reader.read_events_from_log_file()
            collected.extend(audit_events)

        # 2. Auth collector
        if self.auth_reader.is_available():
            auth_events = self.auth_reader.collect_events()
            collected.extend(auth_events)

        # 3. Route through event bus and persist
        for evt in collected:
            self.event_bus.publish(evt)

        if collected:
            self.storage.save_events(collected)

        return collected
