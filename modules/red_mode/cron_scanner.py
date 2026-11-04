"""
PrivWatch 3.0 - Cron & Systemd Timer Scanner (Red Team Mode)
Audits scheduled jobs, cron directories, systemd timers, and referenced script permissions
to identify privilege escalation vulnerabilities without false alerts.
Strictly Linux-native POSIX path and permission evaluation.
"""

import os
from pathlib import Path
import re
import shlex
import stat
from typing import List, Optional, Any, Set

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import (
    find_writable_files_in_path, is_parent_writable,
    get_file_stat_metadata, get_permission_string, is_insecurely_writable
)
from utils.system_info import is_root
from config.settings import VECTOR_CRON, CRON_DIRS


class CronScanner(BaseScanner):
    """Audits cron jobs, directories, and systemd timers for privilege escalation paths"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_CRON, config)
        self.cron_dirs = getattr(config, 'cron_dirs', CRON_DIRS) if config else CRON_DIRS

    def scan(self) -> List[Finding]:
        """Execute scheduled task vulnerability audit"""
        # 1. Audit cron directories and cron files
        for cdir in self.cron_dirs:
            self._audit_cron_directory(cdir)

        # 2. Audit /etc/crontab file and referenced scripts
        self._audit_crontab_file("/etc/crontab")

        # 3. Audit systemd timers if present
        self._audit_systemd_timers()

        return self.findings

    def _audit_cron_directory(self, cron_dir: str):
        """Check if directory is writable or contains writable job definitions"""
        if not os.path.exists(cron_dir):
            return

        # Check if directory itself is insecurely writable
        if is_insecurely_writable(cron_dir):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Writable Cron Directory: {cron_dir}",
                description=f"The system cron directory {cron_dir} is writable by unauthorized users.",
                affected_resource=cron_dir,
                evidence=get_file_stat_metadata(cron_dir),
                detection_method="directory_permission_audit",
                risk_explanation="An attacker can place an arbitrary cron script into this directory that runs automatically with root privileges.",
                remediation=f"Restrict write access to root only: chmod 755 {cron_dir} && chown root:root {cron_dir}",
                confidence=1.0
            )

        # Audit files inside directory
        try:
            for entry in os.scandir(cron_dir):
                if entry.is_file(follow_symlinks=False):
                    self._audit_cron_file(entry.path)
        except PermissionError:
            pass

    def _audit_cron_file(self, file_path: str):
        """Audit single cron configuration or script file"""
        meta = get_file_stat_metadata(file_path)

        # File is writable by unauthorized users
        if is_insecurely_writable(file_path):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Writable Cron Job File: {file_path}",
                description=f"The cron file {file_path} is writable by unauthorized users.",
                affected_resource=file_path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="An unprivileged user can edit this file to execute arbitrary commands when cron triggers.",
                remediation=f"Harden permissions: chmod 644 {file_path} && chown root:root {file_path}",
                confidence=1.0
            )

        # Parse referenced scripts if file is readable
        if os.access(file_path, os.R_OK):
            self._parse_and_check_referenced_scripts(file_path)

    def _audit_crontab_file(self, crontab_path: str):
        """Audit /etc/crontab permissions and entries"""
        if not os.path.exists(crontab_path):
            return

        meta = get_file_stat_metadata(crontab_path)
        if is_insecurely_writable(crontab_path):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Writable System Crontab: /etc/crontab",
                description="The primary system crontab file is writable by unauthorized users.",
                affected_resource=crontab_path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Immediate root privilege escalation via appending root scheduled tasks.",
                remediation="Harden permissions: chmod 644 /etc/crontab && chown root:root /etc/crontab",
                confidence=1.0
            )

        if os.access(crontab_path, os.R_OK):
            self._parse_and_check_referenced_scripts(crontab_path)

    def _parse_and_check_referenced_scripts(self, cron_file_path: str):
        """Extract executable and script paths from cron lines and check their permissions"""
        try:
            with open(cron_file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Look for executable and script paths in cron command
            paths = re.findall(r'((?:[a-zA-Z]:)?[/\\][a-zA-Z0-9_\.\-~]+(?:[/\\][a-zA-Z0-9_\.\-~]+)+)', line)
            for p in paths:
                if os.path.exists(p) and os.path.isfile(p):
                    try:
                        st = os.stat(p)
                        # A script in cron is vulnerable if:
                        # 1. World-writable
                        # 2. Group-writable to non-root
                        # 3. Not owned by root (st_uid != 0)
                        # 4. Or writable by current user
                        curr_euid = os.geteuid() if hasattr(os, 'geteuid') else -1
                        is_insecure = (
                            bool(st.st_mode & stat.S_IWOTH) or
                            bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0) or
                            (st.st_uid != 0) or
                            (curr_euid != 0 and os.access(p, os.W_OK)) or
                            is_insecurely_writable(p)
                        )
                        if is_insecure:
                            self.add_finding(
                                severity=Severity.CRITICAL.value,
                                title=f"Writable Script Referenced in Cron: {p}",
                                description=f"Cron file {cron_file_path} references executable {p}, which is writable or controlled by unauthorized users.",
                                affected_resource=p,
                                evidence={
                                    'cron_file': cron_file_path,
                                    'cron_line': line,
                                    'script_stat': get_file_stat_metadata(p)
                                },
                                detection_method="cron_reference_permission_audit",
                                risk_explanation="Modifying the script will result in command execution under the user running the cron job (often root).",
                                remediation=f"Harden script permissions: chmod 755 {p} && chown root:root {p}",
                                confidence=0.98
                            )
                    except Exception:
                        pass

    def _audit_systemd_timers(self):
        """Audit systemd timers and associated service units"""
        systemd_timer_dirs = [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system"
        ]

        for sdir in systemd_timer_dirs:
            if not os.path.exists(sdir) or not os.path.isdir(sdir):
                continue
            try:
                for entry in os.scandir(sdir):
                    if entry.is_file() and entry.name.endswith(".timer"):
                        # Check associated service
                        service_name = entry.name.replace(".timer", ".service")
                        service_path = os.path.join(sdir, service_name)
                        if os.path.exists(service_path):
                            if is_insecurely_writable(service_path):
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Writable Systemd Timer Service: {service_path}",
                                    description=f"Systemd timer unit {entry.path} triggers {service_path}, which is writable by unauthorized users.",
                                    affected_resource=service_path,
                                    evidence=get_file_stat_metadata(service_path),
                                    detection_method="systemd_unit_permission_audit",
                                    risk_explanation="An attacker can alter ExecStart in the service unit to execute arbitrary root commands upon timer trigger.",
                                    remediation=f"Harden permissions: chmod 644 {service_path} && chown root:root {service_path}",
                                    confidence=1.0
                                )
            except PermissionError:
                pass
