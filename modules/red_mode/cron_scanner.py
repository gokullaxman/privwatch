"""
UATU Linux Edition - Cron & Systemd Service Script Scanner (Red Team Mode)
Audits scheduled jobs, cron directories, systemd timers, and systemd service scripts
to identify privilege escalation vulnerabilities where unprivileged users can modify
scripts executed with root privileges.
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
from config.settings import VECTOR_CRON, CRON_DIRS


class CronScanner(BaseScanner):
    """Audits cron jobs, directories, and systemd timers/services for privilege escalation paths."""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_CRON, config)
        self.cron_dirs = getattr(config, 'cron_dirs', CRON_DIRS) if config else CRON_DIRS

    def scan(self) -> List[Finding]:
        """Execute scheduled task vulnerability audit."""
        # 1. Audit cron directories and cron files
        for cdir in self.cron_dirs:
            self._audit_cron_directory(cdir)

        # 2. Audit /etc/crontab file and referenced scripts
        self._audit_crontab_file("/etc/crontab")

        # 3. Audit systemd timers and service units
        self._audit_systemd_timers_and_services()

        return self.findings

    def _audit_cron_directory(self, cron_dir: str):
        """Check if directory is writable or contains writable job definitions."""
        if not os.path.exists(cron_dir):
            return

        meta = get_file_stat_metadata(cron_dir)
        try:
            st = os.stat(cron_dir)
            is_writable = bool(st.st_mode & stat.S_IWOTH) or bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0)
        except Exception:
            is_writable = False

        if is_writable:
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Writable Cron Directory: {cron_dir}",
                description=f"The system cron directory {cron_dir} is writable by unauthorized users ({meta.get('mode', '')}).",
                affected_resource=cron_dir,
                evidence=meta,
                detection_method="directory_permission_audit",
                risk_explanation="An attacker can place an arbitrary cron script into this directory that runs automatically with root privileges.",
                remediation=f"Restrict write access to root only: chmod 755 {cron_dir} && chown root:root {cron_dir}",
                confidence=1.0
            )

        try:
            for entry in os.scandir(cron_dir):
                if entry.is_file(follow_symlinks=False):
                    self._audit_cron_file(entry.path)
        except PermissionError:
            pass

    def _audit_cron_file(self, file_path: str):
        """Audit single cron configuration or script file."""
        meta = get_file_stat_metadata(file_path)

        try:
            st = os.stat(file_path)
            is_writable = bool(st.st_mode & stat.S_IWOTH) or bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0)
        except Exception:
            is_writable = False

        if is_writable:
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Writable Cron Job File: {file_path}",
                description=f"The cron file {file_path} is writable by unauthorized users ({meta.get('mode', '')}).",
                affected_resource=file_path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="An unprivileged user can edit this file to execute arbitrary commands when cron triggers.",
                remediation=f"Harden permissions: chmod 644 {file_path} && chown root:root {file_path}",
                confidence=1.0
            )

        if os.access(file_path, os.R_OK):
            self._parse_and_check_referenced_scripts(file_path)

    def _audit_crontab_file(self, crontab_path: str):
        """Audit /etc/crontab permissions and entries."""
        if not os.path.exists(crontab_path):
            return

        meta = get_file_stat_metadata(crontab_path)
        try:
            st = os.stat(crontab_path)
            is_writable = bool(st.st_mode & stat.S_IWOTH) or bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0)
        except Exception:
            is_writable = False

        if is_writable:
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Writable System Crontab: /etc/crontab",
                description=f"The primary system crontab file is writable by unauthorized users ({meta.get('mode', '')}).",
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
        """Extract executable and script paths from cron lines and check their permissions."""
        try:
            with open(cron_file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Look for executable and script paths
            paths = re.findall(r'((?:[a-zA-Z]:)?[/\\][a-zA-Z0-9_\.\-~]+(?:[/\\][a-zA-Z0-9_\.\-~]+)+)', line)
            for p in paths:
                if os.path.exists(p) and os.path.isfile(p):
                    try:
                        st = os.stat(p)
                        meta = get_file_stat_metadata(p)
                        is_insecure = (
                            bool(st.st_mode & stat.S_IWOTH) or
                            bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0) or
                            (st.st_uid != 0)
                        )
                        if is_insecure:
                            self.add_finding(
                                severity=Severity.CRITICAL.value,
                                title=f"Writable Script Referenced in Cron: {p}",
                                description=f"Cron file {cron_file_path} references executable {p}, which is writable or controlled by non-root ({meta.get('mode', '')}).",
                                affected_resource=p,
                                evidence={
                                    'owner': meta.get('owner', f"{st.st_uid}:{st.st_gid}"),
                                    'mode': meta.get('mode', get_permission_string(p)),
                                    'cron_file': cron_file_path,
                                    'cron_line': line,
                                    'script_stat': meta
                                },
                                detection_method="cron_reference_permission_audit",
                                risk_explanation="Modifying the script will result in command execution under the user running the cron job (often root).",
                                remediation=f"Harden script permissions: chmod 755 {p} && chown root:root {p}",
                                confidence=0.98
                            )
                    except Exception:
                        pass

    def _audit_systemd_timers_and_services(self):
        """Audit systemd timers and root service units for writable ExecStart scripts."""
        systemd_dirs = [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system"
        ]

        for sdir in systemd_dirs:
            if not os.path.exists(sdir) or not os.path.isdir(sdir):
                continue
            try:
                for entry in os.scandir(sdir):
                    if not entry.is_file():
                        continue

                    # 1. Check timer associated services
                    if entry.name.endswith(".timer"):
                        service_name = entry.name.replace(".timer", ".service")
                        service_path = os.path.join(sdir, service_name)
                        if os.path.exists(service_path):
                            meta = get_file_stat_metadata(service_path)
                            st = os.stat(service_path)
                            if (st.st_mode & stat.S_IWOTH) or ((st.st_mode & stat.S_IWGRP) and st.st_gid != 0):
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Writable Systemd Timer Service: {service_path}",
                                    description=f"Systemd timer unit {entry.path} triggers {service_path}, which is writable ({meta.get('mode', '')}).",
                                    affected_resource=service_path,
                                    evidence=meta,
                                    detection_method="systemd_unit_permission_audit",
                                    risk_explanation="An attacker can alter ExecStart in the service unit to execute arbitrary root commands upon timer trigger.",
                                    remediation=f"Harden permissions: chmod 644 {service_path} && chown root:root {service_path}",
                                    confidence=1.0
                                )

                    # 2. Check service files for ExecStart scripts
                    if entry.name.endswith(".service"):
                        self._check_service_file_execstart(entry.path)
            except PermissionError:
                pass

    def _check_service_file_execstart(self, service_file: str):
        """Parse ExecStart from systemd service file and verify referenced binary/script permissions."""
        try:
            with open(service_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("ExecStart="):
                exec_cmd = line.split("ExecStart=", 1)[1].strip()
                tokens = shlex.split(exec_cmd) if exec_cmd else []
                if tokens:
                    script_path = tokens[0].lstrip("-@+!:")
                    if os.path.exists(script_path) and os.path.isfile(script_path):
                        try:
                            st = os.stat(script_path)
                            meta = get_file_stat_metadata(script_path)
                            is_insecure = (
                                bool(st.st_mode & stat.S_IWOTH) or
                                bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0) or
                                (st.st_uid != 0)
                            )
                            if is_insecure:
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Writable Root Systemd Service Script: {script_path}",
                                    description=f"Systemd service {service_file} executes {script_path}, which is writable or non-root owned ({meta.get('mode', '')}).",
                                    affected_resource=script_path,
                                    evidence={
                                        'owner': meta.get('owner', f"{st.st_uid}:{st.st_gid}"),
                                        'mode': meta.get('mode', get_permission_string(script_path)),
                                        'service_file': service_file,
                                        'exec_line': line,
                                        'script_stat': meta
                                    },
                                    detection_method="systemd_exec_permission_audit",
                                    risk_explanation="Modifying this script allows code execution under the privileges of the systemd service (default root).",
                                    remediation=f"Harden script permissions: chmod 755 {script_path} && chown root:root {script_path}",
                                    confidence=0.98
                                )
                        except Exception:
                            pass
