"""
UATU Linux Edition - Sudo Configuration Scanner (Red Team Mode)
Audits sudoers rules, NOPASSWD entries, wildcard permissions, and sudoers file integrity.
Does NOT flag /etc/sudoers being readable as a finding.
"""

import os
from pathlib import Path
import re
import stat
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.gtfobins import GTFOBins
from utils.file_utils import get_permission_string, get_file_stat_metadata
from config.settings import VECTOR_SUDO, DANGEROUS_SUDO


class SudoScanner(BaseScanner):
    """Audits sudoers configuration and permissions for privilege escalation vectors."""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_SUDO, config)

    def scan(self) -> List[Finding]:
        """Execute sudo configuration assessment."""
        # 1. Audit sudoers file permissions
        self._check_sudoers_file_security("/etc/sudoers")
        sudoers_d = "/etc/sudoers.d"
        if os.path.exists(sudoers_d) and os.path.isdir(sudoers_d):
            try:
                for entry in os.scandir(sudoers_d):
                    if entry.is_file():
                        self._check_sudoers_file_security(entry.path)
            except PermissionError:
                pass

        # 2. Check sudo privileges for current user non-interactively (-n prevents password prompt)
        output = self.run_command(["sudo", "-n", "-l"], timeout=15)
        if output and ("may run the following" in output.lower() or "user" in output.lower()):
            self._analyze_sudo_l_output(output)

        # 3. If readable, analyze /etc/sudoers directly for rules (NOTE: readable /etc/sudoers is NOT a finding)
        if os.path.exists("/etc/sudoers"):
            try:
                self._parse_sudoers_file("/etc/sudoers")
            except Exception:
                pass

        return self.findings

    def _check_sudoers_file_security(self, file_path: str):
        """Verify that sudoers files are strictly owned by root and not writable by non-root."""
        if not os.path.exists(file_path):
            return

        try:
            st = os.stat(file_path)
        except Exception:
            return

        meta = get_file_stat_metadata(file_path)

        # Sudoers must be owned by UID 0
        if st.st_uid != 0:
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Sudoers File Not Owned by Root: {file_path}",
                description=f"The file {file_path} is owned by UID {st.st_uid} instead of root (UID 0).",
                affected_resource=file_path,
                evidence=meta,
                detection_method="file_ownership_audit",
                risk_explanation="The owner can modify sudoers rules to grant themselves unrestricted root execution.",
                remediation=f"Restore root ownership: chown root:root {file_path} && chmod 440 {file_path}",
                confidence=1.0
            )

        # Sudoers must not be writable by non-root (world or group writable)
        is_writable = bool(st.st_mode & stat.S_IWOTH) or bool((st.st_mode & stat.S_IWGRP) and st.st_gid != 0)
        if is_writable:
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Sudoers File Insecurely Writable: {file_path}",
                description=f"The file {file_path} has unauthorized write permissions ({meta.get('mode', '')}).",
                affected_resource=file_path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Direct privilege escalation. Any local user with write access can add arbitrary NOPASSWD: ALL entries.",
                remediation=f"Harden permissions: chmod 440 {file_path}",
                confidence=1.0
            )

    def _analyze_sudo_l_output(self, sudo_output: str):
        """Analyze output of sudo -l for dangerous rules, NOPASSWD, and wildcards."""
        lines = [line.strip() for line in sudo_output.splitlines() if line.strip()]

        for line in lines:
            if not ("(" in line and ")" in line):
                continue

            # Case 1: Check NOPASSWD with ALL commands
            if "NOPASSWD" in line and ("ALL" in line.split(")")[-1]):
                self.add_finding(
                    severity=Severity.CRITICAL.value,
                    title="Sudo NOPASSWD Unrestricted Command Execution",
                    description=f"The current user can execute all commands as root without a password: {line}",
                    affected_resource="sudoers",
                    evidence={'owner': '0:0', 'mode': 'r--r-----', 'rule': line},
                    detection_method="sudo_l_rule_inspection",
                    risk_explanation="Immediate root privilege escalation via arbitrary sudo command execution without authentication.",
                    remediation="Remove NOPASSWD or restrict execution to specific hardened, non-interactive utilities.",
                    confidence=1.0
                )
            elif "NOPASSWD" in line:
                # Case 2: Check for wildcards in NOPASSWD rules
                if "*" in line:
                    self.add_finding(
                        severity=Severity.HIGH.value,
                        title=f"Sudo NOPASSWD Rule with Dangerous Wildcard",
                        description=f"Sudo rule permits NOPASSWD execution with wildcard patterns: {line}",
                        affected_resource="sudoers",
                        evidence={'owner': '0:0', 'mode': 'r--r-----', 'rule': line},
                        detection_method="sudo_l_rule_inspection",
                        risk_explanation="Wildcards in sudo rules frequently allow argument injection or directory traversal to execute arbitrary commands.",
                        remediation="Avoid wildcards in sudoers commands; specify exact binary paths and parameters.",
                        confidence=0.95
                    )

                # Case 3: Check specific dangerous binaries
                for dangerous_cmd in DANGEROUS_SUDO:
                    if re.search(r'\b' + re.escape(dangerous_cmd) + r'\b', line, re.IGNORECASE):
                        gtfo = GTFOBins.lookup(dangerous_cmd)
                        desc = gtfo.get('sudo', 'Command provides shell escaping or root execution capabilities.') if gtfo else 'Potentially dangerous command.'
                        self.add_finding(
                            severity=Severity.HIGH.value,
                            title=f"Dangerous NOPASSWD Sudo Binary: {dangerous_cmd}",
                            description=f"Rule grants NOPASSWD execution of {dangerous_cmd}: {line}",
                            affected_resource=dangerous_cmd,
                            evidence={'owner': '0:0', 'mode': 'r-xr-xr-x', 'rule': line, 'command': dangerous_cmd},
                            detection_method="sudo_l_rule_inspection",
                            risk_explanation=desc,
                            remediation=GTFOBins.get_defense_recommendation(dangerous_cmd),
                            confidence=0.95
                        )

    def _parse_sudoers_file(self, path: str):
        """Parse contents of readable sudoers file."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check for NOPASSWD
            if "NOPASSWD:" in line:
                cmd_part = line.split("NOPASSWD:")[-1].strip()
                if cmd_part == "ALL" or "/bin/sh" in cmd_part or "/bin/bash" in cmd_part or "*" in cmd_part:
                    self.add_finding(
                        severity=Severity.HIGH.value,
                        title=f"Sudoers Rule with NOPASSWD: {line[:50]}",
                        description=f"Detected rule allowing passwordless command execution in {path}: {line}",
                        affected_resource=path,
                        evidence={'owner': '0:0', 'mode': 'r--r-----', 'file': path, 'line': line},
                        detection_method="sudoers_file_static_parse",
                        risk_explanation="Users matching this entry can execute elevated commands without password verification.",
                        remediation="Enforce password authentication or restrict commands using visudo.",
                        confidence=0.90
                    )
