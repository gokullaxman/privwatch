"""
PrivWatch 3.0 - SSH Configuration & Key Security Scanner (Red Team Mode)
Audits sshd_config settings, private host keys, and ~/.ssh/authorized_keys permissions.
"""

import os
from pathlib import Path
import stat
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata


class SshScanner(BaseScanner):
    """Audits SSH daemon configurations and key permissions"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__("SSH_SECURITY", config)

    def scan(self) -> List[Finding]:
        """Execute SSH security audit"""
        self._audit_sshd_config("/etc/ssh/sshd_config")
        self._audit_host_keys("/etc/ssh")
        self._audit_user_authorized_keys()
        return self.findings

    def _audit_sshd_config(self, config_path: str):
        """Audit sshd_config directives"""
        if not os.path.exists(config_path) or not os.access(config_path, os.R_OK):
            return

        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].lower()
                val = parts[1].lower()

                # PermitRootLogin yes
                if key == "permitrootlogin" and val in ["yes", "without-password"]:
                    if val == "yes":
                        self.add_finding(
                            severity=Severity.HIGH.value,
                            title="SSH PermitRootLogin Enabled",
                            description="sshd_config explicitly permits direct remote login as root.",
                            affected_resource=f"{config_path}:PermitRootLogin",
                            evidence={'file': config_path, 'line': line},
                            detection_method="sshd_config_static_parse",
                            risk_explanation="Direct root SSH login exposes the root account to automated password brute force attacks.",
                            remediation="Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config and reload sshd.",
                            confidence=1.0
                        )

                # PermitEmptyPasswords yes
                if key == "permitemptypasswords" and val == "yes":
                    self.add_finding(
                        severity=Severity.CRITICAL.value,
                        title="SSH PermitEmptyPasswords Enabled",
                        description="sshd_config allows authentication to accounts with empty passwords.",
                        affected_resource=f"{config_path}:PermitEmptyPasswords",
                        evidence={'file': config_path, 'line': line},
                        detection_method="sshd_config_static_parse",
                        risk_explanation="Allows remote access without authentication to any system account with an empty password.",
                        remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd.",
                        confidence=1.0
                    )

    def _audit_host_keys(self, ssh_dir: str):
        """Verify private host keys are strictly protected"""
        if not os.path.exists(ssh_dir):
            return

        try:
            curr_euid = os.geteuid() if hasattr(os, 'geteuid') else -1
            is_unprivileged = (curr_euid != 0)
            for entry in os.scandir(ssh_dir):
                if entry.is_file() and entry.name.startswith("ssh_host_") and entry.name.endswith("_key"):
                    st = entry.stat(follow_symlinks=False)
                    is_insecure_read = (st.st_mode & stat.S_IROTH) or ((st.st_mode & stat.S_IRGRP) and st.st_gid != 0) or (is_unprivileged and os.access(entry.path, os.R_OK))
                    if is_insecure_read:
                        self.add_finding(
                            severity=Severity.CRITICAL.value,
                            title=f"Readable SSH Private Host Key: {entry.name}",
                            description=f"The SSH host private key {entry.path} has unauthorized read permissions.",
                            affected_resource=entry.path,
                            evidence=get_file_stat_metadata(entry.path),
                            detection_method="ssh_key_permission_audit",
                            risk_explanation="Exposing host private keys permits adversary man-in-the-middle attacks and host impersonation.",
                            remediation=f"Harden key permissions: chmod 600 {entry.path} && chown root:root {entry.path}",
                            confidence=1.0
                        )
        except PermissionError:
            pass

    def _audit_user_authorized_keys(self):
        """Audit permissions of current user's authorized_keys"""
        home = os.path.expanduser("~")
        auth_keys = os.path.join(home, ".ssh", "authorized_keys")
        if os.path.exists(auth_keys):
            meta = get_file_stat_metadata(auth_keys)
            if meta.get('is_world_writable'):
                self.add_finding(
                    severity=Severity.CRITICAL.value,
                    title=f"World-Writable authorized_keys: {auth_keys}",
                    description=f"The authorized_keys file {auth_keys} is world-writable.",
                    affected_resource=auth_keys,
                    evidence=meta,
                    detection_method="authorized_keys_permission_audit",
                    risk_explanation="Any local user can inject their public key to authenticate as this user.",
                    remediation=f"Harden permissions: chmod 600 {auth_keys}",
                    confidence=1.0
                )
