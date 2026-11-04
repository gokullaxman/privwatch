"""
PrivWatch 3.0 - Password & Authentication File Scanner (Red Team Mode)
Audits /etc/passwd, /etc/shadow, and authentication files for unauthorized write/read access,
rogue UID 0 accounts, and empty password fields.
Adheres strictly to Linux POSIX ownership and permission semantics.
"""

import os
from pathlib import Path
import stat
from typing import List, Optional, Any, Dict

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata, is_insecurely_writable, get_posix_acls
from core.evidence import EvidenceManager
from config.settings import VECTOR_PASSWD


class PasswdScanner(BaseScanner):
    """Audits system authentication and account configuration files."""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_PASSWD, config)

    def scan(self) -> List[Finding]:
        """Execute authentication file vulnerability assessment."""
        self._audit_passwd_file("/etc/passwd")
        self._audit_shadow_file("/etc/shadow")
        self._audit_backup_files()
        return self.findings

    def _audit_passwd_file(self, path: str):
        """Audit /etc/passwd permissions, ownership, and account definitions."""
        if not os.path.exists(path):
            return

        try:
            st = os.stat(path)
        except Exception:
            return

        meta = get_file_stat_metadata(path)
        is_canonical_passwd = (path == "/etc/passwd" or os.path.realpath(path) == "/etc/passwd")

        # 1. Ownership and Permission Integrity
        # Only audit write permissions on the actual /etc/passwd system database
        if is_canonical_passwd and is_insecurely_writable(path):
            self.add_finding(
                    severity=Severity.CRITICAL.value,
                    title="Writable Password Database: /etc/passwd",
                    description=f"The password database '{path}' has unauthorized write permissions.",
                    affected_resource=path,
                    evidence=meta,
                    detection_method="file_permission_audit",
                    risk_explanation="Direct root compromise. Any unauthorized user with write access can add a new account with UID 0.",
                    remediation=f"Harden permissions: chmod 644 {path} && chown root:root {path}",
                    confidence=1.0
                )

        # 2. Parse account definitions if readable
        if os.access(path, os.R_OK):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 3:
                            username = parts[0]
                            pw_field = parts[1]
                            uid_str = parts[2]

                            # Rogue UID 0 accounts (any non-root user with UID 0)
                            if uid_str == "0" and username != "root":
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Non-Root Account with UID 0: {username}",
                                    description=f"Account '{username}' has UID 0 (root equivalent privileges).",
                                    affected_resource=f"{path}:{username}",
                                    evidence={'line_number': line_num, 'username': username, 'uid': 0},
                                    detection_method="account_uid_audit",
                                    risk_explanation="Any non-standard UID 0 account represents either a backdoor or a dangerous administrative duplicate.",
                                    remediation=f"Inspect account necessity and remove if unauthorized: userdel {username}",
                                    confidence=1.0
                                )

                            # Empty password field (allows passwordless login if PAM permits)
                            if pw_field == "":
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Empty Password Field in /etc/passwd: {username}",
                                    description=f"User '{username}' has an empty password field in {path}.",
                                    affected_resource=f"{path}:{username}",
                                    evidence={'username': username, 'line_number': line_num},
                                    detection_method="account_password_field_audit",
                                    risk_explanation="An empty password field in /etc/passwd permits authentication without a password if shadow is bypassed.",
                                    remediation=f"Set a password: passwd {username} or lock account: usermod -L {username}",
                                    confidence=1.0
                                )
            except Exception:
                pass

    def _audit_shadow_file(self, path: str):
        """Audit /etc/shadow permissions and ownership."""
        if not os.path.exists(path):
            return

        try:
            st = os.stat(path)
        except Exception:
            return

        meta = get_file_stat_metadata(path)
        curr_euid = os.geteuid() if hasattr(os, 'geteuid') else -1
        is_root = (curr_euid == 0)

        # Insecure write access:
        if (st.st_mode & stat.S_IWOTH) or ((st.st_mode & stat.S_IWGRP) and st.st_gid not in (0, 42)) or (not is_root and os.access(path, os.W_OK)):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Writable Shadow Database: /etc/shadow",
                description=f"The shadow database '{path}' is writable by unauthorized users.",
                affected_resource=path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="An attacker can overwrite password hashes to gain immediate root access.",
                remediation=f"Harden permissions: chmod 640 {path} && chown root:shadow {path}",
                confidence=1.0
            )

        # Insecure read access:
        if (st.st_mode & stat.S_IROTH) or (not is_root and os.access(path, os.R_OK)):
            self.add_finding(
                severity=Severity.HIGH.value,
                title="Readable Shadow Database: /etc/shadow",
                description=f"The shadow database '{path}' is readable by unprivileged users.",
                affected_resource=path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Exposes system password hashes for offline dictionary and rainbow-table attacks.",
                remediation=f"Restrict read permissions: chmod 640 {path} && chown root:shadow {path}",
                confidence=1.0
            )

    def _audit_backup_files(self):
        """Check for exposed backup files like /etc/passwd- or /etc/shadow-."""
        backup_files = [
            ("/etc/shadow-", Severity.HIGH.value),
            ("/etc/gshadow-", Severity.HIGH.value),
            ("/etc/passwd-", Severity.MEDIUM.value)
        ]

        curr_euid = os.geteuid() if hasattr(os, 'geteuid') else -1
        is_root = (curr_euid == 0)

        for bfile, sev in backup_files:
            if os.path.exists(bfile):
                try:
                    st = os.stat(bfile)
                except Exception:
                    continue

                meta = get_file_stat_metadata(bfile)
                if "shadow" in bfile:
                    is_readable = (st.st_mode & stat.S_IROTH) or (not is_root and os.access(bfile, os.R_OK))
                    if is_readable:
                        self.add_finding(
                            severity=sev,
                            title=f"Readable Authentication Backup: {bfile}",
                            description=f"Backup file {bfile} contains password hashes and is readable by unauthorized users.",
                            affected_resource=bfile,
                            evidence=meta,
                            detection_method="backup_file_permission_audit",
                            risk_explanation="Authentication backups often contain valid password hashes.",
                            remediation=f"Restrict permissions: chmod 600 {bfile} && chown root:root {bfile}",
                            confidence=0.95
                        )
