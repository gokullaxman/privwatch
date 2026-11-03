"""
PrivWatch 3.0 - Password & Authentication File Scanner (Red Team Mode)
Audits /etc/passwd, /etc/shadow, and security files for write access, empty passwords,
rogue UID 0 accounts, and insecure backup files.
"""

import os
from pathlib import Path
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata
from core.evidence import EvidenceManager
from config.settings import VECTOR_PASSWD


class PasswdScanner(BaseScanner):
    """Audits system authentication and account configuration files"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_PASSWD, config)

    def scan(self) -> List[Finding]:
        """Execute authentication file vulnerability assessment"""
        self._audit_passwd_file("/etc/passwd")
        self._audit_shadow_file("/etc/shadow")
        self._audit_backup_files()
        return self.findings

    def _audit_passwd_file(self, path: str):
        """Audit /etc/passwd permissions and account definitions"""
        if not os.path.exists(path):
            return

        meta = get_file_stat_metadata(path)

        # Check write access by non-root
        if os.access(path, os.W_OK) and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Writable Password Database: /etc/passwd",
                description="The /etc/passwd file is writable by the current unprivileged user.",
                affected_resource=path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Direct root compromise. An attacker can append a new account with UID 0 and known password.",
                remediation="Harden permissions: chmod 644 /etc/passwd && chown root:root /etc/passwd",
                confidence=1.0
            )

        # Parse account definitions
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

                            # Rogue UID 0 accounts
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

                            # Empty password field (allows passwordless login)
                            if pw_field == "":
                                self.add_finding(
                                    severity=Severity.CRITICAL.value,
                                    title=f"Empty Password Field in /etc/passwd: {username}",
                                    description=f"User '{username}' has an empty password field in /etc/passwd.",
                                    affected_resource=f"{path}:{username}",
                                    evidence={'username': username, 'line_number': line_num},
                                    detection_method="account_password_field_audit",
                                    risk_explanation="Empty password field may permit authentication without a password over local login or SSH.",
                                    remediation=f"Set a password: passwd {username} or lock account: usermod -L {username}",
                                    confidence=1.0
                                )
            except Exception:
                pass

    def _audit_shadow_file(self, path: str):
        """Audit /etc/shadow permissions"""
        if not os.path.exists(path):
            return

        meta = get_file_stat_metadata(path)

        # Writable shadow file
        if os.access(path, os.W_OK) and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Writable Shadow Database: /etc/shadow",
                description="The /etc/shadow file is writable by unprivileged users.",
                affected_resource=path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="An attacker can overwrite the root password hash with a known hash to gain root access.",
                remediation="Harden permissions: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
                confidence=1.0
            )

        # Readable shadow file by unprivileged user
        if os.access(path, os.R_OK) and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
            self.add_finding(
                severity=Severity.HIGH.value,
                title="Readable Shadow Database: /etc/shadow",
                description="The /etc/shadow file is readable by the current unprivileged user.",
                affected_resource=path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Exposes system password hashes for offline cracking with tools like John the Ripper or Hashcat.",
                remediation="Restrict read permissions: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
                confidence=1.0
            )

    def _audit_backup_files(self):
        """Check for exposed backup files like /etc/passwd- or /etc/shadow-"""
        backup_files = [
            ("/etc/shadow-", Severity.HIGH.value),
            ("/etc/gshadow-", Severity.HIGH.value),
            ("/etc/passwd-", Severity.MEDIUM.value)
        ]

        for bfile, sev in backup_files:
            if os.path.exists(bfile):
                meta = get_file_stat_metadata(bfile)
                if "shadow" in bfile and os.access(bfile, os.R_OK) and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
                    self.add_finding(
                        severity=sev,
                        title=f"Readable Authentication Backup: {bfile}",
                        description=f"Backup file {bfile} contains sensitive password hashes and is readable by unprivileged users.",
                        affected_resource=bfile,
                        evidence=meta,
                        detection_method="backup_file_permission_audit",
                        risk_explanation="Authentication backups often contain valid password hashes.",
                        remediation=f"Restrict permissions: chmod 600 {bfile} && chown root:root {bfile}",
                        confidence=0.95
                    )
