"""
PrivWatch 3.0 - PATH Hijacking & Execution Order Scanner (Red Team Mode)
Audits the PATH environment variable and system profile files for writable directories,
relative directory references ('.'), and execution order hijacking risks.
"""

import os
from pathlib import Path
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata


class PathScanner(BaseScanner):
    """Audits execution path configurations for PATH hijacking vulnerabilities"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__("PATH_HIJACKING", config)

    def scan(self) -> List[Finding]:
        """Execute PATH security audit"""
        path_var = os.getenv("PATH", "")
        if path_var:
            self._audit_path_string(path_var, "User PATH Environment")

        # Audit system-wide PATH configurations
        system_configs = ["/etc/environment", "/etc/profile"]
        for sc in system_configs:
            if os.path.exists(sc) and os.access(sc, os.R_OK):
                self._audit_system_profile(sc)

        return self.findings

    def _audit_path_string(self, path_str: str, source_name: str):
        """Analyze individual directory entries in PATH string"""
        # Split PATH by colon
        entries = path_str.split(":")

        for idx, entry in enumerate(entries):
            # Check for relative path or current directory in PATH ('.' or empty entry)
            if entry == "" or entry == ".":
                self.add_finding(
                    severity=Severity.HIGH.value,
                    title="Relative Directory ('.') in PATH",
                    description=f"{source_name} contains relative entry '{entry}' at position {idx}.",
                    affected_resource="PATH",
                    evidence={'source': source_name, 'raw_path': path_str, 'position': idx},
                    detection_method="path_order_analysis",
                    risk_explanation="Commands executed in a directory containing an attacker-placed binary of the same name will execute the malicious binary instead of the system binary.",
                    remediation="Remove '.' and empty components from PATH in ~/.bashrc, /etc/environment, or profile scripts.",
                    confidence=1.0
                )
                continue

            # Check if directory exists
            if not os.path.exists(entry) or not os.path.isdir(entry):
                continue

            # Check if directory is writable by unprivileged user
            if os.access(entry, os.W_OK) and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
                # If a writable directory appears before /usr/bin or /bin, it's CRITICAL
                is_prioritized = any(
                    std_dir in entries[idx + 1:]
                    for std_dir in ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
                )

                sev = Severity.CRITICAL.value if is_prioritized else Severity.HIGH.value

                self.add_finding(
                    severity=sev,
                    title=f"Writable Directory in PATH: {entry}",
                    description=f"Directory '{entry}' in {source_name} is writable by the current user. "
                                f"{'It precedes standard system binary directories.' if is_prioritized else ''}",
                    affected_resource=entry,
                    evidence={
                        'path_entry': entry,
                        'position': idx,
                        'precedes_system_dirs': is_prioritized,
                        'stat': get_file_stat_metadata(entry)
                    },
                    detection_method="path_write_permission_audit",
                    risk_explanation="An attacker can place a malicious trojan binary (e.g. 'ls', 'sudo', 'cat') in this writable directory, which will be executed by other users when typing standard commands.",
                    remediation=f"Remove write permissions from non-root users: chmod 755 {entry} or remove entry from PATH.",
                    confidence=1.0
                )

    def _audit_system_profile(self, config_path: str):
        """Parse configuration files for PATH assignments"""
        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PATH="):
                        val = line.split("PATH=", 1)[1].strip('"\'')
                        self._audit_path_string(val, f"Configuration {config_path}")
        except Exception:
            pass
