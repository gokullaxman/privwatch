"""
PrivWatch 3.0 / UATU Linux Edition - PATH Hijacking & Execution Order Scanner (Red Team Mode)
Audits root and system service PATH configurations for group/other-writable directories,
relative directory references ('.'), and execution order hijacking risks.
Evaluates root/service PATHs only.
"""

import os
from pathlib import Path
import re
import stat
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata


class PathScanner(BaseScanner):
    """Audits root and service execution path configurations for PATH hijacking vulnerabilities"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__("PATH_HIJACKING", config)

    def scan(self) -> List[Finding]:
        """Execute PATH security audit strictly for root and system services."""
        # 1. Active process PATH is evaluated ONLY if running as root
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            path_var = os.getenv("PATH", "")
            if path_var:
                self._audit_path_string(path_var, "Root PATH Environment")

        # 2. Audit system-wide profile and environment files
        system_configs = [
            "/etc/environment",
            "/etc/profile",
            "/etc/login.defs",
            "/etc/security/pam_env.conf",
            "/etc/systemd/system.conf"
        ]
        for sc in system_configs:
            if os.path.exists(sc) and os.access(sc, os.R_OK):
                self._audit_system_profile(sc)

        # 3. Audit /etc/profile.d/*.sh scripts
        profile_d = "/etc/profile.d"
        if os.path.exists(profile_d) and os.path.isdir(profile_d):
            try:
                for fname in os.listdir(profile_d):
                    if fname.endswith(".sh"):
                        fpath = os.path.join(profile_d, fname)
                        if os.access(fpath, os.R_OK):
                            self._audit_system_profile(fpath)
            except Exception:
                pass

        # 4. Audit sudoers secure_path if readable
        sudoers_files = ["/etc/sudoers"]
        sudoers_d = "/etc/sudoers.d"
        if os.path.exists(sudoers_d) and os.path.isdir(sudoers_d):
            try:
                for fname in os.listdir(sudoers_d):
                    sudoers_files.append(os.path.join(sudoers_d, fname))
            except Exception:
                pass

        for sf in sudoers_files:
            if os.path.exists(sf) and os.access(sf, os.R_OK):
                self._audit_sudoers_secure_path(sf)

        return self.findings

    def _audit_path_string(self, path_str: str, source_name: str):
        """Analyze individual directory entries in root/service PATH string."""
        entries = path_str.split(":")
        seen_entries = set()

        for idx, entry in enumerate(entries):
            entry_clean = entry.strip()

            # Check for relative path or current directory in PATH ('.' or empty entry)
            if entry_clean in ("", ".") or (not entry_clean.startswith("/") and not (len(entry_clean) > 1 and entry_clean[1] == ":")):
                self.add_finding(
                    severity=Severity.HIGH.value,
                    title="Relative Directory ('.') in PATH",
                    description=f"{source_name} contains relative entry '{entry}' at position {idx}.",
                    affected_resource="PATH",
                    evidence={'source': source_name, 'raw_path': path_str, 'position': idx, 'entry': entry},
                    detection_method="path_order_analysis",
                    risk_explanation="Commands executed in a directory containing an attacker-placed binary of the same name will execute the malicious binary instead of the system binary.",
                    remediation="Remove '.' and relative components from system PATH.",
                    confidence=1.0,
                    rule_id="RULE_PATH_RELATIVE_DIR",
                    attack_preconditions="Root or service resolves commands with relative directory present in search PATH",
                    validation_procedure=f"Inspect system PATH configuration: echo '{path_str}'"
                )
                continue

            norm_entry = os.path.normpath(entry_clean)

            # Deduplicate entries within the same evaluation
            if norm_entry in seen_entries:
                continue
            seen_entries.add(norm_entry)

            # Skip virtual / kernel pseudo-filesystems
            if any(norm_entry.startswith(v) for v in ("/proc", "/sys", "/dev", "/run")):
                continue

            # Must exist and be a directory (root-reachable)
            if not os.path.exists(norm_entry) or not os.path.isdir(norm_entry):
                continue

            # Require group-writable (with non-root GID) OR other-writable
            try:
                st = os.stat(norm_entry)
                mode = st.st_mode
                gid = st.st_gid
                is_group_or_other_writable = bool(mode & stat.S_IWOTH) or bool((mode & stat.S_IWGRP) and gid != 0)
            except Exception:
                continue

            if not is_group_or_other_writable:
                continue

            # If a writable directory appears before standard system paths, it's CRITICAL
            is_prioritized = any(
                std_dir in entries[idx + 1:]
                for std_dir in ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
            )

            sev = Severity.CRITICAL.value if is_prioritized else Severity.HIGH.value

            self.add_finding(
                severity=sev,
                title=f"Writable Directory in PATH: {norm_entry}",
                description=f"Directory '{norm_entry}' in {source_name} is group/other-writable by non-root users. "
                            f"{'It precedes standard system binary directories.' if is_prioritized else ''}",
                affected_resource=norm_entry,
                evidence={
                    'path_entry': norm_entry,
                    'position': idx,
                    'precedes_system_dirs': is_prioritized,
                    'stat': get_file_stat_metadata(norm_entry)
                },
                detection_method="path_write_permission_audit",
                risk_explanation="An attacker can place a malicious trojan binary in this writable directory, which will be executed by root/services when resolving commands.",
                remediation=f"Remove write permissions from non-root users: chmod 755 {norm_entry} or remove entry from PATH.",
                confidence=1.0,
                rule_id="RULE_PATH_WRITABLE_DIR",
                attack_preconditions="Attacker has write access to directory traversed by root prior to standard system binary locations",
                validation_procedure=f"ls -ld {norm_entry}"
            )

    def _audit_system_profile(self, config_path: str):
        """Parse configuration files for PATH assignments."""
        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    # Match PATH=..., export PATH=..., ENV_SUPATH PATH=..., etc.
                    m = re.search(r'(?:PATH|ENV_SUPATH|ENV_PATH|DefaultEnvironment)\s*=\s*"?([^"\n]+)"?', line)
                    if m:
                        val = m.group(1).strip()
                        # If prefixed with PATH= inside DefaultEnvironment
                        if "PATH=" in val:
                            val = val.split("PATH=", 1)[1].split()[0]
                        self._audit_path_string(val, f"Configuration {config_path}")
        except Exception:
            pass

    def _audit_sudoers_secure_path(self, sudoers_path: str):
        """Extract Defaults secure_path from sudoers file."""
        try:
            with open(sudoers_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    m = re.search(r'secure_path\s*=\s*"([^"]+)"', line)
                    if m:
                        self._audit_path_string(m.group(1).strip(), f"Sudoers secure_path ({sudoers_path})")
        except Exception:
            pass
