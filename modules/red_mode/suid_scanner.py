"""
PrivWatch 3.0 - SUID/SGID Binary Scanner (Red Team Mode)
Enumerates SUID/SGID binaries across system executable paths, checks parent directories,
identifies unusual executables, and evaluates against GTFOBins knowledge base.
"""

import os
from pathlib import Path
import stat
from typing import List, Optional, Any, Dict

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.gtfobins import GTFOBins
from utils.file_utils import get_permission_string, is_parent_writable, get_file_stat_metadata, is_insecurely_writable
from config.settings import VECTOR_SUID, STANDARD_BIN_DIRS


class SuidScanner(BaseScanner):
    """Audits system binaries for dangerous SUID/SGID privilege escalation vectors"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_SUID, config)
        self.allowlist = set(getattr(config, 'suid_allowlist', [])) if config else set()
        self.target_dirs = getattr(config, 'target_bin_dirs', STANDARD_BIN_DIRS) if config else STANDARD_BIN_DIRS

    def scan(self) -> List[Finding]:
        """Execute targeted SUID/SGID enumeration"""
        discovered_binaries: List[str] = []

        # Enumerate binaries in standard system directories
        for bin_dir in self.target_dirs:
            if not os.path.exists(bin_dir) or not os.path.isdir(bin_dir):
                continue
            try:
                for entry in os.scandir(bin_dir):
                    try:
                        if entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            if (st.st_mode & stat.S_ISUID) or (st.st_mode & stat.S_ISGID):
                                discovered_binaries.append(entry.path)
                    except Exception:
                        continue
            except PermissionError:
                continue

        # De-duplicate real paths (e.g., /bin -> /usr/bin symlink de-duplication)
        seen_paths = set()
        unique_binaries = []
        for b in discovered_binaries:
            try:
                real_p = os.path.realpath(b)
                if real_p not in seen_paths:
                    seen_paths.add(real_p)
                    unique_binaries.append(b)
            except Exception:
                unique_binaries.append(b)

        for binary_path in unique_binaries:
            self._analyze_binary(binary_path)

        return self.findings

    def _analyze_binary(self, binary_path: str):
        """Analyze binary attributes, permissions, and GTFOBins risks"""
        try:
            st = os.stat(binary_path, follow_symlinks=False)
        except Exception:
            return

        binary_name = os.path.basename(binary_path)
        perms = get_permission_string(binary_path)
        meta = get_file_stat_metadata(binary_path)
        is_suid_bit = bool(st.st_mode & stat.S_ISUID)
        is_sgid_bit = bool(st.st_mode & stat.S_ISGID)
        owner_uid = st.st_uid

        gtfo = GTFOBins.lookup(binary_name)
        is_allowed = (
            binary_path in self.allowlist or
            os.path.realpath(binary_path) in self.allowlist or
            binary_name in {
                "passwd", "sudo", "newgrp", "chfn", "chsh", "gpasswd",
                "mount", "umount", "su", "pkexec", "ping", "fusermount", "fusermount3"
            } or
            binary_name.startswith("kismet_cap_")
        )

        # Case 1: Binary is world-writable or insecurely writable by unauthorized users
        if is_insecurely_writable(binary_path):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title=f"Writable SUID Binary: {binary_path}",
                description=f"The elevated binary {binary_path} ({perms}) is writable by the current user. "
                            f"An attacker can overwrite or replace this binary to execute arbitrary code with owner privileges.",
                affected_resource=binary_path,
                evidence=meta,
                detection_method="file_permission_audit",
                risk_explanation="Direct privilege escalation vector. Overwriting an SUID root binary results in instant root compromise.",
                remediation=f"Remove write permissions: chmod 755 {binary_path}",
                confidence=1.0
            )

        # Case 2: Parent directory is writable
        if meta.get('parent_writable'):
            self.add_finding(
                severity=Severity.HIGH.value,
                title=f"SUID Binary in Writable Directory: {binary_path}",
                description=f"The directory containing {binary_path} is writable. "
                            f"A local user can delete or rename this binary and substitute an arbitrary malicious executable.",
                affected_resource=binary_path,
                evidence=meta,
                detection_method="directory_permission_audit",
                risk_explanation="Directory write permissions allow renaming or unlinking elevated executables.",
                remediation=f"Harden parent directory permissions: chmod 755 {os.path.dirname(binary_path)}",
                confidence=0.95
            )

        # Case 3: Binary has known GTFOBins exploitation vector
        if gtfo and is_suid_bit and gtfo.get('suid'):
            severity = Severity.HIGH.value if is_allowed else Severity.CRITICAL.value
            self.add_finding(
                severity=severity,
                title=f"Exploitable SUID Binary: {binary_name}",
                description=f"Binary {binary_path} has SUID bit set and known privilege escalation methods: {gtfo.get('description', '')}",
                affected_resource=binary_path,
                evidence={**meta, 'gtfobins': gtfo.get('suid')},
                detection_method="gtfobins_catalog_match",
                risk_explanation=gtfo.get('suid'),
                remediation=gtfo.get('remediation', f"Remove SUID bit: chmod u-s {binary_path}"),
                references=["https://gtfobins.github.io/"],
                confidence=0.98
            )

        # Case 4: Non-standard / unexpected SUID binary not in allowlist
        elif is_suid_bit and not is_allowed and owner_uid == 0:
            self.add_finding(
                severity=Severity.MEDIUM.value,
                title=f"Non-Standard SUID Binary: {binary_name}",
                description=f"Binary {binary_path} has SUID root bit set ({perms}) and is not in the standard distribution allowlist.",
                affected_resource=binary_path,
                evidence=meta,
                detection_method="allowlist_comparison",
                risk_explanation="Unusual SUID binaries increase attack surface and should be verified for business justification.",
                remediation=f"Verify requirement for SUID bit on {binary_path}. If unneeded, run: chmod u-s {binary_path}",
                confidence=0.85
            )
