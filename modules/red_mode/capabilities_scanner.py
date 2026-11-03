"""
PrivWatch 3.0 - Linux Capabilities Scanner (Red Team Mode)
Enumerates file capabilities on system binaries, evaluates dangerous privilege escalation capabilities,
and explains technical risk factors without executing exploits.
"""

import os
from pathlib import Path
import re
from typing import List, Optional, Any, Dict

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata
from config.settings import VECTOR_CAPABILITIES, STANDARD_BIN_DIRS


# Dangerous capabilities and their privilege escalation mechanisms
DANGEROUS_CAP_DEFINITIONS: Dict[str, Dict[str, str]] = {
    'cap_setuid': {
        'severity': Severity.CRITICAL.value,
        'title': 'CAP_SETUID Capability',
        'risk': 'Allows setting arbitrary user IDs, enabling immediate elevation to root (UID 0).',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_setgid': {
        'severity': Severity.HIGH.value,
        'title': 'CAP_SETGID Capability',
        'risk': 'Allows changing group IDs, enabling access to privileged groups such as shadow, disk, or sudo.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_dac_override': {
        'severity': Severity.CRITICAL.value,
        'title': 'CAP_DAC_OVERRIDE Capability',
        'risk': 'Bypasses file read, write, and execute permission checks, allowing arbitrary modification of system files.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_dac_read_search': {
        'severity': Severity.HIGH.value,
        'title': 'CAP_DAC_READ_SEARCH Capability',
        'risk': 'Bypasses file read and directory search permission checks, enabling read access to /etc/shadow and private keys.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_sys_admin': {
        'severity': Severity.CRITICAL.value,
        'title': 'CAP_SYS_ADMIN Capability',
        'risk': 'Provides vast administrative operations equivalent to root (mounting filesystems, cgroups, namespace control).',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_sys_ptrace': {
        'severity': Severity.HIGH.value,
        'title': 'CAP_SYS_PTRACE Capability',
        'risk': 'Allows tracing arbitrary processes via ptrace, facilitating shellcode injection into privileged processes.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_sys_module': {
        'severity': Severity.CRITICAL.value,
        'title': 'CAP_SYS_MODULE Capability',
        'risk': 'Allows loading and unloading kernel modules, yielding arbitrary ring-0 kernel code execution.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_chown': {
        'severity': Severity.HIGH.value,
        'title': 'CAP_CHOWN Capability',
        'risk': 'Allows changing ownership of arbitrary files, allowing taking ownership of /etc/passwd or /etc/shadow.',
        'remediation': 'Remove capability: setcap -r <binary>'
    },
    'cap_fowner': {
        'severity': Severity.HIGH.value,
        'title': 'CAP_FOWNER Capability',
        'risk': 'Bypasses permission checks on file modifications and ACL adjustments.',
        'remediation': 'Remove capability: setcap -r <binary>'
    }
}


class CapabilitiesScanner(BaseScanner):
    """Audits system binaries for dangerous POSIX capabilities"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_CAPABILITIES, config)
        self.target_dirs = getattr(config, 'target_bin_dirs', STANDARD_BIN_DIRS) if config else STANDARD_BIN_DIRS

    def scan(self) -> List[Finding]:
        """Execute targeted capability audit"""
        # Check if getcap binary exists
        getcap_bin = None
        for path in ['/usr/sbin/getcap', '/sbin/getcap', '/usr/bin/getcap', '/bin/getcap']:
            if os.path.exists(path) and os.access(path, os.X_OK):
                getcap_bin = path
                break

        if not getcap_bin:
            # getcap not installed; return empty list (not a false vulnerability)
            return self.findings

        # Audit target binary directories individually to avoid hanging on entire filesystem
        for directory in self.target_dirs:
            if not os.path.exists(directory) or not os.path.isdir(directory):
                continue

            output = self.run_command([getcap_bin, "-r", directory], timeout=15)
            if not output or "[ERROR]" in output:
                continue

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                self._analyze_capability_line(line)

        return self.findings

    def _analyze_capability_line(self, line: str):
        """Parse getcap output line: /path/to/binary cap_name+ep"""
        parts = line.split()
        if len(parts) < 2:
            return

        binary_path = parts[0]
        cap_string = " ".join(parts[1:]).lower()

        if not os.path.exists(binary_path):
            return

        meta = get_file_stat_metadata(binary_path)

        for cap_name, cap_info in DANGEROUS_CAP_DEFINITIONS.items():
            if cap_name in cap_string:
                self.add_finding(
                    severity=cap_info['severity'],
                    title=f"Dangerous Capability on {os.path.basename(binary_path)}: {cap_name}",
                    description=f"Binary {binary_path} has capability {cap_string}. {cap_info['risk']}",
                    affected_resource=binary_path,
                    evidence={
                        'path': binary_path,
                        'capabilities': cap_string,
                        'stat': meta
                    },
                    detection_method="getcap_targeted_inspection",
                    risk_explanation=cap_info['risk'],
                    remediation=cap_info['remediation'].replace("<binary>", binary_path),
                    references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
                    confidence=0.95
                )
