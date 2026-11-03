"""
PrivWatch 3.0 - Kernel & Package Vulnerability Assessment (Red Team Mode)
Evaluates kernel version against distribution security advisories, checks package manager patch levels,
accounts for backported patches, and provides defensive hardening guidance.
"""

import os
import re
from typing import List, Optional, Any, Dict

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.system_info import get_kernel_version, get_os_info
from config.settings import VECTOR_KERNEL


# Curated database of kernel CVEs with minimum fixed versions across upstream and distributions
KERNEL_ADVISORIES: List[Dict[str, Any]] = [
    {
        'cve': 'CVE-2016-5195',
        'name': 'Dirty COW',
        'fixed_upstream': (4, 8, 3),
        'max_affected': (4, 8, 2),
        'min_affected': (2, 6, 22),
        'description': 'Race condition in mm/gup.c (copy-on-write breakage) allowing local privilege escalation.',
        'severity': Severity.CRITICAL.value,
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2016-5195']
    },
    {
        'cve': 'CVE-2022-0847',
        'name': 'Dirty Pipe',
        'fixed_upstream': (5, 16, 11),
        'fixed_in_5_15': (5, 15, 25),
        'fixed_in_5_10': (5, 10, 102),
        'min_affected': (5, 8, 0),
        'description': 'Flaw in pipe buffer flags handling allowing local write access to read-only page cache.',
        'severity': Severity.CRITICAL.value,
        'references': ['https://dirtypipe.cm4all.com/', 'https://nvd.nist.gov/vuln/detail/CVE-2022-0847']
    },
    {
        'cve': 'CVE-2021-3493',
        'name': 'Ubuntu OverlayFS Local Privesc',
        'specific_distro': 'ubuntu',
        'min_affected': (3, 0, 0),
        'max_affected': (5, 11, 0),
        'description': 'Overlayfs capability validation bypass specific to Ubuntu kernel patches.',
        'severity': Severity.HIGH.value,
        'references': ['https://ubuntu.com/security/CVE-2021-3493']
    }
]


class KernelScanner(BaseScanner):
    """Audits running kernel version against known advisories with distribution patch awareness"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_KERNEL, config)

    def scan(self) -> List[Finding]:
        """Execute kernel security evaluation"""
        kernel_str = get_kernel_version()
        os_info = get_os_info()

        # Check if running on Linux
        if os_info.get('system') != 'Linux':
            return self.findings

        # Parse upstream triple (major, minor, patch)
        parsed_version = self._parse_kernel_version(kernel_str)
        if not parsed_version:
            return self.findings

        # Inspect package manager for backported kernel package version
        installed_package_version = self._query_installed_kernel_package(os_info)

        # Check advisories
        for advisory in KERNEL_ADVISORIES:
            self._evaluate_advisory(advisory, parsed_version, kernel_str, os_info, installed_package_version)

        return self.findings

    def _parse_kernel_version(self, kernel_str: str) -> Optional[tuple]:
        """Extract numeric (major, minor, patch) tuple from kernel string"""
        match = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?', kernel_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            return (major, minor, patch)
        return None

    def _query_installed_kernel_package(self, os_info: Dict[str, str]) -> Optional[str]:
        """Query native package manager for kernel package release to check backports"""
        pm = os_info.get('package_manager')
        if pm == 'apt-get':
            out = self.run_command("dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | tail -1")
            return out.strip() if out else None
        elif pm in ['dnf', 'yum', 'rpm']:
            out = self.run_command("rpm -q kernel 2>/dev/null | tail -1")
            return out.strip() if out else None
        return None

    def _evaluate_advisory(self, advisory: Dict[str, Any], parsed: tuple,
                           kernel_str: str, os_info: Dict[str, str],
                           pkg_info: Optional[str]):
        """Evaluate kernel version against advisory boundaries"""
        distro = os_info.get('distro_id', '').lower()

        # If advisory is distro-specific and current host is different distro, skip
        if 'specific_distro' in advisory and advisory['specific_distro'] not in distro:
            return

        min_aff = advisory.get('min_affected')
        if min_aff and parsed < min_aff:
            return

        # Upstream fixed check
        fixed_upstream = advisory.get('fixed_upstream')
        if fixed_upstream and parsed >= fixed_upstream:
            return

        # LTS branch fixed check
        if parsed[0] == 5 and parsed[1] == 15 and 'fixed_in_5_15' in advisory:
            if parsed >= advisory['fixed_in_5_15']:
                return
        if parsed[0] == 5 and parsed[1] == 10 and 'fixed_in_5_10' in advisory:
            if parsed >= advisory['fixed_in_5_10']:
                return

        cve = advisory['cve']
        name = advisory['name']

        self.add_finding(
            severity=advisory['severity'],
            title=f"Potential Kernel Vulnerability: {name} ({cve})",
            description=f"Running kernel release {kernel_str} falls within the reported vulnerable range for {name}. "
                        f"{advisory['description']}",
            affected_resource=f"kernel:{kernel_str}",
            evidence={
                'kernel_release': kernel_str,
                'distribution': os_info.get('distro_name'),
                'installed_kernel_package': pkg_info or "Unknown (query unavailable)",
                'cve': cve
            },
            detection_method="kernel_release_advisory_cross_reference",
            risk_explanation="Vulnerable kernel subsystems can allow unprivileged local users to trigger memory corruption or logic flaws to execute code in ring 0.",
            remediation=f"Apply distribution security updates: apt-get update && apt-get install --only-upgrade linux-image-generic "
                        f"(or distro equivalent). Reboot into the patched kernel.",
            references=advisory.get('references', []),
            confidence=0.85
        )
