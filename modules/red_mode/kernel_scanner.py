"""
PrivWatch 3.0 - Kernel & Package Vulnerability Assessment (Red Team Mode)
Distribution-aware Linux kernel vulnerability analysis.
Evaluates installed package versions against vendor security advisories (USN, DSA, RHSA),
accounts for backported patches, and uses rigorous assessment states.
"""

from enum import Enum
import os
import re
import shutil
from typing import List, Optional, Any, Dict, Tuple

from core.scanner import BaseScanner, Finding
from core.models import Severity
from core.command_exec import LinuxCommandRunner
from utils.system_info import get_kernel_version, get_os_info
from config.settings import VECTOR_KERNEL


class KernelAssessmentState(str, Enum):
    """Explicit assessment classification states for kernel vulnerabilities."""
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    PATCHED = "PATCHED"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"
    UNVERIFIED = "UNVERIFIED"


# Curated vendor and upstream advisories database with backport awareness
DISTRO_KERNEL_ADVISORIES: List[Dict[str, Any]] = [
    {
        'cve': 'CVE-2016-5195',
        'name': 'Dirty COW',
        'min_upstream': (2, 6, 22),
        'fixed_upstream': (4, 8, 3),
        'min_affected': (2, 6, 22),
        'max_affected': (4, 8, 2),
        'description': 'Race condition in mm/gup.c (copy-on-write breakage) allowing local privilege escalation.',
        'severity': Severity.CRITICAL.value,
        'vendor_fixes': {
            'ubuntu': {
                '16.04': '4.4.0-45.66',
                '14.04': '3.13.0-100.147'
            },
            'debian': {
                '8': '3.16.36-1+deb8u2',
                '9': '4.9.0-3'
            },
            'rhel': {
                '7': '3.10.0-514.el7',
                '6': '2.6.32-642.6.2.el6'
            }
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2016-5195', 'https://dirtycow.ninja/']
    },
    {
        'cve': 'CVE-2022-0847',
        'name': 'Dirty Pipe',
        'min_upstream': (5, 8, 0),
        'fixed_upstream': (5, 16, 11),
        'description': 'Flaw in pipe buffer flags handling allowing local write access to read-only page cache.',
        'severity': Severity.CRITICAL.value,
        'vendor_fixes': {
            'ubuntu': {
                '22.04': '5.15.0-25.25',
                '20.04': '5.4.0-107.121'
            },
            'debian': {
                '11': '5.10.103-1',
                '12': '6.1.0-0'
            },
            'fedora': {
                '35': '5.16.11-200.fc35',
                '36': '5.16.11-200.fc36'
            }
        },
        'references': ['https://dirtypipe.cm4all.com/', 'https://nvd.nist.gov/vuln/detail/CVE-2022-0847']
    },
    {
        'cve': 'CVE-2021-3493',
        'name': 'Ubuntu OverlayFS Local Privesc',
        'min_upstream': (3, 0, 0),
        'fixed_upstream': (5, 12, 0),
        'description': 'Overlayfs capability validation bypass specific to Ubuntu kernel patches.',
        'severity': Severity.HIGH.value,
        'specific_distro': 'ubuntu',
        'vendor_fixes': {
            'ubuntu': {
                '20.04': '5.4.0-72.80',
                '18.04': '4.15.0-142.146',
                '16.04': '4.4.0-208.241'
            }
        },
        'references': ['https://ubuntu.com/security/CVE-2021-3493', 'https://www.exploit-db.com/exploits/50036']
    }
]

KERNEL_ADVISORIES = DISTRO_KERNEL_ADVISORIES


class KernelScanner(BaseScanner):
    """Audits Linux kernel version against known advisories with distribution patch verification."""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_KERNEL, config)

    def scan(self) -> List[Finding]:
        """Execute distribution-aware kernel security evaluation."""
        kernel_str = get_kernel_version()
        os_info = get_os_info()

        if os_info.get('system') != 'Linux':
            return self.findings

        parsed_version = self._parse_kernel_version(kernel_str)
        if not parsed_version:
            return self.findings

        # Query native package manager for installed kernel package version
        installed_pkg, installed_version = self._query_installed_kernel_package(kernel_str, os_info)

        # Evaluate each advisory
        for advisory in DISTRO_KERNEL_ADVISORIES:
            self._evaluate_advisory(
                advisory=advisory,
                parsed_upstream=parsed_version,
                kernel_str=kernel_str,
                os_info=os_info,
                installed_pkg=installed_pkg,
                installed_version=installed_version
            )

        return self.findings

    def _parse_kernel_version(self, kernel_str: str) -> Optional[Tuple[int, int, int]]:
        """Extract numeric (major, minor, patch) tuple from kernel string."""
        match = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?', kernel_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            return (major, minor, patch)
        return None

    def _query_installed_kernel_package(self, kernel_str: str, os_info: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        """Query native package manager for the running kernel's exact package release."""
        pm = os_info.get('package_manager')

        # 1. Debian / Ubuntu / Kali / Mint via dpkg-query
        if pm == 'apt-get' or shutil.which('dpkg-query'):
            pkg_name = f"linux-image-{kernel_str}"
            res = LinuxCommandRunner.execute(["dpkg-query", "-W", "-f=${Package} ${Version}", pkg_name], timeout=5)
            if res.success and res.stdout_clean():
                parts = res.stdout_clean().split()
                if len(parts) >= 2:
                    return (parts[0], parts[1])

        # 2. RHEL / CentOS / Fedora via rpm
        if pm in ['dnf', 'yum', 'rpm'] or shutil.which('rpm'):
            res = LinuxCommandRunner.execute(["rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}", "kernel"], timeout=5)
            if res.success and res.stdout_clean():
                lines = res.stdout_clean().splitlines()
                if lines:
                    parts = lines[-1].split()
                    if len(parts) >= 2:
                        return (parts[0], parts[1])

        # 3. Arch Linux via pacman
        if pm == 'pacman' or shutil.which('pacman'):
            res = LinuxCommandRunner.execute(["pacman", "-Q", "linux"], timeout=5)
            if res.success and res.stdout_clean():
                parts = res.stdout_clean().split()
                if len(parts) >= 2:
                    return (parts[0], parts[1])

        return (None, None)

    def _compare_debian_versions(self, ver1: str, ver2: str) -> int:
        """
        Compare two Debian version strings.
        Returns:
            1 if ver1 > ver2
            0 if ver1 == ver2
           -1 if ver1 < ver2
        """
        # Try native dpkg if installed
        if shutil.which("dpkg"):
            res_gt = LinuxCommandRunner.execute(["dpkg", "--compare-versions", ver1, "gt", ver2], timeout=3)
            if res_gt.return_code == 0:
                return 1
            res_eq = LinuxCommandRunner.execute(["dpkg", "--compare-versions", ver1, "eq", ver2], timeout=3)
            if res_eq.return_code == 0:
                return 0
            return -1

        # Fallback numeric/segment comparator
        def parse_tokens(s):
            return [int(x) if x.isdigit() else x for x in re.split(r'([0-9]+)', s) if x]

        t1 = parse_tokens(ver1)
        t2 = parse_tokens(ver2)
        if t1 > t2:
            return 1
        elif t1 < t2:
            return -1
        return 0

    def _evaluate_advisory(self, advisory: Dict[str, Any], parsed_upstream: Tuple[int, int, int],
                           kernel_str: str, os_info: Dict[str, str],
                           installed_pkg: Optional[str], installed_version: Optional[str]):
        """Evaluate kernel version against advisory boundaries with distribution backport checks."""
        distro_id = os_info.get('distro_id', '').lower()
        distro_ver = os_info.get('distro_version', '')
        cve = advisory['cve']
        name = advisory['name']

        # If advisory is distro-specific (e.g. Ubuntu overlayfs)
        if 'specific_distro' in advisory and advisory['specific_distro'] not in distro_id:
            return

        min_upstream = advisory.get('min_upstream')
        fixed_upstream = advisory.get('fixed_upstream')

        # Check upstream lower and upper bounds
        if min_upstream and parsed_upstream < min_upstream:
            return
        if fixed_upstream and parsed_upstream >= fixed_upstream:
            return

        # Upstream falls within vulnerable range. Now inspect vendor backports:
        assessment_state = KernelAssessmentState.POTENTIALLY_VULNERABLE
        vendor_fixes = advisory.get('vendor_fixes', {}).get(distro_id, {})

        # Find vendor fixed package version for this distribution release
        fixed_pkg_ver = None
        for v_key, v_fix in vendor_fixes.items():
            if distro_ver.startswith(v_key) or v_key in distro_ver:
                fixed_pkg_ver = v_fix
                break

        if fixed_pkg_ver and installed_version:
            # We have both the installed package version and vendor fixed package version
            cmp_result = self._compare_debian_versions(installed_version, fixed_pkg_ver)
            if cmp_result >= 0:
                # Distribution has patched the vulnerability
                assessment_state = KernelAssessmentState.PATCHED
            else:
                assessment_state = KernelAssessmentState.CONFIRMED_VULNERABLE
        elif fixed_pkg_ver and not installed_version:
            assessment_state = KernelAssessmentState.POTENTIALLY_VULNERABLE
        else:
            assessment_state = KernelAssessmentState.POTENTIALLY_VULNERABLE

        # Only register security findings if vulnerability is active or potential
        if assessment_state in [KernelAssessmentState.CONFIRMED_VULNERABLE, KernelAssessmentState.POTENTIALLY_VULNERABLE]:
            confidence = 1.0 if assessment_state == KernelAssessmentState.CONFIRMED_VULNERABLE else 0.80

            self.add_finding(
                severity=advisory['severity'],
                title=f"Kernel Vulnerability [{assessment_state.value}]: {name} ({cve})",
                description=(
                    f"Kernel release {kernel_str} evaluated with state: {assessment_state.value}. "
                    f"{advisory['description']} (Installed package: {installed_pkg or 'unknown'} {installed_version or 'unknown'})."
                ),
                affected_resource=f"kernel:{kernel_str}",
                evidence={
                    'cve': cve,
                    'name': name,
                    'assessment_state': assessment_state.value,
                    'kernel_release': kernel_str,
                    'distribution': os_info.get('distro_name'),
                    'distro_id': distro_id,
                    'distro_version': distro_ver,
                    'installed_package': installed_pkg or "Unknown",
                    'installed_package_version': installed_version or "Unknown",
                    'vendor_fixed_version': fixed_pkg_ver or "Not specified",
                    'fixed_upstream': fixed_upstream
                },
                detection_method="distro_aware_kernel_advisory_audit",
                risk_explanation="Vulnerable kernel subsystems allow unprivileged local attackers to elevate privileges to ring-0.",
                remediation=(
                    f"Apply distribution security updates to upgrade kernel to {fixed_pkg_ver or 'latest'} or later. "
                    f"Example: apt-get update && apt-get --only-upgrade install linux-image-generic && reboot"
                ),
                references=advisory.get('references', []),
                confidence=confidence
            )
