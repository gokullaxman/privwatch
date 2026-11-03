"""
PrivWatch 3.0 - Unit Tests for Red Team Assessment Scanners
"""

import os
from pathlib import Path
import pytest

from core.models import Severity
from core.config import PrivWatchConfig
from modules.red_mode.suid_scanner import SuidScanner
from modules.red_mode.sudo_scanner import SudoScanner
from modules.red_mode.capabilities_scanner import CapabilitiesScanner, DANGEROUS_CAP_DEFINITIONS
from modules.red_mode.cron_scanner import CronScanner
from modules.red_mode.passwd_scanner import PasswdScanner
from modules.red_mode.kernel_scanner import KernelScanner, KERNEL_ADVISORIES
from modules.red_mode.path_scanner import PathScanner


def test_sudo_scanner_nopasswd_all_detection():
    scanner = SudoScanner()
    # Mock sudo -l output
    mock_output = """
    User operator may run the following commands on host01:
        (root) NOPASSWD: ALL
    """
    scanner._analyze_sudo_l_output(mock_output)
    assert len(scanner.findings) >= 1
    crit_finding = [f for f in scanner.findings if f.severity == Severity.CRITICAL.value][0]
    assert "NOPASSWD" in crit_finding.title
    assert crit_finding.confidence == 1.0


def test_sudo_scanner_dangerous_command_detection():
    scanner = SudoScanner()
    mock_output = """
    Matching Defaults entries for testuser:
        env_reset, mail_badpass
    User testuser may run the following commands on localhost:
        (ALL : ALL) NOPASSWD: /usr/bin/vim, /usr/bin/less
    """
    scanner._analyze_sudo_l_output(mock_output)
    titles = [f.title for f in scanner.findings]
    assert any("vim" in t.lower() for t in titles)


def test_cron_scanner_writable_script_detection(temp_dir):
    scanner = CronScanner()

    # Create dummy writable script
    script_file = temp_dir / "backup.sh"
    script_file.write_text("#!/bin/sh\necho backup")
    # In temporary directory, script is writable by current user

    # Create dummy crontab referencing this script
    crontab_file = temp_dir / "crontab"
    crontab_file.write_text(f"* * * * * root {script_file.as_posix()}\n")

    # Run check
    scanner._parse_and_check_referenced_scripts(str(crontab_file))
    assert len(scanner.findings) >= 1
    fnd = scanner.findings[0]
    assert "Writable Script" in fnd.title
    assert fnd.severity == Severity.CRITICAL.value


def test_passwd_scanner_rogue_uid0_and_empty_password(temp_dir):
    scanner = PasswdScanner()

    # Construct test passwd file with a rogue UID 0 account and an empty password user
    fake_passwd = temp_dir / "passwd"
    fake_passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "backdoor:x:0:0:backdoor:/root:/bin/bash\n"
        "nopass::1001:1001:nopass:/home/nopass:/bin/sh\n"
        "normal:x:1002:1002:normal:/home/normal:/bin/bash\n"
    )

    scanner._audit_passwd_file(str(fake_passwd))

    findings = scanner.findings
    assert len(findings) == 2

    titles = [f.title for f in findings]
    assert any("Non-Root Account with UID 0: backdoor" in t for t in titles)
    assert any("Empty Password Field in /etc/passwd: nopass" in t for t in titles)


def test_kernel_scanner_version_boundary_logic():
    scanner = KernelScanner()

    # Test version parsing
    p1 = scanner._parse_kernel_version("5.15.0-89-generic")
    assert p1 == (5, 15, 0)

    p2 = scanner._parse_kernel_version("4.4.1")
    assert p2 == (4, 4, 1)

    # Test advisory boundary: Dirty COW (CVE-2016-5195)
    advisory_cow = [a for a in KERNEL_ADVISORIES if a['cve'] == 'CVE-2016-5195'][0]
    # 4.4.0 should fall within affected range
    assert advisory_cow['min_affected'] <= (4, 4, 0) <= advisory_cow['max_affected']
    # 5.15.0 should NOT fall within affected range
    assert (5, 15, 0) > advisory_cow['max_affected']


def test_path_scanner_relative_entry_detection():
    scanner = PathScanner()
    # Test PATH containing relative '.'
    scanner._audit_path_string("/usr/local/bin:.:/usr/bin:/bin", "Mock PATH")
    assert len(scanner.findings) >= 1
    assert any("Relative Directory" in f.title for f in scanner.findings)


def test_capabilities_scanner_definitions():
    # Verify critical capability definitions exist
    assert 'cap_setuid' in DANGEROUS_CAP_DEFINITIONS
    assert DANGEROUS_CAP_DEFINITIONS['cap_setuid']['severity'] == Severity.CRITICAL.value
    assert 'cap_sys_admin' in DANGEROUS_CAP_DEFINITIONS

