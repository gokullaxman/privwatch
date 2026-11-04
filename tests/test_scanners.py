"""
PrivWatch 3.0 - Unit Tests for Red Team Assessment Scanners
"""

import os
from pathlib import Path
import pytest

from core.models import Severity, Finding
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


def test_cron_scanner_trailing_backslash_no_escaped_character(temp_dir):
    """Verify that CronScanner does not crash with ValueError: No escaped character on trailing backslash."""
    scanner = CronScanner()

    script_file = temp_dir / "service_script.sh"
    script_file.write_text("#!/bin/sh\necho service")

    # Service with trailing backslash (continuation line syntax that triggers 'No escaped character')
    service_file = temp_dir / "vuln.service"
    service_file.write_text(f"[Service]\nExecStart={script_file.as_posix()} \\\n")

    # Should not raise ValueError: No escaped character
    scanner._check_service_file_execstart(str(service_file))
    assert len(scanner.findings) >= 1
    assert "Writable Root Systemd Service Script" in scanner.findings[0].title


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


def test_scanner_findings_stored_as_static_scan_events(temp_dir):
    """Verify that findings are stored as events in the evidence store with data_origin=STATIC_SCAN."""
    from core.orchestrator import PrivWatchOrchestrator
    from core.config import PrivWatchConfig
    from core.event_schema import DataOrigin

    db_path = str(temp_dir / "scan_store_test.db")
    cfg = PrivWatchConfig(db_path=db_path)
    orch = PrivWatchOrchestrator(cfg)

    # Add a mock finding and verify persistence as STATIC_SCAN event
    fnd = Finding(
        vector="SUID/SGID",
        severity=Severity.HIGH.value,
        title="Test Writable SUID",
        description="Testing SUID finding",
        affected_resource="/usr/bin/vuln",
        evidence={'owner': '0:0', 'mode': '-rwsr-xr-x', 'path': '/usr/bin/vuln'}
    )
    orch.findings = [fnd]
    orch.storage.save_findings([fnd])

    # Convert to event as done in orchestrator
    from core.event_schema import UatuEvent, ProvenanceClass, CollectionStatus
    orch.storage.save_events([
        UatuEvent(
            event_id=f"evt_scan_{fnd.finding_id}",
            timestamp=fnd.timestamp,
            source="scanner:SUID/SGID",
            event_type="SCAN_FINDING_SUID",
            severity=fnd.severity,
            command=fnd.title,
            exe=fnd.affected_resource,
            evidence=fnd.evidence,
            evidence_ref=fnd.finding_id,
            provenance_class=ProvenanceClass.DERIVED,
            data_origin=DataOrigin.STATIC_SCAN,
            confidence=fnd.confidence,
            collection_status=CollectionStatus.SUCCESS
        )
    ])

    events = orch.storage.get_uatu_events(data_origin=DataOrigin.STATIC_SCAN.value)
    assert len(events) == 1
    assert events[0].data_origin == DataOrigin.STATIC_SCAN
    assert events[0].evidence["owner"] == "0:0"
    assert events[0].evidence["mode"] == "-rwsr-xr-x"


def test_path_scanner_evaluates_root_paths_and_group_other_writable_only(monkeypatch, temp_dir):
    """Verify PathScanner evaluates root/service paths only and requires group/other-writable AND root-reachable."""
    scanner = PathScanner()

    safe_dir = temp_dir / "safe_bin"
    safe_dir.mkdir(parents=True, exist_ok=True)

    # Mock POSIX stat so safe_dir has 0755 root:root permissions
    import stat as stat_mod
    orig_stat = os.stat
    def mock_stat(path, *args, **kwargs):
        res = orig_stat(path, *args, **kwargs)
        if "safe_bin" in str(path):
            return os.stat_result((stat_mod.S_IFDIR | 0o755, res.st_ino, res.st_dev, res.st_nlink, 0, 0, res.st_size, res.st_atime, res.st_mtime, res.st_ctime))
        return res
    monkeypatch.setattr(os, "stat", mock_stat)

    # Safe directory in root path should NOT trigger a writable finding
    scanner._audit_path_string(f"{safe_dir.as_posix()}:/usr/bin:/bin", "Root PATH")
    assert not any("Writable Directory in PATH" in f.title for f in scanner.findings)

    # When running as non-root (euid != 0), scanner.scan() should not audit user environment PATH
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setenv("PATH", f"{safe_dir.as_posix()}:/some/user/bin")
    findings = scanner.scan()
    assert not any("Root PATH Environment" in f.evidence.get("source", "") for f in findings)



