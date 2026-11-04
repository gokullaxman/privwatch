"""
PrivWatch 3.0 - Linux-Native Hardening & Security Assurance Tests
Covers Privileged Service IPC, Audit Chain Tamper-Evidence, Remediation Rollback,
and Distribution-Aware Kernel Advisory Evaluation.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import pytest
import socket
import sqlite3

from core.command_exec import LinuxCommandRunner, CommandExecutionResult
from core.platform_validator import LinuxPlatformValidator, UnsupportedPlatformError
from core.privileged_service import PrivilegedCollectorService, PrivilegedServiceClient
from core.storage import StorageEngine
from core.models import Finding, Severity
from modules.response.remediation_engine import RemediationEngine, RemediationPlan, RemediationAction
from modules.red_mode.kernel_scanner import KernelScanner, KernelAssessmentState, DISTRO_KERNEL_ADVISORIES


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'), reason="Unix domain sockets require Linux")
def test_privileged_service_ipc_lifecycle(temp_dir):
    """Verify PrivilegedCollectorService starts, validates RPC, and rejects forbidden actions."""
    sock_path = str(temp_dir / "priv_test.sock")
    service = PrivilegedCollectorService(socket_path=sock_path)
    service.start(in_background=True)

    client = PrivilegedServiceClient(socket_path=sock_path)
    assert client.is_available() is True

    # 1. PING test
    res_ping = client.send_request("PING")
    assert res_ping["success"] is True
    assert res_ping["result"] == "PONG"

    # 2. Forbidden action rejection
    res_bad = client.send_request("EXEC_ARBITRARY_SHELL")
    assert res_bad["success"] is False
    assert "forbidden" in res_bad["error"].lower()

    # 3. GET_SYSTEM_HEALTH
    res_health = client.send_request("GET_SYSTEM_HEALTH")
    assert res_health["success"] is True
    assert "system" in res_health["result"]

    service.stop()
    assert client.is_available() is False


def test_audit_chain_tamper_detection(temp_dir):
    """Verify that any modification to audit_trail rows is detected by verify_audit_chain_integrity()."""
    db_path = str(temp_dir / "tamper_test.db")
    storage = StorageEngine(db_path)

    # Insert 3 legitimate chained actions
    storage.log_admin_action("ACTION_A", "res_A", "admin", {"data": 1}, "SUCCESS")
    storage.log_admin_action("ACTION_B", "res_B", "admin", {"data": 2}, "SUCCESS")
    storage.log_admin_action("ACTION_C", "res_C", "admin", {"data": 3}, "SUCCESS")

    valid_before, _ = storage.verify_audit_chain_integrity()
    assert valid_before is True

    # Malicious direct modification of row 2
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_trail SET action = 'ACTION_TAMPERED' WHERE id = 2")
    conn.commit()
    conn.close()

    valid_after, error = storage.verify_audit_chain_integrity()
    assert valid_after is False
    assert "Tampered record" in error or "Broken link" in error


def test_remediation_rollback_on_partial_failure(temp_dir):
    """Verify that RemediationEngine rolls back executed actions if a subsequent action fails."""
    engine = RemediationEngine(read_only=False)

    # Create dummy target file
    target_file = temp_dir / "test_config.cfg"
    target_file.write_text("secure_config=1")
    os.chmod(str(target_file), 0o666)

    # Action 1: Valid chmod
    action1 = RemediationAction(
        action_id="act_1",
        action_type="CHMOD",
        target=str(target_file),
        canonical_target=str(target_file),
        expected_original_mode=0o666,
        desired_mode=0o600,
        backup_required=True
    )

    # Action 2: Targets a nonexistent path, causing an execution exception
    action2 = RemediationAction(
        action_id="act_2",
        action_type="CHMOD",
        target=str(temp_dir / "nonexistent_file_xyz.txt"),
        canonical_target=str(temp_dir / "nonexistent_file_xyz.txt"),
        expected_original_mode=0o644,
        desired_mode=0o600,
        backup_required=False
    )

    plan = RemediationPlan(
        plan_id="plan_fail_test",
        finding_id="fnd_test",
        title="Failure Rollback Test",
        target_resource=str(target_file),
        actions=[action1, action2]
    )

    with pytest.raises(RuntimeError) as exc_info:
        engine.execute_plan(plan, actor="admin", confirmed=True, dry_run=False)

    assert "aborted" in str(exc_info.value).lower()
    # Verify that action1 was rolled back to original mode 0666
    st = os.stat(str(target_file))
    assert oct(st.st_mode)[-3:] == "666"


def test_kernel_scanner_distro_advisory_matching():
    """Verify distribution-aware kernel advisory matching with package version comparison."""
    scanner = KernelScanner()

    # Find Ubuntu overlayfs advisory
    overlay_advisories = [a for a in DISTRO_KERNEL_ADVISORIES if a['cve'] == 'CVE-2021-3493']
    assert len(overlay_advisories) == 1
    adv = overlay_advisories[0]

    os_info_focal = {
        'system': 'Linux',
        'distro_id': 'ubuntu',
        'distro_name': 'Ubuntu',
        'distro_version': '20.04',
        'package_manager': 'apt-get'
    }

    # 1. Test vulnerable package: 5.4.0-70.78 < fixed 5.4.0-72.80
    scanner.findings.clear()
    scanner._evaluate_advisory(
        advisory=adv,
        parsed_upstream=(5, 4, 0),
        kernel_str="5.4.0-70-generic",
        os_info=os_info_focal,
        installed_pkg="linux-image-5.4.0-70-generic",
        installed_version="5.4.0-70.78"
    )
    assert len(scanner.findings) == 1
    assert "CONFIRMED_VULNERABLE" in scanner.findings[0].title
    assert scanner.findings[0].confidence == 1.0

    # 2. Test patched package: 5.4.0-74.83 >= fixed 5.4.0-72.80
    scanner.findings.clear()
    scanner._evaluate_advisory(
        advisory=adv,
        parsed_upstream=(5, 4, 0),
        kernel_str="5.4.0-74-generic",
        os_info=os_info_focal,
        installed_pkg="linux-image-5.4.0-74-generic",
        installed_version="5.4.0-74.83"
    )
    # Patched package produces NO vulnerability findings
    assert len(scanner.findings) == 0
