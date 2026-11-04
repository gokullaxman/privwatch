"""
PrivWatch 3.0 - Unit Tests for Controlled Remediation & Prevention Engine
"""

import pytest

from core.models import Finding, Severity
from modules.response.remediation_engine import RemediationEngine


def test_remediation_plan_generation_suid():
    engine = RemediationEngine(read_only=True)
    finding = Finding(
        finding_id="test_suid_01",
        vector="SUID/SGID",
        severity=Severity.CRITICAL.value,
        title="Exploitable SUID Binary: /usr/bin/vim",
        affected_resource="/usr/bin/vim",
        remediation="chmod u-s /usr/bin/vim"
    )

    plan = engine.generate_plan(finding)
    assert plan.finding_id == "test_suid_01"
    assert "chmod u-s /usr/bin/vim" in plan.proposed_commands
    assert "chmod u+s /usr/bin/vim" in plan.rollback_commands
    assert "Removes the SUID bit" in plan.consequences


def test_remediation_dry_run_safety():
    engine = RemediationEngine(read_only=False)
    finding = Finding(
        vector="CRON",
        title="Writable cron file",
        affected_resource="/etc/cron.d/test_job",
        remediation="chmod 644 /etc/cron.d/test_job"
    )
    plan = engine.generate_plan(finding)

    # Dry run should NOT alter system
    result = engine.execute_plan(plan, actor="admin", confirmed=False, dry_run=True)
    assert result['status'] == "DRY_RUN"
    assert result['executed'] is False


def test_remediation_requires_explicit_confirmation():
    engine = RemediationEngine(read_only=False)
    finding = Finding(
        vector="SUID/SGID",
        title="Exploitable SUID",
        affected_resource="/usr/bin/test_bin"
    )
    plan = engine.generate_plan(finding)

    # If dry_run=False but confirmed=False, must raise PermissionError
    with pytest.raises(PermissionError):
        engine.execute_plan(plan, actor="admin", confirmed=False, dry_run=False)


def test_remediation_rejects_world_writable_mode(temp_dir):
    """Verify that RemediationEngine refuses to apply any chmod granting world-write (e.g. 666)."""
    import stat
    import os
    from modules.response.remediation_engine import RemediationAction, RemediationPlan

    test_file = temp_dir / "insecure_test.sh"
    test_file.write_text("echo test")
    os.chmod(str(test_file), 0o755)

    engine = RemediationEngine(read_only=False)
    bad_action = RemediationAction(
        action_id="act_bad_666",
        action_type="CHMOD",
        target=str(test_file),
        canonical_target=str(test_file),
        expected_original_mode=0o755,
        desired_mode=0o666  # Disallowed world-writable mode!
    )
    bad_plan = RemediationPlan(
        plan_id="plan_bad",
        finding_id="fnd_1",
        title="Bad Remediation",
        target_resource=str(test_file),
        actions=[bad_action]
    )

    with pytest.raises(ValueError) as exc:
        engine.execute_plan(bad_plan, actor="admin", confirmed=True, dry_run=False)
    assert "world-write" in str(exc.value).lower()


def test_remediation_apply_and_rollback_cycle(temp_dir):
    """Verify applying a valid chmod remediation, verifying state, and executing rollback."""
    import stat
    import os
    from modules.response.remediation_engine import RemediationAction, RemediationPlan

    target = temp_dir / "cron_task.sh"
    target.write_text("#!/bin/sh\necho ok")
    os.chmod(str(target), 0o777)
    orig_mode = os.stat(str(target)).st_mode & 0o777

    engine = RemediationEngine(read_only=False)
    action = RemediationAction(
        action_id="act_harden_cron",
        action_type="CHMOD",
        target=str(target),
        canonical_target=str(target),
        expected_original_mode=orig_mode,
        desired_mode=0o755
    )
    plan = RemediationPlan(
        plan_id="plan_harden_cron",
        finding_id="fnd_cron_1",
        title="Harden Cron Script",
        target_resource=str(target),
        actions=[action]
    )

    # 1. Apply confirmed remediation
    res = engine.execute_plan(plan, actor="admin", confirmed=True, dry_run=False)
    assert res['status'] == "SUCCESS"
    assert res['executed'] is True

    # 2. Verify hardened mode on POSIX
    if os.name == 'posix':
        new_mode = os.stat(str(target)).st_mode & 0o777
        assert new_mode == 0o755

    # 3. Rollback
    rb_res = engine.rollback_plan(plan, actor="admin")
    assert rb_res['status'] == "ROLLED_BACK"

    # 4. Verify original mode restored on POSIX
    if os.name == 'posix':
        restored_mode = os.stat(str(target)).st_mode & 0o777
        assert restored_mode == orig_mode


