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

