"""
UATU Linux Edition - Attack Path Engine Tests
Verifies NetworkX graph construction from findings:
- user -> writable script -> root cron -> root
- user -> NOPASSWD sudo -> root
- level is strictly CONFIGURATION_ONLY
- Persistence in storage engine
"""

import pytest

from core.models import Finding, Severity
from core.storage import StorageEngine
from attack_path.graph_builder import AttackPathEngine


def test_attack_path_from_writable_cron_script(temp_dir):
    """Verify attack path generation for writable cron script."""
    db_path = str(temp_dir / "attack_path_test.db")
    storage = StorageEngine(db_path)
    engine = AttackPathEngine(storage=storage)

    finding = Finding(
        vector="CRON",
        severity=Severity.CRITICAL.value,
        title="Writable Script Referenced in Cron: /opt/scripts/backup.sh",
        description="Cron executes writable script",
        affected_resource="/opt/scripts/backup.sh",
        evidence={"owner": "1000:1000", "mode": "-rwxrwxrwx", "cron_line": "* * * * * root /opt/scripts/backup.sh"}
    )

    paths = engine.build_graph_from_findings([finding])
    assert len(paths) == 1
    p = paths[0]

    assert p.start_node == "user:current"
    assert p.target_node == "user:root"
    assert p.level == "CONFIGURATION_ONLY"
    assert p.severity == Severity.CRITICAL.value
    assert p.bottleneck_node == "script:/opt/scripts/backup.sh"
    assert any("chmod 755 /opt/scripts/backup.sh" in p.recommended_disruption for p in [p])

    # Verify node count (user, script, service, root = 4 nodes)
    node_ids = [n["id"] for n in p.nodes]
    assert "user:current" in node_ids
    assert "script:/opt/scripts/backup.sh" in node_ids
    assert "service:root_cron" in node_ids
    assert "user:root" in node_ids


def test_attack_path_from_sudo_nopasswd(temp_dir):
    """Verify attack path generation for sudo NOPASSWD rule."""
    db_path = str(temp_dir / "attack_path_sudo_test.db")
    storage = StorageEngine(db_path)
    engine = AttackPathEngine(storage=storage)

    finding = Finding(
        vector="SUDO",
        severity=Severity.CRITICAL.value,
        title="Sudo NOPASSWD Unrestricted Command Execution",
        description="Current user can execute all commands as root without password",
        affected_resource="sudoers",
        evidence={"rule": "operator ALL=(ALL) NOPASSWD: ALL", "command": "ALL"}
    )

    paths = engine.build_graph_from_findings([finding])
    assert len(paths) == 1
    p = paths[0]

    assert p.start_node == "user:current"
    assert p.target_node == "user:root"
    assert p.level == "CONFIGURATION_ONLY"
    assert p.severity == Severity.CRITICAL.value
    assert "sudo:ALL" in [n["id"] for n in p.nodes]


def test_attack_path_never_claims_exploited():
    """Verify that level is strictly CONFIGURATION_ONLY."""
    engine = AttackPathEngine()
    fnd = Finding(
        vector="SUID/SGID",
        severity=Severity.CRITICAL.value,
        title="Writable SUID Binary: /usr/local/bin/custom_suid",
        affected_resource="/usr/local/bin/custom_suid",
        evidence={"owner": "0:0", "mode": "-rwsrwxrwx"}
    )
    paths = engine.build_graph_from_findings([fnd])
    assert len(paths) == 1
    assert paths[0].level == "CONFIGURATION_ONLY"
    assert "exploited" not in paths[0].level.lower()

