"""
PrivWatch 3.0 - Pytest Configuration & Test Fixtures
All synthetic test fixtures are strictly labeled with is_test_fixture=True.
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import pytest
import tempfile
from typing import List

from core.models import SecurityEvent, Finding, Incident, Severity, utc_now
from core.storage import StorageEngine
from core.config import PrivWatchConfig


@pytest.fixture(autouse=True)
def mock_linux_platform_for_tests(monkeypatch):
    """Ensure unit tests evaluate with Linux OS semantics even when run in isolated dev sandboxes."""
    import platform
    if platform.system() != "Linux":
        monkeypatch.setattr(platform, "system", lambda: "Linux")


@pytest.fixture
def temp_dir():
    """Create isolated temporary directory for test executions"""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        yield Path(td)


@pytest.fixture
def test_db(temp_dir):
    """Create isolated SQLite database for testing"""
    db_path = str(temp_dir / "test_privwatch.db")
    storage = StorageEngine(db_path)
    return storage


@pytest.fixture
def sample_findings() -> List[Finding]:
    """Generate labeled synthetic test findings"""
    return [
        Finding(
            finding_id="test_fnd_01",
            vector="SUID/SGID",
            severity=Severity.CRITICAL.value,
            title="Synthetic SUID Test Binary",
            description="Test fixture representing an exploitable SUID binary",
            affected_resource="/usr/bin/test_vuln",
            evidence={'path': '/usr/bin/test_vuln', 'perms': '-rwsr-xr-x'},
            detection_method="test_fixture",
            risk_explanation="Arbitrary code execution under root UID",
            remediation="chmod u-s /usr/bin/test_vuln",
            is_test_fixture=True
        ),
        Finding(
            finding_id="test_fnd_02",
            vector="SUDO",
            severity=Severity.HIGH.value,
            title="Synthetic Sudo NOPASSWD Test",
            description="Test fixture representing dangerous sudo configuration",
            affected_resource="/etc/sudoers",
            evidence={'rule': 'testuser ALL=(ALL) NOPASSWD: /bin/cat'},
            detection_method="test_fixture",
            risk_explanation="Passwordless elevated file read",
            remediation="Remove NOPASSWD",
            is_test_fixture=True
        )
    ]


@pytest.fixture
def sample_events() -> List[SecurityEvent]:
    """Generate labeled synthetic security events"""
    t0 = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
    return [
        SecurityEvent(
            event_id="test_evt_01",
            timestamp=t0,
            hostname="test-host",
            source="test_auth.log",
            event_type="SUDO_AUTH_FAIL",
            severity=Severity.HIGH.value,
            user="alice",
            pid=1001,
            process="sudo",
            command=None,
            evidence={'message': 'authentication failure'},
            is_test_fixture=True
        ),
        SecurityEvent(
            event_id="test_evt_02",
            timestamp=t0 + timedelta(seconds=30),
            hostname="test-host",
            source="test_auth.log",
            event_type="SUDO_AUTH_FAIL",
            severity=Severity.HIGH.value,
            user="alice",
            pid=1002,
            process="sudo",
            command=None,
            evidence={'message': 'authentication failure'},
            is_test_fixture=True
        ),
        SecurityEvent(
            event_id="test_evt_03",
            timestamp=t0 + timedelta(seconds=120),
            hostname="test-host",
            source="test_auth.log",
            event_type="SUDO_COMMAND",
            severity=Severity.INFO.value,
            user="alice",
            pid=1005,
            process="sudo",
            command="/bin/bash",
            evidence={'message': 'COMMAND=/bin/bash'},
            is_test_fixture=True
        )
    ]

