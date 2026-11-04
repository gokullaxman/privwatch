"""
UATU Linux Edition - Detection & Incident Correlation Tests
Verifies correlation rules:
- Repeated sudo/ssh authentication failures
- Sudo failure sequence followed by success for SAME user only
- Isolation across different users
- SUID executions where euid != uid
- Watched file edits to /etc/sudoers, /etc/passwd, /etc/shadow
"""

from datetime import datetime, timezone, timedelta
import pytest

from core.models import Incident, Severity, IncidentStatus
from core.event_schema import UatuEvent, EventSeverity, DataOrigin
from detection.engine import DetectionEngine


def test_repeated_authentication_failures_rule():
    """Verify >=3 failures generate an incident with ordered event IDs."""
    base_time = datetime.now(timezone.utc)
    engine = DetectionEngine(window_seconds=300, failure_threshold=3)

    events = [
        UatuEvent(event_id="evt_fail_1", timestamp=base_time, user="badactor", event_type="SUDO_AUTH_FAILURE"),
        UatuEvent(event_id="evt_fail_2", timestamp=base_time + timedelta(seconds=10), user="badactor", event_type="SUDO_AUTH_FAILURE"),
        UatuEvent(event_id="evt_fail_3", timestamp=base_time + timedelta(seconds=20), user="badactor", event_type="SUDO_AUTH_FAILURE")
    ]

    incidents = engine.correlate(events)
    assert len(incidents) >= 1
    inc = [i for i in incidents if "Repeated Authentication Failures" in i.title][0]
    assert inc.severity == Severity.HIGH.value
    assert inc.attribution["user"] == "badactor"
    assert inc.event_ids == ["evt_fail_1", "evt_fail_2", "evt_fail_3"]


def test_sudo_brute_to_success_same_user_only():
    """Verify failures followed by success for SAME user creates critical incident."""
    base_time = datetime.now(timezone.utc)
    engine = DetectionEngine(window_seconds=300, failure_threshold=2)

    events = [
        UatuEvent(event_id="evt_f1", timestamp=base_time, user="attacker", event_type="SUDO_AUTH_FAILURE"),
        UatuEvent(event_id="evt_f2", timestamp=base_time + timedelta(seconds=5), user="attacker", event_type="SUDO_AUTH_FAILURE"),
        UatuEvent(event_id="evt_succ", timestamp=base_time + timedelta(seconds=15), user="attacker", event_type="SUDO_AUTH_SUCCESS", command="/bin/bash")
    ]

    incidents = engine.correlate(events)
    assert any("Sudo Brute Force Followed by Root Elevation" in i.title for i in incidents)
    brute_inc = [i for i in incidents if "Sudo Brute Force Followed by Root Elevation" in i.title][0]
    assert brute_inc.severity == Severity.CRITICAL.value
    assert brute_inc.attribution["user"] == "attacker"
    assert brute_inc.event_ids == ["evt_f1", "evt_f2", "evt_succ"]


def test_different_users_do_not_cross_correlate():
    """Verify failures for user_A followed by success for user_B do NOT create a brute-force incident."""
    base_time = datetime.now(timezone.utc)
    engine = DetectionEngine(window_seconds=300, failure_threshold=2)

    events = [
        # user_A fails
        UatuEvent(event_id="evt_a1", timestamp=base_time, user="user_A", event_type="SUDO_AUTH_FAILURE"),
        # user_B succeeds legitimately
        UatuEvent(event_id="evt_b_succ", timestamp=base_time + timedelta(seconds=5), user="user_B", event_type="SUDO_AUTH_SUCCESS", command="/usr/bin/apt update")
    ]

    incidents = engine.correlate(events)
    # Must NOT correlate user_A's failure with user_B's success
    assert not any("Sudo Brute Force Followed by Root Elevation" in i.title for i in incidents)


def test_suid_execution_euid_mismatch():
    """Verify execution of SUID binary with euid != uid creates an incident."""
    evt = UatuEvent(
        event_id="evt_suid_1",
        event_type="SUID_EXECUTION",
        user="www-data",
        uid=33,
        euid=0,
        pid=9090,
        exe="/usr/bin/pkexec"
    )
    engine = DetectionEngine()
    incidents = engine.correlate([evt])

    assert len(incidents) == 1
    assert "SUID Privilege Elevation" in incidents[0].title
    assert incidents[0].attribution["uid"] == 33
    assert incidents[0].attribution["euid"] == 0
    assert incidents[0].event_ids == ["evt_suid_1"]


def test_watched_file_modification_detection():
    """Verify modification of /etc/shadow or /etc/passwd generates critical incident."""
    evt = UatuEvent(
        event_id="evt_shadow_edit",
        event_type="WATCHED_FILE_EDIT_SHADOW",
        user="rogue_user",
        pid=5555,
        command="/bin/sed"
    )
    engine = DetectionEngine()
    incidents = engine.correlate([evt])

    assert len(incidents) == 1
    assert "Tampering with Critical Authentication Database" in incidents[0].title
    assert incidents[0].severity == Severity.CRITICAL.value
    assert incidents[0].attribution["target_file"] == "/etc/shadow"
