"""
PrivWatch 3.0 - Unit Tests for Multi-Factor Event Correlation & Forensics
"""

from datetime import datetime, timedelta, timezone
import pytest

from core.models import SecurityEvent, Severity
from modules.timeline.event_correlator import EventCorrelator


def test_sudo_brute_force_correlation_same_user():
    t0 = datetime(2026, 11, 3, 14, 0, 0, tzinfo=timezone.utc)
    correlator = EventCorrelator(window_seconds=1800)

    # 3 Failed attempts for alice, followed by success for alice
    events = [
        SecurityEvent(timestamp=t0, event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        SecurityEvent(timestamp=t0 + timedelta(seconds=20), event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        SecurityEvent(timestamp=t0 + timedelta(seconds=40), event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        SecurityEvent(timestamp=t0 + timedelta(seconds=90), event_type="SUDO_COMMAND", user="alice", command="/bin/bash", hostname="host-a")
    ]
    correlator.add_events(events)

    incidents = correlator.detect_attack_patterns()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == Severity.CRITICAL.value
    assert "alice" in inc.title
    assert inc.attribution.get('user') == "alice"
    assert len(inc.event_ids) == 4


def test_sudo_brute_force_does_not_correlate_different_users():
    """Verify that user Bob's command is NOT correlated with user Alice's failures"""
    t0 = datetime(2026, 11, 3, 14, 0, 0, tzinfo=timezone.utc)
    correlator = EventCorrelator(window_seconds=1800)

    events = [
        # Alice fails
        SecurityEvent(timestamp=t0, event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        SecurityEvent(timestamp=t0 + timedelta(seconds=20), event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        # Bob succeeds 1 minute later
        SecurityEvent(timestamp=t0 + timedelta(seconds=60), event_type="SUDO_COMMAND", user="bob", command="apt update", hostname="host-a")
    ]
    correlator.add_events(events)

    incidents = correlator.detect_attack_patterns()
    # Must NOT correlate Alice's failure with Bob's command!
    assert len(incidents) == 0


def test_sudo_brute_force_enforces_chronological_ordering():
    """Verify that a successful command BEFORE failures is NOT treated as a brute force success"""
    t0 = datetime(2026, 11, 3, 14, 0, 0, tzinfo=timezone.utc)
    correlator = EventCorrelator(window_seconds=1800)

    events = [
        # Alice succeeds first
        SecurityEvent(timestamp=t0, event_type="SUDO_COMMAND", user="alice", command="/bin/ls", hostname="host-a"),
        # Alice subsequently fails
        SecurityEvent(timestamp=t0 + timedelta(seconds=60), event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a"),
        SecurityEvent(timestamp=t0 + timedelta(seconds=90), event_type="SUDO_AUTH_FAIL", user="alice", hostname="host-a")
    ]
    correlator.add_events(events)

    incidents = correlator.detect_attack_patterns()
    # No success followed the failures, so no brute_to_success incident
    assert len(incidents) == 0


def test_webshell_to_privesc_correlation():
    t0 = datetime(2026, 11, 3, 15, 0, 0, tzinfo=timezone.utc)
    correlator = EventCorrelator(window_seconds=1800)

    shell_event = SecurityEvent(
        timestamp=t0,
        event_type="SUSPICIOUS_SHELL_SPAWNED",
        user="www-data",
        pid=3450,
        process="bash"
    )

    # Spawned child executes SUID binary
    elevated_event = SecurityEvent(
        timestamp=t0 + timedelta(seconds=15),
        event_type="ACTIVE_EUID_ELEVATION",
        user="www-data",
        pid=3452,
        ppid=3450,
        process="pkexec",
        command="/usr/bin/pkexec /bin/sh"
    )

    correlator.add_events([shell_event, elevated_event])
    incidents = correlator.detect_attack_patterns()

    assert len(incidents) == 1
    assert "Web Shell" in incidents[0].title
    assert incidents[0].severity == Severity.CRITICAL.value

