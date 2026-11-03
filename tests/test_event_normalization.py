"""
PrivWatch 3.0 - Unit Tests for Event Normalization & Data Models
"""

from datetime import datetime, timezone
import pytest

from core.models import (
    SecurityEvent, Finding, Incident, SystemPosture, Severity,
    utc_now, format_iso, parse_iso
)


def test_security_event_serialization():
    evt = SecurityEvent(
        hostname="srv-test-01",
        source="auditd",
        event_type="PRIVILEGED_EXECVE",
        severity=Severity.HIGH.value,
        user="testuser",
        uid=1000,
        euid=0,
        pid=1234,
        command="/usr/bin/vim",
        evidence={'test_key': 'test_val'}
    )
    d = evt.to_dict()
    assert d['hostname'] == "srv-test-01"
    assert d['user'] == "testuser"
    assert d['euid'] == 0
    assert 'evidence_hash' in d
    assert len(d['evidence_hash']) == 64  # SHA-256 length

    reconstructed = SecurityEvent.from_dict(d)
    assert reconstructed.hostname == evt.hostname
    assert reconstructed.user == evt.user
    assert reconstructed.uid == evt.uid


def test_finding_evidence_hash_and_model():
    fnd = Finding(
        vector="SUID/SGID",
        severity=Severity.CRITICAL.value,
        title="Test Critical Finding",
        description="Testing description",
        affected_resource="/usr/bin/vuln",
        evidence={'path': '/usr/bin/vuln'},
        remediation="chmod 755 /usr/bin/vuln"
    )
    d = fnd.to_dict()
    assert d['severity'] == "CRITICAL"
    assert d['evidence_hash'] == fnd.evidence_hash()

    reconstructed = Finding.from_dict(d)
    assert reconstructed.finding_id == fnd.finding_id
    assert reconstructed.vector == fnd.vector


def test_system_posture_score_calculation():
    # 1. Zero findings -> Score 100 HEALTHY
    p0 = SystemPosture.calculate([])
    assert p0.score == 100
    assert p0.status == "HEALTHY"
    assert p0.total_findings == 0

    # 2. One Critical finding -> 100 - 25 = 75 ATTENTION_NEEDED
    f_crit = Finding(severity=Severity.CRITICAL.value, title="Crit 1")
    p1 = SystemPosture.calculate([f_crit])
    assert p1.score == 75
    assert p1.status == "ATTENTION_NEEDED"

    # 3. Two Critical and two High findings -> 100 - (50 + 20) = 30 CRITICAL_RISK
    f_high = Finding(severity=Severity.HIGH.value, title="High 1")
    f_high2 = Finding(severity=Severity.HIGH.value, title="High 2")
    p2 = SystemPosture.calculate([f_crit, f_crit, f_high, f_high2])
    assert p2.score == 30
    assert p2.status == "CRITICAL_RISK"

    # 4. Score cannot drop below 0
    many_crit = [Finding(severity=Severity.CRITICAL.value, title=f"Crit {i}") for i in range(10)]
    p3 = SystemPosture.calculate(many_crit)
    assert p3.score == 0
    assert p3.status == "CRITICAL_RISK"


def test_timestamp_iso_helpers():
    now = utc_now()
    iso_str = format_iso(now)
    assert iso_str is not None
    parsed = parse_iso(iso_str)
    assert parsed is not None
    assert parsed.year == now.year
    assert parsed.minute == now.minute

