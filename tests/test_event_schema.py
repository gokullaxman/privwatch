"""
UATU Linux Edition - Event Schema Tests
Verifies UatuEvent schema constraints:
- Monotonic collision-resistant event_id generation
- Rejection of naive timestamps
- Confidence range validation and preservation of 0.0
- Deterministic integrity hash calculation and tampering detection
- Enums normalization and round-trip serialization
"""

from datetime import datetime, timezone
import pytest

from core.event_schema import (
    UatuEvent, ProvenanceClass, DataOrigin, CollectionStatus,
    CollectionMethod, EventSeverity, generate_event_id
)


def test_generate_event_id_format():
    """Verify generated event ID is non-empty, unique, and starts with evt_."""
    id1 = generate_event_id()
    id2 = generate_event_id()
    assert id1.startswith("evt_")
    assert id2.startswith("evt_")
    assert id1 != id2


def test_event_rejects_naive_timestamp():
    """Verify that a naive datetime raises ValueError."""
    naive_dt = datetime(2026, 11, 4, 12, 0, 0)  # No tzinfo
    with pytest.raises(ValueError) as exc:
        UatuEvent(timestamp=naive_dt)
    assert "Naive datetime rejected" in str(exc.value)


def test_event_confidence_validation():
    """Verify confidence is strictly bound to [0.0, 1.0] and 0.0 is preserved."""
    # 0.0 is valid and must be preserved
    evt_zero = UatuEvent(confidence=0.0)
    assert evt_zero.confidence == 0.0

    # 1.0 is valid
    evt_one = UatuEvent(confidence=1.0)
    assert evt_one.confidence == 1.0

    # Intermediate value
    evt_mid = UatuEvent(confidence=0.75)
    assert evt_mid.confidence == 0.75

    # None is valid (unknown confidence)
    evt_none = UatuEvent(confidence=None)
    assert evt_none.confidence is None

    # Values < 0.0 must raise ValueError
    with pytest.raises(ValueError):
        UatuEvent(confidence=-0.1)

    # Values > 1.0 must raise ValueError
    with pytest.raises(ValueError):
        UatuEvent(confidence=1.05)


def test_event_enum_normalization():
    """Verify that string inputs for enums are normalized to typed Enums."""
    evt = UatuEvent(
        provenance_class="observed",
        data_origin="live_telemetry",
        collection_status="success",
        severity="critical"
    )
    assert evt.provenance_class == ProvenanceClass.OBSERVED
    assert evt.data_origin == DataOrigin.LIVE_TELEMETRY
    assert evt.collection_status == CollectionStatus.SUCCESS
    assert evt.severity == EventSeverity.CRITICAL


def test_event_integrity_hash_and_verification():
    """Verify that SHA-256 integrity hash is computed and detects field mutation."""
    evt = UatuEvent(
        event_type="SUDO_EXECUTION",
        user="analyst",
        uid=1001,
        euid=0,
        command="/usr/bin/sudo /bin/bash",
        evidence={"terminal": "/dev/pts/1"}
    )
    assert evt.integrity_hash is not None
    assert evt.verify_integrity() is True

    # Mutate a field
    evt.command = "/bin/cat /etc/shadow"
    assert evt.verify_integrity() is False


def test_event_round_trip_serialization():
    """Verify that to_dict and from_dict preserve all properties accurately."""
    now = datetime.now(timezone.utc)
    original = UatuEvent(
        event_id="evt_test_12345",
        timestamp=now,
        host_id="host_kali_01",
        hostname="kali-security",
        source="auditd",
        collection_method=CollectionMethod.AUDITD_NETLINK,
        event_type="PRIVILEGE_TRANSITION",
        severity=EventSeverity.HIGH,
        uid=1000,
        euid=0,
        pid=4501,
        exe="/usr/bin/pkexec",
        command="/usr/bin/pkexec /bin/sh",
        user="testuser",
        evidence={"capability": "CAP_SETUID"},
        provenance_class=ProvenanceClass.OBSERVED,
        data_origin=DataOrigin.LIVE_TELEMETRY,
        confidence=0.95
    )

    d = original.to_dict()
    reconstructed = UatuEvent.from_dict(d)

    assert reconstructed.event_id == original.event_id
    assert reconstructed.host_id == original.host_id
    assert reconstructed.hostname == original.hostname
    assert reconstructed.event_type == original.event_type
    assert reconstructed.confidence == 0.95
    assert reconstructed.euid == 0
    assert reconstructed.evidence == {"capability": "CAP_SETUID"}
    assert reconstructed.verify_integrity() is True

