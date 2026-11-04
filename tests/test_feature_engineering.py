"""
Tests for PrivWatch 3.1 Linux Feature Engineering Pipeline
Validates 32-dimensional canonical schema, missing value fallbacks, and temporal metrics.
"""

from datetime import datetime, timedelta, timezone
import pytest
import numpy as np

from core.models import SecurityEvent, Severity
from ml.features.feature_schema import FEATURE_NAMES, FEATURE_DESCRIPTIONS, FeatureVector
from ml.features.feature_extractor import LinuxFeatureExtractor


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 32
    assert len(FEATURE_DESCRIPTIONS) == 32


def test_feature_vector_validation_success():
    vals = {name: 0.0 for name in FEATURE_NAMES}
    fv = FeatureVector(event_id="ev_test", timestamp_iso="2026-11-04T00:00:00Z", values=vals)
    assert fv.validate() is True
    arr = fv.to_array()
    assert isinstance(arr, np.ndarray)
    assert arr.shape == (32,)


def test_feature_vector_validation_failure_on_missing_or_nan():
    # Missing feature
    vals = {name: 0.0 for name in FEATURE_NAMES[:-1]}
    fv = FeatureVector(event_id="ev_test", timestamp_iso="2026-11-04T00:00:00Z", values=vals)
    assert fv.validate() is False

    # NaN feature
    vals_nan = {name: 0.0 for name in FEATURE_NAMES}
    vals_nan[FEATURE_NAMES[0]] = float('nan')
    fv_nan = FeatureVector(event_id="ev_test", timestamp_iso="2026-11-04T00:00:00Z", values=vals_nan)
    assert fv_nan.validate() is False


def test_extractor_identity_and_euid_mismatch():
    extractor = LinuxFeatureExtractor()
    ev = SecurityEvent(
        uid=1000,
        euid=0,
        gid=1000,
        egid=0,
        pid=1234,
        ppid=1000,
        process="bash",
        command="/bin/bash"
    )
    fv = extractor.extract_features(ev)
    assert fv.validate() is True
    assert fv.values["uid"] == 1000.0
    assert fv.values["euid"] == 0.0
    assert fv.values["uid_euid_mismatch"] == 1.0
    assert fv.values["euid_is_root"] == 1.0
    assert fv.values["uid_is_root"] == 0.0


def test_extractor_daemon_and_writable_dir():
    extractor = LinuxFeatureExtractor()
    ev = SecurityEvent(
        user="www-data",
        uid=33,
        euid=33,
        process="sh",
        command="/tmp/exploit.sh",
        evidence={"exe": "/tmp/exploit.sh"}
    )
    fv = extractor.extract_features(ev)
    assert fv.values["is_daemon_user"] == 1.0
    assert fv.values["is_interactive_shell"] == 1.0
    assert fv.values["exe_in_writable_dir"] == 1.0


def test_extractor_temporal_sliding_window():
    extractor = LinuxFeatureExtractor()
    t0 = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)

    # 3 prior events
    h1 = SecurityEvent(timestamp=t0 - timedelta(seconds=25), event_type="SUDO_AUTH_FAIL", user="guest")
    h2 = SecurityEvent(timestamp=t0 - timedelta(seconds=8), event_type="SUDO_AUTH_FAIL", user="guest")
    h3 = SecurityEvent(timestamp=t0 - timedelta(seconds=2), event_type="SUDO_AUTH_FAIL", user="guest")

    target = SecurityEvent(timestamp=t0, event_type="SUDO_COMMAND", user="guest", uid=1002, euid=0)
    fv = extractor.extract_features(target, history=[h1, h2, h3])

    assert fv.values["events_last_60s"] == 3.0
    assert fv.values["events_last_10s"] == 2.0  # h2 and h3
    assert fv.values["auth_fails_last_300s"] == 3.0
    assert fv.values["time_delta_prev_event"] == 2.0
