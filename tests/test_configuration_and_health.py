"""
UATU Linux Edition - Configuration & Health Registry Tests
Verifies typed TOML configuration parsing, unknown key rejection, secret masking,
and HealthRegistry component state transitions and drop tracking.
"""

import os
from pathlib import Path
import tempfile
import pytest
from unittest.mock import patch

from core.configuration import UatuConfig, GeneralConfig, PreventionConfig, ContainmentConfig
from core.health import HealthRegistry, HealthState, ComponentHealth


def test_configuration_defaults_are_safe():
    """Verify safe defaults: monitor-only, containment disabled, loopback host."""
    config = UatuConfig()
    assert config.prevention.prevention_enabled is False
    assert config.prevention.policy_enforcement_mode == "MONITOR"
    assert config.containment.auto_containment is False
    assert config.containment.require_confirmation is True
    assert config.dashboard.host == "127.0.0.1"
    assert config.general.read_only_mode is True


def test_configuration_load_valid_toml():
    """Verify loading from valid TOML file."""
    toml_content = b"""
[general]
app_name = "UATU"
mode = "monitor"
output_dir = "./reports"

[detection]
command_timeout_sec = 30
scanner_timeout_sec = 180

[prevention]
prevention_enabled = false

[dashboard]
host = "127.0.0.1"
port = 9000
api_token = "secret-super-token-12345"
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        toml_path = f.name

    try:
        config = UatuConfig.load_from_toml(toml_path)
        assert config.general.app_name == "UATU"
        assert config.detection.scanner_timeout_sec == 180
        assert config.dashboard.port == 9000
        assert config.dashboard.api_token == "secret-super-token-12345"

        # Check secret masking
        redacted = config.get_redacted_dict()
        assert redacted["dashboard"]["api_token"] == "********"
    finally:
        os.remove(toml_path)


def test_configuration_rejects_unknown_section():
    """Verify loading TOML with unknown section raises ValueError."""
    toml_content = b"""
[hacker_backdoor]
enabled = true
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        toml_path = f.name

    try:
        with pytest.raises(ValueError) as exc:
            UatuConfig.load_from_toml(toml_path)
        assert "Unknown configuration sections" in str(exc.value)
    finally:
        os.remove(toml_path)


def test_configuration_rejects_unknown_key():
    """Verify loading TOML with unknown key in known section raises ValueError."""
    toml_content = b"""
[general]
unknown_option_xyz = 123
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        toml_path = f.name

    try:
        with pytest.raises(ValueError) as exc:
            UatuConfig.load_from_toml(toml_path)
        assert "Unknown keys in configuration section [general]" in str(exc.value)
    finally:
        os.remove(toml_path)


def test_health_registry_lifecycle_and_states():
    """Verify HealthRegistry component states, drop counters, and overall system state."""
    registry = HealthRegistry()

    # 1. Initially all registered components OK -> system OK
    c_audit = registry.register("auditd_collector", critical=True)
    c_bus = registry.register("event_bus", critical=True)
    c_ml = registry.register("drift_monitor", critical=False)

    overall, summary = registry.get_system_health()
    assert overall == HealthState.OK
    assert summary["total_components"] == 3

    # 2. Non-critical component degraded -> system DEGRADED
    registry.record_degraded("drift_monitor", "High latency in feature calculation")
    overall, _ = registry.get_system_health()
    assert overall == HealthState.DEGRADED

    # 3. Drops recorded
    registry.record_drop("event_bus", count=5)
    assert registry.get_component("event_bus").drop_count == 5

    # 4. Critical component fatal error -> system UNAVAILABLE
    registry.record_error("auditd_collector", "auditd socket closed unexpectedly", is_fatal=True)
    overall, summary = registry.get_system_health()
    assert overall == HealthState.UNAVAILABLE
    assert summary["components"]["auditd_collector"]["state"] == "UNAVAILABLE"

    # 5. Snapshot generation
    snapshot = registry.create_snapshot("kali-test-host")
    assert snapshot["hostname"] == "kali-test-host"
    assert snapshot["status"] == "UNAVAILABLE"
    assert snapshot["drop_count"] == 5
