"""
UATU Linux Edition - System Diagnostics & Doctor Tests
Verifies that uatu doctor properly verifies platform, subsystems, permissions, and ML manifests.
"""

import json
import os
from pathlib import Path
import pytest
import sys

from core.diagnostics import SystemDiagnostics, DiagnosticCheck


def test_system_diagnostics_runs_all_checks():
    """Verify run_all_checks returns checks across all required categories."""
    diag = SystemDiagnostics()
    checks = diag.run_all_checks()

    categories = {c.category for c in checks}
    assert "ENVIRONMENT" in categories
    assert "TELEMETRY" in categories
    assert "STORAGE" in categories
    assert "SECURITY" in categories
    assert "CONTAINMENT" in categories
    assert "ML_GOVERNANCE" in categories

    for c in checks:
        assert c.status in ("PASS", "WARN", "FAIL")
        assert c.check_id
        assert c.message


def test_platform_check_flags_non_linux(monkeypatch):
    """Verify non-Linux platforms are flagged with status FAIL."""
    diag = SystemDiagnostics()

    # Simulate non-linux platform
    monkeypatch.setattr(sys, "platform", "win32")
    res = diag.check_os_platform()
    assert res.status == "FAIL"
    assert "Non-Linux platform" in res.message

    # Simulate linux platform
    monkeypatch.setattr(sys, "platform", "linux")
    res_linux = diag.check_os_platform()
    assert res_linux.status == "PASS"


def test_ml_manifest_check_detects_tampering(temp_dir):
    """Verify diagnostics detects when a model file does not match manifest checksum."""
    models_dir = temp_dir / "models"
    reg_dir = models_dir / "registry"
    reg_dir.mkdir(parents=True, exist_ok=True)

    # Write a test model
    test_pkl = reg_dir / "test_model.pkl"
    test_pkl.write_bytes(b"TEST_MODEL_BYTES")

    # Write manifest with wrong sha256
    manifest_file = models_dir / "manifest.json"
    manifest_file.write_text(json.dumps({
        "models": {
            "test_model": {
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    }), encoding="utf-8")

    diag = SystemDiagnostics(base_dir=str(temp_dir))
    check = diag.check_ml_manifest_integrity()
    assert check.status == "FAIL"
    assert "Integrity check failed" in check.message
