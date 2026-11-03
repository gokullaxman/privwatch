"""
PrivWatch 3.0 - Security Tests: Input Validation, Path Traversal, and Sensitive Data Protection
"""

import sys
from pathlib import Path
import pytest

from utils.file_utils import safe_resolve_path
from core.evidence import EvidenceManager
from core.scanner import BaseScanner


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
