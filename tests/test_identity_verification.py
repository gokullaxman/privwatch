"""
UATU Linux Edition - Privileged Identity Verification Tests
Verifies real UID/EUID validation, group memberships, sudoers checking,
and immutable audit log recording.
"""

from pathlib import Path
import pytest

from core.identity import PrivilegedIdentityVerifier, IdentityVerificationResult
from core.storage import StorageEngine


def test_root_operator_always_authorized(temp_dir):
    """Root user is always authorized for any action."""
    storage = StorageEngine(str(temp_dir / "audit.db"))
    verifier = PrivilegedIdentityVerifier(storage=storage, etc_dir=str(temp_dir))

    result = verifier.verify_operator(
        actor="root",
        required_privilege="admin",
        action="CONTAINMENT_KILL",
        target="PID 1234"
    )
    assert result.authorized is True
    assert result.is_root is True
    assert "authorized via root privilege" in result.reason

    # Verify audit log in storage
    entries = storage.get_recent_audit_entries()
    assert len(entries) >= 1
    assert entries[0]["action"] == "IDENTITY_VERIFY_CONTAINMENT_KILL"
    assert entries[0]["result"] == "SUCCESS"


def test_sudoer_operator_authorized(temp_dir):
    """User with sudoers entry or sudo group membership is authorized."""
    storage = StorageEngine(str(temp_dir / "audit.db"))
    etc_dir = temp_dir / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)

    # Create sudoers file granting alice sudo
    (etc_dir / "sudoers").write_text("alice ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    verifier = PrivilegedIdentityVerifier(storage=storage, etc_dir=str(etc_dir))

    assert verifier.check_sudo_privilege("alice") is True

    result = verifier.verify_operator(
        actor="alice",
        required_privilege="operator",
        action="REMEDIATION_CHMOD"
    )
    assert result.authorized is True
    assert result.is_sudoer is True


def test_unprivileged_operator_denied(temp_dir):
    """Unprivileged user without sudoers entry is rejected."""
    storage = StorageEngine(str(temp_dir / "audit.db"))
    etc_dir = temp_dir / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    (etc_dir / "sudoers").write_text("# empty sudoers\n", encoding="utf-8")

    verifier = PrivilegedIdentityVerifier(storage=storage, etc_dir=str(etc_dir))

    assert verifier.check_sudo_privilege("bob") is False

    result = verifier.verify_operator(
        actor="bob",
        required_privilege="admin",
        action="MODIFY_POLICY"
    )
    assert result.authorized is False
    assert "denied: admin role required" in result.reason

    # Audit log verifies denial
    entries = storage.get_recent_audit_entries()
    assert len(entries) >= 1
    assert entries[0]["result"] == "DENIED"
