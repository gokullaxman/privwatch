"""
UATU Linux Edition - Platform & Command Runner Tests
Verifies LinuxPlatform enforcement, capability detection, CommandRunner argument security,
environment scrubbing, and immutable CommandResult integrity.
"""

from dataclasses import FrozenInstanceError
import os
import platform
import subprocess
import sys
import pytest
from unittest.mock import patch

from core.platform import LinuxPlatform, UnsupportedPlatformError, CapabilityReport
from core.command_runner import CommandRunner, CommandResult


def test_platform_assert_linux_rejection_on_non_linux():
    """Verify that assert_linux raises UnsupportedPlatformError when OS is not Linux."""
    with patch("platform.system", return_value="Windows"):
        with pytest.raises(UnsupportedPlatformError) as exc_info:
            LinuxPlatform.assert_linux(strict=True)
        assert "FATAL ERROR" in str(exc_info.value)
        assert "Windows" in str(exc_info.value)

    with patch("platform.system", return_value="Darwin"):
        with pytest.raises(UnsupportedPlatformError) as exc_info:
            LinuxPlatform.assert_linux(strict=True)
        assert "Darwin" in str(exc_info.value)


def test_platform_capability_report_structure():
    """Verify capability report contains all required fields and serializes to dict."""
    with patch("platform.system", return_value="Linux"):
        with patch("os.path.exists", return_value=True):
            with patch("os.path.isdir", return_value=True):
                report = LinuxPlatform.assert_linux(strict=False)

    assert isinstance(report, CapabilityReport)
    d = report.to_dict()
    assert "system" in d
    assert "kernel_release" in d
    assert "architecture" in d
    assert "is_root" in d
    assert "available_capabilities" in d
    assert "unavailable_capabilities" in d
    assert "permission_limited" in d
    assert isinstance(d["available_capabilities"], list)


def test_command_runner_rejects_shell_metacharacters():
    """Verify CommandRunner rejects shell metacharacters in string commands."""
    res = CommandRunner.run("ls | grep secret")
    assert not res.success
    assert not res.available
    assert "Shell metacharacters" in res.stderr

    res2 = CommandRunner.run("whoami; cat /etc/shadow")
    assert not res2.success
    assert "Shell metacharacters" in res2.stderr


def test_command_runner_rejects_nul_bytes():
    """Verify CommandRunner rejects NUL bytes in argument strings."""
    res = CommandRunner.run(["ls", "file\x00name"])
    assert not res.success
    assert not res.available
    assert "NUL byte detected" in res.stderr


def test_command_runner_rejects_invalid_timeout():
    """Verify CommandRunner raises ValueError on non-positive timeout values."""
    with pytest.raises(ValueError):
        CommandRunner.run(["echo", "test"], timeout=0)
    with pytest.raises(ValueError):
        CommandRunner.run(["echo", "test"], timeout=-5)


def test_command_runner_immutable_result():
    """Verify CommandResult dataclass is frozen and immutable."""
    result = CommandResult(
        executable="/bin/echo",
        arguments=("hello",),
        return_code=0,
        stdout="hello\n",
        stderr="",
        duration_ms=2.5,
        timed_out=False,
        available=True
    )
    assert result.success is True
    assert result.stdout_clean() == "hello"

    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.return_code = 1  # type: ignore


def test_command_runner_sanitized_environment():
    """Verify CommandRunner environment scrubbing enforces LC_ALL=C and safe PATH."""
    scrubbed = CommandRunner.sanitize_env({"CUSTOM_VAR": "val", "INVAL\x00ID": "bad"})
    assert scrubbed["LC_ALL"] == "C"
    assert scrubbed["LANG"] == "C"
    assert scrubbed["PATH"] == CommandRunner.SAFE_DEFAULT_PATH
    assert scrubbed["CUSTOM_VAR"] == "val"
    assert "INVAL\x00ID" not in scrubbed


def test_command_runner_runs_python_safely():
    """Verify safe execution of standard python executable."""
    py_bin = sys.executable
    res = CommandRunner.run([py_bin, "-c", "print('UATU_TEST_OK')"], timeout=10.0)
    assert res.success is True
    assert res.return_code == 0
    assert "UATU_TEST_OK" in res.stdout_clean()
    assert res.timed_out is False
    assert res.duration_ms > 0
