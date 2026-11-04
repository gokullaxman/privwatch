"""
UATU Linux Edition - Safe Command Runner
Provides strictly validated, non-shell (shell=False) execution of Linux system binaries.
Enforces typed argument lists, NUL-byte rejection, environment scrubbing (fixed safe PATH, LC_ALL=C),
mandatory timeouts, execution duration measurement, and immutable CommandResult outputs.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
from typing import List, Optional, Union, Dict, Any, Tuple


@dataclass(frozen=True)
class CommandResult:
    """Immutable result of a system command execution."""
    executable: str
    arguments: Tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    available: bool = True
    error_message: Optional[str] = None

    @property
    def success(self) -> bool:
        """True if command executed and exited with status code 0."""
        return self.available and not self.timed_out and self.return_code == 0

    def stdout_clean(self) -> str:
        """Return stripped standard output."""
        return self.stdout.strip()


# Backwards compatibility alias
CommandExecutionResult = CommandResult


class CommandRunner:
    """Safe execution of Linux system binaries without shell invocation (shell=False)."""

    FORBIDDEN_CHARS = {'|', ';', '&', '`', '$', '(', ')', '<', '>', '\n', '\r', '\x00'}
    SAFE_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    @classmethod
    def sanitize_env(cls, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Construct sanitized, minimal execution environment with fixed safe PATH."""
        env = {
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": cls.SAFE_DEFAULT_PATH
        }
        if custom_env:
            for k, v in custom_env.items():
                if isinstance(k, str) and isinstance(v, str) and '\x00' not in k and '\x00' not in v:
                    env[k] = v
        return env

    @classmethod
    def run(
        cls,
        cmd: Union[str, List[str]],
        timeout: float = 30.0,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> CommandResult:
        """
        Safely execute an external system binary.
        Enforces shell=False, validates argument strings, rejects NUL bytes,
        and sanitizes process environment.
        """
        if timeout <= 0:
            raise ValueError(f"Command timeout must be positive, got: {timeout}")

        # Parse and validate command arguments
        if isinstance(cmd, list):
            args = list(cmd)
        elif isinstance(cmd, str):
            if any(c in cmd for c in cls.FORBIDDEN_CHARS):
                return CommandResult(
                    executable="<invalid>",
                    arguments=(),
                    return_code=-1,
                    stdout="",
                    stderr=f"Security rejection: Shell metacharacters are strictly forbidden: '{cmd}'",
                    duration_ms=0.0,
                    available=False,
                    error_message="Shell metacharacters forbidden; shell=False is enforced."
                )
            args = shlex.split(cmd)
        else:
            raise TypeError("cmd must be a string or a list of argument strings")

        if not args:
            return CommandResult(
                executable="<empty>",
                arguments=(),
                return_code=-1,
                stdout="",
                stderr="Empty command provided",
                duration_ms=0.0,
                available=False,
                error_message="Empty argument list"
            )

        # Validate arguments for NUL bytes or invalid characters
        for arg in args:
            if not isinstance(arg, str):
                raise TypeError(f"All command arguments must be strings, got: {type(arg)}")
            if '\x00' in arg:
                return CommandResult(
                    executable=args[0],
                    arguments=tuple(args[1:]),
                    return_code=-1,
                    stdout="",
                    stderr="Security rejection: NUL byte detected in command arguments.",
                    duration_ms=0.0,
                    available=False,
                    error_message="NUL byte detected in command arguments."
                )

        binary_name = args[0]
        # Resolve binary path
        resolved_bin = shutil.which(binary_name) if not os.path.isabs(binary_name) else binary_name

        if not resolved_bin or not os.path.exists(resolved_bin):
            return CommandResult(
                executable=binary_name,
                arguments=tuple(args[1:]),
                return_code=-1,
                stdout="",
                stderr=f"Executable '{binary_name}' was not found in system PATH.",
                duration_ms=0.0,
                available=False,
                error_message=f"Missing binary: {binary_name}"
            )

        scrubbed_env = cls.sanitize_env(env)
        start_time = time.perf_counter()

        try:
            completed = subprocess.run(
                [resolved_bin] + args[1:],
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=scrubbed_env,
                cwd=cwd
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CommandResult(
                executable=resolved_bin,
                arguments=tuple(args[1:]),
                return_code=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_ms=elapsed,
                timed_out=False,
                available=True
            )
        except subprocess.TimeoutExpired as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            out = e.stdout.decode('utf-8', errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else (e.stderr or "")
            return CommandResult(
                executable=resolved_bin,
                arguments=tuple(args[1:]),
                return_code=-1,
                stdout=out,
                stderr=f"{err}\nCommand timed out after {timeout} seconds.".strip(),
                duration_ms=elapsed,
                timed_out=True,
                available=True,
                error_message=f"Timeout expired ({timeout}s)"
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CommandResult(
                executable=resolved_bin,
                arguments=tuple(args[1:]),
                return_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=elapsed,
                timed_out=False,
                available=False,
                error_message=str(e)
            )

    @classmethod
    def execute(
        cls,
        cmd: Union[str, List[str]],
        timeout: int = 30,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> CommandResult:
        """Backwards-compatible alias for run()."""
        return cls.run(cmd=cmd, timeout=float(timeout), env=env, cwd=cwd)


# Backwards compatibility class alias
LinuxCommandRunner = CommandRunner
