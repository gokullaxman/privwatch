"""
PrivWatch 3.0 - Linux Command Execution Abstraction
Provides safe, structured execution of system commands without shell invocation (shell=False).
Captures execution duration, timeouts, return codes, and separates stdout/stderr.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
from typing import List, Optional, Union, Dict, Any


@dataclass
class CommandExecutionResult:
    """Structured result of a system command execution."""
    executable: str
    arguments: List[str]
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


class LinuxCommandRunner:
    """Safe execution of Linux system binaries using argument lists and shell=False."""

    FORBIDDEN_SHELL_CHARS = {'|', ';', '&', '`', '$', '(', ')', '<', '>'}

    @classmethod
    def execute(
        cls,
        cmd: Union[str, List[str]],
        timeout: int = 30,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> CommandExecutionResult:
        """
        Safely execute a command using subprocess.run(shell=False).
        Rejects shell metacharacters and verifies executable existence.
        """
        if isinstance(cmd, list):
            args = list(cmd)
        elif isinstance(cmd, str):
            # Inspect for forbidden shell metacharacters
            if any(char in cmd for char in cls.FORBIDDEN_SHELL_CHARS):
                return CommandExecutionResult(
                    executable="<invalid>",
                    arguments=[],
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
            return CommandExecutionResult(
                executable="<empty>",
                arguments=[],
                return_code=-1,
                stdout="",
                stderr="Empty command provided",
                duration_ms=0.0,
                available=False,
                error_message="Empty argument list"
            )

        binary_name = args[0]
        # Resolve executable path safely
        resolved_bin = shutil.which(binary_name) if not os.path.isabs(binary_name) else binary_name

        if not resolved_bin or not os.path.exists(resolved_bin):
            return CommandExecutionResult(
                executable=binary_name,
                arguments=args[1:],
                return_code=-1,
                stdout="",
                stderr=f"Executable '{binary_name}' was not found in system PATH.",
                duration_ms=0.0,
                available=False,
                error_message=f"Missing binary: {binary_name}"
            )

        start_time = time.perf_counter()
        try:
            completed = subprocess.run(
                [resolved_bin] + args[1:],
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=cwd
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CommandExecutionResult(
                executable=resolved_bin,
                arguments=args[1:],
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                duration_ms=elapsed,
                timed_out=False,
                available=True
            )
        except subprocess.TimeoutExpired as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CommandExecutionResult(
                executable=resolved_bin,
                arguments=args[1:],
                return_code=-1,
                stdout=e.stdout.decode('utf-8', errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or ""),
                stderr=f"Command timed out after {timeout} seconds.",
                duration_ms=elapsed,
                timed_out=True,
                available=True,
                error_message=f"Timeout expired ({timeout}s)"
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CommandExecutionResult(
                executable=resolved_bin,
                arguments=args[1:],
                return_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=elapsed,
                timed_out=False,
                available=False,
                error_message=str(e)
            )

