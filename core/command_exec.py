"""
PrivWatch 3.0 / UATU Linux Edition - Command Execution Compatibility Wrapper
Re-exports CommandRunner and CommandResult from core.command_runner.
"""

from core.command_runner import (
    CommandResult,
    CommandExecutionResult,
    CommandRunner,
    LinuxCommandRunner
)

__all__ = [
    "CommandResult",
    "CommandExecutionResult",
    "CommandRunner",
    "LinuxCommandRunner"
]
