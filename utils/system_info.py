"""
PrivWatch 3.0 - Linux System Information Utilities
Linux-native system enumeration, capability checks, and OS telemetry identification.
Strictly relies on POSIX / Linux interfaces (/etc/os-release, /proc, geteuid).
"""

import os
from pathlib import Path
import platform
try:
    import pwd
except ImportError:
    pwd = None
import re
import shutil
import sys
from typing import Dict, Optional, Tuple, List, Any

from core.command_exec import LinuxCommandRunner, CommandExecutionResult


def run_command(cmd: str, timeout: int = 25) -> str:
    """Execute command safely via LinuxCommandRunner (shell=False)."""
    res = LinuxCommandRunner.execute(cmd, timeout=timeout)
    if res.success:
        return res.stdout_clean()
    return ""


def run_command_detailed(cmd: str, timeout: int = 25) -> CommandExecutionResult:
    """Execute command safely and return full CommandExecutionResult."""
    return LinuxCommandRunner.execute(cmd, timeout=timeout)


def get_kernel_version() -> str:
    """Get system kernel release string (e.g. 5.15.0-89-generic)."""
    return platform.release()


def get_architecture() -> str:
    """Get machine hardware architecture (e.g. x86_64, aarch64)."""
    return platform.machine()


def get_os_info() -> Dict[str, str]:
    """
    Get detailed Linux OS identification. Inspects /etc/os-release and system utilities.
    Identifies Ubuntu, Debian, Kali, Linux Mint, Fedora, RHEL, CentOS, and Arch Linux.
    """
    info = {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'distro_id': 'unknown',
        'distro_name': 'Linux',
        'distro_version': '',
        'package_manager': 'unknown'
    }

    # Inspect standard /etc/os-release or /usr/lib/os-release
    os_release_paths = ["/etc/os-release", "/usr/lib/os-release"]
    for path in os_release_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            key, val = line.split("=", 1)
                            val = val.strip('"\'')
                            if key == "ID":
                                info['distro_id'] = val.lower()
                            elif key == "NAME":
                                info['distro_name'] = val
                            elif key == "VERSION_ID":
                                info['distro_version'] = val
                break
            except Exception:
                pass

    # Detect active package manager via system PATH
    for pm in ['apt-get', 'dnf', 'yum', 'pacman', 'zypper', 'apk']:
        if shutil.which(pm):
            info['package_manager'] = pm
            break

    return info


def get_current_user() -> str:
    """Get the current executing username using Linux POSIX user database."""
    if pwd and hasattr(os, 'geteuid'):
        try:
            return pwd.getpwuid(os.geteuid()).pw_name
        except (KeyError, Exception):
            pass

    user = os.getenv('USER')
    if user:
        return user

    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "unknown"


def is_root() -> bool:
    """Check if the current process holds root privileges (EUID 0)."""
    if hasattr(os, 'geteuid'):
        return os.geteuid() == 0
    return False


def get_sudo_version() -> Optional[str]:
    """Get sudo version string safely without spawning interactive password prompts."""
    res = LinuxCommandRunner.execute(["sudo", "-V"], timeout=10)
    if res.success:
        first_line = res.stdout.splitlines()[0] if res.stdout else ""
        match = re.search(r'Sudo version ([0-9a-zA-Z._-]+)', first_line, re.IGNORECASE)
        if match:
            return match.group(1)
        return first_line.strip()
    return None


def get_shell() -> str:
    """Get user default shell from /etc/passwd or SHELL environment variable."""
    return os.getenv('SHELL', '/bin/sh')
