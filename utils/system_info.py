"""
PrivWatch 3.0 - System Information Utilities
Cross-distribution system enumeration, capability checks, and OS telemetry identification.
"""

import os
import platform
import re
import shlex
import subprocess
import sys
from typing import Dict, Optional, Tuple, List


def run_command(cmd: str, timeout: int = 25) -> str:
    """Execute shell command safely with timeout and error capture"""
    try:
        # Check if cmd has pipes or redirects
        if any(c in cmd for c in ['|', '>', '<', '&', ';', '$']):
            shell_bin = '/bin/sh' if os.path.exists('/bin/sh') else None
            result = subprocess.run(
                cmd,
                shell=True,
                executable=shell_bin,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        else:
            argv = shlex.split(cmd, posix=(os.name != 'nt'))
            if not argv:
                return ""
            result = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
    except Exception:
        return ""


def get_kernel_version() -> str:
    """Get system kernel release string (e.g. 5.15.0-89-generic)"""
    return platform.release()


def get_architecture() -> str:
    """Get machine hardware architecture (e.g. x86_64, aarch64)"""
    return platform.machine()


def get_os_info() -> Dict[str, str]:
    """
    Get detailed OS identification. Inspects /etc/os-release and fallback release files.
    Identifies Ubuntu, Debian, Kali, Mint, Fedora, RHEL, CentOS, Arch, and POSIX.
    """
    info = {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'distro_id': 'unknown',
        'distro_name': platform.system(),
        'distro_version': '',
        'package_manager': 'unknown'
    }

    # Inspect /etc/os-release if present (standard on modern Linux)
    os_release_path = "/etc/os-release"
    if not os.path.exists(os_release_path) and os.path.exists("/usr/lib/os-release"):
        os_release_path = "/usr/lib/os-release"

    if os.path.exists(os_release_path):
        try:
            with open(os_release_path, "r", encoding="utf-8", errors="replace") as f:
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
        except Exception:
            pass

    # Detect package manager
    for pm in ['apt-get', 'dnf', 'yum', 'pacman', 'zypper', 'apk']:
        if os.path.exists(f"/usr/bin/{pm}") or os.path.exists(f"/bin/{pm}"):
            info['package_manager'] = pm
            break

    return info


def get_current_user() -> str:
    """Get username running the current process"""
    user = os.getenv('USER') or os.getenv('USERNAME')
    if user:
        return user
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "unknown"


def is_root() -> bool:
    """Check if the current process holds root / administrator privileges"""
    if hasattr(os, 'geteuid'):
        return os.geteuid() == 0
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def get_sudo_version() -> Optional[str]:
    """Get sudo version string safely without spawning interactive prompts"""
    out = run_command("sudo -V")
    if out:
        first_line = out.splitlines()[0]
        match = re.search(r'Sudo version ([0-9a-zA-Z._-]+)', first_line, re.IGNORECASE)
        if match:
            return match.group(1)
        return first_line.strip()
    return None


def get_shell() -> str:
    """Get default login shell"""
    return os.getenv('SHELL', '/bin/sh')


def check_file_writable(file_path: str) -> bool:
    """Check if file is writable by current execution context"""
    return os.access(file_path, os.W_OK)


def check_file_readable(file_path: str) -> bool:
    """Check if file is readable by current execution context"""
    return os.access(file_path, os.R_OK)


def get_file_permissions(file_path: str) -> Optional[str]:
    """Get file permissions in octal format (e.g. 0644, 4755)"""
    try:
        st = os.stat(file_path)
        return oct(st.st_mode)[-4:]
    except Exception:
        return None
