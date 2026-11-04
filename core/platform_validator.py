"""
PrivWatch 3.0 - Linux-Native Platform Validator
Enforces 100% Linux-native execution environment, validates kernel interfaces,
identifies distribution metadata, and checks system security dependencies.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Dict, List, Optional, Any


class UnsupportedPlatformError(RuntimeError):
    """Raised when PrivWatch is executed on a non-Linux or unsupported operating system."""
    pass


@dataclass
class LinuxSystemReport:
    """Detailed metadata representing the verified Linux host environment."""
    system: str
    kernel_release: str
    architecture: str
    distro_id: str
    distro_name: str
    distro_version: str
    distro_codename: str
    is_root: bool
    euid: int
    egid: int
    procfs_available: bool
    sysfs_available: bool
    auditd_available: bool
    journalctl_available: bool
    getcap_available: bool
    missing_dependencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class LinuxPlatformValidator:
    """Validates Linux platform compliance and inspects system capabilities."""

    SUPPORTED_SYSTEMS = {"Linux"}
    SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64", "arm64", "i686", "armv7l"}

    @classmethod
    def validate_platform(cls, strict: bool = True) -> LinuxSystemReport:
        """
        Verify that the host environment is native Linux and meets core requirements.
        Terminates or raises UnsupportedPlatformError if running on Windows, macOS, etc.
        """
        current_system = platform.system()
        if current_system not in cls.SUPPORTED_SYSTEMS:
            err = (
                f"[FATAL ERROR] PrivWatch 3.0 requires a native Linux environment.\n"
                f"Detected operating system: '{current_system}' ({sys.platform}).\n"
                f"Supported platforms: Kali Linux, Debian, Ubuntu, Fedora, RHEL, CentOS, Arch Linux.\n"
                f"Windows, macOS, and BSD systems are strictly unsupported."
            )
            if strict:
                raise UnsupportedPlatformError(err)

        arch = platform.machine()
        kernel = platform.release()

        # Check Linux Virtual Filesystems
        procfs_available = os.path.exists("/proc") and os.path.isdir("/proc") and os.path.exists("/proc/version")
        sysfs_available = os.path.exists("/sys") and os.path.isdir("/sys")

        warnings: List[str] = []
        if not procfs_available:
            warnings.append("Virtual filesystem /proc is unavailable or unmounted. Process telemetry will fail.")
        if not sysfs_available:
            warnings.append("Virtual filesystem /sys is unavailable or unmounted. Hardware/kernel introspection may fail.")

        # Inspect Distribution Metadata from /etc/os-release
        distro_info = cls._parse_os_release()

        # Check User Identity & Privileges via Linux POSIX APIs
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        egid = os.getegid() if hasattr(os, "getegid") else -1
        is_root = (euid == 0)

        if not is_root:
            warnings.append(
                f"Running with unprivileged UID {euid}. Full audit capabilities require root (UID 0) or CAP_DAC_READ_SEARCH."
            )

        # Inspect System Utility Availability
        auditd_available = bool(shutil.which("auditctl") or os.path.exists("/var/log/audit/audit.log"))
        journalctl_available = bool(shutil.which("journalctl"))
        getcap_available = bool(shutil.which("getcap"))

        missing_deps: List[str] = []
        if not getcap_available:
            missing_deps.append("libcap2-bin (getcap)")
        if not auditd_available:
            missing_deps.append("auditd (auditctl)")

        report = LinuxSystemReport(
            system=current_system,
            kernel_release=kernel,
            architecture=arch,
            distro_id=distro_info.get("id", "linux"),
            distro_name=distro_info.get("name", "Linux"),
            distro_version=distro_info.get("version_id", ""),
            distro_codename=distro_info.get("version_codename", ""),
            is_root=is_root,
            euid=euid,
            egid=egid,
            procfs_available=procfs_available,
            sysfs_available=sysfs_available,
            auditd_available=auditd_available,
            journalctl_available=journalctl_available,
            getcap_available=getcap_available,
            missing_dependencies=missing_deps,
            warnings=warnings
        )
        return report

    @classmethod
    def _parse_os_release(cls) -> Dict[str, str]:
        """Parse standard /etc/os-release or /usr/lib/os-release file."""
        candidates = ["/etc/os-release", "/usr/lib/os-release"]
        info: Dict[str, str] = {}

        for path in candidates:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                k, v = line.split("=", 1)
                                info[k.strip().lower()] = v.strip("\"'")
                    break
                except Exception:
                    continue

        return info

