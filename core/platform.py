"""
UATU Linux Edition - Platform Validation & Capability Discovery
Strictly enforces Linux-only native execution, inspects distribution metadata,
validates kernel virtual filesystems (/proc, /sys, /run), checks root/POSIX capabilities,
and inspects system security tool availability.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Dict, List, Optional, Any, Set


class UnsupportedPlatformError(RuntimeError):
    """Raised when UATU is executed on a non-Linux or unsupported operating system."""
    pass


@dataclass
class CapabilityReport:
    """Detailed capability and environmental report for the Linux host."""
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
    runfs_available: bool
    auditd_available: bool
    journalctl_available: bool
    getcap_available: bool
    systemctl_available: bool
    ebpf_available: bool
    network_tools_available: bool
    available_capabilities: List[str] = field(default_factory=list)
    unavailable_capabilities: List[str] = field(default_factory=list)
    permission_limited: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary."""
        return {
            "system": self.system,
            "kernel_release": self.kernel_release,
            "architecture": self.architecture,
            "distro_id": self.distro_id,
            "distro_name": self.distro_name,
            "distro_version": self.distro_version,
            "distro_codename": self.distro_codename,
            "is_root": self.is_root,
            "euid": self.euid,
            "egid": self.egid,
            "procfs_available": self.procfs_available,
            "sysfs_available": self.sysfs_available,
            "runfs_available": self.runfs_available,
            "auditd_available": self.auditd_available,
            "journalctl_available": self.journalctl_available,
            "getcap_available": self.getcap_available,
            "systemctl_available": self.systemctl_available,
            "ebpf_available": self.ebpf_available,
            "network_tools_available": self.network_tools_available,
            "available_capabilities": self.available_capabilities,
            "unavailable_capabilities": self.unavailable_capabilities,
            "permission_limited": self.permission_limited,
            "warnings": self.warnings
        }


# Backwards compatibility alias for PrivWatch 3.0
LinuxSystemReport = CapabilityReport


class LinuxPlatform:
    """Validates Linux platform compliance and inspects system security capabilities."""

    SUPPORTED_SYSTEMS: Set[str] = {"Linux"}
    SUPPORTED_ARCHITECTURES: Set[str] = {"x86_64", "aarch64", "arm64", "i686", "armv7l"}

    @classmethod
    def assert_linux(cls, strict: bool = True) -> CapabilityReport:
        """
        Verify that the host environment is native Linux and meets core requirements.
        Raises UnsupportedPlatformError if running on Windows, macOS, or unsupported OS.
        """
        current_system = platform.system()
        if current_system not in cls.SUPPORTED_SYSTEMS:
            err = (
                f"[FATAL ERROR] UATU Linux Edition requires a native Linux environment.\n"
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
        runfs_available = os.path.exists("/run") and os.path.isdir("/run")

        warnings: List[str] = []
        if not procfs_available:
            warnings.append("Virtual filesystem /proc is unavailable or unmounted. Process telemetry will fail.")
        if not sysfs_available:
            warnings.append("Virtual filesystem /sys is unavailable or unmounted. Hardware/kernel introspection may fail.")

        # Inspect Distribution Metadata from /etc/os-release
        distro_info = cls.parse_os_release()

        # Check User Identity & Privileges via Linux POSIX APIs
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        egid = os.getegid() if hasattr(os, "getegid") else -1
        is_root = (euid == 0)

        # Inspect System Utility Availability
        auditctl_bin = shutil.which("auditctl")
        audit_log_exists = os.path.exists("/var/log/audit/audit.log")
        auditd_available = bool(auditctl_bin or audit_log_exists)

        journalctl_available = bool(shutil.which("journalctl"))
        getcap_available = bool(shutil.which("getcap"))
        systemctl_available = bool(shutil.which("systemctl"))
        ebpf_available = bool(shutil.which("bpftool") or os.path.exists("/sys/fs/bpf"))
        network_tools_available = bool(shutil.which("ss") or shutil.which("ip") or shutil.which("netstat"))

        available_caps: List[str] = []
        unavailable_caps: List[str] = []
        permission_limited: Dict[str, str] = {}

        # Procfs
        if procfs_available:
            available_caps.append("procfs_telemetry")
        else:
            unavailable_caps.append("procfs_telemetry")

        # Sysfs
        if sysfs_available:
            available_caps.append("sysfs_introspection")
        else:
            unavailable_caps.append("sysfs_introspection")

        # Auditd
        if auditd_available:
            if is_root or os.access("/var/log/audit/audit.log", os.R_OK):
                available_caps.append("auditd_telemetry")
            else:
                permission_limited["auditd_telemetry"] = "Requires root (UID 0) or read permissions on /var/log/audit/audit.log"
        else:
            unavailable_caps.append("auditd_telemetry")

        # Journald
        if journalctl_available:
            available_caps.append("journald_telemetry")
        else:
            unavailable_caps.append("journald_telemetry")

        # Capabilities inspection
        if getcap_available:
            available_caps.append("posix_capabilities_audit")
        else:
            unavailable_caps.append("posix_capabilities_audit")

        # Systemd service inspection
        if systemctl_available:
            available_caps.append("systemd_management")
        else:
            unavailable_caps.append("systemd_management")

        # eBPF
        if ebpf_available:
            if is_root:
                available_caps.append("ebpf_probe")
            else:
                permission_limited["ebpf_probe"] = "eBPF subsystem requires root (UID 0) or CAP_BPF / CAP_SYS_ADMIN"
        else:
            unavailable_caps.append("ebpf_probe")

        # Root permission checks
        if not is_root:
            warnings.append(
                f"Running with unprivileged UID {euid}. Full audit & containment capabilities require root (UID 0) or specific capabilities (CAP_DAC_READ_SEARCH, CAP_KILL)."
            )
            permission_limited["process_containment"] = "Process termination (SIGTERM/SIGKILL) across users requires UID 0 or CAP_KILL"
            permission_limited["network_isolation"] = "iptables / nftables network disruption requires UID 0 or CAP_NET_ADMIN"
        else:
            available_caps.append("process_containment")
            available_caps.append("network_isolation")

        report = CapabilityReport(
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
            runfs_available=runfs_available,
            auditd_available=auditd_available,
            journalctl_available=journalctl_available,
            getcap_available=getcap_available,
            systemctl_available=systemctl_available,
            ebpf_available=ebpf_available,
            network_tools_available=network_tools_available,
            available_capabilities=available_caps,
            unavailable_capabilities=unavailable_caps,
            permission_limited=permission_limited,
            warnings=warnings
        )
        return report

    @classmethod
    def validate_platform(cls, strict: bool = True) -> CapabilityReport:
        """Alias for assert_linux to maintain backwards compatibility."""
        return cls.assert_linux(strict=strict)

    @classmethod
    def parse_os_release(cls) -> Dict[str, str]:
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


# Backwards compatibility class alias
LinuxPlatformValidator = LinuxPlatform

