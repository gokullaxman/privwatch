"""
PrivWatch 3.0 - Container Privilege & Breakout Scanner (Red Team Mode)
Audits container environments, exposed docker sockets, privileged flags, and breakout vectors.
"""

import os
from pathlib import Path
from typing import List, Optional, Any

from core.scanner import BaseScanner, Finding
from core.models import Severity
from utils.file_utils import get_file_stat_metadata


class ContainerScanner(BaseScanner):
    """Audits containerization boundaries and container privilege escalation vectors"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__("CONTAINER_PRIVILEGE", config)

    def scan(self) -> List[Finding]:
        """Execute container privilege audit"""
        is_container = self._check_is_container()

        # Audit docker socket access (applicable both inside and outside container)
        self._check_docker_socket()

        if is_container:
            self._check_privileged_container_indicators()

        return self.findings

    def _check_is_container(self) -> bool:
        """Determine if current environment is running inside a container"""
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            return True

        if os.path.exists("/proc/1/cgroup"):
            try:
                with open("/proc/1/cgroup", "r", encoding="utf-8", errors="replace") as f:
                    cgroup = f.read()
                    if any(engine in cgroup for engine in ["docker", "containerd", "kubepods", "lxc"]):
                        return True
            except Exception:
                pass
        return False

    def _check_docker_socket(self):
        """Check for accessible docker.sock / containerd.sock"""
        socket_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/containerd/containerd.sock"
        ]

        for sock in socket_paths:
            if os.path.exists(sock):
                # Check write permissions
                if os.access(sock, os.W_OK):
                    self.add_finding(
                        severity=Severity.CRITICAL.value,
                        title=f"Writable Docker/Container Socket: {sock}",
                        description=f"The container runtime socket {sock} is writable by the current user.",
                        affected_resource=sock,
                        evidence=get_file_stat_metadata(sock),
                        detection_method="container_socket_permission_audit",
                        risk_explanation="Direct root compromise. Any process with write access to the Docker socket can spawn a container with host filesystem mounted to execute commands as host root.",
                        remediation=f"Restrict socket access to the docker group and root: chmod 660 {sock} && chown root:docker {sock}",
                        references=["https://attack.mitre.org/techniques/T1611/"],
                        confidence=1.0
                    )

    def _check_privileged_container_indicators(self):
        """Audit container for privileged breakout indicators"""
        # 1. Check if raw disk devices are exposed
        if os.path.exists("/dev/sda") or os.path.exists("/dev/vda") or os.path.exists("/dev/nvme0n1"):
            self.add_finding(
                severity=Severity.CRITICAL.value,
                title="Privileged Container: Host Block Devices Exposed",
                description="Host block devices (/dev/sda, /dev/vda, etc.) are accessible inside this container.",
                affected_resource="/dev",
                evidence={'devices_present': True},
                detection_method="container_device_inspection",
                risk_explanation="Indicates container was started with --privileged. An attacker inside the container can mount the host filesystem directly.",
                remediation="Do not run containers with --privileged. Use specific granular Linux capabilities instead.",
                references=["https://attack.mitre.org/techniques/T1611/"],
                confidence=0.98
            )

        # 2. Check /proc/kcore access
        if os.path.exists("/proc/kcore") and os.access("/proc/kcore", os.R_OK):
            self.add_finding(
                severity=Severity.HIGH.value,
                title="Readable /proc/kcore Inside Container",
                description="Kernel memory (/proc/kcore) is exposed and readable inside the container.",
                affected_resource="/proc/kcore",
                evidence={'kcore_accessible': True},
                detection_method="proc_kcore_audit",
                risk_explanation="Allows memory extraction and potential kernel exploitation.",
                remediation="Ensure container security profiles (AppArmor, Seccomp) mask /proc/kcore.",
                confidence=0.90
            )
