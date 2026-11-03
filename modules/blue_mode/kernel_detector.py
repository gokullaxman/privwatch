"""
PrivWatch 3.0 - Kernel Exploit & Fault Detector (Blue Team Mode)
Analyzes kernel diagnostics (dmesg / kern.log) to detect kernel crashes, ring-buffer memory faults,
and exploit signatures, avoiding false alerts on ordinary user-space application crashes.
"""

from datetime import datetime, timezone
import os
import re
import shutil
import subprocess
from typing import List, Optional, Any

from core.log_parser import LogParser, Finding
from core.models import SecurityEvent, Severity, utc_now
from config.settings import VECTOR_KERNEL


class KernelDetector(LogParser):
    """Detects kernel memory faults and exploitation indicators in kernel diagnostic buffers"""

    def __init__(self, config: Optional[Any] = None):
        super().__init__(VECTOR_KERNEL, config)

    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Inspect dmesg / kernel diagnostic records for kernel attack indicators"""
        lines = self._get_kernel_log_lines()
        if not lines:
            return self.findings

        # Specific signatures indicating kernel-level privilege escalation or severe corruption
        critical_kernel_patterns = [
            (r'kernel BUG at', 'Kernel BUG Trap Triggered', Severity.CRITICAL.value),
            (r'BUG: unable to handle page fault for address', 'Kernel Page Fault at Kernel Address', Severity.CRITICAL.value),
            (r'general protection fault:.*\[#1\]', 'Kernel Ring-0 General Protection Fault', Severity.CRITICAL.value),
            (r'Kernel panic - not syncing', 'System Kernel Panic', Severity.CRITICAL.value),
            (r'refcount_t: underflow; use-after-free', 'Kernel Refcount Underflow (Use-After-Free Indicator)', Severity.CRITICAL.value),
            (r'Corrupted page table', 'Kernel Page Table Corruption', Severity.CRITICAL.value)
        ]

        for line in lines[-1000:]:  # Check most recent 1000 lines
            line = line.strip()
            if not line:
                continue

            for pattern, title, sev in critical_kernel_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(
                        severity=sev,
                        title=title,
                        description=f"Kernel diagnostic buffer recorded critical failure: {line}",
                        affected_resource="kernel_subsystem",
                        evidence={'log_line': line, 'pattern': pattern},
                        detection_method="dmesg_pattern_analysis",
                        risk_explanation="Kernel memory corruption or ring-0 faults often indicate active local kernel exploitation attempts.",
                        remediation="Investigate running binaries at the timestamp; review kernel core dump if available.",
                        confidence=0.90
                    )
                    self.add_event(
                        timestamp=utc_now(),
                        event_type="KERNEL_FAULT",
                        source="dmesg",
                        details={'line': line, 'pattern': pattern},
                        severity=sev
                    )
                    break

        return self.findings

    def _get_kernel_log_lines(self) -> List[str]:
        """Read kernel messages via dmesg command or /var/log/kern.log"""
        # Try dmesg command
        dmesg_bin = shutil.which("dmesg")
        if dmesg_bin:
            try:
                res = subprocess.run([dmesg_bin, "-T"], capture_output=True, text=True, timeout=10)
                if res.returncode == 0 and res.stdout:
                    return res.stdout.splitlines()
            except Exception:
                pass

        # Try /var/log/kern.log
        for kp in ["/var/log/kern.log", "/var/log/messages"]:
            if os.path.exists(kp) and os.access(kp, os.R_OK):
                try:
                    with open(kp, "r", encoding="utf-8", errors="replace") as f:
                        return f.readlines()
                except Exception:
                    pass

        return []
