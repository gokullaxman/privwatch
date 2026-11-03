"""
PrivWatch 3.0 - Base Scanner Architecture
Abstract base class for all Red Team enumeration and security assessment modules.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import subprocess
from typing import Dict, List, Any, Optional, Union

from core.models import Finding, Severity, utc_now
from core.logger import Logger


class BaseScanner(ABC):
    """Abstract base class for Red Team privilege escalation scanners"""

    def __init__(self, vector_name: str, config: Optional[Any] = None):
        self.vector_name = vector_name
        self.config = config
        self.findings: List[Finding] = []

    def run_command(self, cmd: Union[str, List[str]], timeout: int = 30) -> str:
        """
        Execute command safely using argument lists where possible.
        Applies strict timeout and error capture.
        """
        try:
            if isinstance(cmd, list):
                result = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.stdout.strip()
            else:
                # If string contains shell pipes or redirects, execute via sh safely if on POSIX
                if any(char in cmd for char in ['|', '>', '<', '&', ';', '$']):
                    shell_executable = '/bin/sh' if os.path.exists('/bin/sh') else None
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        executable=shell_executable,
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
        except subprocess.TimeoutExpired:
            return f"[ERROR] Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return ""
        except Exception as e:
            return f"[ERROR] Execution failed: {str(e)}"

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: Any, remediation: str = "",
                    affected_resource: str = "", risk_explanation: str = "",
                    references: Optional[List[str]] = None,
                    confidence: float = 0.90,
                    detection_method: str = "static_audit") -> Finding:
        """Construct, record, and return an evidence-backed Finding"""
        evidence_dict = evidence if isinstance(evidence, dict) else {'raw_evidence': str(evidence)}

        finding = Finding(
            vector=self.vector_name,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            affected_resource=affected_resource or str(evidence_dict.get('path', '')),
            evidence=evidence_dict,
            detection_method=detection_method,
            risk_explanation=risk_explanation or description,
            remediation=remediation,
            references=references or [],
            timestamp=utc_now()
        )
        self.findings.append(finding)
        return finding

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Execute scan and return list of findings"""
        pass
