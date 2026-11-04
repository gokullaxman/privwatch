"""
PrivWatch 3.0 - Base Scanner Architecture
Abstract base class for all Red Team enumeration and security assessment modules.
Enforces Linux-native interfaces and safe subprocess execution (shell=False).
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
from typing import Dict, List, Any, Optional, Union

from core.models import Finding, Severity, utc_now
from core.logger import Logger
from core.command_exec import LinuxCommandRunner, CommandExecutionResult


class BaseScanner(ABC):
    """Abstract base class for Red Team privilege escalation scanners"""

    def __init__(self, vector_name: str, config: Optional[Any] = None):
        self.vector_name = vector_name
        self.config = config
        self.findings: List[Finding] = []

    def run_command(self, cmd: Union[str, List[str]], timeout: int = 30) -> str:
        """
        Execute command safely using LinuxCommandRunner (shell=False).
        Returns stripped stdout if successful, or empty string on failure.
        """
        result = LinuxCommandRunner.execute(cmd, timeout=timeout)
        if result.success:
            return result.stdout.strip()
        return ""

    def run_command_detailed(self, cmd: Union[str, List[str]], timeout: int = 30) -> CommandExecutionResult:
        """Execute command safely and return full structured result."""
        return LinuxCommandRunner.execute(cmd, timeout=timeout)

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: Any, remediation: str = "",
                    affected_resource: str = "", risk_explanation: str = "",
                    references: Optional[List[str]] = None,
                    confidence: float = 0.90,
                    detection_method: str = "static_audit",
                    rule_id: str = "",
                    attack_preconditions: str = "",
                    validation_procedure: str = "") -> Finding:
        """Construct, record, and return an evidence-backed Finding"""
        evidence_dict = evidence if isinstance(evidence, dict) else {'raw_evidence': str(evidence)}

        inferred_rule = rule_id or f"RULE_{self.vector_name.replace('/', '_').upper()}"
        val_proc = validation_procedure or f"Run manual verification: ls -la {affected_resource or evidence_dict.get('path', '')}"

        finding = Finding(
            finding_id=f"fnd_{self.vector_name[:3].lower()}_{secrets.token_hex(6)}",
            rule_id=inferred_rule,
            vector=self.vector_name,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            affected_resource=affected_resource or str(evidence_dict.get('path', '')),
            evidence=evidence_dict,
            detection_method=detection_method,
            attack_preconditions=attack_preconditions,
            risk_explanation=risk_explanation or description,
            remediation=remediation,
            validation_procedure=val_proc,
            references=references or [],
            timestamp=utc_now()
        )
        self.findings.append(finding)
        return finding

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Execute assessment and return discovered findings"""
        pass
