"""
PrivWatch 3.0 - Base Log & Telemetry Parser
Abstract base class for all Blue Team telemetry collection and log forensics modules.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import re
from typing import List, Dict, Any, Optional

from core.models import SecurityEvent, Finding, Severity, utc_now, parse_iso
from core.scanner import BaseScanner


# Backwards compatibility alias
LogEvent = SecurityEvent


class LogParser(ABC):
    """Abstract base class for log parsing and telemetry collection modules"""

    def __init__(self, vector_name: str, config: Optional[Any] = None):
        self.vector_name = vector_name
        self.config = config
        self.findings: List[Finding] = []
        self.events: List[SecurityEvent] = []

    def parse_syslog_timestamp(self, line: str) -> Optional[datetime]:
        """
        Parse timestamp across diverse syslog and journal formats:
        - RFC5424 / ISO-8601: 2026-11-03T18:15:30.123Z or 2026-11-03T18:15:30+00:00
        - RFC3164: Oct  2 16:30:45 or Oct 12 16:30:45
        - Auditd format: msg=audit(1730657730.123:452)
        """
        line = line.strip()
        if not line:
            return None

        # 1. Auditd timestamp regex: msg=audit(1730657730.123:452)
        audit_match = re.search(r'msg=audit\((\d+(?:\.\d+)?):\d+\)', line)
        if audit_match:
            try:
                epoch = float(audit_match.group(1))
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            except Exception:
                pass

        # 2. ISO-8601 regex: 2026-11-03T...
        iso_match = re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', line)
        if iso_match:
            dt = parse_iso(iso_match.group(1))
            if dt:
                return dt

        # 3. Traditional BSD / RFC3164: Oct  4 13:51:21
        bsd_match = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', line)
        if bsd_match:
            month_str, day_str, time_str = bsd_match.groups()
            year = utc_now().year
            timestr = f"{year} {month_str} {int(day_str):02d} {time_str}"
            try:
                dt = datetime.strptime(timestr, "%Y %b %d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        return None

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: Any, remediation: str = "",
                    affected_resource: str = "", risk_explanation: str = "",
                    references: Optional[List[str]] = None,
                    confidence: float = 0.90,
                    detection_method: str = "log_telemetry") -> Finding:
        """Construct and record a verified Finding"""
        evidence_dict = evidence if isinstance(evidence, dict) else {'log_evidence': str(evidence)}

        finding = Finding(
            vector=self.vector_name,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            affected_resource=affected_resource or str(evidence_dict.get('source', '')),
            evidence=evidence_dict,
            detection_method=detection_method,
            risk_explanation=risk_explanation or description,
            remediation=remediation,
            references=references or [],
            timestamp=utc_now()
        )
        self.findings.append(finding)
        return finding

    def add_event(self, timestamp: Optional[datetime], event_type: str,
                  source: str, details: Dict[str, Any],
                  severity: str = Severity.INFO.value,
                  user: Optional[str] = None,
                  pid: Optional[int] = None,
                  ppid: Optional[int] = None,
                  process: Optional[str] = None,
                  command: Optional[str] = None,
                  confidence: float = 1.0) -> SecurityEvent:
        """Construct and register a normalized SecurityEvent"""
        event = SecurityEvent(
            timestamp=timestamp or utc_now(),
            source=source,
            event_type=event_type,
            severity=severity,
            user=user,
            pid=pid,
            ppid=ppid,
            process=process,
            command=command,
            evidence=details,
            confidence=confidence
        )
        self.events.append(event)
        return event

    @abstractmethod
    def parse(self, log_file: Optional[str] = None) -> List[Finding]:
        """Parse log file or telemetry stream and return verified findings"""
        pass

    def get_findings(self) -> List[Finding]:
        return self.findings

    def get_events(self) -> List[SecurityEvent]:
        return self.events
