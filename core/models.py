"""
PrivWatch 3.0 - Standardized Data Models
Strictly typed, evidence-backed security entities for events, findings, incidents, and telemetry health.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Dict, List, Optional, Any
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


def utc_now() -> datetime:
    """Return current UTC datetime with timezone awareness"""
    return datetime.now(timezone.utc)


def format_iso(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime as ISO-8601 UTC string"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 timestamp string into timezone-aware datetime"""
    if not ts:
        return None
    try:
        # Handle trailing Z
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@dataclass
class SecurityEvent:
    """
    Normalized Security Event representing an observed system telemetry record.
    Strictly forbids fabricated fields; unknown attributes default to None.
    """
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}")
    timestamp: datetime = field(default_factory=utc_now)
    hostname: str = "unknown"
    source: str = "unknown"  # e.g., 'auditd', 'journald', 'auth.log', 'procfs'
    event_type: str = "GENERIC_EVENT"
    severity: str = Severity.INFO.value
    user: Optional[str] = None
    uid: Optional[int] = None
    euid: Optional[int] = None
    gid: Optional[int] = None
    egid: Optional[int] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process: Optional[str] = None
    command: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    is_test_fixture: bool = False

    def evidence_hash(self) -> str:
        """Calculate SHA-256 digest of evidence dictionary for provenance verification"""
        try:
            serialized = json.dumps(self.evidence, sort_keys=True, default=str)
        except Exception:
            serialized = str(self.evidence)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary"""
        data = asdict(self)
        data['timestamp'] = format_iso(self.timestamp)
        data['evidence_hash'] = self.evidence_hash()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Reconstruct event from dictionary"""
        d = dict(data)
        d.pop('evidence_hash', None)
        if isinstance(d.get('timestamp'), str):
            d['timestamp'] = parse_iso(d['timestamp']) or utc_now()
        return cls(**d)


@dataclass
class Finding:
    """
    Standardized security weakness or configuration defect identified by Red Team audits.
    Every finding must include real evidence, detection methodology, and defensive remediation.
    """
    finding_id: str = field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:16]}")
    vector: str = "GENERIC"  # e.g., 'SUID/SGID', 'SUDO', 'CAPABILITIES', 'CRON', 'KERNEL'
    severity: str = Severity.MEDIUM.value
    confidence: float = 0.90
    title: str = ""
    description: str = ""
    affected_resource: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    detection_method: str = "static_audit"
    risk_explanation: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=utc_now)
    is_test_fixture: bool = False

    def evidence_hash(self) -> str:
        """Compute SHA-256 digest of evidence for integrity verification"""
        try:
            serialized = json.dumps(self.evidence, sort_keys=True, default=str)
        except Exception:
            serialized = str(self.evidence)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        data = asdict(self)
        data['timestamp'] = format_iso(self.timestamp)
        data['evidence_hash'] = self.evidence_hash()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Reconstruct finding from dictionary"""
        d = dict(data)
        d.pop('evidence_hash', None)
        if isinstance(d.get('timestamp'), str):
            d['timestamp'] = parse_iso(d['timestamp']) or utc_now()
        return cls(**d)


@dataclass
class Incident:
    """
    Correlated security incident combining multiple verified events into an attack sequence.
    """
    incident_id: str = field(default_factory=lambda: f"inc_{uuid.uuid4().hex[:16]}")
    title: str = ""
    severity: str = Severity.HIGH.value
    confidence: float = 0.85
    hypothesis: str = ""
    attribution: Dict[str, Any] = field(default_factory=dict)
    event_ids: List[str] = field(default_factory=list)
    status: str = IncidentStatus.NEW.value
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    is_test_fixture: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary"""
        data = asdict(self)
        data['created_at'] = format_iso(self.created_at)
        data['updated_at'] = format_iso(self.updated_at)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        """Reconstruct incident from dictionary"""
        d = dict(data)
        if isinstance(d.get('created_at'), str):
            d['created_at'] = parse_iso(d['created_at']) or utc_now()
        if isinstance(d.get('updated_at'), str):
            d['updated_at'] = parse_iso(d['updated_at']) or utc_now()
        return cls(**d)


@dataclass
class TelemetrySourceStatus:
    """Health metrics for an individual system telemetry source"""
    name: str
    path_or_cmd: str
    available: bool
    readable: bool
    error_message: Optional[str] = None
    event_count: int = 0
    last_collected_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'path_or_cmd': self.path_or_cmd,
            'available': self.available,
            'readable': self.readable,
            'error_message': self.error_message,
            'event_count': self.event_count,
            'last_collected_at': format_iso(self.last_collected_at)
        }


@dataclass
class TelemetryHealth:
    """Aggregated telemetry collection health across all system sources"""
    hostname: str
    timestamp: datetime = field(default_factory=utc_now)
    sources: Dict[str, TelemetrySourceStatus] = field(default_factory=dict)
    overall_coverage_pct: float = 0.0
    ingestion_rate_eps: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hostname': self.hostname,
            'timestamp': format_iso(self.timestamp),
            'sources': {k: v.to_dict() for k, v in self.sources.items()},
            'overall_coverage_pct': round(self.overall_coverage_pct, 1),
            'ingestion_rate_eps': round(self.ingestion_rate_eps, 2)
        }


@dataclass
class SystemPosture:
    """Mathematical security posture calculated strictly from verified findings"""
    score: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_findings: int
    status: str
    calculated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'score': self.score,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'total_findings': self.total_findings,
            'status': self.status,
            'calculated_at': format_iso(self.calculated_at)
        }

    @staticmethod
    def calculate(findings: List[Finding]) -> "SystemPosture":
        """
        Compute security posture score (0 - 100) strictly from findings.
        Formula:
          Base score: 100
          Penalty: Critical = 25, High = 10, Medium = 3, Low = 1, Info = 0
          Minimum score: 0
        """
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL.value)
        high = sum(1 for f in findings if f.severity == Severity.HIGH.value)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM.value)
        low = sum(1 for f in findings if f.severity == Severity.LOW.value)
        info = sum(1 for f in findings if f.severity == Severity.INFO.value)

        penalty = (crit * 25) + (high * 10) + (med * 3) + (low * 1)
        score = max(0, 100 - penalty)

        if score >= 90:
            status = "HEALTHY"
        elif score >= 70:
            status = "ATTENTION_NEEDED"
        elif score >= 40:
            status = "VULNERABLE"
        else:
            status = "CRITICAL_RISK"

        return SystemPosture(
            score=score,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            total_findings=len(findings),
            status=status,
            calculated_at=utc_now()
        )
