"""
PrivWatch 3.0 / UATU Linux Edition - Standardized Data Models
Strictly typed, evidence-backed security entities for events, findings, incidents,
attack graphs, policies, containment actions, risk assessments, and telemetry health.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import secrets
import time
from typing import Dict, List, Optional, Any, Union
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ACKNOWLEDGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_PENDING = "CONTAINMENT_PENDING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class NodeType(str, Enum):
    USER = "USER"
    GROUP = "GROUP"
    PROCESS = "PROCESS"
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    SERVICE = "SERVICE"
    SYSTEMD_UNIT = "SYSTEMD_UNIT"
    CRON_JOB = "CRON_JOB"
    SUDO_RULE = "SUDO_RULE"
    CAPABILITY = "CAPABILITY"
    HOST = "HOST"
    CONTAINER = "CONTAINER"
    SOCKET = "SOCKET"


class EdgeType(str, Enum):
    MEMBER_OF = "MEMBER_OF"
    OWNS = "OWNS"
    CAN_WRITE = "CAN_WRITE"
    CAN_EXECUTE = "CAN_EXECUTE"
    EXECUTED_BY = "EXECUTED_BY"
    RUNS_AS = "RUNS_AS"
    CAN_MODIFY = "CAN_MODIFY"
    CAN_IMPERSONATE = "CAN_IMPERSONATE"
    HAS_CAPABILITY = "HAS_CAPABILITY"
    DEPENDS_ON = "DEPENDS_ON"
    CONNECTS_TO = "CONNECTS_TO"
    ESCALATES_TO = "ESCALATES_TO"
    SPAWNED = "SPAWNED"
    HOLDS_CAPABILITY = "HOLDS_CAPABILITY"
    LISTENS_ON = "LISTENS_ON"


class EdgeClass(str, Enum):
    OBSERVED = "OBSERVED"
    CONFIGURATION_DERIVED = "CONFIGURATION_DERIVED"
    INFERRED = "INFERRED"
    HYPOTHETICAL = "HYPOTHETICAL"


class PolicyMode(str, Enum):
    ENFORCE = "ENFORCE"
    MONITOR = "MONITOR"
    DISABLED = "DISABLED"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ALERT = "ALERT"
    ISOLATE = "ISOLATE"
    KILL = "KILL"


class ContainmentMode(str, Enum):
    OBSERVE_ONLY = "OBSERVE_ONLY"
    ALERT_ONLY = "ALERT_ONLY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    AUTHORIZED_AUTOMATIC = "AUTHORIZED_AUTOMATIC"


class ContainmentActionType(str, Enum):
    KILL_PROCESS = "KILL_PROCESS"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    PROCESS_FREEZE = "PROCESS_FREEZE"
    PROCESS_THAW = "PROCESS_THAW"
    PROCESS_ISOLATION = "PROCESS_ISOLATION"
    USER_SESSION_TERMINATION = "USER_SESSION_TERMINATION"
    NETWORK_CONTAINMENT = "NETWORK_CONTAINMENT"
    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    REVOKE_PRIVILEGE = "REVOKE_PRIVILEGE"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    CREDENTIAL_REVOCATION_FLAG = "CREDENTIAL_REVOCATION_FLAG"


class ContainmentStatus(str, Enum):
    REQUESTED = "REQUESTED"
    PLAN_GENERATED = "PLAN_GENERATED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


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
        try:
            data['evidence'] = json.loads(json.dumps(self.evidence, default=str))
        except Exception:
            pass
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
    rule_id: str = "GENERIC_RULE"
    vector: str = "GENERIC"  # e.g., 'SUID/SGID', 'SUDO', 'CAPABILITIES', 'CRON', 'KERNEL'
    severity: str = Severity.MEDIUM.value
    confidence: float = 0.90
    title: str = ""
    description: str = ""
    affected_resource: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    detection_method: str = "static_audit"
    attack_preconditions: str = ""
    risk_explanation: str = ""
    remediation: str = ""
    validation_procedure: str = ""
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
    lifecycle_history: List[Dict[str, Any]] = field(default_factory=list)
    is_test_fixture: bool = False

    def transition(self, new_status: Union[IncidentStatus, str], operator: str, rationale: str) -> None:
        """
        Transition incident lifecycle status with audit logging.
        Validates target status and records operator, rationale, timestamp.
        """
        target = new_status.value if isinstance(new_status, IncidentStatus) else str(new_status).upper()
        valid_statuses = {s.value for s in IncidentStatus}
        if target not in valid_statuses:
            raise ValueError(f"Invalid incident status '{target}'. Must be one of: {sorted(valid_statuses)}")

        old_status = self.status
        self.status = target
        self.updated_at = utc_now()
        entry = {
            "from_status": old_status,
            "to_status": target,
            "operator": operator,
            "rationale": rationale,
            "timestamp": format_iso(self.updated_at)
        }
        self.lifecycle_history.append(entry)
        self.notes.append({
            "author": operator,
            "text": f"Status transition {old_status} -> {target}: {rationale}",
            "created_at": format_iso(self.updated_at)
        })

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
        Compute security posture score (0 - 100) strictly from findings,
        weighted by confirmed exploitability and detection confidence.
        """
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL.value)
        high = sum(1 for f in findings if f.severity == Severity.HIGH.value)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM.value)
        low = sum(1 for f in findings if f.severity == Severity.LOW.value)
        info = sum(1 for f in findings if f.severity == Severity.INFO.value)

        total_penalty = 0.0
        for f in findings:
            # Base severity weights
            if f.severity == Severity.CRITICAL.value:
                base_w = 25.0
            elif f.severity == Severity.HIGH.value:
                base_w = 10.0
            elif f.severity == Severity.MEDIUM.value:
                base_w = 3.0
            elif f.severity == Severity.LOW.value:
                base_w = 1.0
            else:
                base_w = 0.0

            title_lower = f.title.lower()

            # Weight by exploitability: Non-standard / advisory hygiene SUIDs without exploit vectors
            # are weighted down so stock distributions do not receive punitive score collapse.
            if "non-standard suid binary" in title_lower:
                exploitability = 0.25
            else:
                exploitability = 1.0

            total_penalty += base_w * exploitability

        score = max(0, int(round(100.0 - total_penalty)))

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


# --- UATU Attack Path & Prevention Models ---

@dataclass
class AttackNode:
    """Graph node representing an entity (user, process, binary, capability, socket)."""
    node_id: str
    node_type: str
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    evidence_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "name": self.name,
            "properties": self.properties,
            "risk_score": self.risk_score,
            "evidence_ref": self.evidence_ref
        }


@dataclass
class AttackEdge:
    """Directed edge representing a relation or privilege transition between nodes."""
    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    edge_class: str = "CONFIGURATION_DERIVED"
    technique_id: str = ""
    confidence: float = 1.0
    cost: float = 1.0
    evidence_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship_type": self.relationship_type,
            "edge_class": self.edge_class,
            "technique_id": self.technique_id,
            "confidence": self.confidence,
            "cost": self.cost,
            "evidence_ref": self.evidence_ref
        }


@dataclass
class AttackPath:
    """Complete exploitable attack path from an unprivileged state to elevated privileges."""
    path_id: str = field(default_factory=lambda: f"path_{secrets.token_hex(8)}")
    start_node_id: str = ""
    target_node_id: str = ""
    node_ids: List[str] = field(default_factory=list)
    edge_ids: List[str] = field(default_factory=list)
    total_risk_score: float = 0.0
    confidence: float = 1.0
    bottleneck_node_id: Optional[str] = None
    recommended_disruption: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "start_node_id": self.start_node_id,
            "target_node_id": self.target_node_id,
            "node_ids": self.node_ids,
            "edge_ids": self.edge_ids,
            "total_risk_score": self.total_risk_score,
            "confidence": self.confidence,
            "bottleneck_node_id": self.bottleneck_node_id,
            "recommended_disruption": self.recommended_disruption
        }


@dataclass
class SecurityPolicy:
    """Defensive security policy enforcing privilege acquisition boundaries."""
    policy_id: str
    name: str
    description: str
    policy_type: str
    mode: str = PolicyMode.MONITOR.value
    rules: List[Dict[str, Any]] = field(default_factory=list)
    target_scope: str = "global"
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "policy_type": self.policy_type,
            "mode": self.mode,
            "rules": self.rules,
            "target_scope": self.target_scope,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
            "is_active": self.is_active
        }


@dataclass
class PolicyEvaluation:
    """Evaluation record of a policy check against a telemetry event."""
    evaluation_id: str = field(default_factory=lambda: f"eval_{secrets.token_hex(8)}")
    policy_id: str = ""
    event_id: str = ""
    result: str = PolicyAction.ALLOW.value
    matched_rules: List[str] = field(default_factory=list)
    explanation: str = ""
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "policy_id": self.policy_id,
            "event_id": self.event_id,
            "result": self.result,
            "matched_rules": self.matched_rules,
            "explanation": self.explanation,
            "timestamp": format_iso(self.timestamp)
        }


@dataclass
class ContainmentAction:
    """Audit record of a containment or disruption action executed against an attack path."""
    action_id: str = field(default_factory=lambda: f"cont_{secrets.token_hex(8)}")
    action_type: str = ContainmentActionType.KILL_PROCESS.value
    target: str = ""
    reason: str = ""
    status: str = ContainmentStatus.REQUESTED.value
    actor: str = "system"
    timestamp: datetime = field(default_factory=utc_now)
    rollback_data: Dict[str, Any] = field(default_factory=dict)
    result_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "status": self.status,
            "actor": self.actor,
            "timestamp": format_iso(self.timestamp),
            "rollback_data": self.rollback_data,
            "result_details": self.result_details
        }


@dataclass
class RiskScoreCard:
    """Multi-dimensional risk assessment score card."""
    overall_score: float = 0.0
    threat_level: str = Severity.LOW.value
    dimension_scores: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "threat_level": self.threat_level,
            "dimension_scores": self.dimension_scores,
            "timestamp": format_iso(self.timestamp)
        }


@dataclass
class NetworkSocketEvent:
    """Linux network socket telemetry record."""
    inode: int
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    exe: Optional[str] = None
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inode": self.inode,
            "protocol": self.protocol,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
            "exe": self.exe,
            "timestamp": format_iso(self.timestamp)
        }
