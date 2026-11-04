"""
UATU Linux Edition - Extended Standardized Event Schema
Strictly typed, versioned, cryptographic-integrity backed event schema for Linux endpoint telemetry.
Enforces UTC timezone-aware timestamps, provenance classification, data origin tracking,
explicit confidence range validation (preserving 0.0), and canonical JSON SHA-256 integrity hashing.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import secrets
import time
from typing import Dict, List, Optional, Any, Union


class ProvenanceClass(str, Enum):
    OBSERVED = "OBSERVED"              # Directly observed from system telemetry (e.g. procfs, auditd)
    DERIVED = "DERIVED"                # Derived via deterministic rules or normalization
    CORRELATED = "CORRELATED"          # Produced by multi-event correlation engine
    ML_INFERENCE = "ML_INFERENCE"      # Output of a machine learning or statistical model
    ANALYST = "ANALYST"                # Manually entered or annotated by a human analyst


class SourceClassification(str, Enum):
    """Explicit classifications for event provenance and ingestion channels."""
    LIVE_AUDITD = "LIVE_AUDITD"
    LIVE_AUTH_LOG = "LIVE_AUTH_LOG"
    LIVE_PROCESS_OBSERVATION = "LIVE_PROCESS_OBSERVATION"
    SYNTHETIC_TEST = "SYNTHETIC_TEST"
    REPLAYED_EVENT = "REPLAYED_EVENT"
    IMPORTED_EVENT = "IMPORTED_EVENT"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"


class DataOrigin(str, Enum):
    LIVE_TELEMETRY = "LIVE_TELEMETRY"  # Captured live from running host
    HISTORICAL_LOG = "HISTORICAL_LOG"  # Parsed from historical system log files
    STATIC_SCAN = "STATIC_SCAN"        # Generated from static posture/system audits
    TEST_FIXTURE = "TEST_FIXTURE"      # Explicitly marked synthetic testing data


class CollectionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    DROPPED = "DROPPED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNAVAILABLE = "UNAVAILABLE"


class CollectionMethod(str, Enum):
    PROCFS = "PROCFS"
    AUDITD_NETLINK = "AUDITD_NETLINK"
    AUDITD_LOG = "AUDITD_LOG"
    SYSTEMD_JOURNAL = "SYSTEMD_JOURNAL"
    AUTH_LOG = "AUTH_LOG"
    SECURE_LOG = "SECURE_LOG"
    SYSLOG = "SYSLOG"
    NETLINK_ROUTE = "NETLINK_ROUTE"
    BPF = "BPF"
    STATIC_AUDIT = "STATIC_AUDIT"
    CONTAINER_API = "CONTAINER_API"
    UNKNOWN = "UNKNOWN"


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


def generate_event_id() -> str:
    """Generate a monotonic, time-ordered, collision-resistant event identifier."""
    # Millisecond timestamp prefix (48-bit equivalent in hex) + 16 random hex characters
    ms = int(time.time() * 1000)
    rnd = secrets.token_hex(8)
    return f"evt_{ms:012x}_{rnd}"


def ensure_utc_aware(dt: Optional[datetime]) -> datetime:
    """Ensure datetime is timezone-aware and set to UTC."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        raise ValueError(f"Naive datetime rejected: '{dt}'. Event timestamps must be timezone-aware UTC.")
    return dt.astimezone(timezone.utc)


def format_iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """Format timezone-aware datetime as ISO 8601 string."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso_utc(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 string into timezone-aware UTC datetime."""
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class UatuEvent:
    """
    Standardized Linux Endpoint Security Telemetry Event.
    Every event carries cryptographic provenance, explicit origin tagging, and zero fabricated telemetry.
    """
    event_id: str = field(default_factory=generate_event_id)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    host_id: str = "unknown"
    hostname: str = "unknown"
    source: str = "unknown"
    source_event_id: Optional[str] = None
    collection_method: Union[CollectionMethod, str] = CollectionMethod.UNKNOWN
    event_type: str = "GENERIC_EVENT"
    severity: Union[EventSeverity, str] = EventSeverity.INFO
    uid: Optional[int] = None
    euid: Optional[int] = None
    suid: Optional[int] = None
    gid: Optional[int] = None
    egid: Optional[int] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_start_time: Optional[datetime] = None
    session_id: Optional[int] = None
    audit_event_id: Optional[str] = None
    exe: Optional[str] = None
    command: Optional[str] = None
    syscall: Optional[str] = None
    user: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_ref: Optional[str] = None
    provenance_class: Union[ProvenanceClass, str] = ProvenanceClass.OBSERVED
    data_origin: Union[DataOrigin, str] = DataOrigin.LIVE_TELEMETRY
    confidence: Optional[float] = 1.0
    collection_status: Union[CollectionStatus, str] = CollectionStatus.SUCCESS
    source_classification: Union[SourceClassification, str] = SourceClassification.UNKNOWN_SOURCE
    collection_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_record_id: Optional[str] = None
    integrity_hash: Optional[str] = None

    def is_synthetic(self) -> bool:
        """Return True if this event is synthetic test data, never live telemetry."""
        return (
            self.data_origin == DataOrigin.TEST_FIXTURE or
            self.source_classification == SourceClassification.SYNTHETIC_TEST
        )

    def __post_init__(self):
        # 1. Enforce timezone-aware UTC timestamp
        if self.timestamp.tzinfo is None:
            raise ValueError(f"Naive datetime rejected for timestamp: '{self.timestamp}'. Must be timezone-aware UTC.")
        self.timestamp = self.timestamp.astimezone(timezone.utc)

        if self.collection_timestamp.tzinfo is None:
            self.collection_timestamp = self.collection_timestamp.replace(tzinfo=timezone.utc)
        else:
            self.collection_timestamp = self.collection_timestamp.astimezone(timezone.utc)

        if self.process_start_time is not None:
            if self.process_start_time.tzinfo is None:
                raise ValueError(f"Naive datetime rejected for process_start_time: '{self.process_start_time}'.")
            self.process_start_time = self.process_start_time.astimezone(timezone.utc)

        # 2. Strict confidence validation (preserve 0.0, reject out-of-range)
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)):
                raise TypeError(f"Confidence must be float or None, got: {type(self.confidence)}")
            self.confidence = float(self.confidence)
            if self.confidence < 0.0 or self.confidence > 1.0:
                raise ValueError(f"Confidence score must be in range [0.0, 1.0], got: {self.confidence}")

        # 3. Enum normalization & validation
        if isinstance(self.provenance_class, str):
            try:
                self.provenance_class = ProvenanceClass(self.provenance_class.upper())
            except ValueError:
                raise ValueError(f"Invalid provenance_class: '{self.provenance_class}'. Valid: {[e.value for e in ProvenanceClass]}")

        if isinstance(self.data_origin, str):
            try:
                self.data_origin = DataOrigin(self.data_origin.upper())
            except ValueError:
                raise ValueError(f"Invalid data_origin: '{self.data_origin}'. Valid: {[e.value for e in DataOrigin]}")

        if isinstance(self.collection_status, str):
            try:
                self.collection_status = CollectionStatus(self.collection_status.upper())
            except ValueError:
                raise ValueError(f"Invalid collection_status: '{self.collection_status}'. Valid: {[e.value for e in CollectionStatus]}")

        if isinstance(self.collection_method, str):
            try:
                self.collection_method = CollectionMethod(self.collection_method.upper())
            except ValueError:
                self.collection_method = CollectionMethod.UNKNOWN

        if isinstance(self.severity, str):
            try:
                self.severity = EventSeverity(self.severity.upper())
            except ValueError:
                self.severity = EventSeverity.INFO

        if isinstance(self.source_classification, str):
            try:
                self.source_classification = SourceClassification(self.source_classification.upper())
            except ValueError:
                self.source_classification = SourceClassification.UNKNOWN_SOURCE

        # Infer source classification when UNKNOWN_SOURCE
        if self.source_classification == SourceClassification.UNKNOWN_SOURCE:
            if self.data_origin == DataOrigin.TEST_FIXTURE:
                self.source_classification = SourceClassification.SYNTHETIC_TEST
            elif self.collection_method in (CollectionMethod.AUDITD_NETLINK, CollectionMethod.AUDITD_LOG):
                self.source_classification = SourceClassification.LIVE_AUDITD
            elif self.collection_method in (CollectionMethod.AUTH_LOG, CollectionMethod.SECURE_LOG, CollectionMethod.SYSTEMD_JOURNAL):
                self.source_classification = SourceClassification.LIVE_AUTH_LOG
            elif self.collection_method == CollectionMethod.PROCFS:
                self.source_classification = SourceClassification.LIVE_PROCESS_OBSERVATION

        # Strict invariant: Never allow synthetic events to masquerade as live host telemetry
        if self.data_origin == DataOrigin.TEST_FIXTURE and self.source_classification in (
            SourceClassification.LIVE_AUDITD,
            SourceClassification.LIVE_AUTH_LOG,
            SourceClassification.LIVE_PROCESS_OBSERVATION
        ):
            raise ValueError(
                f"Provenance Violation: Synthetic test event {self.event_id} cannot be tagged with live classification: {self.source_classification}"
            )
        if self.source_classification == SourceClassification.SYNTHETIC_TEST and self.data_origin == DataOrigin.LIVE_TELEMETRY:
            raise ValueError(
                f"Provenance Violation: Synthetic test event {self.event_id} cannot have data_origin=LIVE_TELEMETRY"
            )

        # Sync source_record_id from audit_event_id if available
        if not self.source_record_id and self.audit_event_id:
            self.source_record_id = self.audit_event_id

        # 4. Compute deterministic integrity hash if not provided
        if not self.integrity_hash:
            self.integrity_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Calculate deterministic SHA-256 hash over canonical event attributes."""
        canonical_dict = {
            "event_id": self.event_id,
            "timestamp": format_iso_utc(self.timestamp),
            "host_id": self.host_id,
            "hostname": self.hostname,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "collection_method": self.collection_method.value if isinstance(self.collection_method, Enum) else str(self.collection_method),
            "event_type": self.event_type,
            "severity": self.severity.value if isinstance(self.severity, Enum) else str(self.severity),
            "uid": self.uid,
            "euid": self.euid,
            "suid": self.suid,
            "gid": self.gid,
            "egid": self.egid,
            "pid": self.pid,
            "ppid": self.ppid,
            "exe": self.exe,
            "command": self.command,
            "syscall": self.syscall,
            "user": self.user,
            "evidence": self.evidence,
            "evidence_ref": self.evidence_ref,
            "provenance_class": self.provenance_class.value if isinstance(self.provenance_class, Enum) else str(self.provenance_class),
            "data_origin": self.data_origin.value if isinstance(self.data_origin, Enum) else str(self.data_origin),
            "source_classification": self.source_classification.value if isinstance(self.source_classification, Enum) else str(self.source_classification),
            "source_record_id": self.source_record_id,
            "confidence": self.confidence,
            "collection_status": self.collection_status.value if isinstance(self.collection_status, Enum) else str(self.collection_status)
        }
        try:
            serialized = json.dumps(canonical_dict, sort_keys=True, default=str)
        except Exception:
            serialized = str(canonical_dict)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that current fields match the recorded integrity hash."""
        return self.compute_hash() == self.integrity_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to serialized dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": format_iso_utc(self.timestamp),
            "collection_timestamp": format_iso_utc(self.collection_timestamp),
            "host_id": self.host_id,
            "hostname": self.hostname,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "source_record_id": self.source_record_id,
            "source_classification": self.source_classification.value if isinstance(self.source_classification, Enum) else str(self.source_classification),
            "collection_method": self.collection_method.value if isinstance(self.collection_method, Enum) else str(self.collection_method),
            "event_type": self.event_type,
            "severity": self.severity.value if isinstance(self.severity, Enum) else str(self.severity),
            "uid": self.uid,
            "euid": self.euid,
            "suid": self.suid,
            "gid": self.gid,
            "egid": self.egid,
            "pid": self.pid,
            "ppid": self.ppid,
            "process_start_time": format_iso_utc(self.process_start_time) if self.process_start_time else None,
            "session_id": self.session_id,
            "audit_event_id": self.audit_event_id,
            "exe": self.exe,
            "command": self.command,
            "syscall": self.syscall,
            "user": self.user,
            "evidence": self.evidence,
            "evidence_ref": self.evidence_ref,
            "provenance_class": self.provenance_class.value if isinstance(self.provenance_class, Enum) else str(self.provenance_class),
            "data_origin": self.data_origin.value if isinstance(self.data_origin, Enum) else str(self.data_origin),
            "confidence": self.confidence,
            "collection_status": self.collection_status.value if isinstance(self.collection_status, Enum) else str(self.collection_status),
            "integrity_hash": self.integrity_hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UatuEvent":
        """Reconstruct UatuEvent from dictionary."""
        d = dict(data)
        if isinstance(d.get("timestamp"), str):
            d["timestamp"] = parse_iso_utc(d["timestamp"]) or datetime.now(timezone.utc)
        if isinstance(d.get("collection_timestamp"), str):
            d["collection_timestamp"] = parse_iso_utc(d["collection_timestamp"]) or datetime.now(timezone.utc)
        if isinstance(d.get("process_start_time"), str):
            d["process_start_time"] = parse_iso_utc(d["process_start_time"])
        return cls(**d)

