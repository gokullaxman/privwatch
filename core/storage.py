"""
PrivWatch 3.0 - Persistence & Audit Storage Engine
SQLite-backed storage for normalized security events, findings, incidents, administrative audit trails, and suppression rules.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Any

from core.models import (
    SecurityEvent, Finding, Incident, IncidentStatus, Severity,
    utc_now, format_iso, parse_iso
)


class StorageEngine:
    """Thread-safe SQLite storage engine for PrivWatch platform"""

    def __init__(self, db_path: str = "./privwatch.db"):
        self.db_path = str(Path(db_path).resolve())
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with foreign keys and dict-like rows"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_db(self):
        """Initialize database schema if not present"""
        with self._get_connection() as conn:
            # Events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    hostname TEXT,
                    source TEXT,
                    event_type TEXT,
                    severity TEXT,
                    user TEXT,
                    uid INTEGER,
                    euid INTEGER,
                    gid INTEGER,
                    egid INTEGER,
                    pid INTEGER,
                    ppid INTEGER,
                    process TEXT,
                    command TEXT,
                    evidence_json TEXT,
                    confidence REAL,
                    is_test_fixture INTEGER DEFAULT 0
                )
            """)

            # Findings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    vector TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_resource TEXT,
                    evidence_json TEXT,
                    detection_method TEXT,
                    risk_explanation TEXT,
                    remediation TEXT,
                    references_json TEXT,
                    timestamp TEXT NOT NULL,
                    is_test_fixture INTEGER DEFAULT 0
                )
            """)

            # Incidents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    hypothesis TEXT,
                    attribution_json TEXT,
                    event_ids_json TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    notes_json TEXT,
                    is_test_fixture INTEGER DEFAULT 0
                )
            """)

            # Admin action audit trail
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    actor TEXT NOT NULL,
                    details_json TEXT,
                    result TEXT NOT NULL
                )
            """)

            # Alert suppression rules
            conn.execute("""
                CREATE TABLE IF NOT EXISTS suppression_rules (
                    rule_id TEXT PRIMARY KEY,
                    vector TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Indices
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_vector ON findings(vector)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            conn.commit()

    # --- Events ---

    def save_event(self, event: SecurityEvent):
        """Save a single normalized security event"""
        self.save_events([event])

    def save_events(self, events: List[SecurityEvent]):
        """Bulk save normalized security events"""
        if not events:
            return
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO events (
                    event_id, timestamp, hostname, source, event_type, severity,
                    user, uid, euid, gid, egid, pid, ppid, process, command,
                    evidence_json, confidence, is_test_fixture
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    e.event_id,
                    format_iso(e.timestamp),
                    e.hostname,
                    e.source,
                    e.event_type,
                    e.severity,
                    e.user,
                    e.uid,
                    e.euid,
                    e.gid,
                    e.egid,
                    e.pid,
                    e.ppid,
                    e.process,
                    e.command,
                    json.dumps(e.evidence, default=str),
                    e.confidence,
                    1 if e.is_test_fixture else 0
                )
                for e in events
            ])
            conn.commit()

    def get_events(self, limit: int = 100, event_type: Optional[str] = None,
                   severity: Optional[str] = None, exclude_fixtures: bool = False) -> List[SecurityEvent]:
        """Query security events with filtering"""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if exclude_fixtures:
            query += " AND is_test_fixture = 0"

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        events = []
        for r in rows:
            events.append(SecurityEvent(
                event_id=r['event_id'],
                timestamp=parse_iso(r['timestamp']) or utc_now(),
                hostname=r['hostname'] or "unknown",
                source=r['source'] or "unknown",
                event_type=r['event_type'] or "UNKNOWN",
                severity=r['severity'] or Severity.INFO.value,
                user=r['user'],
                uid=r['uid'],
                euid=r['euid'],
                gid=r['gid'],
                egid=r['egid'],
                pid=r['pid'],
                ppid=r['ppid'],
                process=r['process'],
                command=r['command'],
                evidence=json.loads(r['evidence_json']) if r['evidence_json'] else {},
                confidence=r['confidence'] or 1.0,
                is_test_fixture=bool(r['is_test_fixture'])
            ))
        return events

    # --- Findings ---

    def save_finding(self, finding: Finding):
        """Save a single finding"""
        self.save_findings([finding])

    def save_findings(self, findings: List[Finding]):
        """Bulk save findings"""
        if not findings:
            return
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO findings (
                    finding_id, vector, severity, confidence, title, description,
                    affected_resource, evidence_json, detection_method,
                    risk_explanation, remediation, references_json, timestamp,
                    is_test_fixture
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    f.finding_id,
                    f.vector,
                    f.severity,
                    f.confidence,
                    f.title,
                    f.description,
                    f.affected_resource,
                    json.dumps(f.evidence, default=str),
                    f.detection_method,
                    f.risk_explanation,
                    f.remediation,
                    json.dumps(f.references),
                    format_iso(f.timestamp),
                    1 if f.is_test_fixture else 0
                )
                for f in findings
            ])
            conn.commit()

    def get_findings(self, vector: Optional[str] = None, severity: Optional[str] = None,
                     exclude_fixtures: bool = False) -> List[Finding]:
        """Query findings with optional filters"""
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []

        if vector:
            query += " AND vector = ?"
            params.append(vector)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if exclude_fixtures:
            query += " AND is_test_fixture = 0"

        query += " ORDER BY timestamp DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        findings = []
        for r in rows:
            findings.append(Finding(
                finding_id=r['finding_id'],
                vector=r['vector'],
                severity=r['severity'],
                confidence=r['confidence'] or 0.9,
                title=r['title'],
                description=r['description'] or "",
                affected_resource=r['affected_resource'] or "",
                evidence=json.loads(r['evidence_json']) if r['evidence_json'] else {},
                detection_method=r['detection_method'] or "static_audit",
                risk_explanation=r['risk_explanation'] or "",
                remediation=r['remediation'] or "",
                references=json.loads(r['references_json']) if r['references_json'] else [],
                timestamp=parse_iso(r['timestamp']) or utc_now(),
                is_test_fixture=bool(r['is_test_fixture'])
            ))
        return findings

    # --- Incidents ---

    def save_incident(self, incident: Incident):
        """Save or update an incident"""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, title, severity, confidence, hypothesis,
                    attribution_json, event_ids_json, status, created_at,
                    updated_at, notes_json, is_test_fixture
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.title,
                incident.severity,
                incident.confidence,
                incident.hypothesis,
                json.dumps(incident.attribution, default=str),
                json.dumps(incident.event_ids),
                incident.status,
                format_iso(incident.created_at),
                format_iso(incident.updated_at),
                json.dumps(incident.notes, default=str),
                1 if incident.is_test_fixture else 0
            ))
            conn.commit()

    def get_incidents(self, status: Optional[str] = None) -> List[Incident]:
        """Query correlated incidents"""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        incidents = []
        for r in rows:
            incidents.append(Incident(
                incident_id=r['incident_id'],
                title=r['title'],
                severity=r['severity'],
                confidence=r['confidence'] or 0.85,
                hypothesis=r['hypothesis'] or "",
                attribution=json.loads(r['attribution_json']) if r['attribution_json'] else {},
                event_ids=json.loads(r['event_ids_json']) if r['event_ids_json'] else [],
                status=r['status'],
                created_at=parse_iso(r['created_at']) or utc_now(),
                updated_at=parse_iso(r['updated_at']) or utc_now(),
                notes=json.loads(r['notes_json']) if r['notes_json'] else [],
                is_test_fixture=bool(r['is_test_fixture'])
            ))
        return incidents

    def update_incident_status(self, incident_id: str, status: str, note: Optional[str] = None):
        """Update incident workflow status and append resolution note"""
        with self._get_connection() as conn:
            row = conn.execute("SELECT notes_json FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return
            notes = json.loads(row['notes_json']) if row['notes_json'] else []
            if note:
                notes.append({
                    'timestamp': format_iso(utc_now()),
                    'note': note,
                    'status': status
                })
            conn.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?, notes_json = ?
                WHERE incident_id = ?
            """, (status, format_iso(utc_now()), json.dumps(notes), incident_id))
            conn.commit()

    # --- Audit Trail ---

    def log_admin_action(self, action: str, target: str, actor: str,
                         details: Dict[str, Any], result: str):
        """Append record to immutable admin action audit trail"""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO audit_trail (timestamp, action, target, actor, details_json, result)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                format_iso(utc_now()),
                action,
                target,
                actor,
                json.dumps(details, default=str),
                result
            ))
            conn.commit()

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent admin audit entries"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM audit_trail ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                'id': r['id'],
                'timestamp': r['timestamp'],
                'action': r['action'],
                'target': r['target'],
                'actor': r['actor'],
                'details': json.loads(r['details_json']) if r['details_json'] else {},
                'result': r['result']
            }
            for r in rows
        ]

    # --- Alert Suppression ---

    def add_suppression(self, rule_id: str, vector: str, pattern: str,
                        reason: str, actor: str, expires_at: Optional[datetime] = None):
        """Register a new false-positive suppression rule with mandatory audit log"""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO suppression_rules (
                    rule_id, vector, pattern, reason, actor, created_at, expires_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                rule_id,
                vector,
                pattern,
                reason,
                actor,
                format_iso(utc_now()),
                format_iso(expires_at) if expires_at else None
            ))
            conn.commit()

        self.log_admin_action(
            action="ADD_SUPPRESSION_RULE",
            target=f"{vector}:{pattern}",
            actor=actor,
            details={'rule_id': rule_id, 'reason': reason},
            result="SUCCESS"
        )

    def is_suppressed(self, vector: str, text: str) -> bool:
        """Check if a finding or alert matches an active suppression pattern"""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT pattern FROM suppression_rules
                WHERE is_active = 1 AND (vector = ? OR vector = '*')
            """, (vector,)).fetchall()

        for r in rows:
            pattern = r['pattern'].lower()
            if pattern in text.lower():
                return True
        return False
