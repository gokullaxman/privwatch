"""
PrivWatch 3.0 / UATU Linux Edition - Persistence & Evidence Storage Engine
SQLite-backed storage for normalized security events, findings, incidents, attack graphs,
policies, containment operations, ML registry, and administrative audit trails.
Features:
- Immutable append-only tables with SQLite ABORT triggers
- Thread-safe WAL mode and PRAGMA foreign_keys = ON
- Cryptographic SHA-256 hash chaining with verify_chain()
- Forward schema migration for legacy databases without data loss
- Zero-confidence preservation (0.0 != None)
- Strict 0600 POSIX file and 0700 directory permissions
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Dict, List, Optional, Any, Tuple, Union

from core.models import (
    SecurityEvent, Finding, Incident, IncidentStatus, Severity,
    AttackNode, AttackEdge, AttackPath, SecurityPolicy, PolicyEvaluation,
    ContainmentAction, RiskScoreCard, NetworkSocketEvent,
    utc_now, format_iso, parse_iso
)
from core.event_schema import (
    UatuEvent, ProvenanceClass, DataOrigin, CollectionStatus,
    CollectionMethod, EventSeverity, format_iso_utc, parse_iso_utc
)


class StorageEngine:
    """Thread-safe SQLite storage engine with cryptographic audit integrity for UATU."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, db_path: str = "./privwatch.db"):
        self.db_path = str(Path(db_path).resolve())
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        self._enforce_directory_permissions(str(db_dir))

        self._lock = threading.RLock()
        self.init_db()
        self._enforce_permissions()

    def _enforce_directory_permissions(self, dir_path: str):
        """Enforce strict 0700 directory permissions on POSIX systems."""
        if hasattr(os, "chmod") and os.name == "posix":
            try:
                os.chmod(dir_path, 0o700)
            except Exception:
                pass

    def _enforce_permissions(self):
        """Enforce strict 0600 read/write permissions on the database file for POSIX systems."""
        if os.path.exists(self.db_path) and hasattr(os, "chmod") and os.name == "posix":
            try:
                os.chmod(self.db_path, 0o600)
            except Exception:
                pass

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with WAL mode, busy timeout, and foreign key constraints."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def init_db(self):
        """Initialize database schema with 22 entity tables, triggers, and forward migrations."""
        with self._lock:
            with self._get_connection() as conn:
                # 1. Hosts
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS hosts (
                        host_id TEXT PRIMARY KEY,
                        hostname TEXT NOT NULL,
                        os_release TEXT,
                        kernel_version TEXT,
                        architecture TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        metadata_json TEXT
                    )
                """)

                # 2. Users
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        uid INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        gid INTEGER,
                        home_dir TEXT,
                        shell TEXT,
                        is_system INTEGER DEFAULT 0,
                        is_privileged INTEGER DEFAULT 0,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL
                    )
                """)

                # 3. Groups
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS groups (
                        gid INTEGER PRIMARY KEY,
                        group_name TEXT NOT NULL,
                        members_json TEXT,
                        is_privileged INTEGER DEFAULT 0,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL
                    )
                """)

                # 4. Processes
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS processes (
                        pid INTEGER,
                        ppid INTEGER,
                        uid INTEGER,
                        euid INTEGER,
                        gid INTEGER,
                        egid INTEGER,
                        exe TEXT,
                        cmdline TEXT,
                        start_time TEXT,
                        status TEXT,
                        host_id TEXT,
                        last_seen TEXT,
                        PRIMARY KEY(pid, start_time)
                    )
                """)

                # 5. Events table (append-only)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        host_id TEXT,
                        hostname TEXT,
                        source TEXT,
                        source_event_id TEXT,
                        collection_method TEXT,
                        event_type TEXT,
                        severity TEXT,
                        user TEXT,
                        uid INTEGER,
                        euid INTEGER,
                        suid INTEGER,
                        gid INTEGER,
                        egid INTEGER,
                        pid INTEGER,
                        ppid INTEGER,
                        process TEXT,
                        process_start_time TEXT,
                        session_id INTEGER,
                        audit_event_id TEXT,
                        exe TEXT,
                        command TEXT,
                        evidence_json TEXT,
                        evidence_ref TEXT,
                        provenance_class TEXT DEFAULT 'OBSERVED',
                        data_origin TEXT DEFAULT 'LIVE_TELEMETRY',
                        confidence REAL,
                        collection_status TEXT DEFAULT 'SUCCESS',
                        integrity_hash TEXT,
                        is_test_fixture INTEGER DEFAULT 0
                    )
                """)

                # 6. Findings table (append-only)
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

                # 7. Incidents table
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

                # 8. Incident-Events Junction Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS incident_events (
                        incident_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        sequence_order INTEGER DEFAULT 0,
                        added_at TEXT NOT NULL,
                        PRIMARY KEY (incident_id, event_id),
                        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
                    )
                """)

                # 9. Graph Nodes (Attack Graph)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS graph_nodes (
                        node_id TEXT PRIMARY KEY,
                        node_type TEXT NOT NULL,
                        name TEXT NOT NULL,
                        properties_json TEXT,
                        risk_score REAL DEFAULT 0.0,
                        evidence_ref TEXT
                    )
                """)

                # 10. Graph Edges (Attack Graph)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS graph_edges (
                        edge_id TEXT PRIMARY KEY,
                        source_node_id TEXT NOT NULL,
                        target_node_id TEXT NOT NULL,
                        relationship_type TEXT NOT NULL,
                        technique_id TEXT,
                        confidence REAL DEFAULT 1.0,
                        cost REAL DEFAULT 1.0,
                        evidence_ref TEXT
                    )
                """)

                # 11. Attack Paths
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS attack_paths (
                        path_id TEXT PRIMARY KEY,
                        start_node_id TEXT,
                        target_node_id TEXT,
                        node_ids_json TEXT,
                        edge_ids_json TEXT,
                        total_risk_score REAL,
                        confidence REAL,
                        bottleneck_node_id TEXT,
                        recommended_disruption TEXT,
                        created_at TEXT NOT NULL
                    )
                """)

                # 12. Risk Assessments
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS risk_assessments (
                        assessment_id TEXT PRIMARY KEY,
                        overall_score REAL NOT NULL,
                        threat_level TEXT NOT NULL,
                        dimension_scores_json TEXT,
                        timestamp TEXT NOT NULL
                    )
                """)

                # 13. Policies
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS policies (
                        policy_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        policy_type TEXT NOT NULL,
                        mode TEXT NOT NULL DEFAULT 'MONITOR',
                        rules_json TEXT NOT NULL,
                        target_scope TEXT DEFAULT 'global',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        is_active INTEGER DEFAULT 1
                    )
                """)

                # 14. Policy Evaluations
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS policy_evaluations (
                        evaluation_id TEXT PRIMARY KEY,
                        policy_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        result TEXT NOT NULL,
                        matched_rules_json TEXT,
                        explanation TEXT,
                        timestamp TEXT NOT NULL
                    )
                """)

                # 15. Enforcement Ops
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS enforcement_ops (
                        op_id TEXT PRIMARY KEY,
                        policy_id TEXT,
                        target TEXT NOT NULL,
                        action TEXT NOT NULL,
                        status TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        details_json TEXT
                    )
                """)

                # 16. Containment Ops
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS containment_ops (
                        action_id TEXT PRIMARY KEY,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        rollback_data_json TEXT,
                        result_details_json TEXT
                    )
                """)

                # 17. Remediation Actions
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS remediation_actions (
                        action_id TEXT PRIMARY KEY,
                        finding_id TEXT,
                        command TEXT NOT NULL,
                        status TEXT NOT NULL,
                        applied_at TEXT NOT NULL,
                        rollback_command TEXT
                    )
                """)

                # 18. Rollback Records
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rollback_records (
                        rollback_id TEXT PRIMARY KEY,
                        containment_action_id TEXT,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        details_json TEXT
                    )
                """)

                # 19. Evidence Objects (Immutable raw objects)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_objects (
                        object_id TEXT PRIMARY KEY,
                        object_type TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL,
                        raw_data BLOB,
                        metadata_json TEXT,
                        created_at TEXT NOT NULL
                    )
                """)

                # 20. Audit Trail / Log (Cryptographically hash-chained)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_trail (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT,
                        actor TEXT NOT NULL,
                        details_json TEXT,
                        result TEXT NOT NULL,
                        prev_hash TEXT,
                        record_hash TEXT
                    )
                """)

                # 21. Model Registry
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS model_registry (
                        model_id TEXT PRIMARY KEY,
                        model_name TEXT NOT NULL,
                        version TEXT NOT NULL,
                        model_type TEXT NOT NULL,
                        hyperparameters_json TEXT,
                        trained_at TEXT NOT NULL,
                        metrics_json TEXT,
                        file_path TEXT,
                        is_active INTEGER DEFAULT 1
                    )
                """)

                # 22. Model Evaluations
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS model_evaluations (
                        evaluation_id TEXT PRIMARY KEY,
                        model_id TEXT NOT NULL,
                        evaluated_at TEXT NOT NULL,
                        dataset_name TEXT,
                        sample_count INTEGER,
                        accuracy REAL,
                        f1_score REAL,
                        roc_auc REAL,
                        drift_score REAL,
                        metrics_json TEXT
                    )
                """)

                # 23. Health Snapshots
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS health_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        status TEXT NOT NULL,
                        coverage_pct REAL,
                        ingestion_eps REAL,
                        sources_json TEXT,
                        drop_count INTEGER DEFAULT 0,
                        queue_depth INTEGER DEFAULT 0
                    )
                """)

                # Suppression Rules (from PrivWatch 3.0)
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

                # Execute forward schema migrations for legacy databases
                self._migrate_schema(conn)

                # Create Append-Only Immutability Triggers
                self._create_immutability_triggers(conn)

                # Create Performance Indices
                self._create_indices(conn)

                conn.commit()

    def _migrate_schema(self, conn: sqlite3.Connection):
        """Forward-migrate columns in pre-existing tables to prevent schema mismatch."""
        # 1. Migrate events table
        event_cols = {col[1] for col in conn.execute("PRAGMA table_info(events)").fetchall()}
        columns_to_add = [
            ("host_id", "TEXT"),
            ("source_event_id", "TEXT"),
            ("collection_method", "TEXT"),
            ("suid", "INTEGER"),
            ("process_start_time", "TEXT"),
            ("session_id", "INTEGER"),
            ("audit_event_id", "TEXT"),
            ("exe", "TEXT"),
            ("evidence_ref", "TEXT"),
            ("provenance_class", "TEXT DEFAULT 'OBSERVED'"),
            ("data_origin", "TEXT DEFAULT 'LIVE_TELEMETRY'"),
            ("collection_status", "TEXT DEFAULT 'SUCCESS'"),
            ("integrity_hash", "TEXT"),
        ]
        for col_name, col_type in columns_to_add:
            if col_name not in event_cols:
                try:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

        # 2. Migrate audit_trail table
        audit_cols = {col[1] for col in conn.execute("PRAGMA table_info(audit_trail)").fetchall()}
        if "prev_hash" not in audit_cols:
            try:
                conn.execute("ALTER TABLE audit_trail ADD COLUMN prev_hash TEXT")
            except Exception:
                pass
        if "record_hash" not in audit_cols:
            try:
                conn.execute("ALTER TABLE audit_trail ADD COLUMN record_hash TEXT")
            except Exception:
                pass

    def _create_immutability_triggers(self, conn: sqlite3.Connection):
        """Install SQLite triggers enforcing append-only immutability for forensic evidence."""
        # Events immutability
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS abort_event_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'Events are immutable security evidence and cannot be updated.');
            END;
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS abort_event_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'Events are immutable security evidence and cannot be deleted.');
            END;
        """)

        # Evidence objects immutability
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS abort_evidence_update
            BEFORE UPDATE ON evidence_objects
            BEGIN
                SELECT RAISE(ABORT, 'Evidence objects are immutable and cannot be updated.');
            END;
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS abort_evidence_delete
            BEFORE DELETE ON evidence_objects
            BEGIN
                SELECT RAISE(ABORT, 'Evidence objects are immutable and cannot be deleted.');
            END;
        """)

    def _create_indices(self, conn: sqlite3.Connection):
        """Create indices for fast retrieval and correlation."""
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_uid ON events(uid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_vector ON findings(vector)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_inc ON incident_events(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_src_tgt ON graph_edges(source_node_id, target_node_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_eval_evt ON policy_evaluations(event_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_containment_target ON containment_ops(target)")

    # --- Events ---

    def save_event(self, event: Union[SecurityEvent, UatuEvent]):
        """Save a single normalized security event."""
        self.save_events([event])

    def save_events(self, events: List[Union[SecurityEvent, UatuEvent]]):
        """
        Append-only bulk save for normalized security events.
        Uses INSERT OR IGNORE to prevent overwriting existing historical evidence.
        """
        if not events:
            return
        with self._lock:
            with self._get_connection() as conn:
                records = []
                for e in events:
                    if isinstance(e, UatuEvent):
                        records.append((
                            e.event_id,
                            format_iso_utc(e.timestamp),
                            e.host_id,
                            e.hostname,
                            e.source,
                            e.source_event_id,
                            e.collection_method.value if hasattr(e.collection_method, "value") else str(e.collection_method),
                            e.event_type,
                            e.severity.value if hasattr(e.severity, "value") else str(e.severity),
                            e.user,
                            e.uid,
                            e.euid,
                            e.suid,
                            e.gid,
                            e.egid,
                            e.pid,
                            e.ppid,
                            e.exe,  # process
                            format_iso_utc(e.process_start_time) if e.process_start_time else None,
                            e.session_id,
                            e.audit_event_id,
                            e.exe,
                            e.command,
                            json.dumps(e.evidence, default=str),
                            e.evidence_ref,
                            e.provenance_class.value if hasattr(e.provenance_class, "value") else str(e.provenance_class),
                            e.data_origin.value if hasattr(e.data_origin, "value") else str(e.data_origin),
                            e.confidence,
                            e.collection_status.value if hasattr(e.collection_status, "value") else str(e.collection_status),
                            e.integrity_hash,
                            1 if e.data_origin == DataOrigin.TEST_FIXTURE else 0
                        ))
                    elif isinstance(e, SecurityEvent):
                        records.append((
                            e.event_id,
                            format_iso(e.timestamp),
                            "unknown",
                            e.hostname,
                            e.source,
                            None,
                            "UNKNOWN",
                            e.event_type,
                            e.severity,
                            e.user,
                            e.uid,
                            e.euid,
                            None,
                            e.gid,
                            e.egid,
                            e.pid,
                            e.ppid,
                            e.process,
                            None,
                            None,
                            None,
                            e.process,
                            e.command,
                            json.dumps(e.evidence, default=str),
                            None,
                            "OBSERVED",
                            "TEST_FIXTURE" if e.is_test_fixture else "LIVE_TELEMETRY",
                            e.confidence,
                            "SUCCESS",
                            e.evidence_hash(),
                            1 if e.is_test_fixture else 0
                        ))

                conn.executemany("""
                    INSERT OR IGNORE INTO events (
                        event_id, timestamp, host_id, hostname, source, source_event_id,
                        collection_method, event_type, severity, user, uid, euid, suid,
                        gid, egid, pid, ppid, process, process_start_time, session_id,
                        audit_event_id, exe, command, evidence_json, evidence_ref,
                        provenance_class, data_origin, confidence, collection_status,
                        integrity_hash, is_test_fixture
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, records)
                conn.commit()

    def save_uatu_events(self, events: List[UatuEvent]):
        """Alias for save_events for typed UatuEvents."""
        self.save_events(events)

    def get_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        exclude_fixtures: bool = False
    ) -> List[SecurityEvent]:
        """Query security events preserving explicit confidence=0.0 (Defect D7)."""
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
            # Preserve stored confidence of 0.0 without coercing to 1.0 (D7)
            conf = r['confidence'] if r['confidence'] is not None else 1.0

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
                process=r['process'] or r['exe'],
                command=r['command'],
                evidence=json.loads(r['evidence_json']) if r['evidence_json'] else {},
                confidence=conf,
                is_test_fixture=bool(r['is_test_fixture'])
            ))
        return events

    def get_uatu_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        provenance_class: Optional[str] = None,
        data_origin: Optional[str] = None
    ) -> List[UatuEvent]:
        """Query typed UatuEvent telemetry records."""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if provenance_class:
            query += " AND provenance_class = ?"
            params.append(provenance_class)
        if data_origin:
            query += " AND data_origin = ?"
            params.append(data_origin)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        uatu_events = []
        for r in rows:
            conf = r['confidence'] if r['confidence'] is not None else 1.0
            uatu_events.append(UatuEvent(
                event_id=r['event_id'],
                timestamp=parse_iso_utc(r['timestamp']) or datetime.now(timezone.utc),
                host_id=r['host_id'] or "unknown",
                hostname=r['hostname'] or "unknown",
                source=r['source'] or "unknown",
                source_event_id=r['source_event_id'],
                collection_method=r['collection_method'] or CollectionMethod.UNKNOWN.value,
                event_type=r['event_type'] or "GENERIC_EVENT",
                severity=r['severity'] or EventSeverity.INFO.value,
                uid=r['uid'],
                euid=r['euid'],
                suid=r['suid'],
                gid=r['gid'],
                egid=r['egid'],
                pid=r['pid'],
                ppid=r['ppid'],
                process_start_time=parse_iso_utc(r['process_start_time']),
                session_id=r['session_id'],
                audit_event_id=r['audit_event_id'],
                exe=r['exe'] or r['process'],
                command=r['command'],
                user=r['user'],
                evidence=json.loads(r['evidence_json']) if r['evidence_json'] else {},
                evidence_ref=r['evidence_ref'],
                provenance_class=r['provenance_class'] or ProvenanceClass.OBSERVED.value,
                data_origin=r['data_origin'] or DataOrigin.LIVE_TELEMETRY.value,
                confidence=conf,
                collection_status=r['collection_status'] or CollectionStatus.SUCCESS.value,
                integrity_hash=r['integrity_hash']
            ))
        return uatu_events

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Query single security event by its unique ID."""
        with self._get_connection() as conn:
            r = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not r:
                return None
            conf = r['confidence'] if r['confidence'] is not None else 1.0
            return SecurityEvent(
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
                process=r['process'] or r['exe'],
                command=r['command'],
                evidence=json.loads(r['evidence_json']) if r['evidence_json'] else {},
                confidence=conf,
                is_test_fixture=bool(r['is_test_fixture'])
            )

    # --- Findings ---

    def save_finding(self, finding: Finding):
        """Save a single finding."""
        self.save_findings([finding])

    def save_findings(self, findings: List[Finding]):
        """Append-only bulk save for findings."""
        if not findings:
            return
        with self._lock:
            with self._get_connection() as conn:
                conn.executemany("""
                    INSERT OR IGNORE INTO findings (
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

    def get_findings(
        self,
        vector: Optional[str] = None,
        severity: Optional[str] = None,
        exclude_fixtures: bool = False
    ) -> List[Finding]:
        """Query findings with optional filters, preserving explicit confidence values."""
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
            conf = r['confidence'] if r['confidence'] is not None else 0.90
            findings.append(Finding(
                finding_id=r['finding_id'],
                vector=r['vector'],
                severity=r['severity'],
                confidence=conf,
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
        """Save or update a security incident case."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO incidents (
                        incident_id, title, severity, confidence, hypothesis,
                        attribution_json, event_ids_json, status, created_at,
                        updated_at, notes_json, is_test_fixture
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        confidence = excluded.confidence,
                        hypothesis = excluded.hypothesis,
                        attribution_json = excluded.attribution_json,
                        event_ids_json = excluded.event_ids_json,
                        status = excluded.status,
                        updated_at = excluded.updated_at,
                        notes_json = excluded.notes_json
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
                    json.dumps(incident.notes),
                    1 if incident.is_test_fixture else 0
                ))

                # Update junction table
                if incident.event_ids:
                    now_str = format_iso(utc_now())
                    for idx, eid in enumerate(incident.event_ids):
                        conn.execute("""
                            INSERT OR IGNORE INTO incident_events (incident_id, event_id, sequence_order, added_at)
                            VALUES (?, ?, ?, ?)
                        """, (incident.incident_id, eid, idx, now_str))

                conn.commit()

    def get_incidents(self, status: Optional[str] = None, exclude_fixtures: bool = False) -> List[Incident]:
        """Query correlated incidents with status filter."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if exclude_fixtures:
            query += " AND is_test_fixture = 0"

        query += " ORDER BY updated_at DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        incidents = []
        for r in rows:
            conf = r['confidence'] if r['confidence'] is not None else 1.0
            incidents.append(Incident(
                incident_id=r['incident_id'],
                title=r['title'],
                severity=r['severity'],
                confidence=conf,
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

    def update_incident_status(self, incident_id: str, new_status: str, note: Optional[str] = None):
        """Update workflow status of an incident and append optional note."""
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute("SELECT notes_json FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
                if not row:
                    return

                notes = json.loads(row['notes_json']) if row['notes_json'] else []
                if note:
                    notes.append({
                        'timestamp': format_iso(utc_now()),
                        'status_change': new_status,
                        'note': note
                    })

                conn.execute("""
                    UPDATE incidents
                    SET status = ?, updated_at = ?, notes_json = ?
                    WHERE incident_id = ?
                """, (new_status, format_iso(utc_now()), json.dumps(notes), incident_id))
                conn.commit()

    # --- Attack Graph Storage ---

    def save_attack_nodes(self, nodes: List[AttackNode]):
        """Save attack graph nodes."""
        if not nodes:
            return
        with self._lock:
            with self._get_connection() as conn:
                conn.executemany("""
                    INSERT OR REPLACE INTO graph_nodes (node_id, node_type, name, properties_json, risk_score, evidence_ref)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, [
                    (n.node_id, n.node_type, n.name, json.dumps(n.properties, default=str), n.risk_score, n.evidence_ref)
                    for n in nodes
                ])
                conn.commit()

    def save_attack_edges(self, edges: List[AttackEdge]):
        """Save attack graph edges."""
        if not edges:
            return
        with self._lock:
            with self._get_connection() as conn:
                conn.executemany("""
                    INSERT OR REPLACE INTO graph_edges (
                        edge_id, source_node_id, target_node_id, relationship_type, technique_id, confidence, cost, evidence_ref
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    (e.edge_id, e.source_node_id, e.target_node_id, e.relationship_type, e.technique_id, e.confidence, e.cost, e.evidence_ref)
                    for e in edges
                ])
                conn.commit()

    def save_attack_path(self, path: AttackPath):
        """Save an identified attack path."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO attack_paths (
                        path_id, start_node_id, target_node_id, node_ids_json, edge_ids_json,
                        total_risk_score, confidence, bottleneck_node_id, recommended_disruption, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    path.path_id,
                    path.start_node_id,
                    path.target_node_id,
                    json.dumps(path.node_ids),
                    json.dumps(path.edge_ids),
                    path.total_risk_score,
                    path.confidence,
                    path.bottleneck_node_id,
                    path.recommended_disruption,
                    format_iso(utc_now())
                ))
                conn.commit()

    def get_attack_paths(self) -> List[Dict[str, Any]]:
        """Retrieve all stored attack paths."""
        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute("""
                    SELECT path_id, start_node_id, target_node_id, node_ids_json, edge_ids_json,
                           total_risk_score, confidence, bottleneck_node_id, recommended_disruption, created_at
                    FROM attack_paths ORDER BY created_at DESC
                """).fetchall()
                paths = []
                for r in rows:
                    paths.append({
                        "path_id": r[0],
                        "start_node_id": r[1],
                        "target_node_id": r[2],
                        "node_ids": json.loads(r[3]) if r[3] else [],
                        "edge_ids": json.loads(r[4]) if r[4] else [],
                        "total_risk_score": r[5],
                        "confidence": r[6],
                        "bottleneck_node_id": r[7],
                        "recommended_disruption": r[8],
                        "created_at": r[9],
                        "level": "CONFIGURATION_ONLY"
                    })
                return paths

    # --- Policies & Evaluations ---

    def save_policy(self, policy: SecurityPolicy):
        """Save or update a defensive security policy."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO policies (
                        policy_id, name, description, policy_type, mode, rules_json,
                        target_scope, created_at, updated_at, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(policy_id) DO UPDATE SET
                        name = excluded.name,
                        description = excluded.description,
                        policy_type = excluded.policy_type,
                        mode = excluded.mode,
                        rules_json = excluded.rules_json,
                        target_scope = excluded.target_scope,
                        updated_at = excluded.updated_at,
                        is_active = excluded.is_active
                """, (
                    policy.policy_id,
                    policy.name,
                    policy.description,
                    policy.policy_type,
                    policy.mode,
                    json.dumps(policy.rules),
                    policy.target_scope,
                    format_iso(policy.created_at),
                    format_iso(policy.updated_at),
                    1 if policy.is_active else 0
                ))
                conn.commit()

    def record_policy_evaluation(self, evaluation: PolicyEvaluation):
        """Record policy evaluation result against an event."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO policy_evaluations (
                        evaluation_id, policy_id, event_id, result, matched_rules_json, explanation, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    evaluation.evaluation_id,
                    evaluation.policy_id,
                    evaluation.event_id,
                    evaluation.result,
                    json.dumps(evaluation.matched_rules),
                    evaluation.explanation,
                    format_iso(evaluation.timestamp)
                ))
                conn.commit()

    # --- Containment Operations ---

    def record_containment_action(self, action: ContainmentAction):
        """Record an executed or requested containment action."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO containment_ops (
                        action_id, action_type, target, reason, status, actor,
                        timestamp, rollback_data_json, result_details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(action_id) DO UPDATE SET
                        status = excluded.status,
                        rollback_data_json = excluded.rollback_data_json,
                        result_details_json = excluded.result_details_json
                """, (
                    action.action_id,
                    action.action_type,
                    action.target,
                    action.reason,
                    action.status,
                    action.actor,
                    format_iso(action.timestamp),
                    json.dumps(action.rollback_data, default=str),
                    json.dumps(action.result_details, default=str)
                ))
                conn.commit()

    # --- Immutable Evidence Objects ---

    def save_evidence_object(
        self,
        object_id: str,
        object_type: str,
        raw_data: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store an immutable evidence object with its computed SHA-256 hash."""
        sha256_hash = hashlib.sha256(raw_data).hexdigest()
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO evidence_objects (
                        object_id, object_type, sha256_hash, raw_data, metadata_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    object_id,
                    object_type,
                    sha256_hash,
                    raw_data,
                    json.dumps(metadata or {}, default=str),
                    format_iso(utc_now())
                ))
                conn.commit()
        return sha256_hash

    # --- Cryptographic Hash Chained Audit Trail ---

    def log_admin_action(
        self,
        action: str,
        target: str,
        actor: str,
        details: Dict[str, Any],
        result: str
    ) -> str:
        """
        Append record to immutable admin action audit trail with SHA-256 hash chaining.
        Returns the computed SHA-256 record hash.
        """
        with self._lock:
            with self._get_connection() as conn:
                last_row = conn.execute(
                    "SELECT record_hash FROM audit_trail ORDER BY id DESC LIMIT 1"
                ).fetchone()

                prev_hash = last_row['record_hash'] if (last_row and last_row['record_hash']) else self.GENESIS_HASH
                ts_str = format_iso(utc_now())
                det_json = json.dumps(details, default=str, sort_keys=True)

                raw_payload = f"{prev_hash}|{ts_str}|{action}|{target}|{actor}|{result}|{det_json}"
                record_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

                conn.execute("""
                    INSERT INTO audit_trail (timestamp, action, target, actor, details_json, result, prev_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (ts_str, action, target, actor, det_json, result, prev_hash, record_hash))
                conn.commit()
                return record_hash

    def verify_audit_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify cryptographic integrity of the audit log hash chain.
        Returns (True, None) if valid, or (False, error_reason) if tampered.
        """
        valid, idx, err = self.verify_chain("audit_trail")
        return valid, err

    def verify_chain(self, table_name: str = "audit_trail") -> Tuple[bool, int, Optional[str]]:
        """
        Verify cryptographic integrity of hash chain in audit_trail.
        Returns (True, -1, None) if intact, or (False, broken_id, error_reason) if tampered.
        """
        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(f"SELECT * FROM {table_name} ORDER BY id ASC").fetchall()

            expected_prev = self.GENESIS_HASH
            for r in rows:
                if r['prev_hash'] != expected_prev:
                    return False, r['id'], f"Broken link at id {r['id']}: expected prev_hash {expected_prev}, got {r['prev_hash']}"

                ts_str = r['timestamp']
                action = r['action']
                target = r['target']
                actor = r['actor']
                result = r['result']
                det_json = r['details_json']

                raw_payload = f"{expected_prev}|{ts_str}|{action}|{target}|{actor}|{result}|{det_json}"
                recomputed_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

                if r['record_hash'] != recomputed_hash:
                    return False, r['id'], f"Tampered record at id {r['id']}: stored hash {r['record_hash']} != calculated {recomputed_hash}"

                expected_prev = r['record_hash']

            return True, -1, None

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent admin audit entries."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                'id': r['id'],
                'timestamp': r['timestamp'],
                'action': r['action'],
                'target': r['target'],
                'actor': r['actor'],
                'details': json.loads(r['details_json']) if r['details_json'] else {},
                'result': r['result'],
                'prev_hash': r['prev_hash'],
                'record_hash': r['record_hash']
            }
            for r in rows
        ]

    # --- Alert Suppression ---

    def add_suppression(
        self,
        rule_id: str,
        vector: str,
        pattern: str,
        reason: str,
        actor: str,
        expires_at: Optional[datetime] = None
    ):
        """Register a new false-positive suppression rule with mandatory audit log."""
        with self._lock:
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
        """Check if a finding or alert matches an active suppression pattern."""
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
