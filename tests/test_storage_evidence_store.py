"""
UATU Linux Edition - Storage & Evidence Store Tests
Verifies SQLite storage engine:
- Forward schema migrations and presence of all 22 required entity tables
- Append-only immutability triggers on events and evidence_objects (rejecting UPDATE/DELETE)
- Cryptographic SHA-256 hash chaining and tamper detection via verify_chain()
- Strict preservation of explicit confidence=0.0 (Defect D7 fix)
- Storing and retrieving UATU events, attack paths, policies, and containment records
"""

from datetime import datetime, timezone
import os
import sqlite3
import tempfile
import pytest

from core.models import (
    SecurityEvent, Finding, Incident, IncidentStatus, Severity,
    AttackNode, AttackEdge, AttackPath, SecurityPolicy, ContainmentAction
)
from core.event_schema import (
    UatuEvent, ProvenanceClass, DataOrigin, CollectionStatus,
    CollectionMethod, EventSeverity
)
from core.storage import StorageEngine


@pytest.fixture
def temp_storage():
    """Create a temporary storage engine instance with clean SQLite DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    engine = StorageEngine(db_path=db_path)
    yield engine

    try:
        os.remove(db_path)
        for ext in ["-wal", "-shm"]:
            if os.path.exists(db_path + ext):
                os.remove(db_path + ext)
    except Exception:
        pass


def test_storage_initializes_all_tables(temp_storage):
    """Verify that all 22 required UATU entity tables are created upon initialization."""
    with temp_storage._get_connection() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    expected_tables = {
        "hosts", "users", "groups", "processes", "events", "findings",
        "incidents", "incident_events", "graph_nodes", "graph_edges",
        "attack_paths", "risk_assessments", "policies", "policy_evaluations",
        "enforcement_ops", "containment_ops", "remediation_actions",
        "rollback_records", "evidence_objects", "audit_trail",
        "model_registry", "model_evaluations", "health_snapshots"
    }

    missing = expected_tables - tables
    assert not missing, f"Missing expected UATU database tables: {missing}"


def test_storage_event_immutability_triggers(temp_storage):
    """Verify that SQLite triggers abort UPDATE or DELETE on events table."""
    evt = UatuEvent(event_id="evt_immutable_test", event_type="TEST_IMMUTABILITY")
    temp_storage.save_event(evt)

    # Attempting UPDATE must be aborted by trigger
    with pytest.raises(sqlite3.DatabaseError) as exc_update:
        with temp_storage._get_connection() as conn:
            conn.execute("UPDATE events SET event_type = 'TAMPERED' WHERE event_id = ?", (evt.event_id,))
    assert "immutable" in str(exc_update.value).lower()

    # Attempting DELETE must be aborted by trigger
    with pytest.raises(sqlite3.DatabaseError) as exc_delete:
        with temp_storage._get_connection() as conn:
            conn.execute("DELETE FROM events WHERE event_id = ?", (evt.event_id,))
    assert "immutable" in str(exc_delete.value).lower()


def test_storage_evidence_object_immutability_triggers(temp_storage):
    """Verify that SQLite triggers abort UPDATE or DELETE on evidence_objects table."""
    obj_id = "obj_log_001"
    temp_storage.save_evidence_object(obj_id, "AUTH_LOG", b"Dec 10 12:00:00 session opened")

    with pytest.raises(sqlite3.DatabaseError) as exc_update:
        with temp_storage._get_connection() as conn:
            conn.execute("UPDATE evidence_objects SET raw_data = ? WHERE object_id = ?", (b"tampered", obj_id))
    assert "immutable" in str(exc_update.value).lower()

    with pytest.raises(sqlite3.DatabaseError) as exc_delete:
        with temp_storage._get_connection() as conn:
            conn.execute("DELETE FROM evidence_objects WHERE object_id = ?", (obj_id,))
    assert "immutable" in str(exc_delete.value).lower()


def test_storage_confidence_zero_preservation(temp_storage):
    """Verify Defect D7 fix: confidence=0.0 is accurately stored and retrieved without being coerced."""
    evt = UatuEvent(
        event_id="evt_conf_zero",
        event_type="UNVERIFIED_ANOMALY",
        confidence=0.0
    )
    temp_storage.save_event(evt)

    # Retrieve via get_events
    events = temp_storage.get_events(event_type="UNVERIFIED_ANOMALY")
    assert len(events) == 1
    assert events[0].confidence == 0.0

    # Retrieve via get_uatu_events
    uatu_events = temp_storage.get_uatu_events(event_type="UNVERIFIED_ANOMALY")
    assert len(uatu_events) == 1
    assert uatu_events[0].confidence == 0.0


def test_storage_audit_hash_chain_verification_and_tamper_detection(temp_storage):
    """Verify SHA-256 hash chaining in audit log and verify_chain detects tampering."""
    # 1. Log three sequential actions
    h1 = temp_storage.log_admin_action("LOGIN", "system", "analyst1", {"ip": "127.0.0.1"}, "SUCCESS")
    h2 = temp_storage.log_admin_action("DISABLE_RULE", "suid_scanner", "analyst1", {"rule": "r1"}, "SUCCESS")
    h3 = temp_storage.log_admin_action("TRIGGER_SCAN", "all", "analyst1", {}, "SUCCESS")

    # Chain must be valid
    valid, broken_id, err = temp_storage.verify_chain("audit_trail")
    assert valid is True
    assert broken_id == -1
    assert err is None

    # 2. Directly tamper with record 2 in the database
    with temp_storage._get_connection() as conn:
        conn.execute("UPDATE audit_trail SET actor = 'attacker' WHERE id = 2")
        conn.commit()

    # Chain verification must now fail on record 2
    valid_tampered, broken_tampered_id, err_tampered = temp_storage.verify_chain("audit_trail")
    assert valid_tampered is False
    assert broken_tampered_id == 2
    assert "Tampered record at id 2" in err_tampered


def test_storage_attack_path_and_policy_persistence(temp_storage):
    """Verify persistence of AttackNode, AttackEdge, AttackPath, and SecurityPolicy."""
    # Save graph node and edge
    node = AttackNode(node_id="node_user_www", node_type="USER", name="www-data", risk_score=50.0)
    edge = AttackEdge(edge_id="edge_sudo_bash", source_node_id="node_user_www", target_node_id="node_root", relationship_type="ESCALATES_TO")
    temp_storage.save_attack_nodes([node])
    temp_storage.save_attack_edges([edge])

    # Save attack path
    path = AttackPath(
        path_id="path_001",
        start_node_id="node_user_www",
        target_node_id="node_root",
        node_ids=["node_user_www", "node_root"],
        edge_ids=["edge_sudo_bash"],
        total_risk_score=95.0,
        bottleneck_node_id="node_user_www"
    )
    temp_storage.save_attack_path(path)

    # Save policy
    pol = SecurityPolicy(
        policy_id="pol_deny_pkexec",
        name="Deny pkexec for service accounts",
        description="Blocks execution of pkexec by non-interactive service accounts",
        policy_type="PROCESS_RESTRICTION",
        rules=[{"binary": "/usr/bin/pkexec", "action": "BLOCK"}]
    )
    temp_storage.save_policy(pol)

    # Save containment action
    action = ContainmentAction(
        action_id="cont_kill_4567",
        action_type="KILL_PROCESS",
        target="4567",
        reason="Suspicious UID change to 0 without sudo authorization",
        status="EXECUTED"
    )
    temp_storage.record_containment_action(action)

    with temp_storage._get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM graph_nodes").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM graph_edges").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM attack_paths").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM policies").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM containment_ops").fetchone()[0] == 1


def test_get_default_db_path_and_isolation(monkeypatch):
    """Verify default DB path resolution and isolation between root and unprivileged users."""
    from core.config import get_default_db_path

    # 1. Environment variable override
    monkeypatch.setenv("UATU_DB_PATH", "/tmp/custom_test_uatu.db")
    assert get_default_db_path() == "/tmp/custom_test_uatu.db"
    monkeypatch.delenv("UATU_DB_PATH", raising=False)

    # 2. Simulated root execution on POSIX
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert get_default_db_path() == "/var/lib/uatu/uatu.db"

    # 3. Simulated non-root execution when /var/lib/uatu does not exist
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    user_path = get_default_db_path()
    assert "/var/lib/uatu" not in user_path or ".local/share/uatu" in user_path


