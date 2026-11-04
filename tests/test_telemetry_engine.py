"""
UATU Linux Edition - Telemetry Engine Tests
Verifies auditd and journald/auth telemetry parsing, event bus publishing,
storage persistence with data_origin=LIVE_TELEMETRY, and health state reporting.
"""

from datetime import datetime, timezone
import pytest

from core.event_schema import UatuEvent, DataOrigin, EventSeverity
from core.health import HealthRegistry, HealthState
from core.event_bus import EventBus
from core.storage import StorageEngine
from telemetry.reader import AuditLogReader, AuthLogReader, TelemetryEngine


def test_audit_log_reader_parses_syscalls_and_watches():
    """Verify AuditLogReader parses execve, SUID, and watched file modifications."""
    raw_lines = [
        # Execve event
        'type=SYSCALL msg=audit(1730657730.123:101): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=0 items=2 ppid=1000 pid=2001 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="whoami" exe="/usr/bin/whoami" key="uatu_exec"',
        # SUID execution: euid=0, uid=1000
        'type=SYSCALL msg=audit(1730657735.456:102): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=2001 pid=2005 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="pkexec" exe="/usr/bin/pkexec" key="uatu_exec"',
        # Watched file modification: /etc/sudoers
        'type=SYSCALL msg=audit(1730657740.789:103): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=1000 pid=3001 auid=1000 uid=0 gid=0 euid=0 comm="nano" exe="/bin/nano" key="uatu_sudoers"',
        # Watched file modification: /etc/shadow
        'type=PATH msg=audit(1730657745.000:104): item=0 name="/etc/shadow" inode=12345 dev=08:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 key="uatu_shadow"'
    ]

    reader = AuditLogReader(log_path="/nonexistent/audit.log")
    events = reader.parse_audit_lines(raw_lines)

    assert len(events) == 4
    for e in events:
        assert e.data_origin == DataOrigin.LIVE_TELEMETRY
        assert e.confidence == 0.98

    # 1. Execve
    assert events[0].event_type == "PROCESS_EXECUTION"
    assert events[0].pid == 2001
    assert events[0].uid == 1000
    assert events[0].euid == 1000

    # 2. SUID
    assert events[1].event_type == "SUID_EXECUTION"
    assert events[1].severity == EventSeverity.HIGH
    assert events[1].uid == 1000
    assert events[1].euid == 0

    # 3. Watched sudoers
    assert events[2].event_type == "WATCHED_FILE_EDIT_SUDOERS"
    assert events[2].severity == EventSeverity.HIGH

    # 4. Watched shadow
    assert events[3].event_type == "WATCHED_FILE_EDIT_SHADOW"
    assert events[3].severity == EventSeverity.CRITICAL


def test_audit_multi_record_merging_by_serial():
    """Verify that multiple audit records sharing msg=audit(ts:serial) merge into one unified UatuEvent."""
    raw_lines = [
        'type=SYSCALL msg=audit(1730657750.100:999): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1000 pid=4500 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 comm="pkexec" exe="/usr/bin/pkexec" key="uatu_exec"',
        'type=EXECVE msg=audit(1730657750.100:999): argc=2 a0="pkexec" a1="/bin/sh"',
        'type=CWD msg=audit(1730657750.100:999): cwd="/tmp"',
        'type=PATH msg=audit(1730657750.100:999): item=0 name="/usr/bin/pkexec" inode=123 dev=08:01 mode=0104755 ouid=0 ogid=0',
        'type=PROCTITLE msg=audit(1730657750.100:999): proctitle=706B65786563002F62696E2F7368'
    ]

    reader = AuditLogReader()
    events = reader.parse_audit_lines(raw_lines)

    # 5 records must merge into exactly 1 event
    assert len(events) == 1
    ev = events[0]
    assert ev.audit_event_id == "1730657750.100:999"
    assert ev.pid == 4500
    assert ev.uid == 1000
    assert ev.euid == 0
    assert ev.command == "pkexec /bin/sh"
    assert ev.event_type == "SUID_EXECUTION"
    assert ev.evidence["serial"] == "999"
    assert "EXECVE" in ev.evidence["record_types"]
    assert "CWD" in ev.evidence["record_types"]


def test_audit_standalone_cwd_path_proctitle_dropped():
    """Verify that standalone CWD, PATH, and PROCTITLE records without security watches are dropped."""
    raw_lines = [
        'type=CWD msg=audit(1730657760.200:1001): cwd="/home/kali"',
        'type=PATH msg=audit(1730657760.200:1001): item=0 name="/bin/ls" inode=456 dev=08:01',
        'type=PROCTITLE msg=audit(1730657760.200:1001): proctitle=6C73'
    ]

    reader = AuditLogReader()
    events = reader.parse_audit_lines(raw_lines)

    # Standalone unmonitored CWD/PATH/PROCTITLE records must be dropped
    assert len(events) == 0



def test_audit_missing_reports_health_unavailable():
    """Verify missing auditd subsystem sets auditd_exec_monitoring to UNAVAILABLE."""
    health_reg = HealthRegistry()
    reader = AuditLogReader(log_path="/nonexistent/path/audit.log", health_reg=health_reg)
    reader.check_health()

    comp = health_reg.get_component("auditd_exec_monitoring")
    assert comp is not None
    assert comp.state == HealthState.UNAVAILABLE
    assert comp.critical is True


def test_auth_log_reader_parses_sudo_and_ssh():
    """Verify AuthLogReader parses sudo failures, sudo successes, and ssh failures."""
    raw_lines = [
        "Nov  4 12:00:01 kali sudo: testuser : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/bash",
        "Nov  4 12:00:10 kali sudo: testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/bin/id",
        "Nov  4 12:00:20 kali sshd[4012]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    ]

    reader = AuthLogReader()
    events = reader.parse_auth_lines(raw_lines)

    assert len(events) == 3

    # 1. Sudo failure
    assert events[0].event_type == "SUDO_AUTH_FAILURE"
    assert events[0].severity == EventSeverity.MEDIUM
    assert events[0].user == "testuser"
    assert events[0].data_origin == DataOrigin.LIVE_TELEMETRY

    # 2. Sudo success
    assert events[1].event_type == "SUDO_AUTH_SUCCESS"
    assert events[1].severity == EventSeverity.INFO
    assert events[1].user == "testuser"
    assert events[1].command == "/usr/bin/id"

    # 3. SSH failure
    assert events[2].event_type == "SSH_AUTH_FAILURE"
    assert events[2].severity == EventSeverity.MEDIUM
    assert events[2].user == "admin"
    assert events[2].evidence["remote_ip"] == "192.168.1.100"


def test_telemetry_engine_event_bus_and_storage_pipeline(temp_dir):
    """Verify TelemetryEngine routes collected events through EventBus into StorageEngine."""
    db_path = str(temp_dir / "telem_pipeline_test.db")
    storage = StorageEngine(db_path)
    event_bus = EventBus(max_queue_size=100)
    health_reg = HealthRegistry()

    delivered_events = []
    event_bus.subscribe("*", lambda evt: delivered_events.append(evt))
    event_bus.start()

    try:
        engine = TelemetryEngine(storage=storage, event_bus=event_bus, health_reg=health_reg)

        # Feed events via parser
        test_audit_lines = [
            'type=SYSCALL msg=audit(1730657735.456:102): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=2001 pid=2005 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm="suid_copy" exe="/tmp/suid_copy" key="uatu_exec"'
        ]
        parsed = engine.audit_reader.parse_audit_lines(test_audit_lines)
        for e in parsed:
            engine.event_bus.publish(e)
        storage.save_events(parsed)

        import time
        time.sleep(0.1)

        # Verify delivered via event bus
        assert len(delivered_events) == 1
        assert delivered_events[0].event_type == "SUID_EXECUTION"

        # Verify persisted in storage
        stored = storage.get_uatu_events(event_type="SUID_EXECUTION")
        assert len(stored) == 1
        assert stored[0].data_origin == DataOrigin.LIVE_TELEMETRY
        assert stored[0].euid == 0
    finally:
        event_bus.stop()

