"""
PrivWatch 3.1 - Verified Laboratory Security Telemetry Scenarios
Generates explicitly-labeled, isolated test fixtures simulating genuine Linux system telemetry scenarios.
Provides multi-host, multi-scenario coverage enabling leakage-free scenario partitioning.
"""

from datetime import datetime, timedelta, timezone
from typing import List

from core.models import SecurityEvent, Severity
from ml.data.schema import LabeledTelemetryRecord, DetectionLabel
from ml.features.feature_extractor import LinuxFeatureExtractor


def generate_curated_telemetry_dataset() -> List[LabeledTelemetryRecord]:
    """
    Generate an isolated, multi-scenario telemetry dataset representing
    benign Linux workloads and verified privilege escalation attack patterns.
    Contains pairs of scenarios for each behavioral category to permit leakage-free partitioning.
    """
    records: List[LabeledTelemetryRecord] = []
    extractor = LinuxFeatureExtractor()
    base_time = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------
    # 1. BENIGN: System Administration Scenarios (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "debian-srv-01"), (2, "debian-srv-02")]:
        events = [
            SecurityEvent(
                event_id=f"benign_sys_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=1),
                hostname=host,
                source="auditd",
                event_type="PROCESS_EXECUTION",
                severity=Severity.INFO.value,
                user="sysadmin",
                uid=1000, euid=1000, gid=1000, egid=1000, pid=2010 + session_idx, ppid=2000,
                process="ls", command="ls -la /var/log",
                evidence={"exe": "/usr/bin/ls", "ancestry_depth": 2},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"benign_sys_{session_idx}_2",
                timestamp=base_time + timedelta(seconds=10),
                hostname=host,
                source="auth.log",
                event_type="SUDO_COMMAND",
                severity=Severity.INFO.value,
                user="sysadmin",
                uid=1000, euid=0, gid=1000, egid=0, pid=2015 + session_idx, ppid=2000,
                process="sudo", command="sudo systemctl status nginx",
                evidence={"exe": "/usr/bin/sudo", "ancestry_depth": 2},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"benign_sys_{session_idx}_3",
                timestamp=base_time + timedelta(seconds=20),
                hostname=host,
                source="auditd",
                event_type="PROCESS_EXECUTION",
                severity=Severity.INFO.value,
                user="sysadmin",
                uid=1000, euid=1000, gid=1000, egid=1000, pid=2020 + session_idx, ppid=2000,
                process="cat", command="cat /etc/os-release",
                evidence={"exe": "/usr/bin/cat", "ancestry_depth": 2},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"benign_sys_{session_idx}_4",
                timestamp=base_time + timedelta(seconds=35),
                hostname=host,
                source="procfs",
                event_type="PROCESS_EXECUTION",
                severity=Severity.INFO.value,
                user="sysadmin",
                uid=1000, euid=1000, gid=1000, egid=1000, pid=2025 + session_idx, ppid=2000,
                process="uptime", command="uptime",
                evidence={"exe": "/usr/bin/uptime", "ancestry_depth": 2},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_benign_sysadmin_{session_idx:02d}",
                kernel_release="6.6.15-amd64",
                distribution="Debian GNU/Linux 12",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.BENIGN.value,
                label_provenance="authorized_sysadmin_lab"
            ))

    # -------------------------------------------------------------
    # 2. BENIGN: Developer Workflows (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "ubuntu-dev-01"), (2, "ubuntu-dev-02")]:
        events = [
            SecurityEvent(
                event_id=f"benign_dev_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=5),
                hostname=host,
                source="procfs",
                event_type="PROCESS_EXECUTION",
                severity=Severity.INFO.value,
                user="developer",
                uid=1001, euid=1001, gid=1001, egid=1001, pid=3100 + session_idx, ppid=3000,
                process="git", command="git status",
                evidence={"exe": "/usr/bin/git", "ancestry_depth": 3},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"benign_dev_{session_idx}_2",
                timestamp=base_time + timedelta(seconds=15),
                hostname=host,
                source="procfs",
                event_type="PROCESS_EXECUTION",
                severity=Severity.INFO.value,
                user="developer",
                uid=1001, euid=1001, gid=1001, egid=1001, pid=3105 + session_idx, ppid=3000,
                process="python3", command="python3 manage.py test",
                evidence={"exe": "/usr/bin/python3", "ancestry_depth": 3},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_benign_dev_{session_idx:02d}",
                kernel_release="6.8.0-generic",
                distribution="Ubuntu 24.04 LTS",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.BENIGN.value,
                label_provenance="authorized_developer_lab"
            ))

    # -------------------------------------------------------------
    # 3. SUSPICIOUS: Sudo Password Brute-Force (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "kali-target-01"), (2, "kali-target-02")]:
        events = [
            SecurityEvent(
                event_id=f"sudo_brute_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=2),
                hostname=host,
                source="auth.log",
                event_type="SUDO_AUTH_FAIL",
                severity=Severity.MEDIUM.value,
                user="guest",
                uid=1002, euid=1002, gid=1002, egid=1002, pid=4001 + session_idx, ppid=3990,
                process="sudo", command="sudo -S id",
                evidence={"auth_fail": True, "ancestry_depth": 2},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"sudo_brute_{session_idx}_2",
                timestamp=base_time + timedelta(seconds=5),
                hostname=host,
                source="auth.log",
                event_type="SUDO_AUTH_FAIL",
                severity=Severity.MEDIUM.value,
                user="guest",
                uid=1002, euid=1002, gid=1002, egid=1002, pid=4002 + session_idx, ppid=3990,
                process="sudo", command="sudo -S id",
                evidence={"auth_fail": True, "ancestry_depth": 2},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"sudo_brute_{session_idx}_3",
                timestamp=base_time + timedelta(seconds=8),
                hostname=host,
                source="auth.log",
                event_type="SUDO_AUTH_FAIL",
                severity=Severity.HIGH.value,
                user="guest",
                uid=1002, euid=1002, gid=1002, egid=1002, pid=4003 + session_idx, ppid=3990,
                process="sudo", command="sudo -S id",
                evidence={"auth_fail": True, "ancestry_depth": 2},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_sudo_brute_{session_idx:02d}",
                kernel_release="6.11.0-kali",
                distribution="Kali GNU/Linux Rolling",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.SUSPICIOUS.value,
                label_provenance="cve_auth_bruteforce_lab"
            ))

    # -------------------------------------------------------------
    # 4. PRIVILEGED EXECUTION ANOMALY: Web Daemon Breakout (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "web-srv-01"), (2, "web-srv-02")]:
        events = [
            SecurityEvent(
                event_id=f"webshell_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=3),
                hostname=host,
                source="procfs",
                event_type="SUSPICIOUS_SHELL_SPAWNED",
                severity=Severity.HIGH.value,
                user="www-data",
                uid=33, euid=33, gid=33, egid=33, pid=5001 + session_idx, ppid=4500,
                process="bash", command="/bin/bash -c id",
                evidence={"exe": "/bin/bash", "ancestry_depth": 4},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"webshell_{session_idx}_2",
                timestamp=base_time + timedelta(seconds=6),
                hostname=host,
                source="procfs",
                event_type="SUSPICIOUS_SHELL_SPAWNED",
                severity=Severity.HIGH.value,
                user="www-data",
                uid=33, euid=33, gid=33, egid=33, pid=5005 + session_idx, ppid=5001,
                process="sh", command="/bin/sh -i",
                evidence={"exe": "/bin/sh", "ancestry_depth": 5},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_webshell_{session_idx:02d}",
                kernel_release="6.5.0-generic",
                distribution="Ubuntu 22.04 LTS",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.PRIVILEGED_EXECUTION_ANOMALY.value,
                label_provenance="simulated_webshell_lab"
            ))

    # -------------------------------------------------------------
    # 5. CONFIRMED MALICIOUS: SUID /tmp Payload Execution (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "pwn-srv-01"), (2, "pwn-srv-02")]:
        events = [
            SecurityEvent(
                event_id=f"suid_pwn_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=7),
                hostname=host,
                source="auditd",
                event_type="SUID_EXECUTION",
                severity=Severity.CRITICAL.value,
                user="attacker",
                uid=1005, euid=0, gid=1005, egid=0, pid=6001 + session_idx, ppid=5900,
                process="rootshell", command="/tmp/rootshell",
                evidence={"exe": "/tmp/rootshell", "ancestry_depth": 3, "is_suid": True},
                is_test_fixture=True
            ),
            SecurityEvent(
                event_id=f"suid_pwn_{session_idx}_2",
                timestamp=base_time + timedelta(seconds=11),
                hostname=host,
                source="auditd",
                event_type="PROCESS_RUNNING_FROM_TMP",
                severity=Severity.HIGH.value,
                user="attacker",
                uid=1005, euid=0, gid=1005, egid=0, pid=6005 + session_idx, ppid=6001,
                process="sh", command="/tmp/payload.sh",
                evidence={"exe": "/tmp/payload.sh", "ancestry_depth": 4},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_suid_exploit_{session_idx:02d}",
                kernel_release="6.1.0-debian",
                distribution="Debian 12",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.CONFIRMED_MALICIOUS.value,
                label_provenance="cve_suid_privesc_lab"
            ))

    # -------------------------------------------------------------
    # 6. CONFIGURATION TAMPERING: Unauthorized Sensitive File Write (01 and 02)
    # -------------------------------------------------------------
    for session_idx, host in [(1, "audit-srv-01"), (2, "audit-srv-02")]:
        events = [
            SecurityEvent(
                event_id=f"tamper_{session_idx}_1",
                timestamp=base_time + timedelta(seconds=9),
                hostname=host,
                source="auditd",
                event_type="AUDIT_SYSCALL",
                severity=Severity.HIGH.value,
                user="unprivileged",
                uid=1007, euid=1007, gid=1007, egid=1007, pid=7001 + session_idx, ppid=6900,
                process="vim", command="vim /etc/passwd",
                evidence={"path": "/etc/passwd", "ancestry_depth": 2},
                is_test_fixture=True
            )
        ]
        vectors = extractor.extract_matrix(events)
        for ev, fv in zip(events, vectors):
            records.append(LabeledTelemetryRecord(
                record_id=f"rec_{ev.event_id}",
                host_id=host,
                scenario_id=f"scen_passwd_tamper_{session_idx:02d}",
                kernel_release="6.8.0-generic",
                distribution="Ubuntu 24.04",
                event=ev,
                feature_vector=fv,
                ground_truth_label=DetectionLabel.CONFIGURATION_TAMPERING.value,
                label_provenance="file_integrity_lab"
            ))

    return records
