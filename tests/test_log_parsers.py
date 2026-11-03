"""
PrivWatch 3.0 - Unit Tests for Log Parsers & Timestamp Multi-Format Support
"""

from datetime import datetime, timezone
import pytest

from core.log_parser import LogParser
from modules.blue_mode.telemetry.auth_collector import AuthLogCollector


class DummyParser(LogParser):
    def parse(self, log_file=None):
        return []


def test_timestamp_parser_rfc3164():
    parser = DummyParser("TEST")
    line = "Oct  4 13:51:21 srv-01 sudo: pam_unix(sudo:auth): authentication failure"
    dt = parser.parse_syslog_timestamp(line)
    assert dt is not None
    assert dt.month == 10
    assert dt.day == 4
    assert dt.hour == 13
    assert dt.minute == 51


def test_timestamp_parser_iso8601():
    parser = DummyParser("TEST")
    line = "2026-11-03T18:15:30.123456Z srv-01 sudo[123]: pam_unix"
    dt = parser.parse_syslog_timestamp(line)
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 11
    assert dt.day == 3
    assert dt.hour == 18


def test_timestamp_parser_auditd():
    parser = DummyParser("TEST")
    # Epoch 1730657730 is in Nov 2024
    line = "type=SYSCALL msg=audit(1730657730.123:452): arch=c000003e syscall=59"
    dt = parser.parse_syslog_timestamp(line)
    assert dt is not None
    assert dt.year >= 2024


def test_auth_collector_normalization():
    collector = AuthLogCollector()
    line = "Nov  3 18:20:10 srv-test sudo[4521]: operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/bin/bash"
    evt = collector._normalize_line(line)
    assert evt is not None
    assert evt.event_type == "SUDO_COMMAND"
    assert evt.user == "operator"
    assert evt.command == "/bin/bash"
    assert evt.pid == 4521


def test_auth_collector_failed_password_normalization():
    collector = AuthLogCollector()
    line = "Nov  3 18:21:00 srv-test sudo[4530]: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=operator rhost=  user=operator"
    evt = collector._normalize_line(line)
    assert evt is not None
    assert evt.event_type == "SUDO_AUTH_FAIL"
    assert evt.user == "operator"
    assert evt.severity == "HIGH"

