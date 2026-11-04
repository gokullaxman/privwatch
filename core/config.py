"""
PrivWatch 3.0 - Configuration Manager
Hierarchical configuration with environment variable support, distribution-aware defaults, and strict validation.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any


# Standard allowed / expected system SUID binaries on common Linux distributions
DEFAULT_SUID_ALLOWLIST = [
    '/usr/bin/passwd',
    '/usr/bin/sudo',
    '/usr/bin/newgrp',
    '/usr/bin/chfn',
    '/usr/bin/chsh',
    '/usr/bin/gpasswd',
    '/usr/bin/mount',
    '/usr/bin/umount',
    '/usr/bin/su',
    '/usr/bin/pkexec',
    '/usr/bin/ping',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/libexec/polkit-agent-helper-1'
]

# Standard directories containing system binaries
STANDARD_BIN_DIRS = [
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/usr/local/bin',
    '/usr/local/sbin',
    '/opt'
]


def get_default_db_path() -> str:
    """
    Get the default SQLite database path for UATU.
    Defaults to /var/lib/uatu/uatu.db (0700 dir, service-owned, 0600 file).
    If unprivileged and /var/lib/uatu is not accessible, falls back to
    ~/.local/share/uatu/uatu.db to eliminate root/user permission mixing.
    Can be overridden via UATU_DB_PATH environment variable.
    """
    env_override = os.environ.get("UATU_DB_PATH") or os.environ.get("PRIVWATCH_DB_PATH")
    if env_override:
        return env_override

    if os.name == "posix":
        var_lib_dir = "/var/lib/uatu"
        try:
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return "/var/lib/uatu/uatu.db"
            if os.path.exists(var_lib_dir) and os.access(var_lib_dir, os.W_OK):
                return "/var/lib/uatu/uatu.db"
        except (AttributeError, OSError):
            pass

        user_home = os.path.expanduser("~")
        return os.path.join(user_home, ".local", "share", "uatu", "uatu.db")

    return "./uatu.db"


@dataclass
class PrivWatchConfig:
    """Master configuration for PrivWatch 3.0 Platform"""
    # General
    app_name: str = "UATU"
    version: str = "3.0.0"
    mode: str = "red"  # 'red', 'blue', 'timeline', 'dashboard'
    output_dir: str = "./reports"
    db_path: str = field(default_factory=get_default_db_path)
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    read_only_mode: bool = True

    # Web Dashboard & API
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8443
    dashboard_auth_enabled: bool = False
    dashboard_admin_user: str = "admin"
    dashboard_admin_password_hash: str = ""
    api_token: str = ""

    # Timeouts & Limits
    command_timeout_sec: int = 25
    scanner_timeout_sec: int = 120
    max_log_lines_per_parse: int = 25000
    timeline_window_sec: int = 3600  # 1 hour default correlation window
    max_events_stored: int = 50000

    # Red Team Scanner Settings
    suid_allowlist: List[str] = field(default_factory=lambda: list(DEFAULT_SUID_ALLOWLIST))
    target_bin_dirs: List[str] = field(default_factory=lambda: list(STANDARD_BIN_DIRS))
    audit_containers: bool = True
    audit_ssh: bool = True
    audit_path_hijacking: bool = True

    # Telemetry Paths (Distribution-Aware)
    auth_log_path: Optional[str] = None
    secure_log_path: Optional[str] = None
    audit_log_path: Optional[str] = None
    syslog_path: Optional[str] = None

    def __post_init__(self):
        """Auto-discover paths and apply environment overrides"""
        self._apply_env_overrides()
        self._discover_telemetry_paths()

    def _apply_env_overrides(self):
        """Override configuration with environment variables if present"""
        if os.getenv("PRIVWATCH_LOG_LEVEL"):
            self.log_level = os.getenv("PRIVWATCH_LOG_LEVEL", "INFO").upper()
        if os.getenv("PRIVWATCH_OUTPUT_DIR"):
            self.output_dir = os.getenv("PRIVWATCH_OUTPUT_DIR")
        if os.getenv("UATU_DB_PATH") or os.getenv("PRIVWATCH_DB_PATH"):
            self.db_path = os.getenv("UATU_DB_PATH") or os.getenv("PRIVWATCH_DB_PATH")
        if os.getenv("PRIVWATCH_HOST"):
            self.dashboard_host = os.getenv("PRIVWATCH_HOST")
        if os.getenv("PRIVWATCH_PORT"):
            try:
                self.dashboard_port = int(os.getenv("PRIVWATCH_PORT"))
            except ValueError:
                pass
        if os.getenv("PRIVWATCH_API_TOKEN"):
            self.api_token = os.getenv("PRIVWATCH_API_TOKEN")

    def _discover_telemetry_paths(self):
        """Detect standard system log locations for the current platform"""
        candidates_auth = ["/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"]
        for p in candidates_auth:
            if os.path.exists(p) and not self.auth_log_path:
                self.auth_log_path = p
                break

        if not self.auth_log_path:
            self.auth_log_path = "/var/log/auth.log"  # default fallback

        if os.path.exists("/var/log/secure"):
            self.secure_log_path = "/var/log/secure"
        if os.path.exists("/var/log/audit/audit.log"):
            self.audit_log_path = "/var/log/audit/audit.log"
        if os.path.exists("/var/log/syslog"):
            self.syslog_path = "/var/log/syslog"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'app_name': self.app_name,
            'version': self.version,
            'mode': self.mode,
            'output_dir': self.output_dir,
            'db_path': self.db_path,
            'log_level': self.log_level,
            'read_only_mode': self.read_only_mode,
            'dashboard_host': self.dashboard_host,
            'dashboard_port': self.dashboard_port,
            'dashboard_auth_enabled': self.dashboard_auth_enabled,
            'command_timeout_sec': self.command_timeout_sec,
            'scanner_timeout_sec': self.scanner_timeout_sec,
            'timeline_window_sec': self.timeline_window_sec,
            'auth_log_path': self.auth_log_path,
            'secure_log_path': self.secure_log_path,
            'audit_log_path': self.audit_log_path,
            'syslog_path': self.syslog_path
        }

    @classmethod
    def load_from_file(cls, path: str) -> "PrivWatchConfig":
        """Load configuration from JSON or YAML file"""
        config_path = Path(path)
        if not config_path.exists():
            return cls()

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                if config_path.suffix.lower() == ".json":
                    data = json.load(f)
                elif config_path.suffix.lower() in [".yaml", ".yml"]:
                    try:
                        import yaml
                        data = yaml.safe_load(f)
                    except ImportError:
                        return cls()
                else:
                    data = json.load(f)
            return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
        except Exception:
            return cls()


# Export UatuConfig for modern imports
from core.configuration import UatuConfig

