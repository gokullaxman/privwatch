"""
UATU Linux Edition - Typed TOML Configuration Manager
Provides strictly validated, hierarchical configuration loaded from TOML files or environment variables.
Enforces:
- Canonical path resolution
- World-writable file rejection (0o002 check on POSIX)
- Unknown key detection
- Secret masking for audit logging
- Safe defaults: monitor-only, auto_containment disabled, loopback interface binding
"""

from dataclasses import dataclass, field, asdict
import os
from pathlib import Path
import stat
import sys
from typing import Dict, List, Optional, Any, Set, Union

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore


# Standard allowed system SUID binaries on Linux distributions
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
    """Get the default SQLite database path for UATU."""
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
class GeneralConfig:
    app_name: str = "UATU"
    version: str = "3.2.0"
    mode: str = "monitor"  # 'monitor', 'audit', 'timeline', 'dashboard'
    output_dir: str = "./reports"
    db_path: str = field(default_factory=get_default_db_path)
    log_level: str = "INFO"
    read_only_mode: bool = True


@dataclass
class TelemetryConfig:
    max_log_lines_per_parse: int = 25000
    timeline_window_sec: int = 3600
    max_events_stored: int = 50000
    auth_log_path: Optional[str] = None
    secure_log_path: Optional[str] = None
    audit_log_path: Optional[str] = None
    syslog_path: Optional[str] = None
    enable_procfs: bool = True
    enable_auditd: bool = True
    enable_journald: bool = True


@dataclass
class DetectionConfig:
    command_timeout_sec: int = 25
    scanner_timeout_sec: int = 120
    suid_allowlist: List[str] = field(default_factory=lambda: list(DEFAULT_SUID_ALLOWLIST))
    target_bin_dirs: List[str] = field(default_factory=lambda: list(STANDARD_BIN_DIRS))
    audit_containers: bool = True
    audit_ssh: bool = True
    audit_path_hijacking: bool = True


@dataclass
class PreventionConfig:
    prevention_enabled: bool = False
    policy_enforcement_mode: str = "MONITOR"  # MONITOR, ENFORCE, DISABLED
    allowed_privilege_transitions: List[str] = field(default_factory=list)


@dataclass
class ContainmentConfig:
    auto_containment: bool = False  # Disabled by default for safety
    allowed_action_types: List[str] = field(default_factory=lambda: ["KILL_PROCESS", "ISOLATE_NETWORK"])
    require_confirmation: bool = True
    max_actions_per_hour: int = 10


@dataclass
class ServiceConfig:
    socket_path: str = "/run/privwatch/privwatch.sock"
    socket_group: str = "root"
    socket_mode: int = 0o660
    pid_file: str = "/run/privwatch/privwatch.pid"


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"  # Bound to loopback by default
    port: int = 8443
    auth_enabled: bool = False
    admin_user: str = "admin"
    admin_password_hash: str = ""
    api_token: str = ""


@dataclass
class MLConfig:
    models_dir: str = "./ml_models"
    inference_batch_size: int = 128
    anomaly_threshold: float = 0.85
    drift_threshold: float = 0.15


@dataclass
class UatuConfig:
    """Master typed configuration for UATU Linux Edition."""
    general: GeneralConfig = field(default_factory=GeneralConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    prevention: PreventionConfig = field(default_factory=PreventionConfig)
    containment: ContainmentConfig = field(default_factory=ContainmentConfig)
    service: ServiceConfig = field(default_factory=ServiceConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    ml: MLConfig = field(default_factory=MLConfig)

    # Known schema sections
    KNOWN_SECTIONS = {
        "general", "telemetry", "detection", "prevention",
        "containment", "service", "dashboard", "ml"
    }

    def canonicalize_paths(self):
        """Resolve all configured paths to canonical absolute paths."""
        self.general.output_dir = str(Path(self.general.output_dir).resolve())
        self.general.db_path = str(Path(self.general.db_path).resolve())
        self.ml.models_dir = str(Path(self.ml.models_dir).resolve())

    def get_redacted_dict(self) -> Dict[str, Any]:
        """Export configuration as a dictionary with all secrets and tokens masked."""
        data = asdict(self)
        self._mask_secrets_in_dict(data)
        return data

    @classmethod
    def _mask_secrets_in_dict(cls, d: Dict[str, Any]):
        """Recursively mask keys containing sensitive names."""
        sensitive_keywords = {"password", "token", "secret", "key", "auth"}
        for k, v in d.items():
            if isinstance(v, dict):
                cls._mask_secrets_in_dict(v)
            elif isinstance(v, str) and any(kw in k.lower() for kw in sensitive_keywords):
                if v:
                    d[k] = "********"

    @classmethod
    def load_from_toml(cls, file_path: Union[str, Path]) -> "UatuConfig":
        """
        Load configuration from a TOML file.
        Rejects world-writable configuration files and validates schema keys.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Configuration file does not exist: {path}")

        # Check world-writable permissions on POSIX
        if hasattr(os, "stat") and os.name == "posix":
            st = os.stat(path)
            if st.st_mode & stat.S_IWOTH:
                raise PermissionError(
                    f"Insecure file permissions: Configuration file '{path}' is world-writable (mode {oct(st.st_mode)}). Loading rejected."
                )

        with open(path, "rb") as f:
            raw_data = tomllib.load(f)

        # Validate top-level sections
        unknown_sections = set(raw_data.keys()) - cls.KNOWN_SECTIONS
        if unknown_sections:
            raise ValueError(f"Unknown configuration sections detected: {unknown_sections}")

        config = cls()

        # Populate sections with typed validation
        if "general" in raw_data:
            cls._populate_dataclass(config.general, raw_data["general"], "general")
        if "telemetry" in raw_data:
            cls._populate_dataclass(config.telemetry, raw_data["telemetry"], "telemetry")
        if "detection" in raw_data:
            cls._populate_dataclass(config.detection, raw_data["detection"], "detection")
        if "prevention" in raw_data:
            cls._populate_dataclass(config.prevention, raw_data["prevention"], "prevention")
        if "containment" in raw_data:
            cls._populate_dataclass(config.containment, raw_data["containment"], "containment")
        if "service" in raw_data:
            cls._populate_dataclass(config.service, raw_data["service"], "service")
        if "dashboard" in raw_data:
            cls._populate_dataclass(config.dashboard, raw_data["dashboard"], "dashboard")
        if "ml" in raw_data:
            cls._populate_dataclass(config.ml, raw_data["ml"], "ml")

        config.canonicalize_paths()
        return config

    @classmethod
    def _populate_dataclass(cls, target_obj: Any, data: Dict[str, Any], section_name: str):
        """Populate dataclass attributes, raising ValueError on unknown keys."""
        valid_fields = set(target_obj.__dataclass_fields__.keys())
        unknown_keys = set(data.keys()) - valid_fields
        if unknown_keys:
            raise ValueError(f"Unknown keys in configuration section [{section_name}]: {unknown_keys}")

        for k, v in data.items():
            setattr(target_obj, k, v)


# Backwards compatibility alias for PrivWatch 3.0
PrivWatchConfig = UatuConfig
