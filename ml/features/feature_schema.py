"""
PrivWatch 3.1 - Standardized Linux Security Feature Schema
Defines the canonical 32-dimensional feature space derived exclusively from genuine Linux telemetry.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import numpy as np


FEATURE_NAMES: List[str] = [
    # 1. Identity & Privilege Features (0-6)
    "uid",
    "euid",
    "gid",
    "egid",
    "uid_euid_mismatch",
    "euid_is_root",
    "uid_is_root",

    # 2. Process Ancestry & Relationship Features (7-14)
    "pid",
    "ppid",
    "pid_ppid_diff",
    "ancestry_depth",
    "is_daemon_user",
    "is_interactive_shell",
    "is_script_interpreter",
    "is_network_tool",

    # 3. Execution Context & Filesystem Features (15-20)
    "exe_in_writable_dir",
    "exe_is_suid",
    "exe_is_sgid",
    "has_file_capabilities",
    "modifies_sensitive_file",
    "syscall_is_elevating",

    # 4. Command & Syntax Features (21-23)
    "command_length",
    "command_arg_count",
    "command_has_pipes",

    # 5. Telemetry Source Encoding (24-26)
    "source_is_auditd",
    "source_is_procfs",
    "source_is_auth_log",

    # 6. Temporal & Sequence Dynamics (27-31)
    "events_last_10s",
    "events_last_60s",
    "auth_fails_last_300s",
    "time_delta_prev_event",
    "consecutive_priv_events",
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "uid": "Real user ID (POSIX UID, -1 if unknown)",
    "euid": "Effective user ID (POSIX EUID, -1 if unknown)",
    "gid": "Real group ID (POSIX GID, -1 if unknown)",
    "egid": "Effective group ID (POSIX EGID, -1 if unknown)",
    "uid_euid_mismatch": "1.0 if real UID differs from effective EUID, else 0.0",
    "euid_is_root": "1.0 if effective UID is root (0), else 0.0",
    "uid_is_root": "1.0 if real UID is root (0), else 0.0",
    "pid": "Process identifier (-1 if unknown)",
    "ppid": "Parent process identifier (-1 if unknown)",
    "pid_ppid_diff": "Absolute difference between PID and PPID",
    "ancestry_depth": "Depth of process lineage in process tree",
    "is_daemon_user": "1.0 if process runs under service user (www-data, apache, nginx, daemon, nobody)",
    "is_interactive_shell": "1.0 if binary is an interactive shell (sh, bash, zsh, dash, ash)",
    "is_script_interpreter": "1.0 if binary is a scripting interpreter (python, perl, ruby, php, lua)",
    "is_network_tool": "1.0 if binary is a networking utility (nc, ncat, socat, curl, wget, ssh)",
    "exe_in_writable_dir": "1.0 if binary path resides in world-writable directory (/tmp, /dev/shm, /var/tmp)",
    "exe_is_suid": "1.0 if binary has SUID permission bit or event is SUID_EXECUTION",
    "exe_is_sgid": "1.0 if binary has SGID permission bit",
    "has_file_capabilities": "1.0 if process or binary possesses Linux capabilities",
    "modifies_sensitive_file": "1.0 if target path involves sensitive config (/etc/passwd, /etc/shadow, /etc/sudoers, cron)",
    "syscall_is_elevating": "1.0 if audit syscall alters credentials (setuid, setreuid, capset, execveat)",
    "command_length": "Character length of the executed command string",
    "command_arg_count": "Count of space-delimited argument tokens in command",
    "command_has_pipes": "1.0 if command contains shell chaining operators (| ; && ||)",
    "source_is_auditd": "1.0 if telemetry originated from Linux auditd kernel subsystem",
    "source_is_procfs": "1.0 if telemetry originated from Linux /proc filesystem or live inspection",
    "source_is_auth_log": "1.0 if telemetry originated from authentication log (/var/log/auth.log)",
    "events_last_10s": "Count of events observed for this host/user within the last 10 seconds",
    "events_last_60s": "Count of events observed within the last 60 seconds",
    "auth_fails_last_300s": "Count of authentication failures observed within the last 5 minutes",
    "time_delta_prev_event": "Time delta in seconds since the preceding observed event (clamped to [0, 3600])",
    "consecutive_priv_events": "Count of consecutive elevated privilege events without intervening unprivileged actions",
}


@dataclass
class FeatureVector:
    """
    Structured feature vector representation for a single security telemetry event.
    Guarantees strict schema adherence and reproducibility.
    """
    event_id: str
    timestamp_iso: str
    values: Dict[str, float] = field(default_factory=dict)

    def to_array(self) -> np.ndarray:
        """Convert feature vector to dense NumPy float64 array ordered by FEATURE_NAMES"""
        arr = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
        for i, name in enumerate(FEATURE_NAMES):
            arr[i] = float(self.values.get(name, 0.0))
        return arr

    def validate(self) -> bool:
        """Validate that all schema features are present and finite"""
        for name in FEATURE_NAMES:
            if name not in self.values:
                return False
            val = self.values[name]
            if not isinstance(val, (int, float)) or np.isnan(val) or np.isinf(val):
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary"""
        return {
            "event_id": self.event_id,
            "timestamp_iso": self.timestamp_iso,
            "values": {k: float(v) for k, v in self.values.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeatureVector":
        """Reconstruct from dictionary"""
        return cls(
            event_id=data["event_id"],
            timestamp_iso=data["timestamp_iso"],
            values=data.get("values", {})
        )
