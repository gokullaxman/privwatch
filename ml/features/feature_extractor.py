"""
PrivWatch 3.1 - Linux Telemetry Feature Extractor
Extracts normalized 32-dimensional numerical feature vectors strictly from verified SecurityEvent records.
"""

from datetime import datetime, timezone
import re
from typing import List, Dict, Any, Optional

from core.models import SecurityEvent, format_iso
from ml.features.feature_schema import FEATURE_NAMES, FeatureVector


DAEMON_USERS = {
    'www-data', 'apache', 'nginx', 'nobody', 'daemon',
    'httpd', 'systemd', 'messagebus', 'syslog', 'postfix'
}

INTERACTIVE_SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'csh', 'tcsh'}

SCRIPT_INTERPRETERS = {'python', 'python3', 'perl', 'ruby', 'php', 'lua', 'node', 'awk'}

NETWORK_TOOLS = {'nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'ssh', 'scp', 'ftp', 'tftp'}

WRITABLE_DIRS = ['/tmp/', '/dev/shm/', '/var/tmp/']

SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d',
    '/etc/crontab', '/etc/cron.', '/etc/pam.d', '/etc/ssh/sshd_config', '/root/'
]

ELEVATING_SYSCALLS = {
    'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid',
    'capset', 'execveat', 'init_module', 'finit_module'
}


class LinuxFeatureExtractor:
    """Extracts genuine 32-feature numerical vectors from Linux SecurityEvents"""

    def __init__(self):
        pass

    def extract_features(
        self,
        event: SecurityEvent,
        history: Optional[List[SecurityEvent]] = None
    ) -> FeatureVector:
        """
        Extract normalized features for a target event given chronological history context.
        All missing values are mapped to explicit non-fabricated defaults.
        """
        values: Dict[str, float] = {}
        hist = history or []

        # 1. Identity & Privilege Features
        uid = float(event.uid) if event.uid is not None else -1.0
        euid = float(event.euid) if event.euid is not None else -1.0
        gid = float(event.gid) if event.gid is not None else -1.0
        egid = float(event.egid) if event.egid is not None else -1.0

        values["uid"] = uid
        values["euid"] = euid
        values["gid"] = gid
        values["egid"] = egid
        values["uid_euid_mismatch"] = 1.0 if (uid >= 0 and euid >= 0 and uid != euid) else 0.0
        values["euid_is_root"] = 1.0 if (euid == 0.0) else 0.0
        values["uid_is_root"] = 1.0 if (uid == 0.0) else 0.0

        # 2. Process Ancestry & Relationship
        pid = float(event.pid) if event.pid is not None else -1.0
        ppid = float(event.ppid) if event.ppid is not None else -1.0
        values["pid"] = pid
        values["ppid"] = ppid
        values["pid_ppid_diff"] = abs(pid - ppid) if (pid >= 0 and ppid >= 0) else 0.0

        # Ancestry depth: inspect evidence if available
        depth = float(event.evidence.get("ancestry_depth", 1.0))
        values["ancestry_depth"] = max(1.0, min(depth, 20.0))

        user_str = (event.user or "").lower()
        proc_str = (event.process or "").lower()
        cmd_str = (event.command or "").lower()

        values["is_daemon_user"] = 1.0 if user_str in DAEMON_USERS else 0.0
        values["is_interactive_shell"] = 1.0 if (proc_str in INTERACTIVE_SHELLS or any(s in cmd_str.split() for s in INTERACTIVE_SHELLS)) else 0.0
        values["is_script_interpreter"] = 1.0 if proc_str in SCRIPT_INTERPRETERS else 0.0
        values["is_network_tool"] = 1.0 if (proc_str in NETWORK_TOOLS or any(n in cmd_str for n in NETWORK_TOOLS)) else 0.0

        # 3. Execution Context & Filesystem
        exe_path = str(event.evidence.get("exe") or event.evidence.get("exe_path") or cmd_str)
        in_writable = any(w in exe_path for w in WRITABLE_DIRS) or event.event_type == "PROCESS_RUNNING_FROM_TMP"
        values["exe_in_writable_dir"] = 1.0 if in_writable else 0.0

        is_suid = (
            event.event_type == "SUID_EXECUTION" or
            bool(event.evidence.get("is_suid")) or
            (values["uid_euid_mismatch"] == 1.0 and values["euid_is_root"] == 1.0)
        )
        values["exe_is_suid"] = 1.0 if is_suid else 0.0
        values["exe_is_sgid"] = 1.0 if bool(event.evidence.get("is_sgid")) else 0.0
        values["has_file_capabilities"] = 1.0 if bool(event.evidence.get("capabilities")) else 0.0

        targets = str(event.evidence.get("target_file") or event.evidence.get("path") or cmd_str)
        modifies_sens = any(s in targets for s in SENSITIVE_FILES)
        values["modifies_sensitive_file"] = 1.0 if modifies_sens else 0.0

        syscall_name = str(event.evidence.get("syscall") or event.evidence.get("comm") or "").lower()
        values["syscall_is_elevating"] = 1.0 if syscall_name in ELEVATING_SYSCALLS else 0.0

        # 4. Command & Syntax
        full_cmd = event.command or event.process or ""
        values["command_length"] = float(len(full_cmd))
        values["command_arg_count"] = float(len(full_cmd.split())) if full_cmd else 0.0
        has_pipes = bool(re.search(r'[|;&]', full_cmd))
        values["command_has_pipes"] = 1.0 if has_pipes else 0.0

        # 5. Telemetry Source Encoding
        src = (event.source or "").lower()
        values["source_is_auditd"] = 1.0 if "audit" in src else 0.0
        values["source_is_procfs"] = 1.0 if ("proc" in src or "process" in src) else 0.0
        values["source_is_auth_log"] = 1.0 if ("auth" in src or "journal" in src) else 0.0

        # 6. Temporal & Sequence Dynamics (from history)
        ev_ts = event.timestamp
        ten_sec_count = 0.0
        sixty_sec_count = 0.0
        auth_fail_count = 0.0
        time_delta = 3600.0  # default large delta
        consecutive_priv = 0.0

        if hist:
            # History should be sorted chronologically
            sorted_hist = sorted(hist, key=lambda e: e.timestamp)
            for prev in reversed(sorted_hist):
                if prev.timestamp > ev_ts:
                    continue
                diff_sec = max(0.0, (ev_ts - prev.timestamp).total_seconds())

                if diff_sec <= 10.0:
                    ten_sec_count += 1.0
                if diff_sec <= 60.0:
                    sixty_sec_count += 1.0
                if diff_sec <= 300.0 and prev.event_type in ["SUDO_AUTH_FAIL", "AUTH_FAILURE"]:
                    auth_fail_count += 1.0

            # Delta to immediate predecessor
            preceding = [p for p in sorted_hist if p.timestamp < ev_ts]
            if preceding:
                time_delta = min(3600.0, max(0.0, (ev_ts - preceding[-1].timestamp).total_seconds()))

            # Consecutive privileged events leading up to this event
            for prev in reversed(preceding):
                if prev.euid == 0 or prev.event_type in ["SUID_EXECUTION", "SUDO_COMMAND", "ACTIVE_EUID_ELEVATION"]:
                    consecutive_priv += 1.0
                else:
                    break

        values["events_last_10s"] = ten_sec_count
        values["events_last_60s"] = sixty_sec_count
        values["auth_fails_last_300s"] = auth_fail_count
        values["time_delta_prev_event"] = time_delta
        values["consecutive_priv_events"] = consecutive_priv

        # Ensure all 32 schema features are populated
        for name in FEATURE_NAMES:
            if name not in values:
                values[name] = 0.0

        return FeatureVector(
            event_id=event.event_id,
            timestamp_iso=format_iso(event.timestamp) or "",
            values=values
        )

    def extract_matrix(
        self,
        events: List[SecurityEvent]
    ) -> List[FeatureVector]:
        """Extract feature vectors across an ordered sequence of events maintaining sliding history"""
        vectors: List[FeatureVector] = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        for i, ev in enumerate(sorted_events):
            history = sorted_events[:i]
            vec = self.extract_features(ev, history)
            vectors.append(vec)
        return vectors
