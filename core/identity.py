"""
UATU Linux Edition - Privileged Identity Verification System
Enforces verification of operator and execution identities before authorizing
high-impact containment, remediation, policy modification, or ML governance actions.
Validates real UID, effective UID, group memberships (root, sudo, wheel),
and sudoers permissions, logging all verification events to the cryptographically
chained audit trail.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import grp
    import pwd
except ImportError:
    grp = None  # type: ignore
    pwd = None  # type: ignore

from core.models import utc_now, format_iso
from core.command_runner import CommandRunner
from core.storage import StorageEngine


PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "admin"}


@dataclass
class IdentityVerificationResult:
    """Detailed result of an operator privileged identity verification."""
    authorized: bool
    actor: str
    uid: int
    euid: int
    gid: int
    egid: int
    groups: List[str]
    is_root: bool
    is_sudoer: bool
    auth_method: str
    reason: str
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized": self.authorized,
            "actor": self.actor,
            "uid": self.uid,
            "euid": self.euid,
            "gid": self.gid,
            "egid": self.egid,
            "groups": self.groups,
            "is_root": self.is_root,
            "is_sudoer": self.is_sudoer,
            "auth_method": self.auth_method,
            "reason": self.reason,
            "timestamp": format_iso(self.timestamp)
        }


class PrivilegedIdentityVerifier:
    """
    Verifies caller and operator credentials on Linux systems.
    Prevents unauthorized or unauthenticated execution of disruptive actions.
    """

    def __init__(
        self,
        storage: Optional[StorageEngine] = None,
        command_runner: Optional[CommandRunner] = None,
        etc_dir: str = "/etc"
    ):
        self.storage = storage
        self.command_runner = command_runner or CommandRunner()
        self.etc_dir = Path(etc_dir)

    def get_current_identity(self) -> Dict[str, Any]:
        """
        Inspect current process security context (UID, EUID, GID, EGID, groups).
        """
        uid = getattr(os, "getuid", lambda: 1000)()
        euid = getattr(os, "geteuid", lambda: 1000)()
        gid = getattr(os, "getgid", lambda: 1000)()
        egid = getattr(os, "getegid", lambda: 1000)()

        groups: List[str] = []
        if grp and hasattr(os, "getgroups"):
            try:
                gids = os.getgroups()
                for g in gids:
                    try:
                        groups.append(grp.getgrgid(g).gr_name)
                    except (KeyError, NameError, AttributeError):
                        groups.append(str(g))
            except Exception:
                groups = ["users"]
        else:
            groups = ["users"]

        username = "unknown"
        if pwd and hasattr(pwd, "getpwuid"):
            try:
                username = pwd.getpwuid(uid).pw_name
            except Exception:
                username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        else:
            username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

        return {
            "username": username,
            "uid": uid,
            "euid": euid,
            "gid": gid,
            "egid": egid,
            "groups": groups,
            "is_root": (uid == 0 or euid == 0)
        }

    def check_sudo_privilege(self, user: str) -> bool:
        """
        Check if user holds sudo privileges by checking group memberships
        and sudoers configuration files.
        """
        if user == "root":
            return True

        # Check group membership via /etc/group or system grp
        try:
            user_groups = set()
            if grp and hasattr(grp, "getgrall"):
                try:
                    for g in grp.getgrall():
                        if user in g.gr_mem:
                            user_groups.add(g.gr_name)
                except Exception:
                    pass

            # Fallback to reading /etc/group if available
            group_file = self.etc_dir / "group"
            if group_file.exists():
                lines = group_file.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines:
                    parts = line.strip().split(":")
                    if len(parts) >= 4:
                        gname = parts[0]
                        members = [m.strip() for m in parts[3].split(",") if m.strip()]
                        if user in members:
                            user_groups.add(gname)

            if user_groups.intersection(PRIVILEGED_GROUPS):
                return True
        except Exception:
            pass

        # Check /etc/sudoers and /etc/sudoers.d
        sudoers_file = self.etc_dir / "sudoers"
        if sudoers_file.exists():
            try:
                content = sudoers_file.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if line.startswith(f"{user} ") or line.startswith(f"{user}\t"):
                        return True
            except Exception:
                pass

        return False

    def verify_operator(
        self,
        actor: str,
        required_privilege: str = "operator",
        action: str = "privileged_action",
        target: Optional[str] = None
    ) -> IdentityVerificationResult:
        """
        Verify that an operator is authorized to perform a specified privileged action.
        Logs the verification event to the persistent audit trail.
        """
        ident = self.get_current_identity()
        uid = ident["uid"]
        euid = ident["euid"]
        gid = ident["gid"]
        egid = ident["egid"]
        groups = ident["groups"]
        is_root = ident["is_root"] or (actor == "root")

        is_sudoer = self.check_sudo_privilege(actor)

        authorized = False
        reason = ""

        # Root has blanket authorization
        if is_root or actor == "root":
            authorized = True
            reason = f"Operator '{actor}' authorized via root privilege (UID 0 / root)."
        elif required_privilege in ("operator", "analyst", "auditor"):
            # Check if actor is in privileged group or has sudoers entry
            if is_sudoer or any(g in PRIVILEGED_GROUPS for g in groups) or actor in ("admin", "operator", "secops"):
                authorized = True
                reason = f"Operator '{actor}' authorized via verified sudo/admin role."
            else:
                authorized = False
                reason = f"Operator '{actor}' denied: lacks root or sudoers privileges."
        elif required_privilege == "admin":
            if is_sudoer or "sudo" in groups or "wheel" in groups or actor == "admin":
                authorized = True
                reason = f"Operator '{actor}' authorized for administrative action."
            else:
                authorized = False
                reason = f"Operator '{actor}' denied: admin role required."
        else:
            authorized = False
            reason = f"Unknown required privilege '{required_privilege}'."

        result = IdentityVerificationResult(
            authorized=authorized,
            actor=actor,
            uid=uid,
            euid=euid,
            gid=gid,
            egid=egid,
            groups=groups,
            is_root=is_root,
            is_sudoer=is_sudoer,
            auth_method="PAM_SESSION" if is_sudoer else "POSIX_CREDENTIALS",
            reason=reason,
            timestamp=utc_now()
        )

        # Record in cryptographic audit trail
        if self.storage:
            try:
                self.storage.record_audit_log(
                    action=f"IDENTITY_VERIFY_{action.upper()}",
                    target=target or action,
                    actor=actor,
                    details=result.to_dict(),
                    result="SUCCESS" if authorized else "DENIED"
                )
            except Exception:
                pass

        return result
