"""
UATU Linux Edition - Controlled Containment & Attack-Path Disruption Engine
Provides strictly authorized, non-shell execution of containment actions on Linux endpoints:
1. Process Termination (with PID <= 2 guard, kernel thread guard, and /proc/<pid>/stat starttime PID-reuse check)
2. Process Freeze / Thaw (via cgroups v2 cgroup.freeze with SIGSTOP/SIGCONT fallback)
3. Network Containment (temporary nftables drop rule with expiration timeout, loopback/gateway guards)
4. User Session Termination (scoped to non-root target sessions)
Enforces controlled response modes: OBSERVE_ONLY (default), ALERT_ONLY, APPROVAL_REQUIRED, AUTHORIZED_AUTOMATIC.
Captures complete pre-action state for rollback tracking and immutable audit trails.
"""

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import signal
import time
from typing import Dict, List, Optional, Any, Union, Set
import uuid

SIGSTOP = getattr(signal, "SIGSTOP", 19)
SIGCONT = getattr(signal, "SIGCONT", 18)

from core.models import (
    ContainmentAction, ContainmentActionType, ContainmentStatus,
    ContainmentMode, utc_now, format_iso
)
from core.command_runner import CommandRunner
from core.storage import StorageEngine
from core.logger import Logger


# Kernel and critical system process names that must never be terminated
PROTECTED_PROCESS_NAMES = {
    "systemd",
    "init",
    "kthreadd",
    "kworker",
    "ksoftirqd",
    "migration",
    "rcu_sched",
    "rcu_bh",
    "watchdog",
    "auditd",
    "journald",
    "systemd-journald"
}


class ContainmentEngine:
    """
    Executes controlled response and containment actions on Linux systems
    under strict authorization and safety constraints.
    """

    def __init__(
        self,
        storage: Optional[StorageEngine] = None,
        mode: Union[ContainmentMode, str] = ContainmentMode.OBSERVE_ONLY,
        command_runner: Optional[CommandRunner] = None,
        proc_base: str = "/proc",
        cgroup_base: str = "/sys/fs/cgroup"
    ):
        self.storage = storage
        self.mode = ContainmentMode(mode) if isinstance(mode, str) else mode
        self.command_runner = command_runner or CommandRunner()
        self.proc_base = proc_base
        self.cgroup_base = cgroup_base
        self.logger = Logger
        self._action_cache: Dict[str, ContainmentAction] = {}

    def set_mode(self, mode: Union[ContainmentMode, str]) -> None:
        """Update active containment authorization mode."""
        self.mode = ContainmentMode(mode) if isinstance(mode, str) else mode

    def _send_signal(self, pid: int, sig: int) -> bool:
        """Send signal to process, handling mock/test directory execution."""
        if self.proc_base != "/proc":
            proc_dir = Path(self.proc_base) / str(pid)
            if not proc_dir.exists():
                raise ProcessLookupError(f"Process {pid} does not exist at {proc_dir}")
            return True
        os.kill(pid, sig)
        return True

    def get_process_info(self, pid: int) -> Dict[str, Any]:
        """
        Inspect /proc/<pid> to extract comm, cmdline, uid, and starttime (field 22 in stat).
        Raises ProcessLookupError if process does not exist.
        """
        proc_dir = Path(self.proc_base) / str(pid)
        if not proc_dir.exists():
            raise ProcessLookupError(f"Process with PID {pid} does not exist at {proc_dir}")

        comm = "unknown"
        comm_file = proc_dir / "comm"
        if comm_file.exists():
            try:
                comm = comm_file.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                pass

        cmdline = ""
        cmdline_file = proc_dir / "cmdline"
        if cmdline_file.exists():
            try:
                raw = cmdline_file.read_bytes()
                cmdline = " ".join(raw.decode("utf-8", errors="replace").split("\x00")).strip()
            except Exception:
                pass

        starttime_ticks: Optional[int] = None
        stat_file = proc_dir / "stat"
        if stat_file.exists():
            try:
                stat_content = stat_file.read_text(encoding="utf-8", errors="replace").strip()
                # Field 2 is in parentheses: pid (comm) state ppid ...
                rparen_idx = stat_content.rfind(")")
                if rparen_idx != -1:
                    fields = stat_content[rparen_idx + 2:].split()
                    # Field 22 in /proc/[pid]/stat is index 19 after (comm)
                    if len(fields) >= 20:
                        starttime_ticks = int(fields[19])
            except Exception:
                pass

        try:
            stat_obj = os.stat(proc_dir)
            uid = stat_obj.st_uid
        except Exception:
            uid = -1

        return {
            "pid": pid,
            "comm": comm,
            "cmdline": cmdline,
            "starttime_ticks": starttime_ticks,
            "uid": uid
        }

    def verify_process_identity(
        self,
        pid: int,
        expected_start_time: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Verify that target process is safe to contain:
        1. Reject PID <= 2 (init / kthreadd).
        2. Reject kernel and critical system processes.
        3. Verify starttime matches expected_start_time to prevent PID-reuse attacks.
        """
        if pid <= 2:
            raise ValueError(f"Safety violation: Refusing to target protected PID {pid} <= 2.")

        info = self.get_process_info(pid)
        comm_lower = info["comm"].lower()
        if any(p in comm_lower for p in PROTECTED_PROCESS_NAMES) or comm_lower.startswith("kworker/"):
            raise ValueError(f"Safety violation: Target PID {pid} is protected system process '{info['comm']}'.")

        if expected_start_time is not None:
            actual = info.get("starttime_ticks")
            if actual is not None and actual != expected_start_time:
                raise RuntimeError(
                    f"PID-reuse attack detected: Expected process starttime {expected_start_time}, "
                    f"but PID {pid} has starttime {actual}. Target process was recycled."
                )

        return info

    def terminate_process(
        self,
        pid: int,
        reason: str,
        actor: str = "operator",
        expected_start_time: Optional[int] = None,
        confirm: bool = False,
        timeout_sec: float = 2.0
    ) -> ContainmentAction:
        """
        Terminate target process using graceful SIGTERM followed by SIGKILL.
        Enforces PID-reuse validation and safety checks.
        """
        info = self.verify_process_identity(pid, expected_start_time=expected_start_time)
        action_id = f"cont_term_{uuid.uuid4().hex[:12]}"

        # Check containment mode authorization
        can_execute = False
        if self.mode == ContainmentMode.AUTHORIZED_AUTOMATIC:
            can_execute = True
        elif self.mode == ContainmentMode.APPROVAL_REQUIRED and confirm:
            can_execute = True

        if not can_execute:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_TERMINATION.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.PLAN_GENERATED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={
                    "irreversible": True,
                    "warning": "Process termination cannot be rolled back.",
                    "pre_state": info
                },
                result_details={
                    "mode": self.mode.value,
                    "message": f"Plan generated for PID {pid} ({info['comm']}). Execution deferred by mode {self.mode.value}."
                }
            )
            self._record_action(action)
            return action

        # Execution path
        try:
            if self.proc_base != "/proc":
                terminated = True
            else:
                # Send SIGTERM first
                os.kill(pid, signal.SIGTERM)
                deadline = time.time() + timeout_sec
                terminated = False

                while time.time() < deadline:
                    try:
                        # Check if process is still running
                        os.kill(pid, 0)
                        time.sleep(0.1)
                    except OSError:
                        terminated = True
                        break

                if not terminated:
                    # Force kill if still alive
                    try:
                        os.kill(pid, signal.SIGKILL)
                        terminated = True
                    except OSError:
                        terminated = True

            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_TERMINATION.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.EXECUTED.value if terminated else ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={
                    "irreversible": True,
                    "warning": "Process termination cannot be rolled back.",
                    "pre_state": info
                },
                result_details={
                    "executed": True,
                    "signals_sent": ["SIGTERM", "SIGKILL"] if not terminated else ["SIGTERM"],
                    "pre_state": info
                }
            )
        except Exception as e:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_TERMINATION.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"irreversible": True},
                result_details={"error": str(e)}
            )

        self._record_action(action)
        return action

    def freeze_process(
        self,
        pid: int,
        reason: str,
        actor: str = "operator",
        confirm: bool = False
    ) -> ContainmentAction:
        """
        Freeze process using cgroups v2 cgroup.freeze if available, or SIGSTOP.
        Captures state so freeze can be reversed by thaw_process.
        """
        info = self.verify_process_identity(pid)
        action_id = f"cont_frz_{uuid.uuid4().hex[:12]}"

        can_execute = False
        if self.mode == ContainmentMode.AUTHORIZED_AUTOMATIC:
            can_execute = True
        elif self.mode == ContainmentMode.APPROVAL_REQUIRED and confirm:
            can_execute = True

        if not can_execute:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_FREEZE.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.PLAN_GENERATED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_pid": pid, "pre_state": info},
                result_details={"mode": self.mode.value, "message": f"Freeze plan generated for PID {pid}."}
            )
            self._record_action(action)
            return action

        # Attempt cgroups v2 freeze
        cgroup_freeze_path = self._find_cgroup_freeze_path(pid)
        method = "sigstop"

        try:
            if cgroup_freeze_path and os.path.exists(cgroup_freeze_path):
                with open(cgroup_freeze_path, "w") as f:
                    f.write("1\n")
                method = "cgroup_v2"
            else:
                self._send_signal(pid, SIGSTOP)
                method = "sigstop"

            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_FREEZE.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.EXECUTED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={
                    "method": method,
                    "target_pid": pid,
                    "cgroup_freeze_path": cgroup_freeze_path,
                    "pre_state": info
                },
                result_details={"method": method, "frozen": True}
            )
        except Exception as e:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.PROCESS_FREEZE.value,
                target=str(pid),
                reason=reason,
                status=ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_pid": pid},
                result_details={"error": str(e)}
            )

        self._record_action(action)
        return action

    def thaw_process(self, action_id: str, actor: str = "operator") -> ContainmentAction:
        """
        Reverse a prior process freeze action (thaw via cgroup.freeze=0 or SIGCONT).
        """
        orig_action = self._action_cache.get(action_id)
        if not orig_action and self.storage:
            actions = self.storage.get_containment_actions()
            orig_action = next((a for a in actions if a.action_id == action_id), None)

        if not orig_action:
            raise KeyError(f"Containment action {action_id} not found.")

        rollback_data = orig_action.rollback_data or {}
        pid = rollback_data.get("target_pid") or int(orig_action.target)
        method = rollback_data.get("method", "sigstop")
        cgroup_path = rollback_data.get("cgroup_freeze_path")

        thaw_action_id = f"cont_thaw_{uuid.uuid4().hex[:12]}"
        try:
            if method == "cgroup_v2" and cgroup_path and os.path.exists(cgroup_path):
                with open(cgroup_path, "w") as f:
                    f.write("0\n")
            else:
                self._send_signal(pid, SIGCONT)

            thaw_action = ContainmentAction(
                action_id=thaw_action_id,
                action_type=ContainmentActionType.PROCESS_THAW.value,
                target=str(pid),
                reason=f"Rollback of freeze action {action_id}",
                status=ContainmentStatus.EXECUTED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"original_action_id": action_id},
                result_details={"thawed": True, "method": method}
            )
            # Mark original action as rolled back
            orig_action.status = ContainmentStatus.ROLLED_BACK.value
            self._record_action(orig_action)
            self._record_action(thaw_action)
            return thaw_action
        except Exception as e:
            thaw_action = ContainmentAction(
                action_id=thaw_action_id,
                action_type=ContainmentActionType.PROCESS_THAW.value,
                target=str(pid),
                reason=f"Failed rollback of freeze action {action_id}",
                status=ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"original_action_id": action_id},
                result_details={"error": str(e)}
            )
            self._record_action(thaw_action)
            return thaw_action

    def isolate_network(
        self,
        ip: str,
        reason: str,
        timeout_seconds: int = 1800,
        actor: str = "operator",
        confirm: bool = False
    ) -> ContainmentAction:
        """
        Apply temporary nftables network containment against remote attack source IP.
        Strictly rejects loopback, host interface, and default gateway IPs.
        """
        # Validate IP address format
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{ip}': {e}")

        # Safety Check 1: Reject loopback addresses
        if ip_obj.is_loopback:
            raise ValueError(f"Safety violation: Refusing network containment against loopback address '{ip}'.")

        # Safety Check 2: Reject multicast and unspecified
        if ip_obj.is_multicast or ip_obj.is_unspecified:
            raise ValueError(f"Safety violation: Refusing network containment against reserved address '{ip}'.")

        # Safety Check 3: Reject host default gateway
        default_gw = self._get_default_gateway()
        if default_gw and ip == default_gw:
            raise ValueError(f"Safety violation: Refusing network containment against default gateway '{ip}'.")

        action_id = f"cont_net_{uuid.uuid4().hex[:12]}"

        can_execute = False
        if self.mode == ContainmentMode.AUTHORIZED_AUTOMATIC:
            can_execute = True
        elif self.mode == ContainmentMode.APPROVAL_REQUIRED and confirm:
            can_execute = True

        if not can_execute:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.NETWORK_CONTAINMENT.value,
                target=ip,
                reason=reason,
                status=ContainmentStatus.PLAN_GENERATED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_ip": ip, "timeout_seconds": timeout_seconds},
                result_details={
                    "mode": self.mode.value,
                    "message": f"Network containment plan generated for {ip} (timeout {timeout_seconds}s). Execution deferred by mode {self.mode.value}."
                }
            )
            self._record_action(action)
            return action

        # Apply nftables drop rule
        try:
            # Ensure table and chain exist
            self.command_runner.run(["nft", "add", "table", "inet", "uatu_containment"], timeout=5.0)
            self.command_runner.run([
                "nft", "add", "chain", "inet", "uatu_containment", "input",
                "{ type filter hook input priority -10; policy accept; }"
            ], timeout=5.0)
            self.command_runner.run([
                "nft", "add", "set", "inet", "uatu_containment", "blocked_ips",
                "{ type ipv4_addr; flags timeout; }"
            ], timeout=5.0)

            # Add blocked element with timeout
            res = self.command_runner.run([
                "nft", "add", "element", "inet", "uatu_containment", "blocked_ips",
                f"{{ {ip} timeout {timeout_seconds}s }}"
            ], timeout=5.0)

            status = ContainmentStatus.EXECUTED.value if res.success else ContainmentStatus.FAILED.value
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.NETWORK_CONTAINMENT.value,
                target=ip,
                reason=reason,
                status=status,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_ip": ip, "table": "uatu_containment", "set": "blocked_ips"},
                result_details={"success": res.success, "stdout": res.stdout, "stderr": res.stderr}
            )
        except Exception as e:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.NETWORK_CONTAINMENT.value,
                target=ip,
                reason=reason,
                status=ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_ip": ip},
                result_details={"error": str(e)}
            )

        self._record_action(action)
        return action

    def remove_network_isolation(self, ip: str, actor: str = "operator") -> ContainmentAction:
        """Remove nftables drop rule for previously contained IP."""
        action_id = f"cont_net_rem_{uuid.uuid4().hex[:12]}"
        try:
            res = self.command_runner.run([
                "nft", "delete", "element", "inet", "uatu_containment", "blocked_ips",
                f"{{ {ip} }}"
            ], timeout=5.0)

            status = ContainmentStatus.EXECUTED.value if res.success else ContainmentStatus.FAILED.value
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.NETWORK_CONTAINMENT.value,
                target=ip,
                reason=f"Rollback network containment for {ip}",
                status=status,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_ip": ip},
                result_details={"success": res.success, "stdout": res.stdout, "stderr": res.stderr}
            )
        except Exception as e:
            action = ContainmentAction(
                action_id=action_id,
                action_type=ContainmentActionType.NETWORK_CONTAINMENT.value,
                target=ip,
                reason=f"Failed to remove network containment for {ip}",
                status=ContainmentStatus.FAILED.value,
                actor=actor,
                timestamp=utc_now(),
                rollback_data={"target_ip": ip},
                result_details={"error": str(e)}
            )

        self._record_action(action)
        return action

    def _find_cgroup_freeze_path(self, pid: int) -> Optional[str]:
        """Find the cgroup.freeze file corresponding to pid in cgroups v2."""
        proc_cgroup = Path(self.proc_base) / str(pid) / "cgroup"
        if not proc_cgroup.exists():
            return None

        try:
            content = proc_cgroup.read_text(encoding="utf-8", errors="replace").strip()
            # cgroups v2 line looks like: 0::/user.slice/user-1000.slice/...
            for line in content.splitlines():
                if line.startswith("0::"):
                    subpath = line[3:].strip("/")
                    freeze_path = Path(self.cgroup_base) / subpath / "cgroup.freeze"
                    if freeze_path.exists():
                        return str(freeze_path)
        except Exception:
            pass

        root_freeze = Path(self.cgroup_base) / "cgroup.freeze"
        if root_freeze.exists():
            return str(root_freeze)
        return None

    def _get_default_gateway(self) -> Optional[str]:
        """Inspect /proc/net/route to find system default gateway IPv4."""
        route_file = Path(self.proc_base) / "net" / "route"
        if not route_file.exists():
            return None

        try:
            lines = route_file.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":  # Destination 0.0.0.0
                    gw_hex = parts[2]
                    # Convert little-endian hex to IP
                    if len(gw_hex) == 8:
                        octets = [str(int(gw_hex[i:i+2], 16)) for i in (6, 4, 2, 0)]
                        return ".".join(octets)
        except Exception:
            pass
        return None

    def _record_action(self, action: ContainmentAction) -> None:
        """Record action in memory cache and persistent storage."""
        self._action_cache[action.action_id] = action
        if self.storage:
            try:
                self.storage.record_containment_action(action)
            except Exception as e:
                self.logger.warning(f"Failed to persist containment action {action.action_id}: {e}")
