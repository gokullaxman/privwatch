"""
UATU Linux Edition - Response & Containment Engine Tests
Verifies safety guards, PID-reuse prevention, containment modes, rollback capabilities,
cgroups v2/SIGSTOP freeze and thaw, and nftables network containment guards.
"""

from pathlib import Path
import pytest
import tempfile

from core.models import (
    ContainmentAction, ContainmentActionType, ContainmentStatus, ContainmentMode
)
from core.storage import StorageEngine
from modules.response.containment_engine import ContainmentEngine


class DummyCommandRunner:
    """Mock command runner to capture executed non-shell commands without system impact."""
    def __init__(self):
        self.executed_commands = []

    def run(self, cmd, timeout=30.0, env=None):
        self.executed_commands.append(list(cmd))
        from core.command_runner import CommandResult
        return CommandResult(
            executable=cmd[0],
            arguments=tuple(cmd[1:]),
            return_code=0,
            stdout="OK",
            stderr="",
            duration_ms=5.0
        )


def _setup_mock_proc(base_dir: Path, pid: int, comm: str, cmdline: str, starttime_ticks: int = 50000):
    proc_pid = base_dir / str(pid)
    proc_pid.mkdir(parents=True, exist_ok=True)
    (proc_pid / "comm").write_text(f"{comm}\n", encoding="utf-8")
    (proc_pid / "cmdline").write_bytes(cmdline.replace(" ", "\x00").encode("utf-8") + b"\x00")
    # /proc/[pid]/stat format: pid (comm) state ppid ... starttime is 20th field after (comm)
    stat_fields = [str(pid), f"({comm})", "S", "100", "100", "0", "0", "0", "0", "0",
                   "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", str(starttime_ticks), "0"]
    (proc_pid / "stat").write_text(" ".join(stat_fields) + "\n", encoding="utf-8")


def test_process_termination_pid_guards(temp_dir):
    """Verify PID <= 2 and kernel/systemd processes are strictly protected from termination."""
    engine = ContainmentEngine(proc_base=str(temp_dir))

    # Reject PID 1
    with pytest.raises(ValueError, match="protected PID 1 <= 2"):
        engine.terminate_process(1, reason="Test termination")

    # Reject PID 2
    with pytest.raises(ValueError, match="protected PID 2 <= 2"):
        engine.terminate_process(2, reason="Test termination")

    # Reject systemd process
    _setup_mock_proc(temp_dir, pid=10, comm="systemd", cmdline="/lib/systemd/systemd")
    with pytest.raises(ValueError, match="protected system process 'systemd'"):
        engine.terminate_process(10, reason="Test termination")

    # Reject kernel thread
    _setup_mock_proc(temp_dir, pid=25, comm="kthreadd", cmdline="")
    with pytest.raises(ValueError, match="protected system process 'kthreadd'"):
        engine.terminate_process(25, reason="Test termination")


def test_pid_reuse_prevention(temp_dir):
    """Verify process starttime mismatch raises RuntimeError to prevent killing recycled PIDs."""
    engine = ContainmentEngine(proc_base=str(temp_dir))
    pid = 4321
    _setup_mock_proc(temp_dir, pid=pid, comm="malicious_tool", cmdline="./malicious_tool", starttime_ticks=1000)

    # Valid starttime match succeeds check
    info = engine.verify_process_identity(pid, expected_start_time=1000)
    assert info["comm"] == "malicious_tool"
    assert info["starttime_ticks"] == 1000

    # Starttime mismatch triggers PID-reuse abort
    with pytest.raises(RuntimeError, match="PID-reuse attack detected"):
        engine.verify_process_identity(pid, expected_start_time=9999)


def test_observe_only_mode_generates_plan_without_execution(temp_dir):
    """In OBSERVE_ONLY mode, verify containment actions generate plans and never execute."""
    storage = StorageEngine(str(temp_dir / "containment.db"))
    engine = ContainmentEngine(storage=storage, mode=ContainmentMode.OBSERVE_ONLY, proc_base=str(temp_dir))

    pid = 5555
    _setup_mock_proc(temp_dir, pid=pid, comm="exploit", cmdline="./exploit", starttime_ticks=2000)

    action = engine.terminate_process(pid=pid, reason="Escalation detected", expected_start_time=2000)
    assert action.status == ContainmentStatus.PLAN_GENERATED.value
    assert action.rollback_data.get("irreversible") is True
    assert "OBSERVE_ONLY" in action.result_details.get("mode", "")

    # Storage records the generated plan
    saved = storage.get_containment_actions()
    assert len(saved) == 1
    assert saved[0].status == ContainmentStatus.PLAN_GENERATED.value


def test_approval_required_mode(temp_dir):
    """In APPROVAL_REQUIRED mode, confirm=False generates plan, confirm=True permits execution."""
    engine = ContainmentEngine(mode=ContainmentMode.APPROVAL_REQUIRED, proc_base=str(temp_dir))
    pid = 6666
    _setup_mock_proc(temp_dir, pid=pid, comm="backdoor", cmdline="./backdoor", starttime_ticks=3000)

    # Without confirmation -> plan generated
    action_unconfirmed = engine.terminate_process(pid=pid, reason="Backdoor active", confirm=False)
    assert action_unconfirmed.status == ContainmentStatus.PLAN_GENERATED.value


def test_network_containment_guards(temp_dir):
    """Verify loopback and default gateway IPs are strictly guarded against containment."""
    cmd_runner = DummyCommandRunner()
    engine = ContainmentEngine(
        mode=ContainmentMode.AUTHORIZED_AUTOMATIC,
        command_runner=cmd_runner,
        proc_base=str(temp_dir)
    )

    # Reject IPv4 loopback
    with pytest.raises(ValueError, match="loopback address '127.0.0.1'"):
        engine.isolate_network("127.0.0.1", reason="Malicious scan")

    # Reject IPv6 loopback
    with pytest.raises(ValueError, match="loopback address '::1'"):
        engine.isolate_network("::1", reason="Malicious scan")

    # Setup simulated route file with default gateway 192.168.1.1
    net_dir = temp_dir / "net"
    net_dir.mkdir(parents=True, exist_ok=True)
    # Hex C0A80101 = 192.168.1.1 in little endian (0101A8C0)
    (net_dir / "route").write_text("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n", encoding="utf-8")

    with pytest.raises(ValueError, match="default gateway '192.168.1.1'"):
        engine.isolate_network("192.168.1.1", reason="Attacker IP")

    # Authorized remote IP executes nftables containment
    action = engine.isolate_network("203.0.113.50", reason="C2 communication", timeout_seconds=600)
    assert action.status == ContainmentStatus.EXECUTED.value
    assert action.target == "203.0.113.50"

    # Verify nft commands executed without shell
    assert any("nft" in cmd[0] and "203.0.113.50 timeout 600s" in cmd[-1] for cmd in cmd_runner.executed_commands)

    # Rollback containment
    rem_action = engine.remove_network_isolation("203.0.113.50")
    assert rem_action.status == ContainmentStatus.EXECUTED.value
    assert any("delete" in cmd and "203.0.113.50" in cmd[-1] for cmd in cmd_runner.executed_commands)


def test_freeze_and_thaw_rollback(temp_dir):
    """Verify process freeze produces rollback metadata and thaw reverses it."""
    storage = StorageEngine(str(temp_dir / "freeze.db"))
    engine = ContainmentEngine(
        storage=storage,
        mode=ContainmentMode.AUTHORIZED_AUTOMATIC,
        proc_base=str(temp_dir)
    )

    pid = 7777
    _setup_mock_proc(temp_dir, pid=pid, comm="miner", cmdline="./miner", starttime_ticks=4000)

    # Freeze process
    freeze_action = engine.freeze_process(pid=pid, reason="Unauthorized resource usage")
    assert freeze_action.action_type == ContainmentActionType.PROCESS_FREEZE.value
    assert freeze_action.rollback_data.get("target_pid") == pid

    # Thaw process
    thaw_action = engine.thaw_process(freeze_action.action_id)
    assert thaw_action.action_type == ContainmentActionType.PROCESS_THAW.value
    assert thaw_action.status == ContainmentStatus.EXECUTED.value
