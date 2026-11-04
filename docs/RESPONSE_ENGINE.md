# UATU Linux Edition — Response & Containment Engine

This document details the controlled response modes, process containment primitives, PID-reuse prevention algorithm, cgroups v2 integration, nftables network containment, and exact remediation rollback mechanisms.

---

## 1. Controlled Response Modes

UATU enforces defense-in-depth through four authorization tiers:

1. `OBSERVE_ONLY` (Default):
   - Constructs containment or remediation plans.
   - Computes consequences and rollback commands.
   - Logs plan to persistent evidence database with status `PLAN_GENERATED`.
   - Modifies zero host state.

2. `ALERT_ONLY`:
   - Generates containment plan and publishes high-priority notification to event bus and operators.
   - Executes zero commands on host.

3. `APPROVAL_REQUIRED`:
   - Requires explicit operator confirmation flag (`confirm=True` or API confirmation token) before modifying system state.
   - Generates plan and consequences for administrative review.

4. `AUTHORIZED_AUTOMATIC`:
   - Automatically executes approved, pre-authorized, non-disruptive containment actions (e.g. process freeze or temporary IP block) strictly bounded by policy constraints.

---

## 2. Process Containment Primitives

### 2.1 PID-Reuse Prevention
Linux recycles process IDs rapidly under heavy process churn. To prevent terminating an innocent process that inherited the PID of a completed exploit, UATU inspects `/proc/<pid>/stat`:
- Field 22 (`starttime` in clock ticks after boot) represents immutable process identity.
- Before issuing signals, `ContainmentEngine.verify_process_identity()` compares the live process's `starttime` against the telemetry event's recorded start time.
- If a mismatch is detected, execution aborts immediately with `RuntimeError("PID-reuse attack detected")`.

### 2.2 System Safety Boundaries
- **Protected PIDs**: Containment strictly rejects targeting PID 1 (`init` / `systemd`) or PID 2 (`kthreadd`).
- **Protected Names**: Process comm/cmdline is validated against `PROTECTED_PROCESS_NAMES` (`systemd`, `init`, `auditd`, `journald`, `kworker/*`, `ksoftirqd`, etc.). Targeting protected processes raises `ValueError`.

### 2.3 Execution Flow
1. Send graceful termination signal: `SIGTERM` (signal 15).
2. Poll process state for up to `timeout_sec` (default 2.0s).
3. If process persists after timeout: issue force termination: `SIGKILL` (signal 9).
4. Document that process termination is irreversible.

---

## 3. Process Freeze & Thaw (cgroups v2)

For reversible containment, UATU leverages cgroups v2:
- **Freeze**: Writes `"1"` to `/sys/fs/cgroup/<slice>/cgroup.freeze` to pause all threads in the cgroup instantaneously without killing processes.
- **Fallback**: If cgroups v2 is unavailable, sends `SIGSTOP` (signal 19).
- **Thaw (Rollback)**: Writes `"0"` to `cgroup.freeze` or sends `SIGCONT` (signal 18), restoring normal execution.

---

## 4. Network Containment (nftables)

To disrupt remote command-and-control (C2) or exfiltration:
- Installs temporary packet filter in dedicated table `inet uatu_containment`:
  ```bash
  nft add table inet uatu_containment
  nft add chain inet uatu_containment input "{ type filter hook input priority -10; policy accept; }"
  nft add set inet uatu_containment blocked_ips "{ type ipv4_addr; flags timeout; }"
  nft add element inet uatu_containment blocked_ips "{ <ip> timeout 1800s }"
  nft add rule inet uatu_containment input ip saddr @blocked_ips drop
  ```
- **Safety Guards**:
  - Rejects loopback addresses (`127.0.0.1`, `::1`).
  - Rejects multicast and unspecified addresses.
  - Rejects host default gateway (extracted dynamically from `/proc/net/route`).
- **Rollback**: Deletes element from set or flushes table.

---

## 5. Defensive Remediation & Rollback

`RemediationEngine` manages filesystem corrections:
- **Dry-Run by Default**: Computes proposed actions, captures pre-remediation mode/owner/group, creates backup if modifying file contents.
- **Symlink Protection**: Resolves canonical target paths via `os.path.realpath()`. Prohibits symlink manipulation.
- **Exact Rollback**: Reverses changes to exact recorded permissions or restores original content from backup copy.
