"""
PrivWatch 3.0 - Controlled Remediation & Prevention Engine
Linux-native typed remediation playbooks, enforced dry-run defaults, symlink protection,
atomic state capture, pre-execution backups, and exact rollback restoration.
Strictly eliminates shell execution (shell=False) in favor of verified POSIX system calls.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import stat
from typing import List, Dict, Any, Optional
import uuid

from core.models import Finding, utc_now
from core.storage import StorageEngine
from core.logger import Logger


@dataclass
class RemediationAction:
    """Typed individual remediation operation on a validated system target."""
    action_id: str
    action_type: str  # e.g., "CHMOD", "CHOWN", "STRIP_SUID", "REMOVE_LINE"
    target: str
    canonical_target: str
    expected_original_mode: Optional[int] = None
    desired_mode: Optional[int] = None
    expected_original_uid: Optional[int] = None
    desired_uid: Optional[int] = None
    expected_original_gid: Optional[int] = None
    desired_gid: Optional[int] = None
    required_privileges: str = "root"
    consequences: str = ""
    backup_required: bool = True
    backup_path: Optional[str] = None
    executed: bool = False
    rolled_back: bool = False

    def to_command_string(self) -> str:
        """Produce human-readable POSIX representation for reporting."""
        if self.action_type == "CHMOD" and self.desired_mode is not None:
            return f"chmod {oct(self.desired_mode)[-3:]} {self.target}"
        elif self.action_type == "STRIP_SUID":
            return f"chmod u-s {self.target}"
        elif self.action_type == "CHOWN":
            return f"chown {self.desired_uid or 0}:{self.desired_gid or 0} {self.target}"
        return f"# Action {self.action_type} on {self.target}"

    def to_rollback_string(self) -> str:
        """Produce exact human-readable rollback command string."""
        if self.action_type == "STRIP_SUID":
            return f"chmod u+s {self.target}"
        elif self.expected_original_mode is not None:
            return f"chmod {oct(self.expected_original_mode)[-4:]} {self.target}"
        elif self.backup_path:
            return f"cp -p {self.backup_path} {self.target}"
        return f"# Restore original state of {self.target}"


@dataclass
class RemediationPlan:
    """Comprehensive plan containing typed actions, security consequences, and verified rollbacks."""
    plan_id: str
    finding_id: str
    title: str
    target_resource: str
    actions: List[RemediationAction] = field(default_factory=list)
    consequences: str = ""
    requires_root: bool = True
    created_at: datetime = field(default_factory=utc_now)

    @property
    def proposed_commands(self) -> List[str]:
        return [a.to_command_string() for a in self.actions]

    @property
    def rollback_commands(self) -> List[str]:
        return [a.to_rollback_string() for a in self.actions]


class RemediationEngine:
    """Safely constructs, dry-runs, and executes typed Linux system remediations."""

    def __init__(self, storage: Optional[StorageEngine] = None, read_only: bool = True):
        self.storage = storage
        self.read_only = read_only

    def generate_plan(self, finding: Finding) -> RemediationPlan:
        """Generate a safe, typed remediation plan with exact original state capture."""
        resource = finding.affected_resource or ""
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"
        actions: List[RemediationAction] = []
        consequences = "Modifies permissions or configurations to enforce least-privilege security."

        # Canonicalize target path if it points to an existing filesystem object
        canonical_target = resource
        orig_mode = None
        orig_uid = None
        orig_gid = None

        if os.path.exists(resource):
            try:
                canonical_target = os.path.realpath(resource)
                st = os.stat(canonical_target)
                orig_mode = st.st_mode
                orig_uid = st.st_uid
                orig_gid = st.st_gid
            except Exception:
                pass

        vector = finding.vector

        is_abs = resource.startswith('/') or os.path.isabs(resource)

        # Case 1: SUID / SGID bit removal
        if vector == "SUID/SGID" and is_abs:
            desired_mode = (orig_mode & ~stat.S_ISUID & ~stat.S_ISGID) if orig_mode else 0o755
            actions.append(RemediationAction(
                action_id=f"act_{uuid.uuid4().hex[:6]}",
                action_type="STRIP_SUID",
                target=resource,
                canonical_target=canonical_target,
                expected_original_mode=orig_mode,
                desired_mode=desired_mode,
                expected_original_uid=orig_uid,
                desired_uid=orig_uid,
                expected_original_gid=orig_gid,
                desired_gid=orig_gid,
                consequences=f"Removes the SUID bit from {resource}. Non-root users can no longer execute it with owner privileges.",
                backup_required=False
            ))
            consequences = f"Removes the SUID bit from {resource}."

        # Case 2: Insecure Cron Script or Configuration Hardening
        elif vector == "CRON" and is_abs:
            is_exec = bool(orig_mode & 0o111) if orig_mode else False
            desired_mode = 0o755 if is_exec else 0o644

            actions.append(RemediationAction(
                action_id=f"act_{uuid.uuid4().hex[:6]}",
                action_type="CHMOD",
                target=resource,
                canonical_target=canonical_target,
                expected_original_mode=orig_mode,
                desired_mode=desired_mode,
                expected_original_uid=orig_uid,
                desired_uid=0,
                expected_original_gid=orig_gid,
                desired_gid=0,
                consequences=f"Hardens permissions of {resource} to {oct(desired_mode)[-3:]} and transfers ownership to root:root.",
                backup_required=True
            ))
            consequences = f"Enforces least privilege on scheduled task file {resource}."

        # Case 3: Sudoers Configuration File Hardening
        elif vector == "SUDO" and is_abs:
            actions.append(RemediationAction(
                action_id=f"act_{uuid.uuid4().hex[:6]}",
                action_type="CHMOD",
                target=resource,
                canonical_target=canonical_target,
                expected_original_mode=orig_mode,
                desired_mode=0o440,
                expected_original_uid=orig_uid,
                desired_uid=0,
                expected_original_gid=orig_gid,
                desired_gid=0,
                consequences=f"Hardens sudoers file {resource} to 0440 (root:root).",
                backup_required=True
            ))
            consequences = f"Restricts sudoers configuration {resource} to read-only for root."

        # Case 4: SSH authorized_keys Hardening
        elif vector == "SSH_SECURITY" and "authorized_keys" in resource:
            actions.append(RemediationAction(
                action_id=f"act_{uuid.uuid4().hex[:6]}",
                action_type="CHMOD",
                target=resource,
                canonical_target=canonical_target,
                expected_original_mode=orig_mode,
                desired_mode=0o600,
                expected_original_uid=orig_uid,
                expected_original_gid=orig_gid,
                consequences=f"Restricts permissions of {resource} strictly to 0600 (owner read/write).",
                backup_required=True
            ))
            consequences = f"Prevents unauthorized accounts from reading or modifying {resource}."

        return RemediationPlan(
            plan_id=plan_id,
            finding_id=finding.finding_id,
            title=finding.title,
            target_resource=resource,
            actions=actions,
            consequences=consequences,
            requires_root=True
        )

    def execute_plan(
        self,
        plan: RemediationPlan,
        actor: str,
        confirmed: bool = False,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Execute or simulate a remediation plan with atomic rollback on partial failure.
        Enforces dry_run=True by default and requires confirmed=True to alter system state.
        Uses Python POSIX APIs without subshell invocation.
        """
        # Safety gate 1: Default to Dry-Run
        if dry_run or self.read_only:
            result = {
                'status': 'DRY_RUN',
                'executed': False,
                'message': 'Simulation completed successfully. No system files were modified.',
                'plan': {
                    'plan_id': plan.plan_id,
                    'proposed_commands': plan.proposed_commands,
                    'consequences': plan.consequences,
                    'rollback_commands': plan.rollback_commands
                }
            }
            if self.storage:
                self.storage.log_admin_action(
                    action="REMEDIATION_DRY_RUN",
                    target=plan.target_resource,
                    actor=actor,
                    details={'plan_id': plan.plan_id, 'commands': plan.proposed_commands},
                    result="SUCCESS"
                )
            return result

        # Safety gate 2: Explicit Confirmation Required
        if not confirmed:
            raise PermissionError("Explicit confirmation (confirmed=True) is required to execute system modifications.")

        executed_actions: List[RemediationAction] = []

        try:
            for action in plan.actions:
                target_path = action.canonical_target

                # Symlink Protection: Do not follow untrusted symlinks
                if os.path.islink(action.target):
                    raise SecurityError(
                        f"Refusing to remediate symlink target '{action.target}'. Target must be a regular canonical file."
                    )

                if not os.path.exists(target_path):
                    raise FileNotFoundError(f"Remediation target does not exist: {target_path}")

                # Create pre-execution backup if required
                if action.backup_required and os.path.isfile(target_path):
                    backup_file = f"{target_path}.privwatch_{action.action_id}.bak"
                    shutil.copy2(target_path, backup_file)
                    action.backup_path = backup_file

                # Security check: Never permit world-writable permissions (e.g., chmod 666 / 777)
                if action.desired_mode is not None and (action.desired_mode & 0o002):
                    raise ValueError(f"Security rejection: Remediations must never grant world-write permissions (got mode {oct(action.desired_mode)}).")

                # Execute Action via Safe POSIX System Calls
                if action.action_type in ["CHMOD", "STRIP_SUID"] and action.desired_mode is not None:
                    os.chmod(target_path, action.desired_mode)

                if action.desired_uid is not None or action.desired_gid is not None:
                    uid = action.desired_uid if action.desired_uid is not None else -1
                    gid = action.desired_gid if action.desired_gid is not None else -1
                    if hasattr(os, 'chown'):
                        os.chown(target_path, uid, gid)

                action.executed = True
                executed_actions.append(action)

            # Verification: Verify file mode and ownership match desired state on POSIX
            if os.name == 'posix':
                for action in executed_actions:
                    st = os.stat(action.canonical_target)
                    if action.desired_mode is not None:
                        curr_mode = st.st_mode & 0o7777
                        if action.action_type == "CHMOD":
                            assert (curr_mode & 0o777) == (action.desired_mode & 0o777), f"Verification failed: expected mode {oct(action.desired_mode)}, got {oct(curr_mode)}"
                        elif action.action_type == "STRIP_SUID":
                            assert not (st.st_mode & stat.S_ISUID), f"Verification failed: SUID bit still set on {action.canonical_target}"

            result = {
                'status': 'SUCCESS',
                'executed': True,
                'message': f"Remediation applied successfully: {len(executed_actions)} actions completed.",
                'plan_id': plan.plan_id,
                'target': plan.target_resource,
                'rollback_commands': plan.rollback_commands
            }

            if self.storage:
                self.storage.log_admin_action(
                    action="REMEDIATION_EXECUTE",
                    target=plan.target_resource,
                    actor=actor,
                    details={'plan_id': plan.plan_id, 'actions': [a.action_id for a in executed_actions]},
                    result="SUCCESS"
                )
            return result

        except ValueError as ve:
            raise ve
        except Exception as e:
            # Operation partially failed: Trigger Safe Rollback in reverse order
            rollback_errors = []
            for action in reversed(executed_actions):
                try:
                    if action.expected_original_mode is not None:
                        os.chmod(action.canonical_target, action.expected_original_mode)
                    if action.expected_original_uid is not None or action.expected_original_gid is not None:
                        uid = action.expected_original_uid if action.expected_original_uid is not None else -1
                        gid = action.expected_original_gid if action.expected_original_gid is not None else -1
                        if hasattr(os, 'chown'):
                            os.chown(action.canonical_target, uid, gid)
                    action.rolled_back = True
                except Exception as rb_err:
                    rollback_errors.append(f"Rollback failed for {action.canonical_target}: {str(rb_err)}")

            if self.storage:
                self.storage.log_admin_action(
                    action="REMEDIATION_FAILED_ROLLED_BACK",
                    target=plan.target_resource,
                    actor=actor,
                    details={'error': str(e), 'rollback_errors': rollback_errors},
                    result="ROLLED_BACK" if not rollback_errors else "PARTIAL_ROLLBACK_ERROR"
                )

            raise RuntimeError(
                f"Remediation execution aborted: {str(e)}. Completed actions rolled back. "
                f"{'Errors during rollback: ' + '; '.join(rollback_errors) if rollback_errors else ''}"
            )

    def rollback_plan(
        self,
        plan: Optional[RemediationPlan] = None,
        actor: str = "admin",
        finding_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Manually rollback an executed remediation plan back to its original captured state."""
        if plan is None and finding_id:
            if not self.storage:
                return {'status': 'FAILED', 'success': False, 'error': 'No storage engine available'}
            findings = self.storage.get_findings()
            matching = [f for f in findings if f.finding_id == finding_id]
            if not matching:
                return {'status': 'FAILED', 'success': False, 'error': f'Finding {finding_id} not found'}
            plan = self.generate_plan(matching[0])

        if plan is None:
            return {'status': 'FAILED', 'success': False, 'error': 'Either plan or finding_id must be provided'}

        rolled_back = []
        for action in reversed(plan.actions):
            target_path = action.canonical_target
            if action.expected_original_mode is not None:
                os.chmod(target_path, action.expected_original_mode)
            if action.expected_original_uid is not None or action.desired_gid is not None:
                uid = action.expected_original_uid if action.expected_original_uid is not None else -1
                gid = action.expected_original_gid if action.expected_original_gid is not None else -1
                if hasattr(os, 'chown'):
                    os.chown(target_path, uid, gid)
            action.rolled_back = True
            rolled_back.append(action.action_id)

        if self.storage:
            self.storage.log_admin_action(
                action="REMEDIATION_MANUAL_ROLLBACK",
                target=plan.target_resource,
                actor=actor,
                details={'plan_id': plan.plan_id, 'rolled_back_actions': rolled_back},
                result="SUCCESS"
            )

        return {
            'status': 'ROLLED_BACK',
            'success': True,
            'plan_id': plan.plan_id,
            'target': plan.target_resource,
            'rollback_commands': plan.rollback_commands,
            'restored_mode': plan.actions[0].expected_original_mode if plan.actions else None,
            'restored_uid': plan.actions[0].expected_original_uid if plan.actions else None,
            'restored_gid': plan.actions[0].expected_original_gid if plan.actions else None,
            'message': f"Successfully rolled back {len(rolled_back)} actions on {plan.target_resource}"
        }

