"""
PrivWatch 3.0 - Controlled Remediation & Prevention Engine
Generates least-privilege remediation plans, enforces dry-run safety by default,
requires explicit administrator authorization, and maintains rollback capability.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
from typing import List, Dict, Any, Optional

from core.models import Finding
from core.storage import StorageEngine
from core.logger import Logger


@dataclass
class RemediationPlan:
    """Action plan detailing exact proposed commands, consequences, and rollback steps"""
    finding_id: str
    title: str
    target_resource: str
    proposed_commands: List[str]
    consequences: str
    rollback_commands: List[str]
    backup_file_path: Optional[str] = None
    requires_root: bool = True


class RemediationEngine:
    """Safely constructs and executes controlled remediation playbooks"""

    def __init__(self, storage: Optional[StorageEngine] = None, read_only: bool = True):
        self.storage = storage
        self.read_only = read_only

    def generate_plan(self, finding: Finding) -> RemediationPlan:
        """Generate a safe, least-privilege remediation plan for a finding"""
        resource = finding.affected_resource or ""
        vector = finding.vector

        proposed: List[str] = []
        rollback: List[str] = []
        consequences = "Modifies permissions or configurations to enforce least-privilege security."

        is_abs = resource.startswith('/') or os.path.isabs(resource)

        # Case 1: SUID bit removal
        if vector == "SUID/SGID" and is_abs:
            proposed = [f"chmod u-s {resource}"]
            rollback = [f"chmod u+s {resource}"]
            consequences = f"Removes the SUID bit from {resource}. Users will no longer be able to execute it with owner privileges."

        # Case 2: Writable cron file hardening
        elif vector == "CRON" and is_abs:
            proposed = [f"chmod 644 {resource}", f"chown root:root {resource}"]
            rollback = [f"chmod 666 {resource}"]
            consequences = f"Changes {resource} permissions to 644 (root:root). Non-root users will lose write access."

        # Case 3: Sudoers file permission hardening
        elif vector == "SUDO" and is_abs:
            proposed = [f"chmod 440 {resource}", f"chown root:root {resource}"]
            rollback = [f"chmod 640 {resource}"]
            consequences = f"Enforces strict 440 permissions and root:root ownership on sudoers configuration {resource}."

        # Case 4: World-writable SSH authorized_keys
        elif vector == "SSH_SECURITY" and "authorized_keys" in resource:
            proposed = [f"chmod 600 {resource}"]
            rollback = [f"chmod 644 {resource}"]
            consequences = f"Restricts {resource} read/write permissions strictly to the account owner."

        # Fallback: Generic instructions
        else:
            proposed = [cmd.strip() for cmd in finding.remediation.splitlines() if cmd.strip() and not cmd.startswith("#")]
            consequences = "Applies recommended hardening steps specified in the security finding."

        return RemediationPlan(
            finding_id=finding.finding_id,
            title=finding.title,
            target_resource=resource,
            proposed_commands=proposed,
            consequences=consequences,
            rollback_commands=rollback,
            requires_root=True
        )

    def execute_plan(self, plan: RemediationPlan, actor: str,
                     confirmed: bool = False, dry_run: bool = True) -> Dict[str, Any]:
        """
        Execute or simulate a remediation plan.
        Strictly requires confirmed=True and dry_run=False to perform any system alteration.
        """
        # Safety gate 1: Default to Dry-Run
        if dry_run or self.read_only:
            result = {
                'status': 'DRY_RUN',
                'executed': False,
                'message': 'Simulation completed successfully. No system files were modified.',
                'plan': {
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
                    details={'commands': plan.proposed_commands},
                    result="SUCCESS"
                )
            return result

        # Safety gate 2: Explicit Confirmation Required
        if not confirmed:
            raise PermissionError("Explicit confirmation (confirmed=True) is required to execute system modifications.")

        # Execute safe commands
        executed_cmds = []
        try:
            # Create backup if target is a file
            if os.path.exists(plan.target_resource) and os.path.isfile(plan.target_resource):
                backup_path = f"{plan.target_resource}.privwatch.bak"
                shutil.copy2(plan.target_resource, backup_path)
                plan.backup_file_path = backup_path

            import subprocess
            for cmd in plan.proposed_commands:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    raise RuntimeError(f"Command '{cmd}' failed: {res.stderr.strip()}")
                executed_cmds.append(cmd)

            result = {
                'status': 'SUCCESS',
                'executed': True,
                'message': f"Remediation executed successfully: {len(executed_cmds)} commands applied.",
                'backup_created': plan.backup_file_path,
                'rollback_commands': plan.rollback_commands
            }

            if self.storage:
                self.storage.log_admin_action(
                    action="REMEDIATION_EXECUTE",
                    target=plan.target_resource,
                    actor=actor,
                    details={'commands': executed_cmds, 'backup': plan.backup_file_path},
                    result="SUCCESS"
                )
            return result

        except Exception as e:
            if self.storage:
                self.storage.log_admin_action(
                    action="REMEDIATION_FAILED",
                    target=plan.target_resource,
                    actor=actor,
                    details={'error': str(e)},
                    result="FAILED"
                )
            return {
                'status': 'FAILED',
                'executed': False,
                'error': str(e)
            }
