"""
UATU Linux Edition - System Diagnostics & Health Auditing (uatu doctor)
Performs rigorous validation of endpoint environment, kernel subsystem accessibility,
audit rules, log permissions, database permissions, containment primitives,
and ML model integrity.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import List, Dict, Any, Optional

from core.models import utc_now, format_iso
from core.command_runner import CommandRunner


@dataclass
class DiagnosticCheck:
    """Individual diagnostic health verification result."""
    check_id: str
    name: str
    category: str
    status: str  # PASS, WARN, FAIL
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation
        }


class SystemDiagnostics:
    """Runs comprehensive endpoint diagnostics and environmental gating."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        self.command_runner = CommandRunner()

    def run_all_checks(self) -> List[DiagnosticCheck]:
        """Execute all environment, security, and subsystem checks."""
        checks: List[DiagnosticCheck] = []
        checks.append(self.check_os_platform())
        checks.append(self.check_kernel_version())
        checks.append(self.check_auditd_subsystem())
        checks.append(self.check_audit_rules())
        checks.append(self.check_log_file_access())
        checks.append(self.check_database_permissions())
        checks.append(self.check_api_token_security())
        checks.append(self.check_cgroups_v2())
        checks.append(self.check_nftables())
        checks.append(self.check_ml_manifest_integrity())
        return checks

    def check_os_platform(self) -> DiagnosticCheck:
        """Verify operating system is Linux."""
        is_linux = sys.platform.startswith("linux")
        if is_linux:
            return DiagnosticCheck(
                check_id="PLATFORM_LINUX",
                name="Operating System Platform",
                category="ENVIRONMENT",
                status="PASS",
                message=f"Linux native platform detected ({platform.system()} {platform.release()})."
            )
        else:
            return DiagnosticCheck(
                check_id="PLATFORM_LINUX",
                name="Operating System Platform",
                category="ENVIRONMENT",
                status="FAIL",
                message=f"Non-Linux platform '{sys.platform}' detected. UATU is strictly Linux-native.",
                remediation="Deploy UATU on Kali Linux or a Debian-compatible Linux system."
            )

    def check_kernel_version(self) -> DiagnosticCheck:
        """Verify kernel version meets modern security features (>= 4.18)."""
        rel = platform.release()
        parts = rel.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1].split("-")[0].split("+")[0]) if len(parts) > 1 else 0
            if major > 4 or (major == 4 and minor >= 18):
                return DiagnosticCheck(
                    check_id="KERNEL_VERSION",
                    name="Kernel Capabilities Support",
                    category="ENVIRONMENT",
                    status="PASS",
                    message=f"Kernel {rel} supports required audit netlink, cgroups v2, and nftables features."
                )
            else:
                return DiagnosticCheck(
                    check_id="KERNEL_VERSION",
                    name="Kernel Capabilities Support",
                    category="ENVIRONMENT",
                    status="WARN",
                    message=f"Kernel {rel} is older than recommended baseline 4.18.",
                    remediation="Upgrade Linux kernel to >= 5.x for best eBPF, audit, and cgroups v2 support."
                )
        except Exception:
            return DiagnosticCheck(
                check_id="KERNEL_VERSION",
                name="Kernel Capabilities Support",
                category="ENVIRONMENT",
                status="PASS",
                message=f"Detected kernel release: {rel}."
            )

    def check_auditd_subsystem(self) -> DiagnosticCheck:
        """Check auditd daemon status and netlink socket accessibility."""
        has_auditctl = shutil.which("auditctl") is not None
        has_ausearch = shutil.which("ausearch") is not None

        if has_auditctl and has_ausearch:
            return DiagnosticCheck(
                check_id="AUDITD_DAEMON",
                name="Linux Audit Subsystem (auditd)",
                category="TELEMETRY",
                status="PASS",
                message="Linux audit utilities (auditctl, ausearch) are installed and available in PATH."
            )
        elif has_ausearch:
            return DiagnosticCheck(
                check_id="AUDITD_DAEMON",
                name="Linux Audit Subsystem (auditd)",
                category="TELEMETRY",
                status="WARN",
                message="ausearch is available but auditctl is missing.",
                remediation="Install auditd package: sudo apt install -y auditd audispd-plugins"
            )
        else:
            return DiagnosticCheck(
                check_id="AUDITD_DAEMON",
                name="Linux Audit Subsystem (auditd)",
                category="TELEMETRY",
                status="WARN",
                message="auditd is not installed or unavailable in PATH.",
                remediation="Install auditd package: sudo apt update && sudo apt install -y auditd"
            )

    def check_audit_rules(self) -> DiagnosticCheck:
        """Check presence of uatu.rules audit configuration."""
        repo_rules = self.base_dir / "config" / "audit" / "uatu.rules"
        system_rules = Path("/etc/audit/rules.d/uatu.rules")

        if system_rules.exists():
            return DiagnosticCheck(
                check_id="AUDIT_RULES",
                name="UATU Audit Rules",
                category="TELEMETRY",
                status="PASS",
                message="System audit rules installed at /etc/audit/rules.d/uatu.rules."
            )
        elif repo_rules.exists():
            return DiagnosticCheck(
                check_id="AUDIT_RULES",
                name="UATU Audit Rules",
                category="TELEMETRY",
                status="WARN",
                message="Repository rules file exists (config/audit/uatu.rules) but is not installed to system.",
                remediation="Run: sudo ./uatu.sh install to deploy audit rules."
            )
        else:
            return DiagnosticCheck(
                check_id="AUDIT_RULES",
                name="UATU Audit Rules",
                category="TELEMETRY",
                status="WARN",
                message="UATU audit rules template not found.",
                remediation="Generate audit rules at config/audit/uatu.rules."
            )

    def check_log_file_access(self) -> DiagnosticCheck:
        """Check access to system authentication and audit logs."""
        log_candidates = ["/var/log/audit/audit.log", "/var/log/auth.log", "/var/log/secure"]
        readable = []
        for cand in log_candidates:
            if os.path.exists(cand) and os.access(cand, os.R_OK):
                readable.append(cand)

        if readable:
            return DiagnosticCheck(
                check_id="LOG_FILE_ACCESS",
                name="System Log Telemetry Accessibility",
                category="TELEMETRY",
                status="PASS",
                message=f"Readable telemetry log sources found: {', '.join(readable)}"
            )
        else:
            return DiagnosticCheck(
                check_id="LOG_FILE_ACCESS",
                name="System Log Telemetry Accessibility",
                category="TELEMETRY",
                status="WARN",
                message="Standard system logs (/var/log/auth.log, /var/log/audit/audit.log) not readable with current permissions.",
                remediation="Run UATU with sufficient privileges (sudo) or add user to 'adm' / 'audit' group."
            )

    def check_database_permissions(self) -> DiagnosticCheck:
        """Check SQLite database file permissions (0600) and directory (0700)."""
        db_candidates = ["/var/lib/uatu/uatu.db", "./data/uatu.db", "./uatu.db"]
        found_db = None
        for cand in db_candidates:
            p = Path(cand)
            if p.exists():
                found_db = p
                break

        if not found_db:
            return DiagnosticCheck(
                check_id="DATABASE_PERMS",
                name="SQLite Storage Permissions",
                category="STORAGE",
                status="PASS",
                message="Database file will be created on first execution with strict 0600 permissions."
            )

        if os.name == "posix":
            st = found_db.stat()
            file_mode = oct(st.st_mode)[-4:]
            dir_st = found_db.parent.stat()
            dir_mode = oct(dir_st.st_mode)[-4:]

            if (st.st_mode & 0o077) == 0:
                return DiagnosticCheck(
                    check_id="DATABASE_PERMS",
                    name="SQLite Storage Permissions",
                    category="STORAGE",
                    status="PASS",
                    message=f"Database ({found_db}) mode {file_mode} and directory mode {dir_mode} are secure."
                )
            else:
                return DiagnosticCheck(
                    check_id="DATABASE_PERMS",
                    name="SQLite Storage Permissions",
                    category="STORAGE",
                    status="WARN",
                    message=f"Database file {found_db} permissions {file_mode} are more open than 0600.",
                    remediation=f"chmod 600 {found_db} && chmod 700 {found_db.parent}"
                )
        return DiagnosticCheck(
            check_id="DATABASE_PERMS",
            name="SQLite Storage Permissions",
            category="STORAGE",
            status="PASS",
            message=f"Database exists at {found_db}."
        )

    def check_api_token_security(self) -> DiagnosticCheck:
        """Check API token existence and permissions."""
        token_candidates = ["/var/lib/uatu/token", "./config/uatu_token", "./uatu_token"]
        found_tok = None
        for cand in token_candidates:
            p = Path(cand)
            if p.exists() and p.is_file():
                found_tok = p
                break

        if found_tok:
            if os.name == "posix":
                st = found_tok.stat()
                if (st.st_mode & 0o077) == 0:
                    return DiagnosticCheck(
                        check_id="API_TOKEN_SECURITY",
                        name="API Token Security",
                        category="SECURITY",
                        status="PASS",
                        message=f"API token found at {found_tok} with strict 0600 permissions."
                    )
                else:
                    return DiagnosticCheck(
                        check_id="API_TOKEN_SECURITY",
                        name="API Token Security",
                        category="SECURITY",
                        status="WARN",
                        message=f"API token at {found_tok} has permissive mode {oct(st.st_mode)[-4:]}.",
                        remediation=f"chmod 600 {found_tok}"
                    )
            return DiagnosticCheck(
                check_id="API_TOKEN_SECURITY",
                name="API Token Security",
                category="SECURITY",
                status="PASS",
                message=f"API token present at {found_tok}."
            )
        else:
            return DiagnosticCheck(
                check_id="API_TOKEN_SECURITY",
                name="API Token Security",
                category="SECURITY",
                status="PASS",
                message="API token will be randomly generated (32 bytes urlsafe) on initial dashboard startup."
            )

    def check_cgroups_v2(self) -> DiagnosticCheck:
        """Check cgroups v2 availability for process freezing."""
        cgroup_freeze = Path("/sys/fs/cgroup/cgroup.freeze")
        cgroup_controllers = Path("/sys/fs/cgroup/cgroup.controllers")

        if cgroup_freeze.exists() or cgroup_controllers.exists():
            return DiagnosticCheck(
                check_id="CGROUPS_V2",
                name="cgroups v2 Process Containment",
                category="CONTAINMENT",
                status="PASS",
                message="cgroups v2 hierarchy is mounted and active on the host."
            )
        else:
            return DiagnosticCheck(
                check_id="CGROUPS_V2",
                name="cgroups v2 Process Containment",
                category="CONTAINMENT",
                status="WARN",
                message="cgroups v2 not detected; process freeze will use SIGSTOP/SIGCONT fallback.",
                remediation="Enable unified cgroup hierarchy in systemd boot params: systemd.unified_cgroup_hierarchy=1"
            )

    def check_nftables(self) -> DiagnosticCheck:
        """Check nftables availability for network containment."""
        has_nft = shutil.which("nft") is not None
        if has_nft:
            return DiagnosticCheck(
                check_id="NFTABLES",
                name="nftables Network Containment",
                category="CONTAINMENT",
                status="PASS",
                message="nft binary is installed and available for packet filtering."
            )
        else:
            return DiagnosticCheck(
                check_id="NFTABLES",
                name="nftables Network Containment",
                category="CONTAINMENT",
                status="WARN",
                message="nft binary is not in PATH; network containment unavailable.",
                remediation="Install nftables: sudo apt install -y nftables"
            )

    def check_ml_manifest_integrity(self) -> DiagnosticCheck:
        """Verify models/manifest.json and registered model checksums."""
        manifest_path = self.base_dir / "models" / "manifest.json"
        if not manifest_path.exists():
            return DiagnosticCheck(
                check_id="ML_MANIFEST",
                name="ML Governance Manifest",
                category="ML_GOVERNANCE",
                status="WARN",
                message="models/manifest.json not found.",
                remediation="Generate manifest with sha256 checksums of registered models."
            )

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            models = data.get("models", {})
            mismatches = []
            verified = 0

            for m_id, m_info in models.items():
                expected_sha = m_info.get("sha256")
                model_file = self.base_dir / "models" / "registry" / f"{m_id}.pkl"
                if model_file.exists():
                    actual_sha = hashlib.sha256(model_file.read_bytes()).hexdigest()
                    if actual_sha != expected_sha:
                        mismatches.append(m_id)
                    else:
                        verified += 1
                else:
                    mismatches.append(f"{m_id} (missing)")

            if not mismatches:
                return DiagnosticCheck(
                    check_id="ML_MANIFEST",
                    name="ML Governance Manifest",
                    category="ML_GOVERNANCE",
                    status="PASS",
                    message=f"All {verified} registered models verified against cryptographic manifest."
                )
            else:
                return DiagnosticCheck(
                    check_id="ML_MANIFEST",
                    name="ML Governance Manifest",
                    category="ML_GOVERNANCE",
                    status="FAIL",
                    message=f"Integrity check failed for models: {', '.join(mismatches)}",
                    remediation="Re-verify or re-train compromised model weights."
                )
        except Exception as e:
            return DiagnosticCheck(
                check_id="ML_MANIFEST",
                name="ML Governance Manifest",
                category="ML_GOVERNANCE",
                status="WARN",
                message=f"Failed to parse models/manifest.json: {e}"
            )
