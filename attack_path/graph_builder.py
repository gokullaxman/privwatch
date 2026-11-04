"""
UATU Linux Edition - Attack Path Graph Engine
Builds directed graphs using NetworkX from verified static security findings:
1. user -> group/write -> writable script -> root cron/service -> root
2. user -> NOPASSWD sudo -> elevated command -> root
3. user -> SUID binary -> root
Labels every identified attack path strictly with level 'CONFIGURATION_ONLY' (never claims exploited).
Identifies critical choke points and recommends defensive disruptions.
"""

from dataclasses import dataclass, field
import hashlib
import json
from typing import List, Dict, Any, Optional, Set, Tuple
import networkx as nx

from core.models import Finding, Severity, AttackNode, AttackEdge, AttackPath, utc_now, format_iso
from core.storage import StorageEngine


@dataclass
class VerifiedAttackPath:
    """Exploitable privilege escalation pathway derived from static configuration findings."""
    path_id: str
    title: str
    start_node: str
    target_node: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    evidence: Dict[str, Any]
    severity: str
    confidence: float
    level: str = "CONFIGURATION_ONLY"  # Non-negotiable: Never claim exploited
    bottleneck_node: Optional[str] = None
    recommended_disruption: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "title": self.title,
            "start_node": self.start_node,
            "target_node": self.target_node,
            "nodes": self.nodes,
            "edges": self.edges,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "level": self.level,
            "bottleneck_node": self.bottleneck_node,
            "recommended_disruption": self.recommended_disruption
        }


class AttackPathEngine:
    """Constructs attack graphs from real scan findings and extracts transitive paths."""

    def __init__(self, storage: Optional[StorageEngine] = None):
        self.storage = storage or StorageEngine()
        self.graph = nx.DiGraph()

    def build_graph_from_findings(self, findings: List[Finding]) -> List[VerifiedAttackPath]:
        """Parse findings into graph nodes and edges, then extract paths leading to root."""
        self.graph.clear()
        self.graph.add_node("user:current", type="USER", label="Unprivileged User")
        self.graph.add_node("user:root", type="ROOT", label="Root (UID 0)")

        paths: List[VerifiedAttackPath] = []

        for f in findings:
            v = f.vector
            title = f.title
            res = f.affected_resource
            evidence = f.evidence

            # Pattern 1: Writable script referenced by root cron or systemd service
            # user -> can_write -> script -> executed_by -> root cron/service -> yields -> root
            if "Writable Script" in title or "Writable Root Systemd" in title:
                script_node = f"script:{res}"
                service_node = "service:root_cron" if "Cron" in title else "service:root_systemd"

                self.graph.add_node(script_node, type="FILE", label=f"Writable Script: {res}", stat=evidence)
                self.graph.add_node(service_node, type="SERVICE", label="Root Scheduled Service")

                self.graph.add_edge("user:current", script_node, relation="CAN_WRITE", finding_id=f.finding_id)
                self.graph.add_edge(script_node, service_node, relation="EXECUTED_BY", finding_id=f.finding_id)
                self.graph.add_edge(service_node, "user:root", relation="RUNS_AS", finding_id=f.finding_id)

                p_id = f"path_cron_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                paths.append(VerifiedAttackPath(
                    path_id=p_id,
                    title=f"Transitive Root Escalation via Writable Scheduled Script ({res})",
                    start_node="user:current",
                    target_node="user:root",
                    nodes=[
                        {"id": "user:current", "type": "USER", "label": "Unprivileged User"},
                        {"id": script_node, "type": "FILE", "label": f"Writable Script ({res})", "stat": evidence},
                        {"id": service_node, "type": "SERVICE", "label": "Root Scheduled Service"},
                        {"id": "user:root", "type": "ROOT", "label": "Root (UID 0)"}
                    ],
                    edges=[
                        {"from": "user:current", "to": script_node, "relation": "CAN_WRITE"},
                        {"from": script_node, "to": service_node, "relation": "EXECUTED_BY"},
                        {"from": service_node, "to": "user:root", "relation": "RUNS_AS"}
                    ],
                    evidence={
                        "finding_id": f.finding_id,
                        "resource": res,
                        "owner": evidence.get("owner", "unknown"),
                        "mode": evidence.get("mode", "unknown"),
                        "line": evidence.get("cron_line") or evidence.get("exec_line")
                    },
                    severity=Severity.CRITICAL.value,
                    confidence=0.98,
                    level="CONFIGURATION_ONLY",
                    bottleneck_node=script_node,
                    recommended_disruption=f"Restrict file permissions to root-only: chmod 755 {res} && chown root:root {res}"
                ))

            # Pattern 2: Sudo NOPASSWD execution
            # user -> can_execute -> sudoers rule -> command -> yields -> root
            elif "NOPASSWD" in title:
                cmd = evidence.get("command") or res or "ALL"
                sudo_node = f"sudo:{cmd}"
                self.graph.add_node(sudo_node, type="SUDO", label=f"NOPASSWD: {cmd}", rule=evidence.get("rule"))

                self.graph.add_edge("user:current", sudo_node, relation="SUDO_EXECUTE", finding_id=f.finding_id)
                self.graph.add_edge(sudo_node, "user:root", relation="YIELDS_ROOT", finding_id=f.finding_id)

                p_id = f"path_sudo_{hashlib.sha256(str(cmd).encode()).hexdigest()[:12]}"
                paths.append(VerifiedAttackPath(
                    path_id=p_id,
                    title=f"Direct Sudo NOPASSWD Elevation via {cmd}",
                    start_node="user:current",
                    target_node="user:root",
                    nodes=[
                        {"id": "user:current", "type": "USER", "label": "Unprivileged User"},
                        {"id": sudo_node, "type": "SUDO", "label": f"Sudo Rule ({cmd})"},
                        {"id": "user:root", "type": "ROOT", "label": "Root (UID 0)"}
                    ],
                    edges=[
                        {"from": "user:current", "to": sudo_node, "relation": "SUDO_EXECUTE"},
                        {"from": sudo_node, "to": "user:root", "relation": "YIELDS_ROOT"}
                    ],
                    evidence={
                        "finding_id": f.finding_id,
                        "rule": evidence.get("rule"),
                        "command": cmd
                    },
                    severity=Severity.CRITICAL.value if "ALL" in str(cmd) else Severity.HIGH.value,
                    confidence=1.0,
                    level="CONFIGURATION_ONLY",
                    bottleneck_node=sudo_node,
                    recommended_disruption=f"Require password authentication or remove NOPASSWD rule for {cmd} in /etc/sudoers"
                ))

            # Pattern 3: Writable SUID binary
            elif "Writable SUID" in title:
                bin_node = f"suid:{res}"
                self.graph.add_node(bin_node, type="SUID", label=f"Writable SUID: {res}")
                self.graph.add_edge("user:current", bin_node, relation="CAN_OVERWRITE", finding_id=f.finding_id)
                self.graph.add_edge(bin_node, "user:root", relation="EXECUTES_AS_ROOT", finding_id=f.finding_id)

                p_id = f"path_suid_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                paths.append(VerifiedAttackPath(
                    path_id=p_id,
                    title=f"Immediate Root Elevation via Overwrite of SUID Binary ({res})",
                    start_node="user:current",
                    target_node="user:root",
                    nodes=[
                        {"id": "user:current", "type": "USER", "label": "Unprivileged User"},
                        {"id": bin_node, "type": "SUID", "label": f"Writable SUID Binary ({res})"},
                        {"id": "user:root", "type": "ROOT", "label": "Root (UID 0)"}
                    ],
                    edges=[
                        {"from": "user:current", "to": bin_node, "relation": "CAN_OVERWRITE"},
                        {"from": bin_node, "to": "user:root", "relation": "EXECUTES_AS_ROOT"}
                    ],
                    evidence={
                        "finding_id": f.finding_id,
                        "resource": res,
                        "owner": evidence.get("owner", "unknown"),
                        "mode": evidence.get("mode", "unknown")
                    },
                    severity=Severity.CRITICAL.value,
                    confidence=1.0,
                    level="CONFIGURATION_ONLY",
                    bottleneck_node=bin_node,
                    recommended_disruption=f"Remove write permissions from {res}: chmod 755 {res}"
                ))

        # Save attack paths to storage
        for p in paths:
            ap_model = AttackPath(
                path_id=p.path_id,
                start_node_id=p.start_node,
                target_node_id=p.target_node,
                node_ids=[n["id"] for n in p.nodes],
                edge_ids=[f"{e['from']}->{e['to']}" for e in p.edges],
                total_risk_score=95.0 if p.severity == Severity.CRITICAL.value else 80.0,
                confidence=p.confidence,
                bottleneck_node_id=p.bottleneck_node,
                recommended_disruption=p.recommended_disruption
            )
            self.storage.save_attack_path(ap_model)

        return paths
