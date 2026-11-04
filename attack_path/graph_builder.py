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

from core.models import (
    Finding, Severity, AttackNode, AttackEdge, AttackPath,
    NodeType, EdgeType, EdgeClass, utc_now, format_iso
)
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
    edge_class: str = EdgeClass.CONFIGURATION_DERIVED.value
    bottleneck_node: Optional[str] = None
    recommended_disruption: Optional[str] = None
    explanation: Optional[str] = None

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
            "edge_class": self.edge_class,
            "bottleneck_node": self.bottleneck_node,
            "recommended_disruption": self.recommended_disruption,
            "explanation": self.explanation
        }


class AttackPathEngine:
    """Constructs attack graphs from real scan findings and extracts transitive paths."""

    def __init__(self, storage: Optional[StorageEngine] = None):
        self.storage = storage or StorageEngine()
        self.graph = nx.DiGraph()

    def build_graph_from_findings(self, findings: List[Finding]) -> List[VerifiedAttackPath]:
        """Parse findings into graph nodes and edges, then extract paths leading to root."""
        self.graph.clear()
        self.graph.add_node("user:current", type=NodeType.USER.value, label="Unprivileged User")
        self.graph.add_node("user:root", type=NodeType.USER.value, label="Root (UID 0)")

        paths: List[VerifiedAttackPath] = []
        seen_path_ids: Set[str] = set()

        for f in findings:
            title = f.title
            res = f.affected_resource
            evidence = f.evidence or {}

            # Pattern 1: Writable script referenced by root cron or systemd service
            if "Writable Script" in title or "Writable Root Systemd" in title:
                script_node = f"script:{res}"
                service_type = NodeType.CRON_JOB.value if "Cron" in title else NodeType.SYSTEMD_UNIT.value
                service_node = "service:root_cron" if "Cron" in title else "service:root_systemd"

                self.graph.add_node(script_node, type=NodeType.FILE.value, label=f"Writable Script: {res}", stat=evidence)
                self.graph.add_node(service_node, type=service_type, label=f"Root Service ({service_type})")

                self.graph.add_edge("user:current", script_node, relation=EdgeType.CAN_WRITE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(script_node, service_node, relation=EdgeType.EXECUTED_BY.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(service_node, "user:root", relation=EdgeType.RUNS_AS.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_cron_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"Transitive Root Escalation via Writable Scheduled Script ({res})",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": script_node, "type": NodeType.FILE.value, "label": f"Writable Script ({res})", "stat": evidence},
                            {"id": service_node, "type": service_type, "label": "Root Scheduled Service"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": script_node, "relation": EdgeType.CAN_WRITE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": script_node, "to": service_node, "relation": EdgeType.EXECUTED_BY.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": service_node, "to": "user:root", "relation": EdgeType.RUNS_AS.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
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
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=script_node,
                        recommended_disruption=f"Restrict file permissions to root-only: chmod 755 {res} && chown root:root {res}",
                        explanation=f"Unprivileged user can write arbitrary commands into script '{res}', which will be executed automatically by root cron/systemd service."
                    ))

            # Pattern 2: Sudo NOPASSWD execution
            elif "NOPASSWD" in title:
                cmd = evidence.get("command") or res or "ALL"
                sudo_node = f"sudo:{cmd}"
                self.graph.add_node(sudo_node, type=NodeType.SUDO_RULE.value, label=f"NOPASSWD: {cmd}", rule=evidence.get("rule"))

                self.graph.add_edge("user:current", sudo_node, relation=EdgeType.CAN_EXECUTE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(sudo_node, "user:root", relation=EdgeType.RUNS_AS.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_sudo_{hashlib.sha256(str(cmd).encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"Direct Sudo NOPASSWD Elevation via {cmd}",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": sudo_node, "type": NodeType.SUDO_RULE.value, "label": f"Sudo Rule ({cmd})"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": sudo_node, "relation": EdgeType.CAN_EXECUTE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": sudo_node, "to": "user:root", "relation": EdgeType.RUNS_AS.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
                        ],
                        evidence={
                            "finding_id": f.finding_id,
                            "rule": evidence.get("rule"),
                            "command": cmd
                        },
                        severity=Severity.CRITICAL.value if "ALL" in str(cmd) else Severity.HIGH.value,
                        confidence=1.0,
                        level="CONFIGURATION_ONLY",
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=sudo_node,
                        recommended_disruption=f"Require password authentication or remove NOPASSWD rule for {cmd} in /etc/sudoers",
                        explanation=f"Sudo configuration permits user to invoke '{cmd}' without password authentication, yielding immediate root privileges."
                    ))

            # Pattern 3: Writable SUID binary
            elif "Writable SUID" in title:
                bin_node = f"file:{res}"
                self.graph.add_node(bin_node, type=NodeType.FILE.value, label=f"Writable SUID: {res}")
                self.graph.add_edge("user:current", bin_node, relation=EdgeType.CAN_WRITE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(bin_node, "user:root", relation=EdgeType.RUNS_AS.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_suid_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"Immediate Root Elevation via Overwrite of SUID Binary ({res})",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": bin_node, "type": NodeType.FILE.value, "label": f"Writable SUID Binary ({res})"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": bin_node, "relation": EdgeType.CAN_WRITE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": bin_node, "to": "user:root", "relation": EdgeType.RUNS_AS.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
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
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=bin_node,
                        recommended_disruption=f"Remove write permissions from {res}: chmod 755 {res}",
                        explanation=f"SUID binary '{res}' has write permissions, allowing an attacker to replace its code with arbitrary payload that executes as root."
                    ))

            # Pattern 4: SUID GTFOBins exploitation
            elif "Exploitable SUID Binary" in title:
                bin_node = f"file:{res}"
                self.graph.add_node(bin_node, type=NodeType.FILE.value, label=f"GTFOBins SUID: {res}")
                self.graph.add_edge("user:current", bin_node, relation=EdgeType.CAN_EXECUTE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(bin_node, "user:root", relation=EdgeType.ESCALATES_TO.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_gtfo_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"GTFOBins Privilege Escalation via SUID Executable ({res})",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": bin_node, "type": NodeType.FILE.value, "label": f"SUID Binary ({res})"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": bin_node, "relation": EdgeType.CAN_EXECUTE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": bin_node, "to": "user:root", "relation": EdgeType.ESCALATES_TO.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
                        ],
                        evidence={
                            "finding_id": f.finding_id,
                            "resource": res,
                            "gtfobins": evidence.get("gtfobins", "")
                        },
                        severity=f.severity,
                        confidence=f.confidence,
                        level="CONFIGURATION_ONLY",
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=bin_node,
                        recommended_disruption=f"Strip SUID bit from binary: chmod u-s {res}",
                        explanation=f"Executable '{res}' contains known shell escape sequence in GTFOBins catalog allowing immediate privilege escalation."
                    ))

            # Pattern 5: Dangerous Linux Capability
            elif "Dangerous File Capability" in title:
                bin_node = f"file:{res}"
                cap_name = evidence.get("capability", "cap_setuid")
                cap_node = f"cap:{cap_name}"
                self.graph.add_node(bin_node, type=NodeType.FILE.value, label=f"Elevated Executable: {res}")
                self.graph.add_node(cap_node, type=NodeType.CAPABILITY.value, label=f"Capability: {cap_name}")

                self.graph.add_edge("user:current", bin_node, relation=EdgeType.CAN_EXECUTE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(bin_node, cap_node, relation=EdgeType.HAS_CAPABILITY.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(cap_node, "user:root", relation=EdgeType.ESCALATES_TO.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_cap_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"Direct Elevation via File Capability {cap_name} on {res}",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": bin_node, "type": NodeType.FILE.value, "label": f"Binary ({res})"},
                            {"id": cap_node, "type": NodeType.CAPABILITY.value, "label": f"Capability ({cap_name})"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": bin_node, "relation": EdgeType.CAN_EXECUTE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": bin_node, "to": cap_node, "relation": EdgeType.HAS_CAPABILITY.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": cap_node, "to": "user:root", "relation": EdgeType.ESCALATES_TO.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
                        ],
                        evidence={"finding_id": f.finding_id, "resource": res, "capability": cap_name},
                        severity=f.severity,
                        confidence=f.confidence,
                        level="CONFIGURATION_ONLY",
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=bin_node,
                        recommended_disruption=f"Strip elevated capability: setcap -r {res}",
                        explanation=f"Binary '{res}' holds '{cap_name}', enabling non-root caller to bypass discretionary access control and acquire root privileges."
                    ))

            # Pattern 6: Writable Directory in PATH
            elif "Writable Directory in PATH" in title:
                dir_node = f"dir:{res}"
                self.graph.add_node(dir_node, type=NodeType.DIRECTORY.value, label=f"Writable PATH Dir: {res}")
                self.graph.add_edge("user:current", dir_node, relation=EdgeType.CAN_WRITE.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)
                self.graph.add_edge(dir_node, "user:root", relation=EdgeType.RUNS_AS.value, edge_class=EdgeClass.CONFIGURATION_DERIVED.value)

                p_id = f"path_dir_{hashlib.sha256(res.encode()).hexdigest()[:12]}"
                if p_id not in seen_path_ids:
                    seen_path_ids.add(p_id)
                    paths.append(VerifiedAttackPath(
                        path_id=p_id,
                        title=f"Execution Order Hijack via Writable PATH Directory ({res})",
                        start_node="user:current",
                        target_node="user:root",
                        nodes=[
                            {"id": "user:current", "type": NodeType.USER.value, "label": "Unprivileged User"},
                            {"id": dir_node, "type": NodeType.DIRECTORY.value, "label": f"Directory ({res})"},
                            {"id": "user:root", "type": NodeType.USER.value, "label": "Root (UID 0)"}
                        ],
                        edges=[
                            {"from": "user:current", "to": dir_node, "relation": EdgeType.CAN_WRITE.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value},
                            {"from": dir_node, "to": "user:root", "relation": EdgeType.RUNS_AS.value, "edge_class": EdgeClass.CONFIGURATION_DERIVED.value}
                        ],
                        evidence={"finding_id": f.finding_id, "resource": res},
                        severity=f.severity,
                        confidence=f.confidence,
                        level="CONFIGURATION_ONLY",
                        edge_class=EdgeClass.CONFIGURATION_DERIVED.value,
                        bottleneck_node=dir_node,
                        recommended_disruption=f"Remove group/other write permissions: chmod 755 {res}",
                        explanation=f"Directory '{res}' is traversed in root PATH and writable by unauthorized users, enabling trojan binary placement."
                    ))

        # Save attack paths, nodes, and edges to storage
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

