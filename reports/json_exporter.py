"""
PrivWatch 3.0 - JSON Report Exporter
Generates machine-readable, schema-compliant JSON security reports with complete evidence trees.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.models import Finding, SecurityEvent, Incident, SystemPosture, TelemetryHealth, format_iso, utc_now


class JSONReportEncoder(json.JSONEncoder):
    """Custom JSON encoder supporting datetime, dataclasses, and sets"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return format_iso(obj)
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


class JSONExporter:
    """Exports assessment findings, incidents, and telemetry health to JSON format"""

    @staticmethod
    def export_findings(findings: List[Finding], output_file: str, mode: str = "red",
                        posture: Optional[SystemPosture] = None,
                        telemetry_health: Optional[TelemetryHealth] = None) -> str:
        """Export comprehensive security report to JSON"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        posture_obj = posture or SystemPosture.calculate(findings)

        report = {
            'report_metadata': {
                'platform': 'PrivWatch',
                'version': '3.0.0',
                'generated_at': format_iso(utc_now()),
                'mode': mode,
                'total_findings': len(findings),
                'posture_score': posture_obj.score,
                'posture_status': posture_obj.status
            },
            'summary': {
                'by_severity': {
                    'CRITICAL': posture_obj.critical_count,
                    'HIGH': posture_obj.high_count,
                    'MEDIUM': posture_obj.medium_count,
                    'LOW': posture_obj.low_count,
                    'INFO': posture_obj.info_count
                },
                'by_vector': JSONExporter._count_by_vector(findings)
            },
            'telemetry_health': telemetry_health.to_dict() if telemetry_health else None,
            'findings': [f.to_dict() for f in findings]
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, cls=JSONReportEncoder)

        return str(out_path)

    @staticmethod
    def export_timeline(events: List[SecurityEvent], incidents: List[Incident],
                        output_file: str) -> str:
        """Export forensic events and correlated incidents to JSON"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            'metadata': {
                'platform': 'PrivWatch',
                'version': '3.0.0',
                'generated_at': format_iso(utc_now()),
                'total_events': len(events),
                'total_incidents': len(incidents)
            },
            'incidents': [i.to_dict() for i in incidents],
            'events': [e.to_dict() for e in events]
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, cls=JSONReportEncoder)

        return str(out_path)

    @staticmethod
    def export_item_json(item: Any, output_file: str, related_events: Optional[List[Any]] = None) -> str:
        """Export a single Finding or Incident to JSON with evidence refs, hashes, and collection limitations"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        is_finding = hasattr(item, "finding_id")
        item_type = "finding" if is_finding else "incident"
        item_id = getattr(item, "finding_id", None) or getattr(item, "incident_id", "unknown")

        report = {
            'report_metadata': {
                'platform': 'UATU',
                'version': '3.0.0',
                'generated_at': format_iso(utc_now()),
                'item_type': item_type,
                'item_id': item_id,
                'collection_limitations': [
                    "Static findings are evaluated based on POSIX filesystem permission bits and system configurations.",
                    "Telemetry events represent observed live kernel (auditd) or systemd journal logs.",
                    "In absence of active kernel audit rules, transient processes executing under 50ms may not appear."
                ]
            },
            'item': item.to_dict() if hasattr(item, "to_dict") else item,
            'evidence_hash': item.evidence_hash() if hasattr(item, "evidence_hash") else None,
            'related_events': [e.to_dict() if hasattr(e, "to_dict") else e for e in (related_events or [])]
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, cls=JSONReportEncoder)

        return str(out_path)

    @staticmethod
    def _count_by_vector(findings: List[Finding]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.vector] = counts.get(f.vector, 0) + 1
        return counts
