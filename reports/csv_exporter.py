"""
PrivWatch 3.0 - CSV Report & Event Exporter
Exports findings, telemetry events, and timeline entries to structured CSV files for spreadsheet analysis.
"""

import csv
import os
from pathlib import Path
from typing import List

from core.models import Finding, SecurityEvent, format_iso


class CSVExporter:
    """Exports assessment findings and telemetry records to CSV format"""

    @staticmethod
    def export_findings(findings: List[Finding], output_file: str) -> str:
        """Export list of findings to CSV"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            'finding_id', 'vector', 'severity', 'confidence', 'title',
            'affected_resource', 'description', 'risk_explanation',
            'remediation', 'detection_method', 'timestamp'
        ]

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    'finding_id': finding.finding_id,
                    'vector': finding.vector,
                    'severity': finding.severity,
                    'confidence': finding.confidence,
                    'title': finding.title,
                    'affected_resource': finding.affected_resource,
                    'description': finding.description,
                    'risk_explanation': finding.risk_explanation,
                    'remediation': finding.remediation,
                    'detection_method': finding.detection_method,
                    'timestamp': format_iso(finding.timestamp)
                })

        return str(out_path)

    @staticmethod
    def export_events(events: List[SecurityEvent], output_file: str) -> str:
        """Export list of normalized security events to CSV"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            'event_id', 'timestamp', 'hostname', 'source', 'event_type',
            'severity', 'user', 'uid', 'pid', 'process', 'command', 'confidence'
        ]

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow({
                    'event_id': event.event_id,
                    'timestamp': format_iso(event.timestamp),
                    'hostname': event.hostname,
                    'source': event.source,
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'user': event.user or '',
                    'uid': event.uid if event.uid is not None else '',
                    'pid': event.pid if event.pid is not None else '',
                    'process': event.process or '',
                    'command': event.command or '',
                    'confidence': event.confidence
                })

        return str(out_path)

