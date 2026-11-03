"""
PrivWatch 3.0 - Forensic Timeline Builder
Assembles unified chronological investigation timelines combining raw security events,
findings, and correlated incident sequences.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from core.models import SecurityEvent, Incident, Severity
from modules.timeline.event_correlator import EventCorrelator
from core.logger import Logger


class TimelineBuilder:
    """Builds and visualizes chronological investigation timelines"""

    def __init__(self, correlator: Optional[EventCorrelator] = None):
        self.correlator = correlator or EventCorrelator()

    def add_events(self, events: List[SecurityEvent]):
        """Ingest events into the timeline builder"""
        self.correlator.add_events(events)

    def build_timeline(self) -> List[Dict[str, Any]]:
        """Construct unified chronological timeline combining events and correlated incidents"""
        events = self.correlator.get_all_events()
        incidents = self.correlator.detect_attack_patterns()

        timeline: List[Dict[str, Any]] = []

        # Add individual normalized events
        for e in events:
            timeline.append({
                'timestamp': e.timestamp,
                'entry_type': 'event',
                'id': e.event_id,
                'event_type': e.event_type,
                'severity': e.severity,
                'source': e.source,
                'user': e.user,
                'pid': e.pid,
                'process': e.process,
                'command': e.command,
                'details': e.evidence
            })

        # Add detected incidents
        for inc in incidents:
            timeline.append({
                'timestamp': inc.created_at,
                'entry_type': 'incident',
                'id': inc.incident_id,
                'event_type': 'CORRELATED_INCIDENT',
                'severity': inc.severity,
                'source': 'correlation_engine',
                'title': inc.title,
                'hypothesis': inc.hypothesis,
                'user': inc.attribution.get('user'),
                'details': inc.attribution,
                'event_ids': inc.event_ids
            })

        # Sort strictly by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline

    def print_timeline(self):
        """Render formatted timeline in terminal output"""
        Logger.header("FORENSIC ATTACK TIMELINE")

        entries = self.build_timeline()
        if not entries:
            Logger.info("No events or security incidents recorded.")
            return

        Logger.info(f"Total timeline records: {len(entries)}\n")

        for entry in entries:
            ts_str = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

            if entry['entry_type'] == 'event':
                Logger.info(f"[{ts_str}] ({entry['severity']}) {entry['event_type']} - User: {entry.get('user') or 'N/A'}")
                if entry.get('command'):
                    print(f"    Command: {entry['command']}")
                elif entry.get('process'):
                    print(f"    Process: {entry['process']} (PID: {entry.get('pid')})")

            elif entry['entry_type'] == 'incident':
                Logger.critical(f"[{ts_str}] INCIDENT DETECTED: {entry.get('title')}")
                print(f"    Hypothesis: {entry.get('hypothesis')}")
                print(f"    Attribution: User={entry.get('user')}")
                print(f"    Correlated Events: {len(entry.get('event_ids', []))}\n")
