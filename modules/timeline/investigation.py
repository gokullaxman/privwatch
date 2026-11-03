"""
PrivWatch 3.0 - Forensic Case Management & Investigation Workflow
Manages forensic case files, notes, evidence attachments, and remediation tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import List, Dict, Any, Optional
import uuid

from core.models import utc_now, format_iso, parse_iso, IncidentStatus
from core.storage import StorageEngine


@dataclass
class InvestigationCase:
    """Represents an active or resolved forensic security investigation"""
    case_id: str = field(default_factory=lambda: f"case_{uuid.uuid4().hex[:12]}")
    title: str = ""
    assigned_analyst: str = "security_analyst"
    status: str = IncidentStatus.NEW.value
    incident_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'case_id': self.case_id,
            'title': self.title,
            'assigned_analyst': self.assigned_analyst,
            'status': self.status,
            'incident_ids': self.incident_ids,
            'finding_ids': self.finding_ids,
            'notes': self.notes,
            'created_at': format_iso(self.created_at),
            'updated_at': format_iso(self.updated_at)
        }


class InvestigationManager:
    """Manages case lifecycle and updates in persistent storage"""

    def __init__(self, storage: StorageEngine):
        self.storage = storage

    def create_case(self, title: str, incident_ids: Optional[List[str]] = None,
                    finding_ids: Optional[List[str]] = None, analyst: str = "admin") -> InvestigationCase:
        """Create a new forensic case"""
        case = InvestigationCase(
            title=title,
            assigned_analyst=analyst,
            incident_ids=incident_ids or [],
            finding_ids=finding_ids or [],
            status=IncidentStatus.INVESTIGATING.value,
            notes=[{
                'timestamp': format_iso(utc_now()),
                'author': analyst,
                'content': f"Case created for incidents: {incident_ids or []}"
            }]
        )
        self.storage.log_admin_action(
            action="CREATE_INVESTIGATION_CASE",
            target=case.case_id,
            actor=analyst,
            details={'title': title, 'incidents': incident_ids},
            result="CREATED"
        )
        return case

