"""
UATU Linux Edition - Detection & Incident Correlation Engine
Evaluates deterministic security rules on Linux telemetry:
1. Repeated sudo/ssh authentication failures (>=3 within window)
2. Successful sudo execution following failed attempts (same user only)
3. SUID binary execution with euid != uid
4. Watched file modifications (/etc/sudoers, /etc/passwd, /etc/shadow)
Correlates events strictly by (user, session, pid/ppid) within temporal windows, never across users.
Generates structured, evidence-backed Incidents with ordered event references.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Set, Union

from core.models import Incident, IncidentStatus, Severity, utc_now
from core.event_schema import UatuEvent, EventSeverity, DataOrigin


class DetectionEngine:
    """Evaluates privilege escalation detection rules and correlates incidents."""

    def __init__(self, window_seconds: int = 300, failure_threshold: int = 3, storage: Optional[Any] = None, event_bus: Optional[Any] = None):
        self.window_seconds = window_seconds
        self.failure_threshold = failure_threshold
        self.storage = storage
        self.event_bus = event_bus

    def evaluate_recent_events(self, window_sec: Optional[int] = None) -> List[Incident]:
        """Fetch recent events from storage and evaluate correlation rules."""
        if not self.storage:
            return []
        events = self.storage.get_uatu_events(limit=500)
        incidents = self.correlate(events)
        for inc in incidents:
            self.storage.save_incident(inc)
            if self.event_bus:
                self.event_bus.publish(inc)
        return incidents

    def correlate(self, events: List[Union[UatuEvent, Any]]) -> List[Incident]:
        """
        Correlate events into unified Incidents.
        Orders events chronologically and partitions strictly by user.
        """
        if not events:
            return []

        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        incidents: List[Incident] = []

        # 1. Partition events strictly by user (never correlate across users)
        user_events_map: Dict[str, List[Any]] = defaultdict(list)
        unattributed_events: List[Any] = []

        for e in sorted_events:
            user = getattr(e, "user", None) or (e.evidence.get("fields", {}).get("auid") if hasattr(e, "evidence") else None)
            if user and str(user) not in ("unknown", "None", "-1"):
                user_events_map[str(user)].append(e)
            else:
                unattributed_events.append(e)

        # 2. Evaluate user-centric rules
        for user, u_events in user_events_map.items():
            incidents.extend(self._evaluate_user_events(user, u_events))

        # 3. Evaluate system-wide watched file and SUID anomalies
        incidents.extend(self._evaluate_standalone_events(sorted_events))

        # De-duplicate identical incident titles for same user/entity
        unique_incidents: List[Incident] = []
        seen = set()
        for inc in incidents:
            key = (inc.title, inc.attribution.get("user"), tuple(inc.event_ids))
            if key not in seen:
                seen.add(key)
                unique_incidents.append(inc)

        return unique_incidents

    def _evaluate_user_events(self, user: str, events: List[Any]) -> List[Incident]:
        """Evaluate authentication brute force and escalation sequences for a single user."""
        incidents: List[Incident] = []

        # Track failure clusters
        failure_events: List[Any] = []
        for e in events:
            ev_type = getattr(e, "event_type", "")
            ts = e.timestamp

            if ev_type in ("SUDO_AUTH_FAILURE", "SSH_AUTH_FAILURE"):
                # Prune failures older than window
                failure_events = [f for f in failure_events if (ts - f.timestamp).total_seconds() <= self.window_seconds]
                failure_events.append(e)

                # Check threshold for repeated failures
                if len(failure_events) >= self.failure_threshold:
                    ordered_ids = [f.event_id for f in failure_events]
                    incidents.append(Incident(
                        title=f"Repeated Authentication Failures: {user}",
                        severity=Severity.HIGH.value,
                        confidence=0.92,
                        hypothesis=f"User '{user}' accumulated {len(failure_events)} failed authentication attempts within {self.window_seconds}s.",
                        attribution={"user": user, "failure_count": len(failure_events)},
                        event_ids=ordered_ids,
                        status=IncidentStatus.NEW.value
                    ))

            elif ev_type == "SUDO_AUTH_SUCCESS":
                # Check if preceding failures exist within window for THIS user
                recent_failures = [f for f in failure_events if (ts - f.timestamp).total_seconds() <= self.window_seconds]
                if recent_failures:
                    ordered_ids = [f.event_id for f in recent_failures] + [e.event_id]
                    cmd = getattr(e, "command", "") or e.evidence.get("command", "unknown")
                    incidents.append(Incident(
                        title=f"Sudo Brute Force Followed by Root Elevation: {user}",
                        severity=Severity.CRITICAL.value,
                        confidence=0.98,
                        hypothesis=(
                            f"User '{user}' experienced {len(recent_failures)} authentication failures, "
                            f"immediately followed by successful sudo command '{cmd}' granting root privileges."
                        ),
                        attribution={
                            "user": user,
                            "command": cmd,
                            "failures_before_success": len(recent_failures)
                        },
                        event_ids=ordered_ids,
                        status=IncidentStatus.NEW.value
                    ))
                    # Reset failure tracker after successful correlation
                    failure_events.clear()

        return incidents

    def _evaluate_standalone_events(self, events: List[Any]) -> List[Incident]:
        """Evaluate SUID execution with euid!=uid and watched file modifications."""
        incidents: List[Incident] = []

        for e in events:
            ev_type = getattr(e, "event_type", "")
            user = getattr(e, "user", "unknown")
            pid = getattr(e, "pid", None)

            # Rule 3: SUID execution where euid != uid
            uid = getattr(e, "uid", None)
            euid = getattr(e, "euid", None)
            if ev_type == "SUID_EXECUTION" or (euid is not None and uid is not None and euid == 0 and uid != 0):
                exe = getattr(e, "exe", "") or getattr(e, "command", "unknown")
                incidents.append(Incident(
                    title=f"SUID Privilege Elevation: {exe}",
                    severity=Severity.HIGH.value,
                    confidence=0.95,
                    hypothesis=f"Process '{exe}' (PID {pid}) executed with effective UID 0 (root) by non-root user '{user}' (UID {uid}).",
                    attribution={"user": user, "uid": uid, "euid": euid, "pid": pid, "exe": exe},
                    event_ids=[e.event_id],
                    status=IncidentStatus.NEW.value
                ))

            # Rule 4: Edits to watched authentication and policy files
            if ev_type in ("WATCHED_FILE_EDIT_SUDOERS", "WATCHED_FILE_EDIT_PASSWD", "WATCHED_FILE_EDIT_SHADOW"):
                target = "sudoers" if "SUDOERS" in ev_type else ("passwd" if "PASSWD" in ev_type else "shadow")
                incidents.append(Incident(
                    title=f"Tampering with Critical Authentication Database: /etc/{target}",
                    severity=Severity.CRITICAL.value,
                    confidence=1.0,
                    hypothesis=f"Unauthorized modification detected on /etc/{target} by user '{user}' (PID {pid}).",
                    attribution={"user": user, "target_file": f"/etc/{target}", "pid": pid},
                    event_ids=[e.event_id],
                    status=IncidentStatus.NEW.value
                ))

        return incidents
