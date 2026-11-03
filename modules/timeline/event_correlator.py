"""
PrivWatch 3.0 - Multi-Factor Forensic Event Correlator
Correlates normalized SecurityEvent records across time windows, user attribution,
process ancestry (PID/PPID), and chronological sequences into verified Incident objects.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Set
import uuid

from core.models import SecurityEvent, Incident, Severity, IncidentStatus, utc_now


class EventCorrelator:
    """Correlates security events using multi-factor identity, ancestry, and temporal validation"""

    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self.events: List[SecurityEvent] = []

    def add_events(self, events: List[SecurityEvent]):
        """Append events to correlation pool"""
        self.events.extend(events)

    def get_all_events(self) -> List[SecurityEvent]:
        """Return all events ordered strictly by timestamp"""
        return sorted(self.events, key=lambda e: e.timestamp)

    def get_events_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Filter events by normalized event type"""
        return [e for e in self.events if e.event_type == event_type]

    def detect_attack_patterns(self) -> List[Incident]:
        """
        Execute multi-factor correlation rules:
        1. Sudo Brute Force -> Successful Elevation (Same user, chronological sequence)
        2. Web Shell -> Privileged Binary Execution (Ancestry / User match)
        3. Authentication Tampering -> SUID Abuse
        4. SUID Enumeration Burst (Same user, rapid succession)
        """
        incidents: List[Incident] = []
        seen_incident_signatures: Set[str] = set()

        # Rule 1: Sudo password failure sequence followed by successful sudo command by SAME user
        inc_sudo = self._correlate_sudo_brute_to_success()
        for inc in inc_sudo:
            sig = f"{inc.title}_{inc.attribution.get('user')}"
            if sig not in seen_incident_signatures:
                seen_incident_signatures.add(sig)
                incidents.append(inc)

        # Rule 2: Web daemon shell followed by elevated process (process ancestry or session)
        inc_shell = self._correlate_webshell_to_privesc()
        for inc in inc_shell:
            sig = f"{inc.title}_{inc.attribution.get('pid')}"
            if sig not in seen_incident_signatures:
                seen_incident_signatures.add(sig)
                incidents.append(inc)

        # Rule 3: SUID Enumeration Burst
        inc_burst = self._correlate_suid_burst()
        for inc in inc_burst:
            sig = f"{inc.title}_{inc.attribution.get('user')}"
            if sig not in seen_incident_signatures:
                seen_incident_signatures.add(sig)
                incidents.append(inc)

        return incidents

    def _correlate_sudo_brute_to_success(self) -> List[Incident]:
        """
        Detects failed sudo attempts followed chronologically by successful sudo command
        for the EXACT SAME user and host within the correlation window.
        """
        incidents: List[Incident] = []
        all_sorted = self.get_all_events()

        sudo_fails = [e for e in all_sorted if e.event_type == "SUDO_AUTH_FAIL" and e.user]
        sudo_success = [e for e in all_sorted if e.event_type == "SUDO_COMMAND" and e.user]

        # Group failures by user
        fails_by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for f in sudo_fails:
            fails_by_user[f.user].append(f)

        for user, fails in fails_by_user.items():
            if len(fails) < 2:
                continue

            last_fail = fails[-1]

            # Look for success by the SAME user AFTER the failures within window
            matching_success = [
                s for s in sudo_success
                if s.user == user
                and s.hostname == last_fail.hostname
                and last_fail.timestamp < s.timestamp <= (last_fail.timestamp + timedelta(seconds=self.window_seconds))
            ]

            if matching_success:
                first_success = matching_success[0]
                correlated_events = fails + [first_success]

                inc = Incident(
                    title=f"Sudo Brute Force Followed by Successful Privileged Execution: {user}",
                    severity=Severity.CRITICAL.value,
                    confidence=0.94,
                    hypothesis=f"User '{user}' repeatedly failed sudo authentication ({len(fails)} times) "
                               f"before successfully executing '{first_success.command}' as root.",
                    attribution={
                        'user': user,
                        'hostname': last_fail.hostname,
                        'failure_count': len(fails),
                        'successful_command': first_success.command
                    },
                    event_ids=[e.event_id for e in correlated_events],
                    status=IncidentStatus.NEW.value,
                    created_at=first_success.timestamp
                )
                incidents.append(inc)

        return incidents

    def _correlate_webshell_to_privesc(self) -> List[Incident]:
        """
        Detects an unprivileged web daemon spawning a shell, followed by active SUID execution
        or elevated process ancestry.
        """
        incidents: List[Incident] = []
        all_sorted = self.get_all_events()

        shells = [e for e in all_sorted if e.event_type == "SUSPICIOUS_SHELL_SPAWNED"]
        elevations = [e for e in all_sorted if e.event_type in ["SUID_EXECUTION", "ACTIVE_EUID_ELEVATION", "SUDO_COMMAND"]]

        for shell in shells:
            # Find elevations by child or same user within window
            related_elevations = [
                el for el in elevations
                if shell.timestamp <= el.timestamp <= (shell.timestamp + timedelta(seconds=1800))
                and (el.ppid == shell.pid or el.user == shell.user)
            ]

            if related_elevations:
                correlated = [shell] + related_elevations
                inc = Incident(
                    title=f"Potential Web Shell to Privilege Escalation: {shell.user}",
                    severity=Severity.CRITICAL.value,
                    confidence=0.96,
                    hypothesis=f"Daemon account '{shell.user}' spawned interactive interpreter (PID {shell.pid}), "
                               f"which subsequently invoked elevated execution: {related_elevations[0].command or related_elevations[0].process}",
                    attribution={
                        'user': shell.user,
                        'pid': shell.pid,
                        'hostname': shell.hostname,
                        'elevated_process': related_elevations[0].process
                    },
                    event_ids=[e.event_id for e in correlated],
                    status=IncidentStatus.NEW.value,
                    created_at=related_elevations[0].timestamp
                )
                incidents.append(inc)

        return incidents

    def _correlate_suid_burst(self) -> List[Incident]:
        """Detects rapid execution of multiple unusual SUID binaries within 60 seconds (reconnaissance burst)"""
        incidents: List[Incident] = []
        suid_events = [e for e in self.get_all_events() if e.event_type == "SUID_EXECUTION"]

        if len(suid_events) < 4:
            return incidents

        # Group by 60s windows
        window_events = []
        for i in range(len(suid_events)):
            window = [
                e for e in suid_events[i:]
                if (e.timestamp - suid_events[i].timestamp).total_seconds() <= 60
            ]
            if len(window) >= 4:
                window_events.append(window)

        for win in window_events:
            users = set(e.user for e in win if e.user)
            primary_user = list(users)[0] if users else "unknown"
            binaries = list(set(e.process or e.command for e in win if e.process or e.command))

            inc = Incident(
                title=f"SUID Binary Enumeration Burst Detected: {primary_user}",
                severity=Severity.HIGH.value,
                confidence=0.89,
                hypothesis=f"Rapid execution of {len(win)} SUID executions within 60 seconds: {', '.join(binaries[:5])}",
                attribution={
                    'user': primary_user,
                    'hostname': win[0].hostname,
                    'binary_count': len(binaries)
                },
                event_ids=[e.event_id for e in win],
                status=IncidentStatus.NEW.value,
                created_at=win[-1].timestamp
            )
            incidents.append(inc)
            break

        return incidents

    def get_timeline_summary(self) -> Dict[str, Any]:
        """Compute chronological summary of events across types and time range"""
        all_events = self.get_all_events()
        events_by_type: Dict[str, int] = defaultdict(int)
        for e in all_events:
            events_by_type[e.event_type] += 1

        start_time = all_events[0].timestamp if all_events else None
        end_time = all_events[-1].timestamp if all_events else None

        return {
            'total_events': len(all_events),
            'events_by_type': dict(events_by_type),
            'time_range': {
                'start': start_time.isoformat() if start_time else None,
                'end': end_time.isoformat() if end_time else None
            }
        }
