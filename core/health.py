"""
UATU Linux Edition - Health Registry & Telemetry Drop Tracking
Monitors the operational health of all system components (telemetry collectors, event bus,
detection engine, risk scoring, privileged service, persistence store).
Tracks component states (OK, DEGRADED, UNAVAILABLE), event drops, error frequencies,
and generates structured health snapshots.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Dict, List, Optional, Any, Tuple


class HealthState(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ComponentHealth:
    """Operational health record of an individual subsystem component."""
    name: str
    state: HealthState = HealthState.UNKNOWN
    reason: str = "Uninitialized"
    critical: bool = True
    last_success: Optional[datetime] = None
    last_error: Optional[datetime] = None
    error_count: int = 0
    drop_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value if isinstance(self.state, Enum) else str(self.state),
            "reason": self.reason,
            "critical": self.critical,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_error": self.last_error.isoformat() if self.last_error else None,
            "error_count": self.error_count,
            "drop_count": self.drop_count,
            "metadata": self.metadata
        }


class HealthRegistry:
    """Thread-safe centralized registry for subsystem health and drop monitoring."""

    def __init__(self):
        self._components: Dict[str, ComponentHealth] = {}
        self._lock = threading.RLock()

    def register(self, name: str, critical: bool = True, metadata: Optional[Dict[str, Any]] = None) -> ComponentHealth:
        """Register a new component in the health registry."""
        with self._lock:
            if name not in self._components:
                self._components[name] = ComponentHealth(
                    name=name,
                    state=HealthState.OK,
                    reason="Initialized",
                    critical=critical,
                    last_success=datetime.now(timezone.utc),
                    metadata=metadata or {}
                )
            return self._components[name]

    def record_success(self, name: str, message: str = "Operating normally"):
        """Record successful operation of a component."""
        with self._lock:
            comp = self._components.get(name)
            if not comp:
                comp = self.register(name)
            comp.state = HealthState.OK
            comp.reason = message
            comp.last_success = datetime.now(timezone.utc)

    def record_degraded(self, name: str, reason: str):
        """Mark component as degraded with an explicit reason."""
        with self._lock:
            comp = self._components.get(name)
            if not comp:
                comp = self.register(name)
            comp.state = HealthState.DEGRADED
            comp.reason = reason
            comp.last_error = datetime.now(timezone.utc)
            comp.error_count += 1

    def record_error(self, name: str, reason: str, is_fatal: bool = False):
        """Record an error; marks component as DEGRADED or UNAVAILABLE."""
        with self._lock:
            comp = self._components.get(name)
            if not comp:
                comp = self.register(name)
            comp.state = HealthState.UNAVAILABLE if is_fatal else HealthState.DEGRADED
            comp.reason = reason
            comp.last_error = datetime.now(timezone.utc)
            comp.error_count += 1

    def record_drop(self, name: str, count: int = 1):
        """Increment telemetry or event drop counter for a component."""
        with self._lock:
            comp = self._components.get(name)
            if not comp:
                comp = self.register(name)
            comp.drop_count += count

    def get_component(self, name: str) -> Optional[ComponentHealth]:
        """Retrieve component health record."""
        with self._lock:
            return self._components.get(name)

    def get_all_components(self) -> Dict[str, ComponentHealth]:
        """Retrieve shallow copy of all registered component states."""
        with self._lock:
            return dict(self._components)

    def get_system_health(self) -> Tuple[HealthState, Dict[str, Any]]:
        """
        Evaluate overall system health:
        - UNAVAILABLE if any critical component is UNAVAILABLE
        - DEGRADED if any component is DEGRADED or a non-critical component is UNAVAILABLE
        - OK if all components are OK
        """
        with self._lock:
            if not self._components:
                return HealthState.OK, {"overall": "OK", "total_components": 0, "components": {}}

            overall = HealthState.OK
            critical_unavailable = False
            has_degraded = False

            comp_dict = {}
            total_drops = 0
            total_errors = 0

            for name, comp in self._components.items():
                comp_dict[name] = comp.to_dict()
                total_drops += comp.drop_count
                total_errors += comp.error_count

                if comp.state == HealthState.UNAVAILABLE:
                    if comp.critical:
                        critical_unavailable = True
                    else:
                        has_degraded = True
                elif comp.state == HealthState.DEGRADED:
                    has_degraded = True

            if critical_unavailable:
                overall = HealthState.UNAVAILABLE
            elif has_degraded:
                overall = HealthState.DEGRADED

            summary = {
                "overall": overall.value,
                "total_components": len(self._components),
                "total_drops": total_drops,
                "total_errors": total_errors,
                "components": comp_dict
            }
            return overall, summary

    def create_snapshot(self, hostname: str = "localhost") -> Dict[str, Any]:
        """Generate snapshot dictionary suitable for persistence in health_snapshots table."""
        overall, summary = self.get_system_health()
        return {
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": overall.value,
            "coverage_pct": 100.0 if overall == HealthState.OK else (50.0 if overall == HealthState.DEGRADED else 0.0),
            "ingestion_eps": 0.0,
            "sources": summary["components"],
            "drop_count": summary["total_drops"],
            "queue_depth": 0
        }


# Global default instance
default_health_registry = HealthRegistry()
