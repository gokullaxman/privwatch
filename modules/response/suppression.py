"""
PrivWatch 3.0 - False-Positive Suppression & Alert Management
Provides auditable suppression rules to mute expected administrative alerts.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import uuid

from core.storage import StorageEngine


class SuppressionManager:
    """Manages suppression rules and alert acknowledgments with audit logging"""

    def __init__(self, storage: StorageEngine):
        self.storage = storage

    def add_rule(self, vector: str, pattern: str, reason: str, actor: str) -> str:
        """Register a new suppression pattern"""
        rule_id = f"rule_{uuid.uuid4().hex[:10]}"
        self.storage.add_suppression(
            rule_id=rule_id,
            vector=vector,
            pattern=pattern,
            reason=reason,
            actor=actor
        )
        return rule_id

    def check_is_suppressed(self, vector: str, text: str) -> bool:
        """Check if an alert is muted by an active rule"""
        return self.storage.is_suppressed(vector, text)

