"""
PrivWatch 3.0 - Evidence Management & Integrity Engine
Handles cryptographic fingerprinting, provenance tracking, and data sanitization for security findings.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Dict, Any, Optional


class EvidenceManager:
    """Manages evidence lifecycle, provenance hashing, and sensitive data sanitization"""

    @staticmethod
    def fingerprint(data: Any) -> str:
        """Generate SHA-256 cryptographic digest of evidence payload"""
        if isinstance(data, dict):
            serialized = json.dumps(data, sort_keys=True, default=str)
        elif isinstance(data, str):
            serialized = data
        else:
            serialized = str(data)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def create_evidence(source: str, raw_data: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Bundle raw observation with collection provenance and integrity hash"""
        meta = metadata or {}
        payload = {
            'source': source,
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'raw_data': raw_data,
            'metadata': meta,
        }
        payload['sha256'] = EvidenceManager.fingerprint(raw_data)
        return payload

    @staticmethod
    def verify_integrity(evidence: Dict[str, Any]) -> bool:
        """Verify that raw_data matches the recorded SHA-256 fingerprint"""
        recorded = evidence.get('sha256')
        raw_data = evidence.get('raw_data')
        if not recorded or raw_data is None:
            return False
        return EvidenceManager.fingerprint(raw_data) == recorded

    @staticmethod
    def sanitize(text: str) -> str:
        """
        Sanitize sensitive credentials (e.g., password hashes in /etc/shadow or tokens)
        prior to terminal or web display to prevent credential exposure.
        """
        if not text:
            return ""

        # Redact SHA-512 crypt hashes ($6$...), yescrypt ($y$...), bcrypt ($2a$...)
        sanitized = re.sub(
            r'(\$(?:1|2[aby]?|5|6|y)\$[^\s:;,\'"]{8,128})',
            r'[REDACTED_PASSWORD_HASH]',
            text
        )

        # Redact common private key markers
        sanitized = re.sub(
            r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----',
            r'[REDACTED_PRIVATE_KEY]',
            sanitized
        )

        return sanitized
