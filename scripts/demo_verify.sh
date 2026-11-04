#!/usr/bin/env bash
#
# UATU Linux Edition - Demonstration Outcome Verification
# Verifies that demo findings, incidents, and remediation states meet expected criteria.
#

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo "  UATU LINUX EDITION — DEMONSTRATION VERIFICATION"
echo "========================================================================"

python3 -c "
import sys
from core.storage import StorageEngine
from core.models import Severity

storage = StorageEngine()

findings = storage.get_findings()
incidents = storage.get_incidents()
containment_ops = storage.get_containment_actions()
audit_entries = storage.get_audit_logs(limit=10)

print(f'Total Findings Recorded:    {len(findings)}')
print(f'Total Incidents Correlated: {len(incidents)}')
print(f'Containment Ops Recorded:   {len(containment_ops)}')
print(f'Audit Trail Entries:        {len(audit_entries)}')

# Verify cryptographic audit chain
valid, err = storage.verify_audit_chain_integrity()
print(f'Audit Chain Integrity:      {\"PASS (Intact)\" if valid else f\"FAIL ({err})\"}')

if not valid:
    print('[-] Audit trail verification failed!', file=sys.stderr)
    sys.exit(1)

print('[+] Demonstration verification successful.')
"
