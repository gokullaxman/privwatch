#!/usr/bin/env bash
#
# UATU Linux Edition - Live End-to-End Prototype Demo Script
# Demonstrates:
#   D1: Writable script in cron/systemd -> Scan -> Attack Path mapped [CONFIGURATION_ONLY]
#   D2: Repeated sudo authentication failures -> Watch generates Correlated Incident
#   D3: Remediate finding (dry-run & apply) -> Verification -> Rollback -> Verification
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DEMO_DIR="/tmp/uatu_demo_$$"
mkdir -p "$DEMO_DIR"

cleanup() {
    echo -e "\n[+] Cleaning up temporary demo artifacts..."
    rm -rf "$DEMO_DIR"
    rm -f /etc/cron.d/uatu_demo_cron 2>/dev/null || true
    echo "[+] Done."
}
trap cleanup EXIT

echo "========================================================================"
echo "  UATU LINUX EDITION — LIVE END-TO-END PROTOTYPE DEMONSTRATION"
echo "========================================================================"
echo "Working directory: $SCRIPT_DIR"
echo "Demo temp dir:     $DEMO_DIR"
echo

# ----------------------------------------------------------------------
# DEMO 1: Writable script -> Static Scan -> Attack Path Mapping
# ----------------------------------------------------------------------
echo "------------------------------------------------------------------------"
echo "  DEMO 1: SCRIPT SCANNING & ATTACK PATH GRAPH GENERATION"
echo "------------------------------------------------------------------------"

DEMO_SCRIPT="$DEMO_DIR/backup_job.sh"
cat << 'EOF' > "$DEMO_SCRIPT"
#!/bin/bash
# Simulated sensitive scheduled maintenance job
echo "Running system backup..."
EOF

# Make script world-writable to create an exploitable vulnerability
chmod 777 "$DEMO_SCRIPT"
echo "[+] Created simulated maintenance script: $DEMO_SCRIPT"
ls -la "$DEMO_SCRIPT"

# If running with root permissions, link to /etc/cron.d for live scan detection
if [[ $EUID -eq 0 ]]; then
    cat << EOF > /etc/cron.d/uatu_demo_cron
* * * * * root $DEMO_SCRIPT
EOF
    echo "[+] Linked into /etc/cron.d/uatu_demo_cron (root:root)"
fi

echo -e "\n[*] Running UATU Scan to discover weaknesses and build attack path..."
python3 uatu_cli.py scan

# ----------------------------------------------------------------------
# DEMO 2: Telemetry & Detection Engine (3 Failed Sudo Attempts)
# ----------------------------------------------------------------------
echo -e "\n------------------------------------------------------------------------"
echo "  DEMO 2: TELEMETRY INGESTION & INCIDENT CORRELATION"
echo "------------------------------------------------------------------------"

echo "[*] Ingesting simulated sudo authentication sequence (3 failures)..."
python3 -c "
from datetime import datetime, timezone
from core.orchestrator import PrivWatchOrchestrator
from core.config import PrivWatchConfig
from core.event_schema import UatuEvent, EventSeverity, ProvenanceClass, DataOrigin, CollectionMethod
from detection.engine import DetectionEngine

config = PrivWatchConfig()
orchestrator = PrivWatchOrchestrator(config)
storage = orchestrator.storage
bus = orchestrator.event_bus

test_user = 'demo_attacker'
events = []
for i in range(3):
    ev = UatuEvent(
        source='auth.log',
        collection_method=CollectionMethod.AUTH_LOG.value,
        event_type='SUDO_AUTH_FAILURE',
        severity=EventSeverity.HIGH.value,
        user=test_user,
        command='/usr/bin/sudo id',
        provenance_class=ProvenanceClass.OBSERVED.value,
        data_origin=DataOrigin.LIVE_TELEMETRY.value,
        evidence={'attempt': i + 1, 'failure_reason': 'incorrect password'}
    )
    events.append(ev)

storage.save_uatu_events(events)
print(f'[+] Stored {len(events)} telemetry events into evidence store.')

# Run detection engine
det_engine = DetectionEngine(storage=storage, event_bus=bus)
incidents = det_engine.evaluate_recent_events(window_sec=300)
print(f'[+] Detection evaluation produced {len(incidents)} correlated incident(s).')
for inc in incidents:
    print(f'    * Incident ID:   {inc.incident_id}')
    print(f'    * Title:         {inc.title}')
    print(f'    * Hypothesis:    {inc.hypothesis}')
    print(f'    * Ordered Events:{inc.event_ids}')
"

# ----------------------------------------------------------------------
# DEMO 3: Remediation Console (Dry Run, Apply & Exact Rollback)
# ----------------------------------------------------------------------
echo -e "\n------------------------------------------------------------------------"
echo "  DEMO 3: REMEDIATION PLANNING, APPLICATION & RESTORATION"
echo "------------------------------------------------------------------------"

python3 -c "
from core.orchestrator import PrivWatchOrchestrator
from core.config import PrivWatchConfig
from core.models import Finding, Severity
from modules.response.remediation_engine import RemediationEngine
import os

config = PrivWatchConfig()
orchestrator = PrivWatchOrchestrator(config)
storage = orchestrator.storage

# Register finding for our demo script
fnd = Finding(
    finding_id='fnd_demo_writable_script',
    vector='CRON',
    severity=Severity.CRITICAL.value,
    title='Writable Script Referenced in Scheduled Task',
    affected_resource='$DEMO_SCRIPT',
    evidence={'owner': 'current', 'mode': '0777'},
    remediation='Remove write permissions: chmod 755 $DEMO_SCRIPT'
)
storage.save_finding(fnd)

rem = RemediationEngine(storage=storage, read_only=False)
plan = rem.generate_plan(fnd)

print('[+] Generated Least-Privilege Remediation Plan:')
print(f'    Target:            {plan.target_resource}')
print(f'    Proposed Commands: {plan.proposed_commands}')
print(f'    Rollback Commands: {plan.rollback_commands}')
print(f'    Consequences:      {plan.consequences}')

print('\n[*] 1. Executing Dry-Run Simulation...')
dry_res = rem.execute_plan(plan, actor='demo_admin', confirmed=False, dry_run=True)
print(f'    Dry-run Status: {dry_res.get(\"status\")}')

print('\n[*] 2. Executing Real Remediation (--apply)...')
apply_res = rem.execute_plan(plan, actor='demo_admin', confirmed=True, dry_run=False)
print(f'    Apply Status:   {apply_res.get(\"status\")}')
print(f'    Verification:   {apply_res.get(\"verification\")}')

print('\n[*] 3. Executing Exact Rollback to Restore Pre-Remediation Permissions...')
rb_res = rem.rollback_plan(finding_id=fnd.finding_id, actor='demo_admin')
print(f'    Rollback Result:{rb_res.get(\"success\")}')
print(f'    Restored Mode:  {oct(rb_res.get(\"restored_mode\", 0))}')
"

echo -e "\n========================================================================"
echo "  DEMO COMPLETE: All stages (D1, D2, D3) succeeded without errors."
echo "========================================================================"
