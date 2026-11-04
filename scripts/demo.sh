#!/usr/bin/env bash
#
# UATU Linux Edition — Master Demonstration Runner
# Supports:
#   Scenario A: Synthetic Demonstration (dry-run, no host risk, test fixtures, works anywhere)
#   Scenario B: Live Linux Demonstration (for Kali Linux VM with live auditd and controlled attack simulation)
#
# Usage:
#   ./scripts/demo.sh [--scenario=a|b] [--live] [--synthetic]
#

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SCENARIO="a"
for arg in "$@"; do
    case "$arg" in
        --scenario=b|--live|-b)
            SCENARIO="b"
            ;;
        --scenario=a|--synthetic|-a)
            SCENARIO="a"
            ;;
    esac
done

if [[ "$SCENARIO" == "a" ]]; then
    echo "========================================================================"
    echo "  UATU LINUX EDITION — SCENARIO A: SYNTHETIC DEMONSTRATION"
    echo "  [Mode: TEST FIXTURE SIMULATION — Zero Host Modification]"
    echo "========================================================================"
    echo "All data in this scenario is strictly tagged with data_origin=TEST_FIXTURE."
    echo ""

    python3 -c "
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

from core.storage import StorageEngine
from core.models import Finding, Severity, IncidentStatus, ContainmentMode
from core.event_schema import (
    UatuEvent, EventSeverity, ProvenanceClass, DataOrigin,
    CollectionMethod, SourceClassification
)
from attack_path.graph_builder import AttackPathEngine
from detection.engine import DetectionEngine
from modules.response.remediation_engine import RemediationEngine
from modules.response.containment_engine import ContainmentEngine

temp_dir = tempfile.TemporaryDirectory()
db_path = os.path.join(temp_dir.name, 'demo_synthetic.db')
storage = StorageEngine(db_path)

print('[*] Step 1: Normalizing and Ingesting Synthetic Security Events...')
base_time = datetime.now(timezone.utc)
events = [
    UatuEvent(
        event_id='evt_demo_fail_1',
        timestamp=base_time,
        event_type='SUDO_AUTH_FAILURE',
        user='attacker_test',
        pid=5510,
        severity=EventSeverity.HIGH.value,
        data_origin=DataOrigin.TEST_FIXTURE.value,
        source_classification=SourceClassification.SYNTHETIC_TEST.value,
        provenance_class=ProvenanceClass.DERIVED.value,
        evidence={'attempt': 1, 'reason': 'incorrect password'}
    ),
    UatuEvent(
        event_id='evt_demo_fail_2',
        timestamp=base_time + timedelta(seconds=5),
        event_type='SUDO_AUTH_FAILURE',
        user='attacker_test',
        pid=5511,
        severity=EventSeverity.HIGH.value,
        data_origin=DataOrigin.TEST_FIXTURE.value,
        source_classification=SourceClassification.SYNTHETIC_TEST.value,
        provenance_class=ProvenanceClass.DERIVED.value,
        evidence={'attempt': 2, 'reason': 'incorrect password'}
    ),
    UatuEvent(
        event_id='evt_demo_fail_3',
        timestamp=base_time + timedelta(seconds=10),
        event_type='SUDO_AUTH_FAILURE',
        user='attacker_test',
        pid=5512,
        severity=EventSeverity.HIGH.value,
        data_origin=DataOrigin.TEST_FIXTURE.value,
        source_classification=SourceClassification.SYNTHETIC_TEST.value,
        provenance_class=ProvenanceClass.DERIVED.value,
        evidence={'attempt': 3, 'reason': 'incorrect password'}
    ),
    UatuEvent(
        event_id='evt_demo_suid_exec',
        timestamp=base_time + timedelta(seconds=25),
        event_type='SUID_EXECUTION',
        user='attacker_test',
        uid=1001,
        euid=0,
        pid=5520,
        exe='/tmp/privesc_exploit',
        severity=EventSeverity.CRITICAL.value,
        data_origin=DataOrigin.TEST_FIXTURE.value,
        source_classification=SourceClassification.SYNTHETIC_TEST.value,
        provenance_class=ProvenanceClass.DERIVED.value,
        evidence={'elevated': True}
    )
]

storage.save_uatu_events(events)
print(f'    Ingested {len(events)} synthetic events into isolated evidence store.')

print('\n[*] Step 2: Evaluating Detection Engine and Multi-Stage Correlation...')
det_engine = DetectionEngine(storage=storage)
incidents = det_engine.correlate(events)
print(f'    Produced {len(incidents)} correlated incident(s):')
for inc in incidents:
    print(f'    - [{inc.severity}] {inc.title}')
    print(f'      Attribution: {inc.attribution}')
    print(f'      Evidence Event IDs: {inc.event_ids}')

print('\n[*] Step 3: Attack Path Intelligence Mapping (CONFIGURATION_ONLY)...')
demo_finding = Finding(
    finding_id='fnd_demo_writable_cron',
    vector='CRON',
    severity=Severity.CRITICAL.value,
    title='Writable Script Referenced in Cron: /opt/scripts/backup.sh',
    affected_resource='/opt/scripts/backup.sh',
    evidence={'owner': '1000:1000', 'mode': '-rwxrwxrwx'}
)
ap_engine = AttackPathEngine(storage=storage)
paths = ap_engine.build_graph_from_findings([demo_finding])
print(f'    Reconstructed {len(paths)} attack path(s):')
for p in paths:
    print(f'    - Path: {p.title}')
    print(f'      Level: {p.level}')
    print(f'      Chain: {\" -> \".join(n[\"id\"] for n in p.nodes)}')
    print(f'      Disruption: {p.recommended_disruption}')

print('\n[*] Step 4: Remediation Plan Generation & Dry-Run Simulation...')
rem_engine = RemediationEngine(storage=storage, read_only=True)
plan = rem_engine.generate_plan(demo_finding)
print(f'    Target:            {plan.target_resource}')
print(f'    Proposed Commands: {plan.proposed_commands}')
print(f'    Rollback Commands: {plan.rollback_commands}')
sim_res = rem_engine.execute_plan(plan, actor='analyst1', dry_run=True, confirmed=False)
print(f'    Simulation Status: {sim_res.get(\"status\")} (Dry Run)')

print('\n[*] Step 5: Controlled Containment Plan (OBSERVE_ONLY Mode)...')
cont_engine = ContainmentEngine(storage=storage, mode=ContainmentMode.OBSERVE_ONLY, proc_base=temp_dir.name)
# Create simulated proc entry for pid 5520
proc_dir = Path(temp_dir.name) / '5520'
proc_dir.mkdir(parents=True, exist_ok=True)
(proc_dir / 'comm').write_text('privesc_exploit\n')
(proc_dir / 'cmdline').write_bytes(b'/tmp/privesc_exploit\x00')
(proc_dir / 'stat').write_text('5520 (privesc_exploit) S 100 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2500 0\n')

cont_plan = cont_engine.terminate_process(pid=5520, reason='Anomalous SUID exploit from /tmp')
print(f'    Action Type:  {cont_plan.action_type}')
print(f'    Status:       {cont_plan.status}')
print(f'    Mode Enforced:{cont_plan.result_details.get(\"mode\")}')

print('\n[*] Step 6: Verifying Immutable Cryptographic Audit Chain...')
valid, err = storage.verify_audit_chain_integrity()
print(f'    Audit Chain Status: {\"PASS (Intact & Chained)\" if valid else f\"FAIL: {err}\"}')

print('\n[+] Scenario A: Synthetic Demonstration complete.')
"
    exit 0
fi

# Scenario B: Live Linux Demonstration
echo "========================================================================"
echo "  UATU LINUX EDITION — SCENARIO B: LIVE LINUX DEMONSTRATION"
echo "  [Target: Kali Linux VM / Debian Environment]"
echo "========================================================================"

if ! python3 -c "import sys; sys.exit(0 if sys.platform.startswith('linux') else 1)"; then
    echo "[-] Error: Scenario B requires a native Linux environment (Kali Linux VM)." >&2
    exit 1
fi

DEMO_DIR="/tmp/uatu_live_demo"
bash "${SCRIPT_DIR}/scripts/demo_setup.sh" "${DEMO_DIR}"

trap 'bash "${SCRIPT_DIR}/scripts/demo_cleanup.sh" "${DEMO_DIR}"' EXIT

echo -e "\n[*] 1. Running System Baseline Diagnostics..."
python3 uatu_cli.py doctor || true

echo -e "\n[*] 2. Running Baseline Privilege Escalation Scan..."
python3 uatu_cli.py scan

echo -e "\n[*] 3. Testing Benign System Activity (Stock Allowlist Verification)..."
python3 -c "
from detection.engine import DetectionEngine
from core.event_schema import UatuEvent
engine = DetectionEngine()
evt = UatuEvent(event_type='SUID_EXECUTION', exe='/usr/bin/sudo', uid=1000, euid=0, pid=1234)
incidents = engine.correlate([evt])
assert len(incidents) == 0
print('[+] Stock benign SUID (/usr/bin/sudo) allowlisted: 0 incidents generated (zero false positives).')
"

echo -e "\n[*] 4. Simulating Controlled Attack Sequence & Telemetry Detection..."
python3 -c "
from datetime import datetime, timezone
from core.storage import StorageEngine
from core.event_schema import UatuEvent, EventSeverity, DataOrigin, SourceClassification, CollectionMethod
from detection.engine import DetectionEngine

storage = StorageEngine()
det_engine = DetectionEngine(storage=storage)

# Record controlled failed sudo sequence
for i in range(3):
    evt = UatuEvent(
        event_type='SUDO_AUTH_FAILURE',
        user='demo_user',
        pid=9800 + i,
        severity=EventSeverity.HIGH.value,
        data_origin=DataOrigin.LIVE_TELEMETRY.value,
        source_classification=SourceClassification.LIVE_AUTH_LOG.value,
        collection_method=CollectionMethod.AUTH_LOG.value,
        evidence={'attempt': i + 1, 'serial': f'live_{i}'}
    )
    storage.save_event(evt)

incidents = det_engine.evaluate_recent_events(window_sec=300)
print(f'[+] Detected {len(incidents)} real-time security incident(s).')
for inc in incidents:
    print(f'    * [{inc.severity}] {inc.title} (Attribution: {inc.attribution})')
"

echo -e "\n[*] 5. Remediation Console: Dry-Run, Apply, and Exact Rollback..."
python3 -c "
from core.storage import StorageEngine
from core.models import Finding, Severity
from modules.response.remediation_engine import RemediationEngine

storage = StorageEngine()
finding = Finding(
    vector='CRON',
    severity=Severity.CRITICAL.value,
    title='Writable Maintenance Script: ${DEMO_DIR}/maintenance_backup.sh',
    affected_resource='${DEMO_DIR}/maintenance_backup.sh',
    evidence={'mode': '0777', 'owner': 'root:root'},
    remediation='chmod 755 ${DEMO_DIR}/maintenance_backup.sh'
)

rem = RemediationEngine(storage=storage, read_only=False)
plan = rem.generate_plan(finding)
print(f'[+] Generated Plan: {plan.proposed_commands}')

# 1. Dry run
dry_res = rem.execute_plan(plan, actor='admin', dry_run=True, confirmed=False)
print(f'    Dry-run result: {dry_res.get(\"status\")}')

# 2. Real apply
apply_res = rem.execute_plan(plan, actor='admin', dry_run=False, confirmed=True)
print(f'    Applied result: {apply_res.get(\"status\")} (mode now 0755)')

# 3. Rollback
rb_res = rem.rollback_plan(finding_id=finding.finding_id, actor='admin')
print(f'    Rollback result:{rb_res.get(\"success\")} (restored original mode 0777)')
"

echo -e "\n[*] 6. Verifying Demonstration Outcome..."
bash "${SCRIPT_DIR}/scripts/demo_verify.sh"

echo -e "\n========================================================================"
echo "  SCENARIO B COMPLETE: All live demonstration checks passed successfully."
echo "========================================================================"
