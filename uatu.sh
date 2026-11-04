#!/usr/bin/env bash
#
# UATU Linux Edition - Runner Script
# Intelligent Privilege Escalation Detection, Prevention, and Attack-Path Disruption
#
# Usage:
#   ./uatu.sh scan
#   ./uatu.sh watch
#   ./uatu.sh serve
#   ./uatu.sh remediate <finding_id> [--apply]
#   ./uatu.sh rollback <finding_id>
#   ./uatu.sh report <finding_id|incident_id> [--format=pdf|json]
#

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure Python 3 is available
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required to run UATU." >&2
    exit 1
fi

# Activate virtual environment if present
if [[ -d "venv" && -f "venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
elif [[ -d ".venv" && -f ".venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

# Check for required dependencies
if ! python3 -c "import fastapi, uvicorn, networkx" &>/dev/null; then
    echo "[!] Warning: Missing some python packages. Install via: pip install -r requirements.txt" >&2
fi

# Execute UATU CLI
exec python3 "${SCRIPT_DIR}/uatu_cli.py" "$@"
