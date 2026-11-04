#!/usr/bin/env bash
#
# UATU Linux Edition - Demonstration Environment Setup
# Prepares disposable, non-destructive test fixtures in /tmp for live evaluation.
#

set -eo pipefail

DEMO_DIR="${1:-/tmp/uatu_demo}"
echo "[*] Setting up UATU demonstration environment at: ${DEMO_DIR}"

mkdir -p "${DEMO_DIR}"
chmod 0755 "${DEMO_DIR}"

# 1. Create simulated vulnerable maintenance script
DEMO_SCRIPT="${DEMO_DIR}/maintenance_backup.sh"
cat << 'EOF' > "${DEMO_SCRIPT}"
#!/usr/bin/env bash
# UATU Demonstration Vulnerability: World-Writable Maintenance Script
echo "Executing daily backup routine..."
EOF
chmod 0777 "${DEMO_SCRIPT}"
echo "[+] Created world-writable script: ${DEMO_SCRIPT} (0777)"

# 2. If running as root, link into cron for live scan discovery
if [[ $(id -u) -eq 0 && -d "/etc/cron.d" ]]; then
    cat << EOF > /etc/cron.d/uatu_demo_cron
# UATU Demonstration Test Cron Job
* * * * * root ${DEMO_SCRIPT}
EOF
    chmod 0644 /etc/cron.d/uatu_demo_cron
    echo "[+] Linked into /etc/cron.d/uatu_demo_cron"
fi

echo "[+] Setup complete. Ready for demonstration."
