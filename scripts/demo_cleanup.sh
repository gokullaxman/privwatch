#!/usr/bin/env bash
#
# UATU Linux Edition - Demonstration Environment Cleanup
# Safely removes all demonstration artifacts, temporary test files, and test cron entries.
#

set -eo pipefail

DEMO_DIR="${1:-/tmp/uatu_demo}"
echo "[*] Cleaning up UATU demonstration environment..."

if [[ -d "${DEMO_DIR}" ]]; then
    rm -rf "${DEMO_DIR}"
    echo "[+] Removed demo directory: ${DEMO_DIR}"
fi

if [[ -f "/etc/cron.d/uatu_demo_cron" ]]; then
    if [[ $(id -u) -eq 0 ]]; then
        rm -f /etc/cron.d/uatu_demo_cron
        echo "[+] Removed /etc/cron.d/uatu_demo_cron"
    else
        echo "[!] Notice: Please run as root to remove /etc/cron.d/uatu_demo_cron"
    fi
fi

# Clean up any demo DB or token files in /tmp
rm -f /tmp/uatu_demo_*.db* 2>/dev/null || true

echo "[+] Cleanup complete. Host returned to clean baseline state."
