#!/usr/bin/env bash
# UATU Linux Edition - Audit Rules Installer
# Requires explicit sudo / root privileges to copy rules into /etc/audit/rules.d/ and reload auditd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RULES_FILE="${REPO_ROOT}/config/audit/uatu.rules"

echo "=========================================================="
echo " UATU Linux Edition — Auditd Rule Deployment Script"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This installation script requires root privileges to configure auditd."
    echo "[*] Please execute with sudo: sudo bash $0"
    exit 1
fi

if [ ! -f "$RULES_FILE" ]; then
    echo "[-] Error: Audit rules template not found at $RULES_FILE"
    exit 1
fi

echo "[*] Verifying auditd availability..."
if ! command -v auditctl >/dev/null 2>&1; then
    echo "[-] Warning: auditctl is not installed on this system."
    echo "[*] Install auditd first (e.g. apt-get install -y auditd audispd-plugins)"
    exit 1
fi

TARGET_DIR="/etc/audit/rules.d"
TARGET_FILE="${TARGET_DIR}/uatu.rules"

mkdir -p "$TARGET_DIR"
cp "$RULES_FILE" "$TARGET_FILE"
chmod 0600 "$TARGET_FILE"
chown root:root "$TARGET_FILE"

echo "[+] Copied rules to $TARGET_FILE (mode 0600, root:root)"

echo "[*] Applying rules via augenrules and auditctl..."
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$TARGET_FILE"
fi

echo "[+] Audit rules successfully deployed and loaded."
echo "[*] Current auditd status:"
auditctl -s
