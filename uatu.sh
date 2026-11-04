#!/usr/bin/env bash
#
# UATU Linux Edition — Intelligent Privilege Escalation Detection, Prevention & Attack-Path Disruption
# Master Lifecycle & Operations Script
#
# Usage:
#   ./uatu.sh install                     Deploy systemd service, auditd rules, and directories (root)
#   ./uatu.sh doctor                      Run comprehensive environmental and subsystem diagnostics
#   ./uatu.sh status                      Display system posture, incidents, and telemetry health
#   ./uatu.sh scan                        Execute privilege escalation weakness scan & attack graphs
#   ./uatu.sh watch [--verbose]           Live telemetry stream ingestion and real-time detection
#   ./uatu.sh serve [--port=8443]         Start operational REST API and security dashboard
#   ./uatu.sh remediate <id> [--apply]    Plan (dry-run) or apply least-privilege permission correction
#   ./uatu.sh rollback <id>               Restore exact pre-remediation permissions from captured state
#   ./uatu.sh report <id> [--format=pdf]  Generate single finding or incident evidence report
#   ./uatu.sh test                        Execute automated pytest validation suite
#   ./uatu.sh demo [--live]               Run structured demonstration scenario
#   ./uatu.sh logs [--limit=N]            Display immutable audit trail entries
#   ./uatu.sh version                     Show version, architecture, and platform information
#   ./uatu.sh uninstall [--confirm]       Clean removal of rules, service, and state files (root)
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

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    install)
        echo "========================================================================"
        echo "  UATU LINUX EDITION — SYSTEM INSTALLATION"
        echo "========================================================================"
        if [[ $(id -u) -ne 0 ]]; then
            echo "[-] Error: 'install' requires root privileges. Please run with sudo:" >&2
            echo "    sudo ./uatu.sh install" >&2
            exit 1
        fi

        echo "[*] Creating secure directory structures..."
        mkdir -p /etc/uatu
        mkdir -p /var/lib/uatu && chmod 0700 /var/lib/uatu
        mkdir -p /var/log/uatu && chmod 0700 /var/log/uatu

        echo "[*] Installing UATU auditd rules..."
        if [[ -d "/etc/audit/rules.d" && -f "${SCRIPT_DIR}/config/audit/uatu.rules" ]]; then
            cp -f "${SCRIPT_DIR}/config/audit/uatu.rules" /etc/audit/rules.d/uatu.rules
            chmod 0640 /etc/audit/rules.d/uatu.rules
            if command -v augenrules &>/dev/null; then
                augenrules --load || true
            elif command -v auditctl &>/dev/null; then
                auditctl -R /etc/audit/rules.d/uatu.rules || true
            fi
            echo "[+] Audit rules installed to /etc/audit/rules.d/uatu.rules"
        else
            echo "[!] Warning: /etc/audit/rules.d not found; audit rules not loaded."
        fi

        echo "[*] Installing systemd service..."
        if [[ -d "/etc/systemd/system" && -f "${SCRIPT_DIR}/config/systemd/uatu.service" ]]; then
            cp -f "${SCRIPT_DIR}/config/systemd/uatu.service" /etc/systemd/system/uatu.service
            chmod 0644 /etc/systemd/system/uatu.service
            systemctl daemon-reload || true
            echo "[+] Systemd unit installed to /etc/systemd/system/uatu.service"
            echo "    Enable and start with: sudo systemctl enable --now uatu.service"
        fi

        echo "[+] Installation complete."
        ;;

    uninstall)
        echo "========================================================================"
        echo "  UATU LINUX EDITION — SYSTEM UNINSTALLATION"
        echo "========================================================================"
        if [[ $(id -u) -ne 0 ]]; then
            echo "[-] Error: 'uninstall' requires root privileges. Please run with sudo:" >&2
            echo "    sudo ./uatu.sh uninstall" >&2
            exit 1
        fi

        CONFIRMED=false
        for arg in "$@"; do
            if [[ "$arg" == "--confirm" || "$arg" == "-y" ]]; then
                CONFIRMED=true
            fi
        done

        if [[ "$CONFIRMED" != "true" ]]; then
            read -r -p "Are you sure you want to stop and remove UATU services and rules? [y/N] " resp
            if [[ "$resp" != "y" && "$resp" != "Y" ]]; then
                echo "Uninstallation aborted."
                exit 0
            fi
        fi

        echo "[*] Stopping and disabling uatu.service..."
        systemctl stop uatu.service 2>/dev/null || true
        systemctl disable uatu.service 2>/dev/null || true
        rm -f /etc/systemd/system/uatu.service
        systemctl daemon-reload || true

        echo "[*] Removing audit rules..."
        rm -f /etc/audit/rules.d/uatu.rules
        if command -v augenrules &>/dev/null; then
            augenrules --load || true
        fi

        echo "[+] UATU system components successfully uninstalled."
        ;;

    doctor)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" doctor "$@"
        ;;

    status)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" status "$@"
        ;;

    scan)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" scan "$@"
        ;;

    watch)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" watch "$@"
        ;;

    serve)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" serve "$@"
        ;;

    remediate)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" remediate "$@"
        ;;

    rollback)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" rollback "$@"
        ;;

    report)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" report "$@"
        ;;

    logs)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" logs "$@"
        ;;

    version)
        exec python3 "${SCRIPT_DIR}/uatu_cli.py" version
        ;;

    test)
        if command -v pytest &>/dev/null; then
            exec pytest "${SCRIPT_DIR}/tests" "$@"
        else
            exec python3 -m pytest "${SCRIPT_DIR}/tests" "$@"
        fi
        ;;

    demo)
        if [[ -f "${SCRIPT_DIR}/scripts/demo.sh" ]]; then
            exec bash "${SCRIPT_DIR}/scripts/demo.sh" "$@"
        else
            echo "[-] Error: scripts/demo.sh not found." >&2
            exit 1
        fi
        ;;

    help|--help|-h|*)
        echo "UATU Linux Edition — Intelligent Privilege Escalation Disruption"
        echo "Usage: ./uatu.sh <command> [options]"
        echo ""
        echo "Commands:"
        echo "  doctor                      Run system and environment diagnostics"
        echo "  status                      Show posture, active findings, and telemetry coverage"
        echo "  scan                        Run privilege escalation scan and build attack graphs"
        echo "  watch [--verbose]           Live telemetry stream ingestion and real-time detection"
        echo "  serve [--port=8443]         Start operational REST API and security dashboard"
        echo "  remediate <id> [--apply]    Plan (dry-run) or apply permission remediation"
        echo "  rollback <id>               Restore exact pre-remediation state"
        echo "  report <id> [--format=pdf]  Generate item report (JSON or ReportLab PDF)"
        echo "  test                        Run automated test suite"
        echo "  demo [--live]               Run demonstration scenario"
        echo "  logs [--limit=N]            Display immutable cryptographic audit trail"
        echo "  version                     Show UATU product version and platform info"
        echo "  install                     Install system auditd rules and systemd service (root)"
        echo "  uninstall                   Remove system rules and services (root)"
        exit 0
        ;;
esac
