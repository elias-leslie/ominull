#!/usr/bin/env bash
set -euo pipefail

ANCHOR_NAME="ominull_isolation"
ANCHOR_FILE="/etc/pf.anchors/ominull_isolation"

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] Error: Administrator/root privileges (sudo) required."
        exit 1
    fi
}

case "${1:-help}" in
    isolate)
        ensure_root
        HUB_IP="${2:-10.0.0.57}"
        echo "[*] Activating macOS BSD Packet Filter Isolation (Anchor: ${ANCHOR_NAME})..."
        mkdir -p /etc/pf.anchors
        cat << PFRULES > "${ANCHOR_FILE}"
# Ominull Zero-Friction Network Quarantine Anchor
set skip on lo0
pass out quick proto tcp to ${HUB_IP} keep state
pass out quick proto udp to any port 67:68
block drop all
PFRULES
        pfctl -E 2>/dev/null || true
        pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"
        echo "[+] SUCCESS: macOS Host is now QUARANTINED (Default-Deny active, Hub pinhole to ${HUB_IP})."
        ;;
    unisolate)
        ensure_root
        echo "[*] Lifting macOS Network Isolation..."
        pfctl -a "${ANCHOR_NAME}" -F all 2>/dev/null || true
        rm -f "${ANCHOR_FILE}"
        echo "[+] SUCCESS: macOS Isolation removed. Normal traffic restored."
        ;;
    block-ip)
        ensure_root
        TARGET_IP="${2:-}"
        if [[ -z "${TARGET_IP}" ]]; then
            echo "[-] Error: Missing target IP address."
            exit 1
        fi
        echo "[*] Blocking IP ${TARGET_IP} on macOS..."
        pfctl -E 2>/dev/null || true
        echo "block drop out quick to ${TARGET_IP}" | pfctl -a "${ANCHOR_NAME}" -f -
        echo "[+] SUCCESS: Blocked ${TARGET_IP} via native Packet Filter."
        ;;
    test)
        echo "[+] macOS Native Packet Filter Engine Ready."
        which pfctl
        ;;
    *)
        echo "Ominull macOS Zero-Friction BSD Packet Filter Engine"
        echo "Usage:"
        echo "  sudo ./pf_engine.sh isolate <hub_ip>  - Default-deny quarantine with Hub pinhole"
        echo "  sudo ./pf_engine.sh unisolate         - Lift quarantine and restore traffic"
        echo "  sudo ./pf_engine.sh block-ip <ip>     - Block specific IP address"
        echo "  ./pf_engine.sh test                   - Verify pfctl tool availability"
        exit 1
        ;;
esac
