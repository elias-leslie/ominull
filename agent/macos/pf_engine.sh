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

# write_state regenerates the anchor from one description of what this host
# should be enforcing, and is what the daemon calls.
#
# Regenerating rather than appending is the point. `block-ip` used to pipe a
# single rule into `pfctl -a <anchor> -f -`, which replaces the anchor's whole
# rule set: blocking a peer silently wiped an active isolation, and blocking a
# second peer wiped the first. There is one writer now and it always writes the
# complete set.
write_state() {
    local isolated="$1" hub_ip="$2"
    shift 2

    mkdir -p /etc/pf.anchors
    {
        echo "# Ominull enforcement anchor - generated, do not edit"
        echo "set skip on lo0"
        # Quarantined peers are dropped whether or not this host is isolated.
        for peer in "$@"; do
            echo "block drop out quick to ${peer}"
            echo "block drop in quick from ${peer}"
        done
        if [[ "${isolated}" == "1" ]]; then
            # The hub pinhole, then the two services a cut-off host still needs
            # to keep an address and find the hub by name. Same shape as the
            # Linux chains and the Windows filters.
            [[ -n "${hub_ip}" ]] && echo "pass out quick proto tcp to ${hub_ip} keep state"
            [[ -n "${hub_ip}" ]] && echo "pass in quick proto tcp from ${hub_ip} keep state"
            echo "pass out quick proto udp to any port 67:68"
            echo "pass out quick proto udp to any port 53"
            echo "block drop all"
        fi
    } > "${ANCHOR_FILE}"

    pfctl -E 2>/dev/null || true
    pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"
}

case "${1:-help}" in
    sync)
        # sync <0|1 isolated> <hub_ip> [peer ...]
        ensure_root
        ISOLATED="${2:-0}"
        HUB_IP="${3:-}"
        shift 3 2>/dev/null || shift $#
        write_state "${ISOLATED}" "${HUB_IP}" "$@"
        ;;
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
        # Appended to the anchor rather than replacing it: the previous form
        # piped one rule into -f -, which discarded every other rule in the
        # anchor, including an active isolation.
        mkdir -p /etc/pf.anchors
        touch "${ANCHOR_FILE}"
        if ! grep -q "block drop out quick to ${TARGET_IP}\$" "${ANCHOR_FILE}"; then
            printf 'block drop out quick to %s\nblock drop in quick from %s\n' \
                "${TARGET_IP}" "${TARGET_IP}" >> "${ANCHOR_FILE}"
        fi
        pfctl -E 2>/dev/null || true
        pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"
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
        echo "  sudo ./pf_engine.sh sync <0|1> <hub_ip> [peer ...]"
        echo "                                        - Write the whole enforcement state (what the daemon calls)"
        echo "  ./pf_engine.sh test                   - Verify pfctl tool availability"
        exit 1
        ;;
esac
