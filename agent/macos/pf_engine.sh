#!/usr/bin/env bash
set -euo pipefail

ANCHOR_NAME="ominull_isolation"
ANCHOR_FILE="/etc/pf.anchors/ominull_isolation"
# Our own main ruleset. It includes Apple's verbatim and adds one anchor, so
# reloading it cannot lose a rule the system put there.
MAIN_FILE="/etc/ominull/pf.conf"
SYSTEM_PF_CONF="/etc/pf.conf"

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] Error: Administrator/root privileges (sudo) required."
        exit 1
    fi
}

# ensure_pf_enabled turns pf on only when it is off.
#
# `pfctl -E` was previously called on every write. Each call takes a reference
# on the enable count and returns a token, and nothing ever released them, so a
# host that had been quarantined and released a few hundred times carried a few
# hundred outstanding references and could not be disabled by anything short of
# a reboot.
ensure_pf_enabled() {
    if pfctl -s info 2>/dev/null | head -1 | grep -q "Enabled"; then
        return 0
    fi
    pfctl -E >/dev/null 2>&1 || true
}

# ensure_anchor_attached puts the anchor into the ruleset pf actually evaluates.
#
# This is what was missing. `pfctl -a <anchor> -f <file>` loads rules into a
# named anchor, and every one of them is dead unless the main ruleset names that
# anchor. macOS ships a /etc/pf.conf that references only Apple's own anchors,
# so every isolation this agent ever applied on a Mac loaded cleanly, reported
# success, and filtered nothing: the host stayed on the network while the hub
# and the console both showed it quarantined.
#
# The main ruleset is rebuilt rather than edited, and it starts by including
# Apple's file, so a system rule added at startup survives the reload and an OS
# update that rewrites /etc/pf.conf is picked up rather than clobbered.
ensure_anchor_attached() {
    if pfctl -s rules 2>/dev/null | grep -q "anchor \"${ANCHOR_NAME}\""; then
        return 0
    fi

    mkdir -p "$(dirname "${MAIN_FILE}")"
    cat > "${MAIN_FILE}" <<CONF
# Ominull main ruleset - generated, do not edit.
# Apple's ruleset is included rather than copied, so anything the system adds to
# it is still loaded and an OS update to that file is picked up here.
include "${SYSTEM_PF_CONF}"
anchor "${ANCHOR_NAME}"
load anchor "${ANCHOR_NAME}" from "${ANCHOR_FILE}"
CONF

    [[ -f "${ANCHOR_FILE}" ]] || : > "${ANCHOR_FILE}"
    pfctl -f "${MAIN_FILE}" 2>&1 | grep -v "^pfctl: Use of -f option" || true

    if ! pfctl -s rules 2>/dev/null | grep -q "anchor \"${ANCHOR_NAME}\""; then
        echo "[-] The ${ANCHOR_NAME} anchor is not in the loaded ruleset, so nothing written to it would be enforced. Refusing to report success." >&2
        return 1
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
        # `set skip on lo0` would be rejected here: options are only valid in a
        # main ruleset, not inside an anchor. An explicit quick pass is the
        # equivalent that an anchor can actually carry.
        echo "pass quick on lo0 all"
        # Quarantined peers are dropped whether or not this host is isolated.
        for peer in "$@"; do
            echo "block drop out quick to ${peer}"
            echo "block drop in quick from ${peer}"
        done
        if [[ "${isolated}" == "1" ]]; then
            # The hub pinhole, then the two services a cut-off host still needs
            # to keep an address and find the hub by name. Same shape as the
            # Linux chains and the Windows filters.
            if [[ -n "${hub_ip}" ]]; then
                echo "pass out quick proto tcp to ${hub_ip} keep state"
                echo "pass in quick proto tcp from ${hub_ip} keep state"
            fi
            echo "pass out quick proto udp to any port 67:68"
            # UDP only, deliberately. A quarantined host needs to be able to
            # re-resolve a hub named by DNS, and that is one query. Allowing
            # TCP/53 to any host would have handed anything on the box a
            # general-purpose outbound tunnel through the quarantine, which is
            # a much larger hole than the name lookup it was meant to permit.
            echo "pass out quick proto udp to any port 53"
            # Not quick: every pass above wins on first match, and this is the
            # last rule left to match, so it is the default deny.
            echo "block drop all"
        fi
    } > "${ANCHOR_FILE}"

    ensure_pf_enabled
    ensure_anchor_attached || return 1
    pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"

    # Loading without error is not evidence the rules are in the kernel. Read
    # them back: an anchor that came out empty when it should be enforcing is
    # exactly the failure this agent used to report as success.
    if [[ "${isolated}" == "1" ]] || [[ $# -gt 0 ]]; then
        if ! pfctl -a "${ANCHOR_NAME}" -s rules 2>/dev/null | grep -q "block drop"; then
            echo "[-] The ${ANCHOR_NAME} anchor loaded no blocking rules; this host is not enforcing what it was told to." >&2
            return 1
        fi
    fi
    return 0
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
        HUB_IP="${2:-}"
        if [[ -z "${HUB_IP}" ]]; then
            echo "[-] Error: isolate requires the hub's address. Isolating without a pinhole for the hub leaves no way to lift it." >&2
            exit 1
        fi
        echo "[*] Activating macOS BSD Packet Filter Isolation (Anchor: ${ANCHOR_NAME})..."
        write_state 1 "${HUB_IP}"
        echo "[+] SUCCESS: macOS Host is now QUARANTINED (Default-Deny active, Hub pinhole to ${HUB_IP})."
        ;;
    unisolate)
        ensure_root
        echo "[*] Lifting macOS Network Isolation..."
        # The anchor stays attached and is emptied. Detaching it would mean
        # reloading the main ruleset on every release, and an empty anchor
        # filters nothing.
        write_state 0 ""
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
        ensure_pf_enabled
        ensure_anchor_attached || exit 1
        pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"
        echo "[+] SUCCESS: Blocked ${TARGET_IP} via native Packet Filter."
        ;;
    status)
        # What is actually loaded, for an operator who needs to know whether a
        # host is really cut off rather than only recorded as cut off.
        pfctl -s info 2>/dev/null | head -1
        echo "-- main ruleset references --"
        pfctl -s rules 2>/dev/null | grep "anchor" || echo "(none)"
        echo "-- ${ANCHOR_NAME} --"
        pfctl -a "${ANCHOR_NAME}" -s rules 2>/dev/null || echo "(anchor not loaded)"
        ;;
    test)
        echo "[+] macOS Native Packet Filter Engine Ready."
        which pfctl
        ;;
    *)
        echo "Ominull macOS Zero-Friction BSD Packet Filter Engine"
        echo "Usage:"
        echo "  sudo ./pf_engine.sh sync <0|1> <hub_ip> [peer ...]"
        echo "                                        - Write the whole enforcement state (what the daemon calls)"
        echo "  sudo ./pf_engine.sh isolate <hub_ip>  - Default-deny quarantine with Hub pinhole"
        echo "  sudo ./pf_engine.sh unisolate         - Lift quarantine and restore traffic"
        echo "  sudo ./pf_engine.sh block-ip <ip>     - Block specific IP address"
        echo "  sudo ./pf_engine.sh status            - Show what is actually loaded in the kernel"
        echo "  ./pf_engine.sh test                   - Verify pfctl tool availability"
        exit 1
        ;;
esac
