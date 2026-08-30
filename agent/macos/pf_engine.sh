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
#
# Rule order is the other half of it. Every pass and block here is `quick`, so
# the first match wins and the order in this file *is* the precedence. The
# ladder is the same one the Windows agent expresses as filter weights and the
# Linux agent as chain order:
#
#   hub pinhole  >  loopback  >  DHCP  >  peer quarantine  >  DNS  >  allow list  >  deny
#
# The peer blocks used to be written above the hub pinhole, so quarantining the
# controller - or anything the isolation floor depends on - took away the only
# path by which the host could be released. They sit below it now, and the hub
# pass is written whenever there is anything to enforce rather than only while
# isolated.
# baseline_spec is the resolved baseline policy, flattened by the daemon into
# records of service|destination|protocol|port separated by commas. The pipe is
# the field separator because an IPv6 destination is full of colons, and bash 3.2
# is the reason it is a string at all rather than an array. The literal
# "__legacy__" means the hub sent no policy - a hub too old to have one - and the
# built-in permits are kept rather than tightening the floor under a fleet whose
# hub never asked for it.
write_state() {
    local isolated="$1" hub_ip="$2" allow_csv="$3" peers_csv="$4" baseline_spec="${5:-__legacy__}"
    local peer addr peer_count rec b_service b_dest b_proto b_port
    # Deliberately not bash arrays. macOS ships bash 3.2, where ${#arr[@]} and
    # "${arr[@]}" on an *empty* array are treated as unbound under `set -u` -
    # so the array form worked for every host that had a peer quarantined and
    # died on the one case that matters most, the empty list that means "lift
    # everything". The anchor was left half-written and this helper exited
    # non-zero on every beat. These values are address literals validated by the
    # hub and again by the daemon, so plain word splitting is safe.
    peer_count=0
    if [ -n "${peers_csv}" ]; then
        peer_count=$(printf '%s' "${peers_csv}" | tr ',' '\n' | grep -c .)
    fi

    mkdir -p /etc/pf.anchors
    {
        echo "# Ominull enforcement anchor - generated, do not edit"

        # 1. The hub, ahead of every block below it. Written whenever anything
        #    is being enforced: a peer block that named the controller is not an
        #    operation with a way back.
        if [[ -n "${hub_ip}" ]] && { [[ "${isolated}" == "1" ]] || [ "${peer_count}" -gt 0 ]; }; then
            echo "pass out quick proto tcp to ${hub_ip} keep state"
            echo "pass in quick proto tcp from ${hub_ip} keep state"
        fi

        # 2. Loopback. `set skip on lo0` would be rejected here: options are
        #    only valid in a main ruleset, not inside an anchor. An explicit
        #    quick pass is the equivalent that an anchor can actually carry.
        echo "pass quick on lo0 all"

        # 3. DHCP, above the peer blocks: a lease that expires because a
        #    quarantine named the DHCP server costs this host the address the
        #    hub reaches it on. Both directions - the request goes out and the
        #    reply comes back in, and the reply is not always part of the state
        #    the request created.
        #
        #    Which servers is the baseline policy's business, not this helper's.
        #    Only the DHCP records go here; the rest of the baseline sits below
        #    the peer blocks with DNS, so quarantining a rogue resolver still
        #    wins while quarantining something cannot cost this host its lease.
        if [[ "${isolated}" == "1" ]]; then
            if [[ "${baseline_spec}" == "__legacy__" ]]; then
                echo "pass out quick proto udp to any port 67:68"
                echo "pass in quick proto udp from any port 67:68"
                echo "pass out quick proto udp to any port 546:547"
                echo "pass in quick proto udp from any port 546:547"
            else
                for rec in ${baseline_spec//,/ }; do
                    # Four pipe-separated fields or it is not a rule. This also
                    # absorbs the "policy exists and is empty" sentinel, which
                    # must produce no rules rather than one nonsense rule.
                    [[ "${rec}" == *"|"*"|"*"|"* ]] || continue
                    b_service="${rec%%|*}"
                    [[ "${b_service}" == "dhcp" ]] || continue
                    rec="${rec#*|}"; b_dest="${rec%%|*}"
                    rec="${rec#*|}"; b_proto="${rec%%|*}"
                    b_port="${rec#*|}"
                    echo "pass out quick proto ${b_proto} to ${b_dest} port ${b_port}"
                    echo "pass in quick proto ${b_proto} from ${b_dest} port ${b_port}"
                done
            fi
        fi

        # 4. Mesh quarantine. Applies whether or not this host is isolated.
        for peer in ${peers_csv//,/ }; do
            [[ -n "${peer}" ]] || continue
            echo "block drop out quick to ${peer}"
            echo "block drop in quick from ${peer}"
        done

        if [[ "${isolated}" == "1" ]]; then
            # 5. The rest of the baseline - DNS, NTP, whatever else the policy
            #    names - below the peer block on purpose: quarantining a rogue
            #    resolver has to beat the rule that lets this host resolve
            #    names.
            if [[ "${baseline_spec}" == "__legacy__" ]]; then
                # No policy from this hub. UDP only, deliberately - allowing
                # TCP/53 to any host would hand anything on the box a
                # general-purpose outbound tunnel through the quarantine, which
                # is a much larger hole than the name lookup it was meant to
                # permit.
                echo "pass out quick proto udp to any port 53"
                echo "pass in quick proto udp from any port 53"
            else
                for rec in ${baseline_spec//,/ }; do
                    [[ "${rec}" == *"|"*"|"*"|"* ]] || continue
                    b_service="${rec%%|*}"
                    [[ "${b_service}" != "dhcp" ]] || continue
                    rec="${rec#*|}"; b_dest="${rec%%|*}"
                    rec="${rec#*|}"; b_proto="${rec%%|*}"
                    b_port="${rec#*|}"
                    echo "pass out quick proto ${b_proto} to ${b_dest} port ${b_port}"
                    echo "pass in quick proto ${b_proto} from ${b_dest} port ${b_port}"
                done
            fi

            # 6. The hub's allow list - a scoped trust rule, below a peer block
            #    so a quarantine still wins over standing trust that named the
            #    same address. This was parsed by the hub and delivered to every
            #    agent, and macOS was the platform that silently ignored it.
            for addr in ${allow_csv//,/ }; do
                [[ -n "${addr}" ]] || continue
                echo "pass out quick to ${addr}"
                echo "pass in quick from ${addr}"
            done

            # 7. Not quick: every pass above wins on first match, and this is
            #    the last rule left to match, so it is the default deny.
            echo "block drop all"
        fi
    } > "${ANCHOR_FILE}"

    ensure_pf_enabled
    ensure_anchor_attached || return 1
    pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_FILE}"

    # Loading without error is not evidence the rules are in the kernel. Read
    # them back: an anchor that came out empty when it should be enforcing is
    # exactly the failure this agent used to report as success.
    if [[ "${isolated}" == "1" ]] || [ "${peer_count}" -gt 0 ]; then
        if ! pfctl -a "${ANCHOR_NAME}" -s rules 2>/dev/null | grep -q "block drop"; then
            echo "[-] The ${ANCHOR_NAME} anchor loaded no blocking rules; this host is not enforcing what it was told to." >&2
            return 1
        fi
    fi

    return 0
}

case "${1:-help}" in
    apply)
        # apply --isolated <0|1> --hub <ip> [--allow a,b] [--peers x,y]
        #
        # A new verb rather than another positional on `sync`, because the
        # daemon's skew check looks for the verb: an installed helper too old to
        # carry an allow list does not have `apply)` in it, so the daemon
        # notices and repairs itself from the signed archive instead of quietly
        # dropping the list.
        ensure_root
        ISOLATED=0; HUB_IP=""; ALLOW=""; PEERS=""; BASELINE="__legacy__"
        shift
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --isolated) ISOLATED="${2:-0}"; shift 2 ;;
                --hub)      HUB_IP="${2:-}";    shift 2 ;;
                --allow)    ALLOW="${2:-}";     shift 2 ;;
                --peers)    PEERS="${2:-}";     shift 2 ;;
                --baseline) BASELINE="${2:-__legacy__}"; shift 2 ;;
                *) echo "[-] Unknown option: $1" >&2; exit 1 ;;
            esac
        done
        write_state "${ISOLATED}" "${HUB_IP}" "${ALLOW}" "${PEERS}" "${BASELINE}"
        ;;
    sync)
        # sync <0|1 isolated> <hub_ip> [peer ...]
        #
        # Kept so a daemon older than this helper still works across an upgrade
        # where the two move independently. It carries no allow list; `apply` is
        # what the current daemon calls.
        ensure_root
        ISOLATED="${2:-0}"
        HUB_IP="${3:-}"
        shift 3 2>/dev/null || shift $#
        PEERS=$(printf '%s,' "$@"); PEERS="${PEERS%,}"
        write_state "${ISOLATED}" "${HUB_IP}" "" "${PEERS}"
        ;;
    isolate)
        ensure_root
        HUB_IP="${2:-}"
        if [[ -z "${HUB_IP}" ]]; then
            echo "[-] Error: isolate requires the hub's address. Isolating without a pinhole for the hub leaves no way to lift it." >&2
            exit 1
        fi
        echo "[*] Activating macOS BSD Packet Filter Isolation (Anchor: ${ANCHOR_NAME})..."
        write_state 1 "${HUB_IP}" "" ""
        echo "[+] SUCCESS: macOS Host is now QUARANTINED (Default-Deny active, Hub pinhole to ${HUB_IP})."
        ;;
    unisolate)
        ensure_root
        echo "[*] Lifting macOS Network Isolation..."
        # The anchor stays attached and is emptied. Detaching it would mean
        # reloading the main ruleset on every release, and an empty anchor
        # filters nothing.
        write_state 0 "" "" ""
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
        echo "  sudo ./pf_engine.sh apply --isolated <0|1> --hub <ip> [--allow a,b] [--peers x,y]"
        echo "                                        - Write the whole enforcement state (what the daemon calls)"
        echo "  sudo ./pf_engine.sh sync <0|1> <hub_ip> [peer ...]"
        echo "                                        - The same, without an allow list (kept for an older daemon)"
        echo "  sudo ./pf_engine.sh isolate <hub_ip>  - Default-deny quarantine with Hub pinhole"
        echo "  sudo ./pf_engine.sh unisolate         - Lift quarantine and restore traffic"
        echo "  sudo ./pf_engine.sh block-ip <ip>     - Block specific IP address"
        echo "  sudo ./pf_engine.sh status            - Show what is actually loaded in the kernel"
        echo "  ./pf_engine.sh test                   - Verify pfctl tool availability"
        exit 1
        ;;
esac
