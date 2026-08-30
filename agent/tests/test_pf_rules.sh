#!/usr/bin/env bash
# What the macOS agent writes into the pf anchor, checked without a Mac.
#
# write_state is the function that decides what an isolated host can still
# reach. A rule missing from its output strands the host; a rule too wide is a
# hole in every isolation. Neither shows up in a syntax check, so the generated
# ruleset is compared directly.
#
# The function is lifted out of the helper and given stubs for the three things
# that need a real Mac - pfctl and its two wrappers. Everything else is the
# shipped code.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE="${ROOT_DIR}/agent/macos/pf_engine.sh"
DAEMON="${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

ANCHOR_FILE="${WORK}/anchor"
ANCHOR_NAME="ominull_isolation"
ensure_pf_enabled() { :; }
ensure_anchor_attached() { return 0; }
pfctl() { echo "block drop all"; }   # the read-back check looks for a block rule
# write_state creates the anchor directory on the host it runs on. Here it must
# not touch /etc, so mkdir is redirected into the temporary tree.
mkdir() { command mkdir -p "${WORK}/etc-pf.anchors"; }

# shellcheck disable=SC1090
source /dev/stdin <<< "$(sed -n '/^write_state() {/,/^}$/p' "${ENGINE}")"
source /dev/stdin <<< "$(sed -n '/^json_baseline() {/,/^}$/p' "${DAEMON}")"

failures=0
check() {
    if [ "$1" = "yes" ]; then printf '  [+] %s\n' "$2"; else printf '  [-] %s\n' "$2"; failures=$((failures + 1)); fi
}
has()     { grep -qF -- "$2" "${ANCHOR_FILE}" && echo yes || echo no; }
hasnt()   { grep -qF -- "$2" "${ANCHOR_FILE}" && echo no  || echo yes; }

echo "[*] macOS pf ruleset - baseline isolation policy"

# 1. A hub with a policy: exactly those destinations, and nothing to "any".
write_state 1 "10.0.0.58" "" "" "dns|10.0.0.1|udp|53,dhcp|10.0.0.1|udp|67,ntp|10.0.0.2|udp|123" >/dev/null
check "$(has . 'pass out quick proto udp to 10.0.0.1 port 53')"  "the named resolver is permitted outbound"
check "$(has . 'pass in quick proto udp from 10.0.0.1 port 53')" "and inbound, because a reply is a new flow"
check "$(has . 'pass out quick proto udp to 10.0.0.1 port 67')"  "the named DHCP server is permitted"
check "$(has . 'pass out quick proto udp to 10.0.0.2 port 123')" "the named time server is permitted"
check "$(hasnt . 'to any port 53')"                              "DNS to any destination is gone"
check "$(hasnt . 'to any port 67:68')"                           "DHCP to any destination is gone"
check "$(has . 'block drop all')"                                "the default deny is still the last rule"

# 2. Precedence. DHCP has to sit above the peer blocks so a quarantine cannot
#    cost this host its lease; DNS has to sit below them so quarantining a rogue
#    resolver still wins. Both are position, not content.
write_state 1 "10.0.0.58" "" "10.0.0.9" "dns|10.0.0.1|udp|53,dhcp|10.0.0.1|udp|67" >/dev/null
dhcp_line=$(grep -n 'port 67' "${ANCHOR_FILE}" | head -1 | cut -d: -f1)
peer_line=$(grep -n 'block drop out quick to 10.0.0.9' "${ANCHOR_FILE}" | head -1 | cut -d: -f1)
dns_line=$(grep -n 'port 53' "${ANCHOR_FILE}" | head -1 | cut -d: -f1)
hub_line=$(grep -n 'pass out quick proto tcp to 10.0.0.58' "${ANCHOR_FILE}" | head -1 | cut -d: -f1)
check "$([ "${hub_line}" -lt "${peer_line}" ] && echo yes || echo no)"  "the hub pinhole is above the peer blocks"
check "$([ "${dhcp_line}" -lt "${peer_line}" ] && echo yes || echo no)" "DHCP is above the peer blocks"
check "$([ "${dns_line}" -gt "${peer_line}" ] && echo yes || echo no)"  "DNS is below the peer blocks"

# 3. An empty policy means hub and loopback only, and must not produce a
#    nonsense rule out of its own sentinel.
write_state 1 "10.0.0.58" "" "" "__none__" >/dev/null
check "$(hasnt . '__none__')"          "the empty-policy sentinel does not reach the ruleset"
check "$(hasnt . 'port 53')"           "an empty policy permits no DNS at all"
check "$(has . 'block drop all')"      "an empty policy still denies by default"
check "$(has . 'pass out quick proto tcp to 10.0.0.58')" "an empty policy still keeps the hub pinhole"

# 4. A hub too old to send a policy keeps the permits that were always there.
write_state 1 "10.0.0.58" "" "" "__legacy__" >/dev/null
check "$(has . 'pass out quick proto udp to any port 53')"    "a hub with no policy keeps the built-in DNS permit"
check "$(has . 'pass out quick proto udp to any port 67:68')" "a hub with no policy keeps the built-in DHCP permit"

# 5. Not isolated: the peer blocks still apply, the floor does not.
write_state 0 "10.0.0.58" "" "10.0.0.9" "dns|10.0.0.1|udp|53" >/dev/null
check "$(has . 'block drop out quick to 10.0.0.9')" "a mesh quarantine applies when the host is not isolated"
check "$(hasnt . 'block drop all')"                 "a host that is not isolated has no default deny"

# 6. The daemon's parser, against the wire form the hub actually sends.
echo "[*] macOS daemon - baseline parser"
absent=$(json_baseline '{"status":"ok","is_isolated":false}')
check "$([ "${absent}" = "__legacy__" ] && echo yes || echo no)" "a reply with no baseline key reports \"absent\""
empty=$(json_baseline '{"isolation_baseline":[],"is_isolated":false}')
check "$([ "${empty}" = "__none__" ] && echo yes || echo no)"    "an empty baseline is distinguishable from an absent one"
parsed=$(json_baseline '{"isolation_baseline":[{"service":"dns","destination":"10.0.0.1","protocol":"udp","port":53},{"service":"dhcp","destination":"10.0.0.1","protocol":"udp","port":67}]}')
check "$([ "${parsed}" = "dns|10.0.0.1|udp|53,dhcp|10.0.0.1|udp|67" ] && echo yes || echo no)" "two rules flatten to the helper's record form"
hostile=$(json_baseline '{"isolation_baseline":[{"service":"dns","destination":"10.0.0.1 keep state","protocol":"udp","port":53},{"service":"dns","destination":"10.0.0.2","protocol":"icmp","port":53},{"service":"dns","destination":"10.0.0.3","protocol":"udp","port":99999},{"service":"dns","destination":"10.0.0.9","protocol":"udp","port":53}]}')
check "$([ "${hostile}" = "dns|10.0.0.9|udp|53" ] && echo yes || echo no)" "entries that would become pf syntax are dropped"

if [ "${failures}" -ne 0 ]; then
    echo "[-] ${failures} check(s) failed"
    exit 1
fi
echo "[+] All macOS enforcement checks passed"
