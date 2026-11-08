#!/usr/bin/env bash
# Install a published agent release on the Linux machines, over root access that
# does not depend on the agent itself (Windows endpoints take it from the hub).
#
#   scripts/update-linux-agents.sh VERSION [--canary IDS] [--only IDS] [--reinstall]
#
#   --canary IDS   comma-separated endpoints to do first
#   --only IDS     just these endpoints
#   --reinstall    also machines already on VERSION
#
# Machines go one at a time and the first failure stops the run: that machine
# gets its previous binary back, also when it stayed up but the hub never heard
# from it, and the rest stay as they are. Rerun to pick up machines that were
# powered off; a stopped machine is never started for this. With --reinstall the
# version the hub reports was already right, so it only shows the machine is up.
#
# Routes: `aico machines` gives each guest's power state and id; a guest is
# reached through the Proxmox host (ssh_alias in the production config, pct or qm
# guest exec). An endpoint is the machine named by its id without "linux-", or
# what linux_agent_machines in the production config says ("@local" for this
# computer, "@proxmox" for the Proxmox host).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${OMINULL_PRODUCTION_CONFIG:-${ROOT_DIR}/scripts/st_extension/production.local.json}"
. "${ROOT_DIR}/scripts/lib/hub-admin-key.sh"
. "${ROOT_DIR}/scripts/hub-request.sh"

VERSION="${1:-}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { sed -n '2,10p' "$0" >&2; exit 2; }
shift
CANARY="" ONLY="" REINSTALL=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --canary) CANARY="${2:?--canary needs endpoint IDs}"; shift 2 ;;
        --only) ONLY="${2:?--only needs endpoint IDs}"; shift 2 ;;
        --reinstall) REINSTALL=1; shift ;;
        *) echo "[-] Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Only a package the release key every agent pins signed is offered to any machine.
DEB="${ROOT_DIR}/dist/ominull-agent_${VERSION}_amd64.deb"
for f in "${DEB}" "${DEB}.sig"; do
    [ -f "${f}" ] || { echo "[-] Missing ${f}; build and sign first." >&2; exit 1; }
done
PUB="$(sed -n '/define OMINULL_RELEASE_PUBKEY_PEM/,/END PUBLIC KEY/ s/^ *"\(.*\)\\n".*$/\1/p' "${ROOT_DIR}/agent/include/release_key.h")"
[ -n "${PUB}" ] || { echo "[-] No release key in agent/include/release_key.h." >&2; exit 1; }
openssl dgst -sha256 -verify <(printf '%s\n' "${PUB}") -signature "${DEB}.sig" "${DEB}" >/dev/null || {
    echo "[-] ${DEB} does not verify against the release key." >&2; exit 1; }
SHA="$(sha256sum "${DEB}" | cut -d' ' -f1)"

hub_admin_key_from_config
ALIAS="$(jq -r '.ssh_alias // empty' "${CFG}")"
[[ "${ALIAS}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "[-] ${CFG} needs ssh_alias." >&2; exit 1; }
HUB_URL="${OMINULL_HUB_URL}"
hub_url_safe "${HUB_URL}" || exit 1
api_get() {
    exec 3< <(hub_curl_config "${OMINULL_ADMIN_KEY}" "${HUB_URL}")
    curl -fsS --connect-timeout 5 --max-time 20 -K /dev/fd/3 "${HUB_URL}$1"
}

if api_get /api/v1/agents/update-status | jq -e --arg v "${VERSION}" '(.retired_versions // []) | index($v) != null' >/dev/null; then
    echo "[-] v${VERSION} was retired; release a newer version instead." >&2; exit 1
fi
MACHINES="$(aico machines --json)"
ENDPOINTS="$(api_get /api/v1/endpoints | jq -c .)"
# Linux endpoints: canaries first, in the order named, then the rest by id.
list_json() { jq -cn --arg s "$1" '$s | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))'; }
# A mistyped name would otherwise drop out quietly and the fleet would go first.
unknown_ids() { # list, endpoints filter
    printf '%s' "${ENDPOINTS}" | jq -r --argjson ids "$(list_json "$1")" "[$2 | .id] as \$known | \$ids - \$known | join(\", \")"
}
LINUX_EPS='.[] | select(.status != "retired" and ((.os // "") | ascii_downcase | contains("linux")))'
bad="$(unknown_ids "${CANARY}" '.[]')"
[ -z "${bad}" ] || { echo "[-] Unknown canary: ${bad}." >&2; exit 1; }
bad="$(unknown_ids "${ONLY}" "${LINUX_EPS}")"
[ -z "${bad}" ] || { echo "[-] Not a Linux endpoint: ${bad}." >&2; exit 1; }
TARGETS="$(printf '%s' "${ENDPOINTS}" | jq -r --argjson only "$(list_json "${ONLY}")" --argjson canary "$(list_json "${CANARY}")" '
    [.[] | select(.status != "retired" and ((.os // "") | ascii_downcase | contains("linux")))
         | select(($only | length) == 0 or (.id as $i | $only | index($i) != null))] as $eps |
    ([$canary[] as $c | $eps[] | select(.id == $c)] + ($eps | sort_by(.id) | map(select(.id as $i | $canary | index($i) == null))))
    | .[].id')"

route_of() { # endpoint id -> "@local", "@proxmox", "ct VMID", "vm VMID", "off" or "none"
    # Only a stopped guest counts as off: a state nobody can read is not "off".
    local id="$1" name
    name="$(jq -r --arg id "${id}" '.linux_agent_machines[$id] // empty' "${CFG}")"
    [ -n "${name}" ] || name="${id#linux-}"
    case "${name}" in @local|@proxmox) echo "${name}"; return ;; esac
    printf '%s' "${MACHINES}" | jq -r --arg name "${name}" '
        ([(.machines? // .)[] | select(.name == $name) | .guest] | first) as $g |
        if $g == null or $g.vmid == null then "none"
        elif $g.state == "stopped" then "off"
        elif $g.state == "running" then "\($g.kind) \($g.vmid)"
        else "none" end'
}

run_installer() { # "route" installer-args...: runs it as root there, printing its output
    local installer="${ROOT_DIR}/scripts/lib/install-agent-deb.sh" route out
    read -r -a route <<<"$1"; shift
    local remote="sh -s -- $*"
    case "${route[0]}" in
        @local) timeout 600 sudo -n sh -s -- "$@" <"${installer}" ;;
        @proxmox) timeout 600 ssh -o BatchMode=yes -- "${ALIAS}" "${remote}" <"${installer}" ;;
        ct) timeout 600 ssh -o BatchMode=yes -- "${ALIAS}" "pct exec ${route[1]} -- ${remote}" <"${installer}" ;;
        vm)
            out="$(timeout 600 ssh -o BatchMode=yes -- "${ALIAS}" "qm guest exec ${route[1]} --pass-stdin 1 --timeout 400 -- ${remote}" <"${installer}")" || return 1
            printf '%s' "${out}" | jq -r '(."out-data" // "") + (."err-data" // "")'
            if [ "$(printf '%s' "${out}" | jq -r '.exited // 0')" != 1 ]; then
                echo "[-] VM ${route[1]} did not finish in time; it may still be installing." >&2
                return 1
            fi
            [ "$(printf '%s' "${out}" | jq -r '.exitcode // 1')" = 0 ]
            ;;
        *) return 1 ;;
    esac
}

# The hub hears the new version from the machine itself, or the install failed.
reports_version() {
    local id="$1" _
    for _ in $(seq 1 24); do
        if api_get /api/v1/endpoints 2>/dev/null | jq -e --arg id "${id}" --arg v "${VERSION}" \
            '.[] | select(.id == $id and .driver_version == $v)' >/dev/null; then
            return 0
        fi
        sleep 5
    done
    return 1
}

done_ids=() current=() pending=() noroute=()
for id in ${TARGETS}; do
    ep="$(printf '%s' "${ENDPOINTS}" | jq -c --arg id "${id}" '.[] | select(.id == $id)')"
    if [ "${REINSTALL}" -eq 0 ] && [ "$(printf '%s' "${ep}" | jq -r .driver_version)" = "${VERSION}" ]; then
        current+=("${id}"); continue
    fi
    route="$(route_of "${id}")"
    case "${route}" in
        off) pending+=("${id}"); continue ;;
        none)
            # Off the hub and no machine to reach it on: gone or asleep, not a failure.
            if [ "$(printf '%s' "${ep}" | jq -r .status)" = online ]; then noroute+=("${id}"); else pending+=("${id}"); fi
            continue ;;
    esac
    echo "[*] ${id}: installing v${VERSION} (${route})."
    if ! run_installer "${route}" "${VERSION}" "${SHA}"; then
        echo "[-] ${id} did not take v${VERSION}; stopping. Done so far: ${done_ids[*]:-none}." >&2
        exit 1
    fi
    if ! reports_version "${id}"; then
        echo "[-] ${id} runs v${VERSION} but the hub never heard it; restoring its previous binary and stopping. Done so far: ${done_ids[*]:-none}." >&2
        run_installer "${route}" --restore || echo "[-] ${id}: restore failed; it still runs v${VERSION}." >&2
        exit 1
    fi
    echo "[+] ${id} runs v${VERSION}."
    done_ids+=("${id}")
done

echo "[+] Updated: ${done_ids[*]:-none}. Already current: ${current[*]:-none}."
[ "${#pending[@]}" -eq 0 ] || echo "[*] Off or not reachable, rerun after they start: ${pending[*]}."
if [ "${#noroute[@]}" -gt 0 ]; then
    echo "[-] No route (set linux_agent_machines in ${CFG}): ${noroute[*]}." >&2
    exit 1
fi
