#!/usr/bin/env bash
# Run the Linux security baseline on machines that take no hub-signed scripts,
# over root access that does not depend on the agent, and record each result on
# the hub as an ordinary run. Daily, from the Aico routine ominull-posture-collect.
#
#   scripts/posture-collect.sh [--only IDS]
#
# It checks only: what runs is the committed package, and only when that is the
# library's current version; the hub also refuses anything else. A machine that is off is left off and reported as skipped; its last
# answer stays and goes stale. The security switch for a machine is honored, and
# the package's own parameters come from its settings on the hub.
#
# Routes are the ones scripts/update-linux-agents.sh uses (production config,
# linux_agent_machines). Exit 0 when every running machine answered and recorded;
# an online machine with no route is a failure.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${OMINULL_PRODUCTION_CONFIG:-${ROOT_DIR}/scripts/st_extension/production.local.json}"
. "${ROOT_DIR}/scripts/lib/hub-admin-key.sh"
. "${ROOT_DIR}/scripts/hub-request.sh"

PACKAGE=linux-security-baseline
SOURCE_PATH=packages/linux/security-baseline.sh
TIMEOUT=300
RESULT_MAX=100000

ONLY=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --only) ONLY="${2:?--only needs endpoint IDs}"; shift 2 ;;
        *) sed -n '2,12p' "$0" >&2; exit 2 ;;
    esac
done

hub_admin_key_from_config >/dev/null
ALIAS="$(jq -r '.ssh_alias // empty' "${CFG}")"
[[ "${ALIAS}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "[-] ${CFG} needs ssh_alias." >&2; exit 1; }
HUB_URL="${OMINULL_HUB_URL}"
hub_url_safe "${HUB_URL}" || exit 1
api_get() {
    exec 3< <(hub_curl_config "${OMINULL_ADMIN_KEY}" "${HUB_URL}")
    curl -fsS --connect-timeout 5 --max-time 20 -K /dev/fd/3 "${HUB_URL}$1"
}

route_of() { # endpoint id -> "@local", "@proxmox", "ct VMID", "vm VMID", "off" or "none"
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

# run_package "route" env-words...: the package's output on stdout; RUN_EXIT is its exit code.
RUN_EXIT=0
run_package() {
    local route out
    read -r -a route <<<"$1"; shift
    local remote="env $* sh -s"
    RUN_EXIT=0
    case "${route[0]}" in
        @local) timeout "${TIMEOUT}" sudo -n env "$@" sh -s <"${SOURCE}" 2>/dev/null || RUN_EXIT=$? ;;
        @proxmox) timeout "${TIMEOUT}" ssh -o BatchMode=yes -- "${ALIAS}" "${remote}" <"${SOURCE}" 2>/dev/null || RUN_EXIT=$? ;;
        ct) timeout "${TIMEOUT}" ssh -o BatchMode=yes -- "${ALIAS}" "pct exec ${route[1]} -- ${remote}" <"${SOURCE}" 2>/dev/null || RUN_EXIT=$? ;;
        vm)
            out="$(timeout "${TIMEOUT}" ssh -o BatchMode=yes -- "${ALIAS}" "qm guest exec ${route[1]} --pass-stdin 1 --timeout 120 -- ${remote}" <"${SOURCE}" 2>/dev/null)" || { RUN_EXIT=$?; return 0; }
            printf '%s' "${out}" | jq -r '."out-data" // ""'
            RUN_EXIT="$(printf '%s' "${out}" | jq -r '.exitcode // 1')"
            ;;
        *) RUN_EXIT=1 ;;
    esac
}

# Never run the working tree as root: another change may be in progress there.
SOURCE="$(mktemp)"
trap 'rm -f "${SOURCE}"' EXIT
git -C "${ROOT_DIR}" show "HEAD:${SOURCE_PATH}" >"${SOURCE}"
SHA="$(sha256sum "${SOURCE}" | cut -d' ' -f1)"
LIBRARY_SHA="$(api_get /api/v1/maintenance/settings | jq -r --arg p "${PACKAGE}" '[.packages[]? | select(.name == $p) | .digest_sha256] | first // empty')"
[ -n "${LIBRARY_SHA}" ] || { echo "[-] The hub has no ${PACKAGE}; deploy the hub first." >&2; exit 1; }
if [ "${LIBRARY_SHA}" != "${SHA}" ]; then
    echo "[-] The committed ${PACKAGE} is not the hub's current version; deploy the hub first. Nothing ran." >&2
    exit 1
fi

MACHINES="$(aico machines --json)"
ENDPOINTS="$(api_get /api/v1/endpoints)"
LINUX='.[] | select(.status != "retired" and ((.os // "") | ascii_downcase | contains("linux")))'
if [ -n "${ONLY}" ]; then
    bad="$(printf '%s' "${ENDPOINTS}" | jq -r --arg only "${ONLY}" "[${LINUX} | .id] as \$known | (\$only | split(\",\")) - \$known | join(\" \")")"
    [ -z "${bad}" ] || { echo "[-] Not a Linux endpoint: ${bad}." >&2; exit 1; }
fi
TARGETS="$(printf '%s' "${ENDPOINTS}" | jq -r --arg only "${ONLY}" "
    (\$only | split(\",\") | map(select(length > 0))) as \$ids |
    ${LINUX} | select((\$ids | length) == 0 or (.id as \$i | \$ids | index(\$i) != null)) | .id")"

recorded=() off=() switched=() failed=()
for id in ${TARGETS}; do
    route="$(route_of "${id}")"
    case "${route}" in
        off) off+=("${id}"); continue ;;
        none)
            if [ "$(printf '%s' "${ENDPOINTS}" | jq -r --arg id "${id}" '.[] | select(.id == $id) | .status')" = online ]; then
                echo "[-] ${id}: online, but no route (set linux_agent_machines in the production config)." >&2
                failed+=("${id}")
            else
                off+=("${id}")
            fi
            continue ;;
    esac
    setting="$(api_get "/api/v1/maintenance/settings?endpoint_id=${id}" | jq -c --arg p "${PACKAGE}" '[.packages[]? | select(.name == $p)] | first // empty')" || setting=""
    if [ -z "${setting}" ]; then
        echo "[-] ${id}: the hub has no ${PACKAGE}; sync the library first." >&2
        failed+=("${id}"); continue
    fi
    if [ "$(printf '%s' "${setting}" | jq -r '.effective.category_enabled')" = false ]; then
        switched+=("${id}"); continue
    fi
    envs=(OMINULL_PARAM_MODE=audit)
    while IFS=$'\t' read -r k v; do
        [ -n "${k}" ] || continue
        # This run is an audit whatever is saved; it is recorded as one below.
        [ "${k}" != mode ] || continue
        if ! [[ "${k}" =~ ^[a-z0-9_]+$ && "${v}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
            echo "[-] ${id}: ignoring a parameter with unexpected characters." >&2; continue
        fi
        envs+=("OMINULL_PARAM_${k^^}=${v}")
    done < <(printf '%s' "${setting}" | jq -r '.effective.params // {} | to_entries[] | "\(.key)\t\(.value)"')
    out="$(run_package "${route}" "${envs[@]}"; echo "exit:${RUN_EXIT}")"
    code="${out##*exit:}"
    out="${out%exit:*}"
    line="$(printf '%s\n' "${out}" | grep -E '^\{' | tail -n 1 || true)"
    if [ -z "${line}" ] || ! printf '%s' "${line}" | jq -e '.v == 1' >/dev/null 2>&1; then
        echo "[-] ${id}: no result (exit ${code})." >&2
        failed+=("${id}"); continue
    fi
    if [ "${#line}" -gt "${RESULT_MAX}" ]; then
        echo "[-] ${id}: the result is too large to record." >&2
        failed+=("${id}"); continue
    fi
    body="$(jq -cn --arg e "${id}" --arg p "${PACKAGE}" --arg s "${SHA}" --arg o "${line}" --argjson c "${code}" \
        '{endpoint_id:$e, package:$p, sha256:$s, mode:"audit", stdout:$o, exit_code:$c}')"
    if answer="$(hub_post "${HUB_URL}" OMINULL_ADMIN_KEY /api/v1/maintenance/host-run "${body}")"; then
        printf '[+] %s: %s\n' "${id}" "$(printf '%s' "${answer}" | jq -r '"\(.state): \(.pass // 0) pass, \(.fail // 0) fail"')"
        recorded+=("${id}")
    else
        echo "[-] ${id}: the hub refused the result: ${answer}" >&2
        failed+=("${id}")
    fi
done

echo "${#recorded[@]} recorded, ${#off[@]} off, ${#switched[@]} switched off, ${#failed[@]} failed."
[ "${#off[@]}" -eq 0 ] || echo "Off: ${off[*]}."
[ "${#failed[@]}" -eq 0 ] || { echo "Failed: ${failed[*]}." >&2; exit 1; }
