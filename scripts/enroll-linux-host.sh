#!/bin/bash
# enroll-linux-host.sh --role ROLE [--location ID] [--monitor-only REASON] -- RUN...
#
# Enrol one Linux host: the hub renders a one-use installer with the role baked
# in, RUN executes it as root on the host (the script arrives on stdin, so the
# enrollment code never sits on a command line), and with --monitor-only the
# new endpoint is made monitor-only, so the hub refuses to isolate it.
#
# RUN is a command prefix that runs its arguments as root on the host, e.g.
#   ssh -o BatchMode=yes root@pve-host pct exec 190 --     (a Proxmox container)
#   ssh -o BatchMode=yes agent-work sudo -n                  (a VM with sudo)
#
# Needs OMINULL_HUB_URL (https://HUB:9443) and OMINULL_ADMIN_KEY.
set -euo pipefail
ROLE="" LOCATION="loc-home" MONITOR=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --role) ROLE="${2:?--role needs a value}"; shift 2 ;;
        --location) LOCATION="${2:?--location needs a value}"; shift 2 ;;
        --monitor-only) MONITOR="${2:?--monitor-only needs a reason}"; shift 2 ;;
        --) shift; break ;;
        *) sed -n '2,13p' "$0" >&2; exit 2 ;;
    esac
done
[ -n "${ROLE}" ] && [ "$#" -gt 0 ] || { sed -n '2,13p' "$0" >&2; exit 2; }
RUN=("$@")
HUB_URL="${OMINULL_HUB_URL:?export OMINULL_HUB_URL, e.g. https://10.0.0.58:9443}"
: "${OMINULL_ADMIN_KEY:?export OMINULL_ADMIN_KEY with the hub admin key}"
# shellcheck source=scripts/hub-request.sh
. "$(dirname "${BASH_SOURCE[0]}")/hub-request.sh"

host="$("${RUN[@]}" hostname | tr -d '\r\n')"
[ -n "${host}" ] || { echo "[-] The host did not answer." >&2; exit 1; }
endpoint="linux-${host,,}"
echo "[*] Enrolling ${host} as ${endpoint} (role ${ROLE})."
# The agent package depends on iptables, which minimal images leave out.
"${RUN[@]}" sh -c 'command -v iptables >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -y -q install iptables >/dev/null; }'

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
body="$(jq -nc --arg role "${ROLE}" --arg loc "${LOCATION}" \
    '{platform: "linux", kind: "invitation", tenant_id: "default", location_id: $loc, role: $role}')"
hub_post "${HUB_URL}" OMINULL_ADMIN_KEY /api/v1/enrolment/script "${body}" > "${tmp}/answer.json"
jq -r .script "${tmp}/answer.json" > "${tmp}/install.sh"
"${RUN[@]}" bash -s < "${tmp}/install.sh"

if [ -n "${MONITOR}" ]; then
    body="$(jq -nc --arg id "${endpoint}" --arg why "${MONITOR}" '{endpoint_id: $id, reason: $why}')"
    hub_post "${HUB_URL}" OMINULL_ADMIN_KEY /api/v1/endpoints/monitor-only "${body}" | jq -c .
fi
echo "[+] ${endpoint} enrolled."
