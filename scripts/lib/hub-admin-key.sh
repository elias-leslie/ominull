#!/usr/bin/env bash
# hub_admin_key_from_config: fill OMINULL_HUB_URL and OMINULL_ADMIN_KEY when unset.
#
# The target comes from the owner's scripts/st_extension/production.local.json
# (OMINULL_PRODUCTION_CONFIG overrides the path): hub_base_url, and ssh_alias +
# lxc_id for the Proxmox host. The key is the first line of /etc/ominull/admin.key
# in that container, read over the alias's root SSH into the environment only;
# it is never printed or written to disk.
#
# Run directly (scripts/lib/hub-admin-key.sh --check) it fetches the key and asks
# the hub which release it serves, printing only that version.

hub_admin_key_from_config() {
    local root cfg alias lxc url key
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    cfg="${OMINULL_PRODUCTION_CONFIG:-${root}/scripts/st_extension/production.local.json}"
    if [ -z "${OMINULL_ADMIN_KEY:-}" ] || [ -z "${OMINULL_HUB_URL:-}" ]; then
        [ -f "${cfg}" ] || { echo "[-] ${cfg} is missing; set OMINULL_HUB_URL and OMINULL_ADMIN_KEY." >&2; return 1; }
        url="$(jq -r '.hub_base_url // empty' "${cfg}")"
        alias="$(jq -r '.ssh_alias // empty' "${cfg}")"
        lxc="$(jq -r '.lxc_id // empty' "${cfg}")"
    fi
    if [ -z "${OMINULL_HUB_URL:-}" ]; then
        [ -n "${url}" ] || { echo "[-] ${cfg} has no hub_base_url." >&2; return 1; }
        export OMINULL_HUB_URL="${url}"
    fi
    if [ -z "${OMINULL_ADMIN_KEY:-}" ]; then
        [[ "${alias}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ && "${lxc}" =~ ^[1-9][0-9]*$ ]] || {
            echo "[-] ${cfg} needs ssh_alias and lxc_id to read the admin key." >&2; return 1; }
        key="$(ssh -o BatchMode=yes -o ConnectTimeout=5 -- "${alias}" "pct exec ${lxc} -- head -n1 /etc/ominull/admin.key")" &&
            [ -n "${key}" ] || { echo "[-] Could not read the admin key from CT ${lxc} through ${alias}." >&2; return 1; }
        export OMINULL_ADMIN_KEY="${key}"
        echo "[*] Admin key read from CT ${lxc} through ${alias}."
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    [ "${1:-}" = --check ] || { echo "usage: hub-admin-key.sh --check" >&2; exit 2; }
    . "$(dirname "${BASH_SOURCE[0]}")/../hub-request.sh"
    hub_admin_key_from_config
    hub_url_safe "${OMINULL_HUB_URL}"
    exec 3< <(hub_curl_config "${OMINULL_ADMIN_KEY}" "${OMINULL_HUB_URL}")
    curl -fsS --connect-timeout 5 --max-time 20 -K /dev/fd/3 "${OMINULL_HUB_URL}/api/v1/agents/update-status" | jq -r '"hub serves release " + .latest_version'
fi
