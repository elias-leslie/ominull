#!/usr/bin/env bash
# Install the signed hub package through Proxmox's hub-install key (release.sh's deploy step).
#
#   scripts/deploy-hub.sh          send dist/ominull-hub_VERSION_amd64.deb, .sig and .release.sig
#   scripts/deploy-hub.sh --check  ask the key which hub is installed (release.sh runs this before
#                                  building, so a missing key never wastes a signing tap)
#
# The key (alias OMINULL_HUB_INSTALL_ALIAS, default ominull-hub-install; root installs it with
# scripts/pve/install.sh) runs only scripts/pve/ominull-hub-install on Proxmox. That verifies both
# signatures against the release key it pins, refuses an older version, runs dpkg -i in CT 150 and
# waits for the hub to listen. The package's postinst publishes the agent packages bundled in it.
# This side then checks over TLS that the console serves this version and the API answers.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALIAS="${OMINULL_HUB_INSTALL_ALIAS:-ominull-hub-install}"
VERSION="${OMINULL_RELEASE_VERSION:-$("${ROOT_DIR}/scripts/version.sh" show)}"
DIST_DIR="${ROOT_DIR}/dist"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)

: "${OMINULL_HUB_URL:?set OMINULL_HUB_URL (https://HUB:9443) for the post-install check}"
: "${OMINULL_ADMIN_KEY:?set OMINULL_ADMIN_KEY for the post-install check}"
# shellcheck source=owner-approval.sh
. "${ROOT_DIR}/scripts/owner-approval.sh"
hub_url_safe "${OMINULL_HUB_URL}" || exit 1
HUB_CA="${OMINULL_HUB_CA:-/etc/ominull/ca.crt}"
[ -f "${HUB_CA}" ] || { echo "[-] Hub CA ${HUB_CA} is missing; set OMINULL_HUB_CA." >&2; exit 1; }

if [ "${1:-}" = --check ]; then
    if ! installed="$(ssh "${ssh_opts[@]}" -- "${ALIAS}" version)"; then
        echo "[-] The hub-install key (${ALIAS}) does not answer; root installs it with scripts/pve/install.sh." >&2
        echo "    Until then, release with OMINULL_DEPLOY_CMD=scripts/deploy_remote.sh (the owner's root alias)." >&2
        exit 1
    fi
    echo "[*] Hub install key answers: ${installed}"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: deploy-hub.sh [--check]" >&2; exit 2; }

deb="ominull-hub_${VERSION}_amd64.deb"
for file in "${deb}" "${deb}.sig" "${deb}.release.sig"; do
    [ -f "${DIST_DIR}/${file}" ] || { echo "[-] Missing dist/${file}; build and sign first." >&2; exit 1; }
done

echo "[*] Installing hub package v${VERSION} through ${ALIAS}."
tar -C "${DIST_DIR}" --owner=0 --group=0 --numeric-owner -cf - "${deb}" "${deb}.sig" "${deb}.release.sig" |
    ssh "${ssh_opts[@]}" -- "${ALIAS}" "install ${VERSION}"

hdr() {
    printf 'header = "X-API-Key: %s"\n' "${OMINULL_ADMIN_KEY}"
}
deadline=$((SECONDS + 60))
while :; do
    # The console page needs the key too; each curl reads its own descriptor.
    exec 3< <(hdr) 4< <(hdr)
    if curl -fsS --max-time 5 --cacert "${HUB_CA}" -K /dev/fd/4 "${OMINULL_HUB_URL}/" 2>/dev/null | grep -qF "app.css?v=${VERSION}\"" &&
        status="$(curl -fsS --max-time 5 --cacert "${HUB_CA}" -K /dev/fd/3 "${OMINULL_HUB_URL}/api/v1/hierarchy" 2>/dev/null)" &&
        printf '%s' "${status}" | jq -e . >/dev/null 2>&1; then
        echo "[+] Hub package v${VERSION} is live: console reports v${VERSION}, API answering."
        exit 0
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
        echo "[-] Hub did not answer as v${VERSION} with a healthy API within 60 s of the install." >&2
        exit 1
    fi
    sleep 1
done
