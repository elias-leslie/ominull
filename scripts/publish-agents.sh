#!/usr/bin/env bash
# Publish signed agent packages on the hub and make it offer them (scripts/release.sh runs this).
#
#   scripts/publish-agents.sh [VERSION]    default: scripts/version.sh show
#
# Streams dist/ominull-agent_VERSION_amd64.deb and dist/ominull-agent-windows-VERSION.msi with their
# .sig, .sha256 and .release.sig into the hub's download directory (/opt/ominull/bin, what /download/
# serves and agents update from), sets OMINULL_AGENT_VERSION in /etc/ominull/hub.env, restarts the hub
# and waits until /api/v1/agents/update-status offers VERSION. The hub binary itself is deployed by
# scripts/deploy-hub.sh. Target: ssh_alias and lxc_id from scripts/st_extension/production.local.json.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${OMINULL_PRODUCTION_CONFIG:-${ROOT_DIR}/scripts/st_extension/production.local.json}"
VERSION="${1:-${OMINULL_RELEASE_VERSION:-$("${ROOT_DIR}/scripts/version.sh" show)}}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "[-] Not a release version: ${VERSION}" >&2; exit 2; }
[ -f "${CFG}" ] || { echo "[-] ${CFG} is missing (needs ssh_alias and lxc_id)." >&2; exit 1; }
ALIAS="$(jq -r '.ssh_alias // empty' "${CFG}")"
LXC="$(jq -r '.lxc_id // empty' "${CFG}")"
[[ "${ALIAS}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ && "${LXC}" =~ ^[1-9][0-9]*$ ]] || {
    echo "[-] ${CFG} needs ssh_alias and lxc_id." >&2; exit 1; }

files=()
for base in "ominull-agent_${VERSION}_amd64.deb" "ominull-agent-windows-${VERSION}.msi"; do
    for suffix in "" .sig .sha256 .release.sig; do
        [ -f "${ROOT_DIR}/dist/${base}${suffix}" ] || { echo "[-] Missing dist/${base}${suffix}; build and sign first." >&2; exit 1; }
        files+=("${base}${suffix}")
    done
done

# Runs inside the container (POSIX sh): $1 = version, the packages arrive as a tar on stdin.
# shellcheck disable=SC2016
REMOTE='
set -eu
v="$1"
stage="$(mktemp -d /var/lib/ominull-publish.XXXXXX)"
tar -C "$stage" --no-same-owner -xf -
for f in "$stage"/*; do
    n="$(basename "$f")"
    install -o root -g root -m 0644 "$f" "/opt/ominull/bin/.$n.new" && mv -f "/opt/ominull/bin/.$n.new" "/opt/ominull/bin/$n"
done
rm -rf "$stage"
if grep -q "^OMINULL_AGENT_VERSION=" /etc/ominull/hub.env; then
    sed -i "s/^OMINULL_AGENT_VERSION=.*/OMINULL_AGENT_VERSION=$v/" /etc/ominull/hub.env
else
    printf "OMINULL_AGENT_VERSION=%s\n" "$v" >> /etc/ominull/hub.env
fi
systemctl restart ominull-hub.service
i=0
while [ "$i" -lt 120 ]; do
    if printf "header = \"X-API-Key: %s\"\n" "$(head -n1 /etc/ominull/admin.key)" |
        curl -fsS --max-time 5 -K - http://127.0.0.1:9999/api/v1/agents/update-status 2>/dev/null |
        grep -qF "\"latest_version\":\"$v\""; then
        echo "hub offers agent $v"; exit 0
    fi
    i=$((i + 1)); sleep 1
done
echo "the hub does not offer agent $v 120 s after the restart" >&2
exit 1
'
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
echo "[*] Publishing agent ${VERSION} packages to CT ${LXC} through ${ALIAS}."
ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh -c 'cat > /root/.ominull-publish.sh'" <<<"${REMOTE}"
tar -C "${ROOT_DIR}/dist" --owner=0 --group=0 --numeric-owner -cf - "${files[@]}" |
    ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh -c 'sh /root/.ominull-publish.sh ${VERSION}; rc=\$?; rm -f /root/.ominull-publish.sh; exit \$rc'"
echo "[+] Agent ${VERSION} published; the hub offers it."
