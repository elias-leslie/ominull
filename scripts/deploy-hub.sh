#!/usr/bin/env bash
# Deploy the hub like any other service: build, copy, restart, check.
#
#   scripts/deploy-hub.sh             build the committed HEAD and put it live
#   scripts/deploy-hub.sh --rev REV   build that commit instead (e.g. to go back further than one deploy)
#   scripts/deploy-hub.sh --rollback  put the previous binaries back and restart
#
# Builds ominull-hub and ominullctl from `git archive REV`
# (never the working tree, so other work in the checkout is not shipped), streams them
# into the hub container over the Proxmox root SSH alias, keeps each replaced binary as
# <name>.prev, restarts what changed and waits for /api/v1/agents/update-status to report
# the new build. If the hub does not come back on the new build, the previous binaries
# go back automatically, then the hub's maintenance package library is synced from the same
# commit. No package, signing or version bump: agent packages are published
# by the agent release (scripts/release.sh), which also sets the agent version the hub offers.
#
# Target: ssh_alias and lxc_id from scripts/st_extension/production.local.json
# (OMINULL_PRODUCTION_CONFIG overrides the path). Run heavy builds through admission:
#   st tools run --label "ominull hub deploy" -- scripts/deploy-hub.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${OMINULL_PRODUCTION_CONFIG:-${ROOT_DIR}/scripts/st_extension/production.local.json}"
REV=HEAD
mode=deploy
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rev) REV="${2:?--rev needs a commit}"; shift 2 ;;
        --rollback) mode=rollback; shift ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -f "${CFG}" ] || { echo "[-] ${CFG} is missing (needs ssh_alias and lxc_id)." >&2; exit 1; }
ALIAS="$(jq -r '.ssh_alias // empty' "${CFG}")"
LXC="$(jq -r '.lxc_id // empty' "${CFG}")"
[[ "${ALIAS}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ && "${LXC}" =~ ^[1-9][0-9]*$ ]] || {
    echo "[-] ${CFG} needs ssh_alias and lxc_id." >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
in_ct() { ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh -s -- $*"; }

# Runs inside the container (POSIX sh). $1 = action, $2 = expected build (deploy only).
# shellcheck disable=SC2016
REMOTE='
set -eu
BIN=/opt/ominull/bin
STAGE=/var/lib/ominull-deploy
action="$1"; want="${2:-}"
health() {
    i=0
    while [ "$i" -lt 120 ]; do
        if out="$(printf "header = \"X-API-Key: %s\"\n" "$(head -n1 /etc/ominull/admin.key)" |
            curl -fsS --max-time 5 -K - http://127.0.0.1:9999/api/v1/agents/update-status 2>/dev/null)"; then
            build="$(printf "%s" "$out" | sed -n "s/.*\"hub_build\":\"\([^\"]*\)\".*/\1/p")"
            if [ -z "$want" ] || [ "$build" = "$want" ]; then echo "$build"; return 0; fi
        fi
        i=$((i + 1)); sleep 1
    done
    return 1
}
swap_back() {
    for b in ominull-hub; do
        [ -f "$BIN/$b.prev" ] || continue
        cp -p "$BIN/$b" "$STAGE/$b.undo"
        install -m 0755 -o root -g root "$BIN/$b.prev" "$BIN/$b.new" && mv -f "$BIN/$b.new" "$BIN/$b"
        mv -f "$STAGE/$b.undo" "$BIN/$b.prev"
    done
    if [ -f /usr/bin/ominullctl.prev ]; then cp -p /usr/bin/ominullctl.prev /usr/bin/ominullctl; fi
    systemctl restart ominull-hub.service
}
case "$action" in
stage)
    rm -rf "$STAGE"; install -d -m 0700 "$STAGE"; tar -C "$STAGE" -xf -
    ;;
deploy)
    changed=""
    for b in ominull-hub; do
        [ -f "$STAGE/$b" ] || continue
        if [ -f "$BIN/$b" ] && cmp -s "$STAGE/$b" "$BIN/$b"; then continue; fi
        [ -f "$BIN/$b" ] && cp -p "$BIN/$b" "$BIN/$b.prev"
        install -m 0755 -o root -g root "$STAGE/$b" "$BIN/$b.new" && mv -f "$BIN/$b.new" "$BIN/$b"
        changed="$changed $b"
    done
    if [ -f "$STAGE/ominullctl" ]; then
        [ -f /usr/bin/ominullctl ] && cp -p /usr/bin/ominullctl /usr/bin/ominullctl.prev
        install -m 0755 -o root -g root "$STAGE/ominullctl" /usr/bin/ominullctl.new && mv -f /usr/bin/ominullctl.new /usr/bin/ominullctl
    fi
    rm -rf "$STAGE"
    systemctl restart ominull-hub.service
    echo "replaced:${changed:- nothing (same bytes), restarted the hub}"
    if build="$(health)"; then echo "live build $build"; exit 0; fi
    echo "the hub did not report build $want within 120 s; putting the previous binaries back" >&2
    journalctl -u ominull-hub.service -n 20 --no-pager >&2 || true
    install -d -m 0700 "$STAGE"
    swap_back
    rm -rf "$STAGE"
    want=""; health >/dev/null && echo "previous build is back" >&2
    exit 1
    ;;
rollback)
    [ -f "$BIN/ominull-hub.prev" ] || { echo "no previous hub binary to go back to" >&2; exit 1; }
    install -d -m 0700 "$STAGE"
    swap_back
    rm -rf "$STAGE"
    if build="$(health)"; then echo "live build ${build:-unknown}"; exit 0; fi
    echo "the hub did not answer within 120 s after the rollback" >&2
    exit 1
    ;;
esac
'

if [ "${mode}" = rollback ]; then
    echo "[*] Rolling the hub in CT ${LXC} back to its previous binaries."
    printf '%s' "${REMOTE}" | in_ct rollback
    exit 0
fi

sha="$(git -C "${ROOT_DIR}" rev-parse --verify "${REV}^{commit}")"
build="${sha:0:12}"
work="$(mktemp -d "${TMPDIR:-/tmp}/ominull-hub-deploy.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
git -C "${ROOT_DIR}" archive "${sha}" hub packages scripts/sync-package-library.sh | tar -x -C "${work}"
mkdir -p "${work}/out"
echo "[*] Building hub ${build} ($(git -C "${ROOT_DIR}" log -1 --format=%s "${sha}" | cut -c1-80))."
(
    cd "${work}/hub"
    export CGO_ENABLED=0
    go build -trimpath -ldflags "-X main.version=${build}" -o "${work}/out/ominull-hub" ./cmd
    go build -trimpath -o "${work}/out/ominullctl" ./cmd/ominullctl
)
echo "[*] Copying to CT ${LXC} through ${ALIAS}."
# The remote script arrives first on stdin, then the tar: sh -s reads only the script.
tar -C "${work}/out" --owner=0 --group=0 --numeric-owner -cf "${work}/bins.tar" .
ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh -c 'cat > /root/.ominull-deploy.sh'" <<<"${REMOTE}"
ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh /root/.ominull-deploy.sh stage" <"${work}/bins.tar"
echo "[*] Swapping binaries and restarting."
ssh "${ssh_opts[@]}" -- "${ALIAS}" "pct exec ${LXC} -- sh -c 'sh /root/.ominull-deploy.sh deploy ${build}; rc=\$?; rm -f /root/.ominull-deploy.sh; exit \$rc'"
echo "[+] Hub ${build} is live."
# The maintenance package library ships with the hub (grants/released_packages.json).
# shellcheck source=lib/hub-admin-key.sh
. "${ROOT_DIR}/scripts/lib/hub-admin-key.sh"
hub_admin_key_from_config
echo "[*] Syncing the hub's package library."
CTL="${work}/out/ominullctl" "${work}/scripts/sync-package-library.sh"
