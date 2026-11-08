#!/usr/bin/env bash
# The hub deploy's container script against stand-in tools: a new hub that never
# reports healthy gives the previous binary back, and --rollback swaps them.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "${T:?}"' EXIT
fail=0

# The script as it reaches the container, with its folders moved under ${T}.
sed -n "/^REMOTE='/,/^'\$/p" "${ROOT_DIR}/scripts/deploy-hub.sh" | sed "1s/^REMOTE='//; \$d" |
    sed "s#/opt/ominull/bin#${T}/bin#; s#/var/lib/ominull-deploy#${T}/stage#; s#/usr/bin/ominullctl#${T}/ctl/ominullctl#g; s#-lt 120#-lt 2#; s#sleep 1#:#" >"${T}/remote.sh"
mkdir -p "${T}/tools" "${T}/ctl" "${T}/etc"
for tool in systemctl journalctl; do printf '#!/bin/sh\n' >"${T}/tools/${tool}"; done
printf '#!/bin/sh\nexit 22\n' >"${T}/tools/curl"
printf '#!/bin/sh\nargs=""\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) args="$args $1"; shift ;; esac; done\nexec /usr/bin/install $args\n' >"${T}/tools/install"
chmod +x "${T}"/tools/*

setup() {
    rm -rf "${T:?}/bin" "${T:?}/stage"
    mkdir -p "${T}/bin" "${T}/stage"
    echo running >"${T}/bin/ominull-hub"
    echo older >"${T}/bin/ominull-hub.prev"
    echo new >"${T}/stage/ominull-hub"
}
run() { PATH="${T}/tools:${PATH}" sh "${T}/remote.sh" "$@" >"${T}/out" 2>&1 && echo 0 || echo 1; }
check() {
    if [ "$2" != "$3" ]; then echo "[-] $1: want $2, got $3"; cat "${T}/out"; fail=1; else echo "[+] $1"; fi
}

setup
check "a hub that never answers fails the deploy" 1 "$(run deploy abc)"
check "the running binary comes back" running "$(cat "${T}/bin/ominull-hub")"
check "the new binary is kept as the previous one" new "$(cat "${T}/bin/ominull-hub.prev")"
check "the stage folder is gone" no "$([ -e "${T}/stage" ] && echo yes || echo no)"

setup
check "rollback runs without a stage folder" 1 "$(rm -rf "${T:?}/stage"; run rollback)"
check "rollback swaps in the previous binary" older "$(cat "${T}/bin/ominull-hub")"

exit "${fail}"
