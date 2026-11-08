#!/usr/bin/env bash
# The Linux agent installer against stand-in tools: a good package installs, a
# wrong digest never reaches dpkg, and a package that will not install, start or
# stay running gives the machine its previous binary back.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/lib/install-agent-deb.sh"
T="$(mktemp -d)"
trap 'rm -rf "${T:?}"' EXIT
fail=0

# dpkg: good | broken (new binary will not run) | refused (dpkg fails, new binary unpacked)
# service: up | crashing (restart count climbs) | down (not active) | restarted-before (count cleared by the restart)
setup() {
    rm -rf "${T:?}/root" "${T:?}/bin" "${T:?}/log" "${T:?}/restarted"
    mkdir -p "${T}/root/etc/ominull" "${T}/root/opt/ominull/bin" "${T}/root/var/lib/ominull" "${T}/bin"
    printf 'hub_url=https://hub.test:9443\nca_path=/ca.crt\npin_hub_ca=1\n' >"${T}/root/etc/ominull/agent.conf"
    printf '#!/bin/sh\necho previous\n' >"${T}/root/opt/ominull/bin/ominulld"
    chmod +x "${T}/root/opt/ominull/bin/ominulld"
    printf 'package bytes\n' >"${T}/pkg"
    cat >"${T}/bin/curl" <<EOS
#!/bin/sh
while [ \$# -gt 0 ]; do case "\$1" in -o) cp "${T}/pkg" "\$2"; shift ;; esac; shift; done
EOS
    local new_body='echo new' dpkg_exit=0
    [ "$1" != broken ] || new_body='exit 1'
    [ "$1" != refused ] || dpkg_exit=1
    cat >"${T}/bin/dpkg" <<EOS
#!/bin/sh
echo dpkg >>"${T}/log"
printf '#!/bin/sh\n${new_body}\n' >"${T}/root/opt/ominull/bin/ominulld"
chmod +x "${T}/root/opt/ominull/bin/ominulld"
exit ${dpkg_exit}
EOS
    cat >"${T}/bin/systemctl" <<EOS
#!/bin/sh
case "\$1" in
    show)
        case "$2" in
            crashing) n=\$(cat "${T}/shows" 2>/dev/null || echo 0); echo \$((n + 1)) >"${T}/shows"; echo "\${n}" ;;
            restarted-before) if [ -f "${T}/restarted" ]; then echo 0; else echo 3; fi ;;
            *) echo 0 ;;
        esac ;;
    restart) touch "${T}/restarted" ;;
    is-active) [ "$2" != down ] ;;
esac
EOS
    rm -f "${T}/shows"
    chmod +x "${T}"/bin/*
}
run() { # args -> exit status
    PATH="${T}/bin:${PATH}" OMINULL_INSTALL_ROOT="${T}/root" OMINULL_INSTALL_SETTLE=0 \
        sh "${SCRIPT}" "$@" >"${T}/out" 2>&1 && echo 0 || echo 1
}
check() { # name want got
    if [ "$2" != "$3" ]; then echo "[-] $1: want $2, got $3"; cat "${T}/out"; fail=1; else echo "[+] $1"; fi
}
good_sha() { sha256sum "${T}/pkg" | cut -d' ' -f1; }
binary() { "${T}/root/opt/ominull/bin/ominulld"; }
package_left() { [ -e "${T}/root/var/lib/ominull/updates/agent.deb" ] && echo yes || echo no; }

setup good up
check "good package installs" 0 "$(run 9.9.9 "$(good_sha)")"
check "good package is the new binary" new "$(binary)"
check "package removed after install" no "$(package_left)"
check "a machine that never reaches the hub can be restored" 0 "$(run --restore)"
check "restore puts the previous binary back" previous "$(binary)"

setup good up
check "restore with nothing kept fails" 1 "$(run --restore)"

setup good up
check "wrong digest fails" 1 "$(run 9.9.9 0000000000000000000000000000000000000000000000000000000000000000)"
check "wrong digest never reaches dpkg" no "$([ -f "${T}/log" ] && echo yes || echo no)"
check "wrong digest keeps the binary" previous "$(binary)"
check "wrong digest removes the download" no "$(package_left)"

setup refused up
check "dpkg failure fails" 1 "$(run 9.9.9 "$(good_sha)")"
check "dpkg failure is rolled back" previous "$(binary)"

setup broken up
check "package that will not start fails" 1 "$(run 9.9.9 "$(good_sha)")"
check "package that will not start is rolled back" previous "$(binary)"

setup good crashing
check "package that keeps restarting fails" 1 "$(run 9.9.9 "$(good_sha)")"
check "package that keeps restarting is rolled back" previous "$(binary)"

setup good down
check "package that stops fails" 1 "$(run 9.9.9 "$(good_sha)")"
check "package that stops is rolled back" previous "$(binary)"

setup good restarted-before
check "earlier crashes do not fail a healthy install" 0 "$(run 9.9.9 "$(good_sha)")"
check "earlier crashes keep the new binary" new "$(binary)"

exit "${fail}"
