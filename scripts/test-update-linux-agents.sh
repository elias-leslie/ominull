#!/usr/bin/env bash
# scripts/update-linux-agents.sh against stand-in tools: the order machines go in,
# what stops the run, what counts as off, and that a machine the hub never hears
# from gets its previous binary back. The installer has its own test.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "${T:?}"' EXIT
mkdir -p "${T}/tree/scripts/lib" "${T}/tree/agent/include" "${T}/tree/dist" "${T}/bin"
cp "${ROOT_DIR}/scripts/update-linux-agents.sh" "${ROOT_DIR}/scripts/hub-request.sh" "${T}/tree/scripts/"
cp "${ROOT_DIR}/scripts/lib/hub-admin-key.sh" "${ROOT_DIR}/scripts/lib/install-agent-deb.sh" "${T}/tree/scripts/lib/"
cp "${ROOT_DIR}/agent/include/release_key.h" "${T}/tree/agent/include/"
echo pkg >"${T}/tree/dist/ominull-agent_2.0.0_amd64.deb"
echo sig >"${T}/tree/dist/ominull-agent_2.0.0_amd64.deb.sig"
echo '{"ssh_alias":"px","linux_agent_machines":{"linux-renamed":"guest-ct"}}' >"${T}/cfg.json"

# Each stand-in reads ${T}/mode: ok, fail (install fails), silent (installs, hub
# never hears it), timeout (qm gives up waiting).
cat >"${T}/bin/curl" <<EOS
#!/bin/sh
for a; do url="\$a"; done
case "\${url}" in
    */update-status) cat "${T}/status" ;;
    */endpoints) cat "${T}/endpoints" ;;
esac
EOS
cat >"${T}/bin/aico" <<EOS
#!/bin/sh
cat "${T}/machines"
EOS
cat >"${T}/bin/openssl" <<EOS
#!/bin/sh
cat "${T}/sig_ok" >/dev/null
EOS
cat >"${T}/bin/sleep" <<'EOS'
#!/bin/sh
EOS
cat >"${T}/bin/ssh" <<EOS
#!/bin/sh
cat >/dev/null
for a; do cmd="\$a"; done
echo "\${cmd}" >>"${T}/log"
mode="\$(cat "${T}/mode")"
case "\${cmd}" in *--restore*) mode=ok ;; esac
case "\${cmd}" in
    pct*) id=linux-renamed ;;
    qm*)  id=linux-vm ;;
esac
if [ "\${mode}" = ok ] && ! echo "\${cmd}" | grep -q -- --restore; then
    jq --arg id "\${id}" '(.[] | select(.id == \$id)).driver_version = "2.0.0"' "${T}/endpoints" >"${T}/e" && mv "${T}/e" "${T}/endpoints"
fi
case "\${cmd}" in
    qm*)
        case "\${mode}" in
            timeout) echo '{"exited":0,"pid":7}' ;;
            fail) echo '{"exited":1,"exitcode":1,"out-data":"failed there"}' ;;
            *) echo '{"exited":1,"exitcode":0,"out-data":"ok there"}' ;;
        esac ;;
    *) [ "\${mode}" != fail ] ;;
esac
EOS
chmod +x "${T}"/bin/*

ep() { printf '{"id":"%s","os":"%s","status":"%s","driver_version":"1.0.0"}' "$1" "$2" "$3"; }
setup() {
    : >"${T}/log"; echo ok >"${T}/mode"; touch "${T}/sig_ok"
    echo '{"retired_versions":[]}' >"${T}/status"
    printf '[%s,%s,%s,%s,%s]' "$(ep linux-vm 'Linux 6.8' online)" "$(ep linux-renamed 'Linux 6.8' online)" \
        "$(ep linux-off 'Linux 6.8' offline)" "$(ep linux-gone 'Linux 6.8' offline)" "$(ep win 'Windows 11' online)" >"${T}/endpoints"
    cat >"${T}/machines" <<'EOS'
[{"name":"vm","guest":{"vmid":180,"kind":"vm","state":"running"}},
 {"name":"guest-ct","guest":{"vmid":191,"kind":"ct","state":"running"}},
 {"name":"off","guest":{"vmid":112,"kind":"vm","state":"stopped"}}]
EOS
}
run() {
    PATH="${T}/bin:${PATH}" OMINULL_HUB_URL=http://127.0.0.1:1 OMINULL_ADMIN_KEY=stand-in OMINULL_PRODUCTION_CONFIG="${T}/cfg.json" \
        bash "${T}/tree/scripts/update-linux-agents.sh" 2.0.0 "$@" >"${T}/out" 2>&1 && echo 0 || echo 1
}
fail=0
check() { # name want got
    if [ "$2" != "$3" ]; then echo "[-] $1: want '$2', got '$3'"; cat "${T}/out"; fail=1; else echo "[+] $1"; fi
}
hosts() { sed -E 's/^(pct|qm)( guest)? exec ([0-9]+).*/\3/' "${T}/log" | tr '\n' ' '; }
says() { grep -qF -- "$1" "${T}/out" && echo yes || echo no; }

setup
check "a normal run succeeds" 0 "$(run)"
check "machines go by id; off and Windows are left alone" "191 180 " "$(hosts)"
check "a stopped machine and a gone one are listed for a rerun" yes "$(says 'rerun after they start: linux-gone linux-off')"

setup
run --canary linux-vm >/dev/null
check "a canary goes first" "180 191 " "$(hosts)"

setup
check "a Windows canary is fine here" 0 "$(run --canary win)"

setup; echo fail >"${T}/mode"
check "a failed install stops the run" 1 "$(run --canary linux-vm)"
check "nothing after the failure is touched" "180 " "$(hosts)"

setup; echo silent >"${T}/mode"
check "a machine the hub never hears from fails" 1 "$(run --only linux-vm)"
check "that machine gets its previous binary back" yes "$(grep -c -- '--restore' "${T}/log" | grep -q 1 && echo yes || echo no)"

setup; echo timeout >"${T}/mode"
check "a VM that outlasts qm's wait fails" 1 "$(run --only linux-vm)"
check "and says so" yes "$(says 'did not finish in time')"

setup
check "a mistyped canary refuses" 1 "$(run --canary linux-typo)"
check "before anything is installed" "" "$(hosts)"
check "a mistyped --only refuses" 1 "$(run --only linux-typo)"
check "a Windows --only refuses" 1 "$(run --only win)"
check "still nothing installed" "" "$(hosts)"

setup; rm "${T}/sig_ok"
check "a bad signature refuses" 1 "$(run)"
check "before anything is installed" "" "$(hosts)"

setup; echo '{"retired_versions":["2.0.0"]}' >"${T}/status"
check "a retired release refuses" 1 "$(run)"
check "before anything is installed" "" "$(hosts)"

setup; jq '(.[] | select(.id == "linux-off")).status = "online"' "${T}/endpoints" >"${T}/e"; mv "${T}/e" "${T}/endpoints"
sed -i 's/"stopped"/"starting"/' "${T}/machines"
check "an online machine in an unknown state has no route and fails" 1 "$(run)"
check "and is named" yes "$(says 'No route')"

exit "${fail}"
