#!/usr/bin/env bash
# scripts/posture-collect.sh against stand-in tools: which machines run the package
# and how, that only the committed version runs and only when it is the hub's, what
# counts as off or failed, and what the hub is asked to record.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "${T:?}"' EXIT
mkdir -p "${T}/tree/scripts/lib" "${T}/tree/packages/linux" "${T}/bin" "${T}/posts"
cp "${ROOT_DIR}/scripts/posture-collect.sh" "${ROOT_DIR}/scripts/hub-request.sh" "${T}/tree/scripts/"
cp "${ROOT_DIR}/scripts/lib/hub-admin-key.sh" "${T}/tree/scripts/lib/"
echo '{"ssh_alias":"px","linux_agent_machines":{"linux-renamed":"guest-ct","linux-host":"@proxmox","linux-here":"@local"}}' >"${T}/cfg.json"

# The committed package differs from the file on disk, as with a change in progress.
PKG="${T}/tree/packages/linux/security-baseline.sh"
echo 'committed package' >"${PKG}"
git -C "${T}/tree" init -q
git -C "${T}/tree" add packages/linux/security-baseline.sh
git -C "${T}/tree" -c user.name=t -c user.email=t@t commit -qm package
echo 'unfinished edit' >"${PKG}"
SHA="$(printf 'committed package\n' | sha256sum | cut -d' ' -f1)"

# Each root-access stand-in logs its command and what it was fed, then answers with
# ${T}/result and exits ${T}/exit. The qm one wraps that the way qm guest exec does.
cat >"${T}/bin/ssh" <<EOS
#!/bin/sh
for a; do cmd="\$a"; done
echo "\${cmd}" >>"${T}/log"
cat >>"${T}/fed"
case "\${cmd}" in
    qm*) jq -cn --rawfile o "${T}/result" --argjson c "\$(cat "${T}/exit")" '{exited:1, exitcode:\$c, "out-data":\$o}' ;;
    *) cat "${T}/result"; exit "\$(cat "${T}/exit")" ;;
esac
EOS
cat >"${T}/bin/sudo" <<EOS
#!/bin/sh
echo "sudo \$*" >>"${T}/log"
cat >>"${T}/fed"
cat "${T}/result"
exit "\$(cat "${T}/exit")"
EOS
cat >"${T}/bin/aico" <<EOS
#!/bin/sh
cat "${T}/machines"
EOS
# GETs answer from files; a POST lands in posts/ and answers with ${T}/post_code.
cat >"${T}/bin/curl" <<EOS
#!/bin/sh
body=""; post=no; prev=""
for a; do
    [ "\${prev}" = --data ] && body="\${a}"
    [ "\${a}" = POST ] && post=yes
    prev="\${a}"; url="\${a}"
done
if [ "\${post}" = yes ]; then
    printf '%s\n' "\${body}" >>"${T}/posts/all"
    printf '{"state":"ok","pass":3,"fail":1,"error":"refused"}\n%s' "\$(cat "${T}/post_code")"
    exit 0
fi
case "\${url}" in
    */api/v1/endpoints) cat "${T}/endpoints" ;;
    *settings\?endpoint_id=*) f="${T}/settings.\${url##*=}"; [ -f "\${f}" ] && cat "\${f}" || cat "${T}/settings" ;;
    *settings) cat "${T}/library" ;;
esac
EOS
chmod +x "${T}"/bin/*

ep() { printf '{"id":"%s","os":"%s","status":"%s"}' "$1" "$2" "$3"; }
setting() { # category_enabled params-json
    jq -cn --arg s "${SHA}" --argjson on "$1" --argjson p "$2" \
        '{packages:[{name:"linux-security-baseline",digest_sha256:$s,effective:{category_enabled:$on,params:$p}}]}'
}
setup() {
    : >"${T}/log"; : >"${T}/fed"; : >"${T}/posts/all"
    echo 0 >"${T}/exit"; echo 200 >"${T}/post_code"
    echo '{"v":1,"state":"drift","detail":{"controls":[]}}' >"${T}/result"
    rm -f "${T}"/settings.*
    setting true '{}' >"${T}/settings"
    setting true '{}' >"${T}/library"
    printf '[%s]' "$(ep linux-ct 'Linux 6.8' online),$(ep linux-vm 'Linux 6.8' online),$(ep linux-renamed 'Linux 6.8' online),$(ep linux-host 'Linux 6.8' online),$(ep linux-here 'Linux 6.8' online),$(ep linux-off 'Linux 6.8' offline),$(ep linux-gone 'Linux 6.8' offline),$(ep win 'Windows 11' online)" >"${T}/endpoints"
    cat >"${T}/machines" <<'EOS'
[{"name":"ct","guest":{"vmid":191,"kind":"ct","state":"running"}},
 {"name":"vm","guest":{"vmid":180,"kind":"vm","state":"running"}},
 {"name":"guest-ct","guest":{"vmid":192,"kind":"ct","state":"running"}},
 {"name":"off","guest":{"vmid":112,"kind":"vm","state":"stopped"}}]
EOS
}
run() {
    PATH="${T}/bin:${PATH}" OMINULL_HUB_URL=http://127.0.0.1:1 OMINULL_ADMIN_KEY=stand-in OMINULL_PRODUCTION_CONFIG="${T}/cfg.json" \
        bash "${T}/tree/scripts/posture-collect.sh" "$@" >"${T}/out" 2>&1 && echo 0 || echo 1
}
fail=0
check() { # name want got
    if [ "$2" != "$3" ]; then echo "[-] $1: want '$2', got '$3'"; cat "${T}/out"; fail=1; else echo "[+] $1"; fi
}
says() { grep -qF -- "$1" "${T}/out" && echo yes || echo no; }
ran() { wc -l <"${T}/log" | tr -d ' '; }
recorded() { jq -r '.endpoint_id' "${T}/posts/all" | sort | tr '\n' ' '; }

setup
check "a normal run succeeds" 0 "$(run)"
check "every running Linux machine answers, and only those" "linux-ct linux-here linux-host linux-renamed linux-vm " "$(recorded)"
check "each goes by its own route" yes "$(grep -q '^pct exec 191 ' "${T}/log" && grep -q '^qm guest exec 180 ' "${T}/log" && grep -q '^pct exec 192 ' "${T}/log" && grep -q '^env ' "${T}/log" && grep -q '^sudo -n env ' "${T}/log" && echo yes || echo no)"
check "the summary counts them" yes "$(says '5 recorded, 2 off, 0 switched off, 0 failed.')"
check "a machine that is off is named, not started" yes "$(says 'Off: linux-off linux-gone.')"
check "the committed package ran, not the file on disk" "5 0" "$(grep -c '^committed package$' "${T}/fed") $(grep -c unfinished "${T}/fed" || true)"
check "the hub is told what ran" "linux-security-baseline|${SHA}|audit|0|1" \
    "$(jq -r 'select(.endpoint_id == "linux-vm") | [.package, .sha256, .mode, .exit_code, (.stdout | fromjson | .v)] | map(tostring) | join("|")' "${T}/posts/all")"

setup; setting true '{}' | jq -c '.packages[0].digest_sha256 = "other"' >"${T}/library"
check "a package that is not the hub's version refuses" 1 "$(run)"
check "and nothing ran" 0 "$(ran)"
check "and it says to deploy the hub" yes "$(says 'deploy the hub first')"

setup; echo '{"packages":[]}' >"${T}/library"
check "a hub without the package refuses" 1 "$(run)"
check "and nothing ran" 0 "$(ran)"

setup; setting false '{}' >"${T}/settings.linux-vm"
check "the security switch is not a failure" 0 "$(run)"
check "a machine switched off does not run" "" "$(grep '^qm' "${T}/log" || true)"
check "and is counted" yes "$(says '1 switched off')"

setup; setting true '{"journal_min_days":14,"backup_max_age_days":"7; reboot","mode":"enforce"}' >"${T}/settings.linux-ct"
run --only linux-ct >/dev/null
check "a saved parameter reaches the package" yes "$(grep -q 'OMINULL_PARAM_JOURNAL_MIN_DAYS=14' "${T}/log" && echo yes || echo no)"
check "a value with unexpected characters stays out" 0 "$(grep -c 'reboot' "${T}/log" || true)"
check "and is reported" yes "$(says 'ignoring a parameter')"
check "a saved mode cannot make the check anything but an audit" "0 1" "$(grep -c 'MODE=enforce' "${T}/log" || true) $(grep -c 'OMINULL_PARAM_MODE=audit' "${T}/log")"

setup
check "--only runs just that machine" 0 "$(run --only linux-vm)"
check "and records just that one" "linux-vm " "$(recorded)"

setup
check "--only with a typo refuses" 1 "$(run --only linux-typo)"
check "--only with a Windows machine refuses" 1 "$(run --only win)"
check "before anything runs" 0 "$(ran)"

setup; echo 3 >"${T}/exit"; echo '{"v":1,"state":"failed"}' >"${T}/result"
run --only linux-ct >/dev/null
check "a failed package with a result is still recorded, with its exit code" 3 "$(jq -r '.exit_code' "${T}/posts/all")"

setup; echo 'bash: no such thing' >"${T}/result"; echo 127 >"${T}/exit"
check "a machine with no result fails" 1 "$(run --only linux-ct)"
check "and records nothing" "" "$(recorded)"
check "and names it with the exit code" yes "$(says 'linux-ct: no result (exit 127)')"

setup; echo '{"v":2}' >"${T}/result"
check "a result in an unknown format fails" 1 "$(run --only linux-vm)"

setup; jq -cn '{v:1, pad:("x" * 100001)}' >"${T}/result"
check "a result too large to record fails" 1 "$(run --only linux-ct)"
check "and is not sent" "" "$(recorded)"

setup; echo 400 >"${T}/post_code"
check "a result the hub refuses fails" 1 "$(run --only linux-ct)"
check "and says so" yes "$(says 'the hub refused the result')"

setup; echo '[]' >"${T}/machines"
check "an online machine with no route fails" 1 "$(run --only linux-ct)"
check "and says how to fix it" yes "$(says 'linux_agent_machines')"

setup; echo '[]' >"${T}/machines"
check "an offline machine with no route is just off" 0 "$(run --only linux-gone)"
check "and is listed" yes "$(says 'Off: linux-gone.')"

exit "${fail}"
