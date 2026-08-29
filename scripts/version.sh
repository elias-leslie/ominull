#!/usr/bin/env bash
#
# Single source of truth for the Ominull release version.
#
# The version is compiled into the hub, into three agent codebases, and into the
# package filenames the hub serves for self-update. If any of those drift, endpoints
# either never see an update or are offered a package the hub cannot serve, so this
# script owns every one of those sites.
#
#   version.sh show          Print the canonical version.
#   version.sh check         Verify every source agrees with VERSION (exit 1 on drift).
#   version.sh bump <ver>    Rewrite every source to <ver>.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/VERSION"

canonical() { tr -d '[:space:]' < "${VERSION_FILE}"; }

# Each entry is "<label>|<file>|<grep -Po pattern extracting the version>".
version_sites() {
    cat <<SITES
hub bundled agent|hub/cmd/main.go|(?<=defaultAgentVersion = ")[^"]+
linux agent|agent/linux/main.c|(?<=OMINULL_LINUX_AGENT_VERSION ")[^"]+
windows/portable agent|agent/include/agent.h|(?<=OMINULL_AGENT_VERSION ")[^"]+
macos daemon --version|agent/macos/ominull_mac_daemon.sh|(?<=^AGENT_VERSION=")[^"]+
macos daemon banner|agent/macos/ominull_mac_daemon.sh|(?<=Telemetry Daemon \(v)[0-9]+\.[0-9]+\.[0-9]+
macos daemon telemetry|agent/macos/ominull_mac_daemon.sh|(?<="driver_version": ")[0-9]+\.[0-9]+\.[0-9]+
package builder|scripts/build-packages.sh|(?<=^VERSION=")[^"]+
debian control|scripts/build-packages.sh|(?<=^Version: )[0-9]+\.[0-9]+\.[0-9]+
SITES
}

cmd_check() {
    local want status=0
    want="$(canonical)"
    while IFS='|' read -r label file pattern; do
        [ -n "${label}" ] || continue
        local got
        got="$(grep -Pom1 "${pattern}" "${ROOT_DIR}/${file}" || true)"
        if [ "${got}" != "${want}" ]; then
            echo "  [-] ${label} (${file}): ${got:-<not found>} != ${want}"
            status=1
        else
            echo "  [+] ${label} (${file}): ${got}"
        fi
    done < <(version_sites)
    if [ "${status}" -ne 0 ]; then
        echo "[-] Version drift detected. Run: scripts/version.sh bump ${want}"
    else
        echo "[+] All release version sites agree on v${want}."
    fi
    return "${status}"
}

cmd_bump() {
    local new="$1" old
    if ! printf '%s' "${new}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "[-] Version must be major.minor.patch (got '${new}')" >&2
        exit 1
    fi
    old="$(canonical)"
    printf '%s\n' "${new}" > "${VERSION_FILE}"

    sed -i "s/defaultAgentVersion = \"${old}\"/defaultAgentVersion = \"${new}\"/" "${ROOT_DIR}/hub/cmd/main.go"
    sed -i "s/OMINULL_LINUX_AGENT_VERSION \"${old}\"/OMINULL_LINUX_AGENT_VERSION \"${new}\"/" "${ROOT_DIR}/agent/linux/main.c"
    sed -i "s/OMINULL_AGENT_VERSION \"[0-9.]*\"/OMINULL_AGENT_VERSION \"${new}\"/" "${ROOT_DIR}/agent/include/agent.h"
    sed -i "s/^AGENT_VERSION=\"[0-9.]*\"/AGENT_VERSION=\"${new}\"/" "${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh"
    sed -i "s/Telemetry Daemon (v[0-9.]*)/Telemetry Daemon (v${new})/" "${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh"
    sed -i "s/\"driver_version\": \"[0-9.]* (PF)\"/\"driver_version\": \"${new} (PF)\"/" "${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh"
    sed -i "s/^VERSION=\"${old}\"/VERSION=\"${new}\"/" "${ROOT_DIR}/scripts/build-packages.sh"
    sed -i "s/^Version: [0-9.]*$/Version: ${new}/" "${ROOT_DIR}/scripts/build-packages.sh"

    echo "[+] Bumped Ominull ${old} -> ${new}"
    cmd_check
}

case "${1:-show}" in
    show)  canonical; echo ;;
    check) cmd_check ;;
    bump)  cmd_bump "${2:?usage: version.sh bump <major.minor.patch>}" ;;
    *)     echo "usage: version.sh [show|check|bump <version>]" >&2; exit 1 ;;
esac
