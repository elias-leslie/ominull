#!/usr/bin/env bash
# Keep the checked-in release identifiers used by the retained hub and agents aligned.
# Package filenames take VERSION at build time; they are deliberately not duplicated here.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/VERSION"

canonical() { tr -d '[:space:]' < "${VERSION_FILE}"; }

version_sites() {
    cat <<SITES
hub bundled agent|hub/cmd/main.go|(?<=defaultAgentVersion = ")[0-9]+\.[0-9]+\.[0-9]+
linux agent|agent/linux/main.c|(?<=OMINULL_LINUX_AGENT_VERSION ")[0-9]+\.[0-9]+\.[0-9]+
windows agent|agent/include/agent.h|(?<=OMINULL_AGENT_VERSION ")[0-9]+\.[0-9]+\.[0-9]+
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
        echo "[-] Version drift detected. Run: scripts/version.sh bump ${want}" >&2
    else
        echo "[+] All retained release version sites agree on v${want}."
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
    sed -i "s/OMINULL_AGENT_VERSION \"[0-9.]\+\"/OMINULL_AGENT_VERSION \"${new}\"/" "${ROOT_DIR}/agent/include/agent.h"

    echo "[+] Bumped Ominull ${old} -> ${new}"
    cmd_check
}

case "${1:-show}" in
    show) canonical; echo ;;
    check) cmd_check ;;
    bump) cmd_bump "${2:?usage: version.sh bump <version>}" ;;
    *) echo "usage: version.sh [show|check|bump <version>]" >&2; exit 1 ;;
esac
