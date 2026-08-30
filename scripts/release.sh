#!/usr/bin/env bash
#
# Ominull end-to-end release pipeline: version -> build -> hub -> agents.
#
# Rolling a code change to the fleet is two hops, and skipping either one leaves the
# fleet on stale code: the hub has to be running the new build (it is what serves the
# packages and decides who is outdated), and only then can the agents be told to take
# it. This script owns both hops so the sequence cannot be run out of order.
#
#   release.sh [--version X.Y.Z] [--skip-tests] [--hub-only] [--agents-only] [--no-wait]
#
# Environment:
#   OMINULL_HUB_URL     Hub base URL for the agent roll-out (default http://127.0.0.1:9999)
#   OMINULL_ADMIN_KEY   Hub admin key (required for --agents-only / the roll-out phase)
#   OMINULL_DEPLOY_CMD  Command that ships build output to the hub host. Defaults to
#                       scripts/deploy_remote.sh, which is deployment-specific and
#                       therefore untracked; see deploy_remote.sh.example.
#   OMINULL_SIGNING_KEY Release signing key, from the operations vault. Required:
#                       agents refuse any package that is not signed with it.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
DEPLOY_CMD="${OMINULL_DEPLOY_CMD:-${ROOT_DIR}/scripts/deploy_remote.sh}"

VERSION=""
SKIP_TESTS=0
DO_HUB=1
DO_AGENTS=1
WAIT_FOR_AGENTS=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)     VERSION="${2:?--version needs a value}"; shift 2 ;;
        --skip-tests)  SKIP_TESTS=1; shift ;;
        --hub-only)    DO_AGENTS=0; shift ;;
        --agents-only) DO_HUB=0; shift ;;
        --no-wait)     WAIT_FOR_AGENTS=0; shift ;;
        -h|--help)     sed -n '2,20p' "$0"; exit 0 ;;
        *)             echo "[-] Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -n "${VERSION}" ]; then
    echo "[*] Bumping release version to ${VERSION}..."
    "${ROOT_DIR}/scripts/version.sh" bump "${VERSION}"
else
    VERSION="$("${ROOT_DIR}/scripts/version.sh" show)"
    echo "[*] Releasing Ominull v${VERSION} (no bump requested)."
    "${ROOT_DIR}/scripts/version.sh" check
fi

if [ "${DO_HUB}" -eq 1 ]; then
    if [ "${SKIP_TESTS}" -eq 0 ]; then
        echo "[*] Running hub test suite (race detector)..."
        (cd "${ROOT_DIR}/hub" && go test -race ./...)
        echo "[*] Compiling C stream-DPI unit tests..."
        gcc -O2 -Wall -Wextra -o "${ROOT_DIR}/agent/bin/test_dpi" "${ROOT_DIR}/agent/tests/test_dpi.c"
        "${ROOT_DIR}/agent/bin/test_dpi"
        # The baseline parser turns a hub reply into iptables arguments on a host
        # that is about to be cut off. It compiles the agent in, so it is also a
        # second compile of main.c under -Wall -Wextra.
        echo "[*] Compiling baseline isolation policy unit tests..."
        gcc -O2 -Wall -Wextra -o "${ROOT_DIR}/agent/bin/test_baseline" "${ROOT_DIR}/agent/tests/test_baseline.c"
        "${ROOT_DIR}/agent/bin/test_baseline"
        # The macOS ruleset, checked without a Mac. bash -n proves the helper
        # parses; this proves it writes the right rules in the right order,
        # which is the part that decides whether an isolated host can be got
        # back.
        echo "[*] Checking the macOS pf ruleset the agent generates..."
        bash "${ROOT_DIR}/agent/tests/test_pf_rules.sh"
    fi

    echo "[*] Building cross-platform agent packages..."
    "${ROOT_DIR}/scripts/build-packages.sh"

    # Agents verify every package against a key compiled into them and install
    # nothing that fails, and the hub refuses to advertise a release with no
    # signature beside it. So signing is not a release step that can be skipped
    # - an unsigned build is one the fleet will simply never take.
    echo "[*] Signing packages with the release key..."
    "${ROOT_DIR}/scripts/sign-release.sh"

    echo "[*] Shipping hub build and agent packages to the hub host..."
    if [ -x "${DEPLOY_CMD}" ]; then
        OMINULL_RELEASE_VERSION="${VERSION}" "${DEPLOY_CMD}"
    else
        echo "[-] No deploy command at ${DEPLOY_CMD}."
        echo "    Set OMINULL_DEPLOY_CMD, or copy scripts/deploy_remote.sh.example to"
        echo "    scripts/deploy_remote.sh and fill in this deployment's hub host."
        exit 1
    fi
fi

if [ "${DO_AGENTS}" -eq 0 ]; then
    echo "[+] Hub is running v${VERSION}. Agents not rolled (--hub-only)."
    exit 0
fi

ADMIN_KEY="${OMINULL_ADMIN_KEY:?export OMINULL_ADMIN_KEY to roll the agent fleet}"
api() {
    curl -fsS -X "$1" -H "X-API-Key: ${ADMIN_KEY}" -H "Content-Type: application/json" \
        ${3:+-d "$3"} "${HUB_URL}$2"
}

# The roll-out phase talks to a running hub. If it cannot, the release stops here
# rather than continuing to a convergence check that cannot mean anything.
if ! api GET /api/v1/agents/update-status >/dev/null 2>&1; then
    echo "[-] The hub at ${HUB_URL} did not answer, so no endpoint can be told about"
    echo "    v${VERSION}. The packages are built, signed and published, but the fleet"
    echo "    is still on the previous agent."
    echo "    Set OMINULL_HUB_URL to this hub's address (the default assumes the hub"
    echo "    runs on this machine), or re-run with --hub-only if that is intended."
    exit 1
fi

echo "[*] Publishing agent v${VERSION} to every outdated endpoint..."
api POST /api/v1/agents/update "{\"all\":true,\"version\":\"${VERSION}\"}" | jq . 2>/dev/null || true

if [ "${WAIT_FOR_AGENTS}" -eq 0 ]; then
    echo "[+] Roll-out published. Agents apply it on their next telemetry heartbeat."
    exit 0
fi

# Agents pick the update up on their telemetry heartbeat, install it, and are restarted
# by the package's postinst; the job only retires once one reports the new version back.
echo "[*] Waiting for endpoints to report v${VERSION} (up to 5 minutes)..."
# A hub that does not answer is not a converged fleet. The check used to fall back
# to '{}' on a failed call, and an empty object has no .outdated, so a length of 0
# came back and the release announced the whole fleet was on the new version without
# ever having reached a hub. Silence is now counted, and reported as silence.
unreachable=0
for _ in $(seq 1 60); do
    if ! status="$(api GET /api/v1/agents/update-status)"; then
        unreachable=$((unreachable + 1))
        if [ "${unreachable}" -ge 3 ]; then
            echo "[-] The hub at ${HUB_URL} stopped answering during the roll-out."
            echo "    The fleet's version is unknown; it is not confirmed on v${VERSION}."
            exit 1
        fi
        echo "    Hub did not answer (${unreachable}/3)..."
        sleep 5
        continue
    fi
    unreachable=0
    if ! outdated="$(printf '%s' "${status}" | jq -e '(.outdated // []) | length' 2>/dev/null)"; then
        echo "    Hub answered with something this script could not read; retrying..."
        sleep 5
        continue
    fi
    if [ "${outdated}" = "0" ]; then
        echo "[+] Entire fleet is running agent v${VERSION}."
        exit 0
    fi
    echo "    ${outdated} endpoint(s) still outdated..."
    sleep 5
done

echo "[!] Fleet did not fully converge within the timeout. Remaining:"
api GET /api/v1/agents/update-status | jq '.outdated' 2>/dev/null || true
echo "    Endpoints still on an agent from before self-update shipped need one manual"
echo "    push to get onto a build that can update itself:"
echo "    scripts/ominull-cli deploy <ip> <user> <password>"
exit 1
