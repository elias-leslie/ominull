#!/usr/bin/env bash
# Canonical Ominull release workflow.
#
# The order is part of the update contract: build and sign the native artifacts,
# install the hub package, then ask the running hub to roll the retained fleet.
# Every endpoint release is a signed native package. The hub package is
# installed first, then the retained Linux and Windows agents self-update.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUB_URL="${OMINULL_HUB_URL:-}"
DEPLOY_CMD="${OMINULL_DEPLOY_CMD:-${ROOT_DIR}/scripts/deploy_remote.sh}"

VERSION=""
SKIP_TESTS=0
DO_HUB=1
DO_AGENTS=1
WAIT_FOR_AGENTS=1
CANARY_IDS=""

usage() {
    sed -n '2,8p' "$0"
    cat <<'EOF'

Options:
  --version X.Y.Z  release version (otherwise use VERSION)
  --canary IDS     comma-separated endpoint IDs; roll these, verify, then roll all
  --skip-tests     skip local quality tests (never skips signing or live checks)
  --hub-only       build, sign, install hub, and publish artifacts; do not roll agents
  --agents-only    skip build/deploy; roll agents against an already-live hub
  --no-wait        queue the update and return without claiming convergence
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --canary) CANARY_IDS="${2:?--canary needs endpoint IDs}"; shift 2 ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --hub-only) DO_AGENTS=0; shift ;;
        --agents-only) DO_HUB=0; shift ;;
        --no-wait) WAIT_FOR_AGENTS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[-] Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -n "${VERSION}" ]; then
    "${ROOT_DIR}/scripts/version.sh" bump "${VERSION}"
else
    VERSION="$(${ROOT_DIR}/scripts/version.sh show)"
    "${ROOT_DIR}/scripts/version.sh" check
fi

if [ "${DO_HUB}" -eq 1 ] && [ "${SKIP_TESTS}" -eq 0 ]; then
    echo "[*] Running retained quality gates."
    mapfile -t go_files < <(find "${ROOT_DIR}/hub" -name '*.go' -type f -print)
    if [ "${#go_files[@]}" -gt 0 ]; then
        if [ "$(gofmt -l "${go_files[@]}")" ]; then
            echo "[-] gofmt reports unformatted Go files." >&2
            gofmt -l "${go_files[@]}" >&2
            exit 1
        fi
    fi
    (cd "${ROOT_DIR}/hub" && go test -race ./... && go vet ./...)
    node --check "${ROOT_DIR}/hub/pkg/server/web/app.js"
    bash -n "${ROOT_DIR}/scripts/build-packages.sh" "${ROOT_DIR}/scripts/sign-release.sh" \
        "${ROOT_DIR}/scripts/deploy_remote.sh.example" \
        "${ROOT_DIR}/scripts/retire-macos-agent.sh" \
        "${ROOT_DIR}/scripts/retire-hub-host-agent.sh" \
        "${ROOT_DIR}/scripts/test-package-lifecycle.sh"

    echo "[*] Running Linux collector and isolation feedback loops."
    mkdir -p "${ROOT_DIR}/build"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_baseline" "${ROOT_DIR}/agent/tests/test_baseline.c" -lcurl
    "${ROOT_DIR}/build/test_baseline"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_linux_collector" "${ROOT_DIR}/agent/tests/test_linux_collector.c" -lcurl
    "${ROOT_DIR}/build/test_linux_collector"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_der_sig" "${ROOT_DIR}/agent/tests/test_der_sig.c"
    "${ROOT_DIR}/build/test_der_sig"
fi

if [ "${DO_HUB}" -eq 1 ]; then
    [ -x "${DEPLOY_CMD}" ] || {
        echo "[-] Deploy hook is missing or not executable: ${DEPLOY_CMD}" >&2
        echo "    Copy scripts/deploy_remote.sh.example to scripts/deploy_remote.sh and fill only its ignored deployment values." >&2
        exit 1
    }
    echo "[*] Building native packages for v${VERSION}."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/build-packages.sh"
    echo "[*] Signing native packages for v${VERSION}."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/sign-release.sh"
    echo "[*] Verifying native package lifecycle in an isolated root."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/test-package-lifecycle.sh"
    echo "[*] Installing hub package first and publishing signed endpoint packages."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${DEPLOY_CMD}"
fi

if [ "${DO_AGENTS}" -eq 0 ]; then
    echo "[+] Hub package v${VERSION} deployed. Agent rollout not requested."
    exit 0
fi

[ -n "${HUB_URL}" ] || {
    echo "[-] OMINULL_HUB_URL is required for an agent rollout." >&2
    exit 1
}
ADMIN_KEY="${OMINULL_ADMIN_KEY:?export OMINULL_ADMIN_KEY for the rollout phase}"
HEADER_FILE="$(mktemp "${TMPDIR:-/tmp}/ominull-release-header.XXXXXX")"
chmod 0600 "${HEADER_FILE}"
printf 'X-API-Key: %s\n' "${ADMIN_KEY}" > "${HEADER_FILE}"
unset ADMIN_KEY
cleanup() { rm -f -- "${HEADER_FILE}"; }
trap cleanup EXIT

api() {
    local method="$1" path="$2" body="${3:-}"
    if [ -n "${body}" ]; then
        curl -fsS --connect-timeout 5 --max-time 20 -X "${method}" \
            -H "@${HEADER_FILE}" -H 'Content-Type: application/json' \
            --data "${body}" "${HUB_URL}${path}"
    else
        curl -fsS --connect-timeout 5 --max-time 20 -X "${method}" \
            -H "@${HEADER_FILE}" "${HUB_URL}${path}"
    fi
}

api GET /api/v1/agents/update-status >/dev/null || {
    echo "[-] Live hub did not answer at ${HUB_URL}; no rollout was queued." >&2
    exit 1
}

target_json() {
    jq -cn --arg ids "${1}" '$ids | split(",") | map(gsub("^[[:space:]]+|[[:space:]]+$"; "")) | map(select(length > 0))'
}

queue() {
    local ids="$1" body
    if [ -n "${ids}" ]; then
        body="$(jq -cn --arg version "${VERSION}" --argjson ids "$(target_json "${ids}")" \
            '{endpoint_ids:$ids,version:$version}')"
    else
        body="$(jq -cn --arg version "${VERSION}" '{all:true,version:$version}')"
    fi
    api POST /api/v1/agents/update "${body}"
}

wait_for() {
    local ids="$1" status remaining native
    status='{}'
    local ids_json="[]"
    if [ -n "${ids}" ]; then ids_json="$(target_json "${ids}")"; fi
    local scope="retained fleet"
    if [ -n "${ids}" ]; then scope="canary endpoints"; fi
    echo "[*] Waiting for ${scope} to report v${VERSION}."
    for _ in $(seq 1 60); do
        if ! status="$(api GET /api/v1/agents/update-status 2>/dev/null)"; then
            echo "    Hub did not answer; retrying."
            sleep 5
            continue
        fi
        if [ -n "${ids}" ]; then
            remaining="$(printf '%s' "${status}" | jq -r --argjson ids "${ids_json}" \
                '[.outdated[]? | select(.endpoint_id as $id | ($ids | index($id)) != null)] | length')"
            native="$(printf '%s' "${status}" | jq -r --argjson ids "${ids_json}" \
                '[.provenance_issues[]? | select(.endpoint_id as $id | ($ids | index($id)) != null)] | length')"
        else
            remaining="$(printf '%s' "${status}" | jq -r '(.outdated // []) | length')"
            native="$(printf '%s' "${status}" | jq -r '(.provenance_issues // []) | length')"
        fi
        if [ "${remaining}" = "0" ] && [ "${native}" = "0" ]; then
            echo "[+] ${scope} converged on v${VERSION}; native provenance gate passed."
            return 0
        fi
        echo "    ${remaining} outdated, ${native} provenance issue(s)."
        sleep 5
    done
    echo "[-] Rollout did not converge within five minutes." >&2
    printf '%s\n' "${status}" | jq '{outdated_count: ((.outdated // []) | length), provenance_issue_count: ((.provenance_issues // []) | length), retired_count: ((.retired // []) | length), pending_count: ((.pending // []) | length)}' >&2 || true
    return 1
}

queue_report() {
    local ids="$1" response
    response="$(queue "${ids}")"
    printf '%s' "${response}" | jq -c '{desired_version,scheduled_count: ((.scheduled // []) | length),unsupported_count: ((.unsupported // []) | length)}'
}

if [ -n "${CANARY_IDS}" ]; then
    queue_report "${CANARY_IDS}"
    if [ "${WAIT_FOR_AGENTS}" -eq 1 ]; then wait_for "${CANARY_IDS}"; fi
    if [ "${WAIT_FOR_AGENTS}" -eq 0 ]; then
        echo "[+] Canary update queued; full-fleet queue deferred by --no-wait."
        exit 0
    fi
fi

queue_report ""
if [ "${WAIT_FOR_AGENTS}" -eq 0 ]; then
    echo "[+] v${VERSION} queued for retained endpoints."
    exit 0
fi
wait_for ""
