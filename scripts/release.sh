#!/usr/bin/env bash
# Canonical Ominull release workflow.
#
# The order is part of the update contract: build and sign the native artifacts,
# deploy the hub (scripts/deploy-hub.sh: build, copy, restart), publish the agent
# packages on it (scripts/publish-agents.sh), install on the Linux machines
# (scripts/update-linux-agents.sh), then ask the running hub to roll the Windows fleet. Every endpoint release is a signed native package. A hub-only
# change needs none of this: scripts/deploy-hub.sh alone puts it live.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Unset OMINULL_HUB_URL / OMINULL_ADMIN_KEY come from the owner's production
# config and the hub's own key file (scripts/lib/hub-admin-key.sh).
. "${ROOT_DIR}/scripts/lib/hub-admin-key.sh"
case " $* " in *" -h "*|*" --help "*|*" --hub-only "*) ;; *) hub_admin_key_from_config || exit 1 ;; esac
HUB_URL="${OMINULL_HUB_URL:-}"

VERSION=""
SKIP_TESTS=0
DO_HUB=1
DO_AGENTS=1
WAIT_FOR_AGENTS=1
CANARY_IDS=""
# A hub release goes out whenever something it ships changed; none when nothing
# did (docs/project-guide.md, "Releases"). Thresholds are tuning data on the hub,
# so a threshold change needs no release at all.

usage() {
    sed -n '2,8p' "$0"
    cat <<'EOF'

Options:
  --version X.Y.Z  release version (otherwise use VERSION)
  --canary IDS     comma-separated endpoint IDs to do first: Linux ones head the Linux
                   run; the hub rolls Windows ones, then the rest once they are healthy
  --skip-tests     skip local quality tests (never skips signing or live checks)
  --hub-only       deploy the hub only (runs scripts/deploy-hub.sh: no version, no signing)
  --agents-only    skip build/deploy; roll agents against an already-live hub
  --no-wait        queue the update and return without claiming convergence

Batching: refuses when nothing the agents ship (agent, packaging, screen, the build
scripts; tests and docs excluded) changed since the last "Release X.Y.Z" commit.

Gates (skipped by --skip-tests): gofmt, hub go test -race and vet, topology and router
script tests, release header/convergence/batching tests, the Linux installer test, bash -n on the release scripts,
BPF build and the Linux collector feedback loops, fuzz-agent.sh --regress; then build,
sign, fresh-install verify, package lifecycle, deploy-hub.sh, publish-agents.sh, the Linux
machines (update-linux-agents.sh), then the hub's Windows rollout.

Environment:
  OMINULL_SIGNING_BACKEND, OMINULL_SIGNING_COMMAND   signer (sign-release.sh)
  OMINULL_HUB_URL, OMINULL_ADMIN_KEY   hub API; unset: read from the production config
  BPFTOOL                       bpftool path for build-bpf.sh (e.g. /usr/sbin/bpftool)

Run it under st tools run (heavy lane). The exact command (signer) is in the private
operations brief, "Gates and release".
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
if [ "${DO_AGENTS}" -eq 0 ]; then
    exec "${ROOT_DIR}/scripts/deploy-hub.sh"
fi

if [ "${DO_HUB}" -eq 1 ]; then
    # The last release is the last "Release X.Y.Z" commit. What ships is the
    # agents and their packaging; tests and docs change no bytes, and a hub
    # change deploys on its own (scripts/deploy-hub.sh). That commit lands after
    # the build, so agent work committed meanwhile sits behind it and never
    # shipped: compare with the commit the release was built from, VERSION.source.
    last_release="$(git -C "${ROOT_DIR}" log -1 --format='%H %ct %s' --grep='^Release [0-9]' 2>/dev/null || true)"
    if [ -n "${last_release}" ]; then
        read -r last_sha _ last_subject <<<"${last_release}"
        last_name="$(printf '%s' "${last_subject}" | cut -d' ' -f1-2 | sed -E 's/[.:]+$//')"
        # Committed changes only: a rerun after a failed run must not count
        # the version bump that run left in the working tree.
        built_from="$(git -C "${ROOT_DIR}" show HEAD:VERSION.source 2>/dev/null | tr -d '[:space:]' || true)"
        if ! git -C "${ROOT_DIR}" merge-base --is-ancestor "${built_from:-none}" HEAD 2>/dev/null; then
            built_from="${last_sha}"
        fi
        shipped="$(git -C "${ROOT_DIR}" diff --name-only "${built_from}" HEAD -- agent packaging screen \
            scripts/build.sh scripts/build-packages.sh scripts/lib/native-sign.sh scripts/build-linux-agent.sh scripts/build-bpf.sh scripts/build-hub-input.sh \
            ':(exclude)*_test.go' ':(exclude)agent/tests' ':(exclude,glob)hub/**/testdata/**' ':(exclude)*.md')"
        if [ -z "${shipped}" ]; then
            echo "[-] Nothing the agents ship has changed since ${last_name}; nothing to release (a hub change: scripts/deploy-hub.sh)." >&2
            exit 1
        fi
    fi
    # The gates and package builds read the working tree, so another session's
    # unfinished work would ship. A failed run leaves its one-line version bumps.
    dirty="$(git -C "${ROOT_DIR}" status --porcelain -- agent hub packaging packages screen scripts)"
    for f in agent/include/agent.h agent/linux/main.c hub/cmd/main.go; do
        if [ "$(git -C "${ROOT_DIR}" diff --numstat -- "${f}" | cut -f1,2)" = "$(printf '1\t1')" ] &&
            # Only the version line: any other one-line change is someone's work.
            ! git -C "${ROOT_DIR}" diff -U0 -- "${f}" | grep -E '^[-+][^-+]' | grep -qvE 'VERSION|defaultAgentVersion'; then
            dirty="$(printf '%s\n' "${dirty}" | grep -vF " ${f}" || true)"
        fi
    done
    if [ -n "${dirty}" ]; then
        echo "[-] Uncommitted files would ship; release from a clean worktree (docs/RELEASE.md):" >&2
        printf '%s\n' "${dirty}" >&2
        exit 1
    fi
fi

if [ -n "${VERSION}" ]; then
    "${ROOT_DIR}/scripts/version.sh" bump "${VERSION}"
else
    VERSION="$("${ROOT_DIR}/scripts/version.sh" show)"
    "${ROOT_DIR}/scripts/version.sh" check
fi
if [ "${DO_HUB}" -eq 1 ]; then
    git -C "${ROOT_DIR}" rev-parse HEAD > "${ROOT_DIR}/VERSION.source"
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
    bash "${ROOT_DIR}/scripts/check-topology.sh"
    python3 "${ROOT_DIR}/scripts/router/test-address-filter.py"
    python3 "${ROOT_DIR}/scripts/router/test-dhcp-fingerprint.py"
    python3 "${ROOT_DIR}/scripts/router/test-poll-delivery.py"
    python3 "${ROOT_DIR}/scripts/test-proveout-weekly.py"
    python3 "${ROOT_DIR}/scripts/test-release-headers.py"
    python3 "${ROOT_DIR}/scripts/test-release-convergence.py"
    bash "${ROOT_DIR}/scripts/test-release-batching.sh"
    bash "${ROOT_DIR}/scripts/test-install-agent-deb.sh"
    bash "${ROOT_DIR}/scripts/test-deploy-hub-rollback.sh"
    bash "${ROOT_DIR}/scripts/test-update-linux-agents.sh"
    bash "${ROOT_DIR}/scripts/test-posture-collect.sh"
    bash "${ROOT_DIR}/scripts/test-native-sign.sh"
    # bash -n reads only its first file.
    for script in build-packages.sh sign-release.sh lib/native-sign.sh sign-trust-bundle.sh update-linux-agents.sh posture-collect.sh lib/install-agent-deb.sh \
        deploy-hub.sh publish-agents.sh pve/install.sh lib/hub-admin-key.sh retire-macos-agent.sh retire-hub-host-agent.sh \
        test-package-lifecycle.sh; do
        bash -n "${ROOT_DIR}/scripts/${script}"
    done

    bash "${ROOT_DIR}/scripts/build-bpf.sh"
    echo "[*] Running Linux collector and isolation feedback loops."
    mkdir -p "${ROOT_DIR}/build"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_baseline" "${ROOT_DIR}/agent/tests/test_baseline.c" -lbpf -lcurl
    "${ROOT_DIR}/build/test_baseline"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_linux_collector" "${ROOT_DIR}/agent/tests/test_linux_collector.c" -lbpf -lcurl
    "${ROOT_DIR}/build/test_linux_collector"
    bash "${ROOT_DIR}/scripts/test-native-telemetry.sh"
    bash "${ROOT_DIR}/scripts/test-native-ipv6.sh"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_process_lineage_linux" "${ROOT_DIR}/agent/tests/test_process_lineage_linux.c"
    "${ROOT_DIR}/build/test_process_lineage_linux"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_session_block_linux" "${ROOT_DIR}/agent/tests/test_session_block_linux.c"
    "${ROOT_DIR}/build/test_session_block_linux"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_der_sig" "${ROOT_DIR}/agent/tests/test_der_sig.c"
    "${ROOT_DIR}/build/test_der_sig"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_response_dispatcher" "${ROOT_DIR}/agent/tests/test_response_dispatcher.c"
    (cd "${ROOT_DIR}" && ./build/test_response_dispatcher)
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_data_inventory_linux" "${ROOT_DIR}/agent/tests/test_data_inventory_linux.c"
    "${ROOT_DIR}/build/test_data_inventory_linux"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_terminal_frame" "${ROOT_DIR}/agent/tests/test_terminal_frame.c"
    "${ROOT_DIR}/build/test_terminal_frame"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_gzip_encode" "${ROOT_DIR}/agent/tests/test_gzip_encode.c" -lz
    "${ROOT_DIR}/build/test_gzip_encode"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_terminal_linux" "${ROOT_DIR}/agent/tests/test_terminal_linux.c" -lcurl -lutil
    "${ROOT_DIR}/build/test_terminal_linux"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_script_exec_linux" "${ROOT_DIR}/agent/tests/test_script_exec_linux.c"
    "${ROOT_DIR}/build/test_script_exec_linux"
    gcc -O2 -Wall -Wextra -Wformat=2 -I"${ROOT_DIR}/agent/include" \
        -o "${ROOT_DIR}/build/test_cert_renewal" "${ROOT_DIR}/agent/tests/test_cert_renewal.c"
    "${ROOT_DIR}/build/test_cert_renewal"
    echo "[*] Replaying the hub-input fuzz seeds and fixed crashes under ASan/UBSan."
    # With the Rust library switched in, as the agent ships.
    FUZZ_HUB_INPUT=1 "${ROOT_DIR}/scripts/fuzz-agent.sh" --regress
    echo "[*] Comparing the Rust hub-input library with the C readers, and running the agent tests on it."
    "${ROOT_DIR}/scripts/test-agent-hub-input.sh"
fi

if [ "${DO_HUB}" -eq 1 ]; then
    echo "[*] Building native packages for v${VERSION}."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/build-packages.sh"
    echo "[*] Signing native packages for v${VERSION}."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/sign-release.sh"
    # A fresh install verifies the published package with the key the hub's
    # bootstrap embeds, not the one the running agents pin. A rotation release
    # signed only with the outgoing key left every new install refusing the
    # package (1.8.71); this gate is never skipped.
    echo "[*] Verifying the published packages as a fresh install will."
    (cd "${ROOT_DIR}/hub" && OMINULL_FRESH_INSTALL_DIST="${ROOT_DIR}/dist" OMINULL_RELEASE_VERSION="${VERSION}" \
        go test -count=1 -run TestPublishedPackagesVerifyForFreshInstall ./pkg/bootstrap)
    echo "[*] Verifying native package lifecycle in an isolated root."
    OMINULL_RELEASE_VERSION="${VERSION}" \
        "${ROOT_DIR}/scripts/test-package-lifecycle.sh"
    echo "[*] Deploying the hub first, then publishing the signed endpoint packages on it."
    "${ROOT_DIR}/scripts/deploy-hub.sh"
    "${ROOT_DIR}/scripts/publish-agents.sh" "${VERSION}"
    # A workstation copy of ominullctl left from an older release misread
    # newer command lines (agents update took a second id as the version), so
    # an existing copy on the operator's PATH is refreshed with this build.
    ctl_copy="${OMINULL_CTL_COPY:-${HOME}/.local/bin/ominullctl}"
    if [ -f "${ctl_copy}" ] && [ -x "${ROOT_DIR}/build/ominullctl" ]; then
        install -m 0775 "${ROOT_DIR}/build/ominullctl" "${ctl_copy}" && echo "[+] Refreshed ${ctl_copy}."
    fi
fi

if [ "${DO_AGENTS}" -eq 0 ]; then
    echo "[+] Hub package v${VERSION} deployed. Agent rollout not requested."
    exit 0
fi

[ -n "${HUB_URL}" ] || {
    echo "[-] OMINULL_HUB_URL is required for an agent rollout." >&2
    exit 1
}
: "${OMINULL_ADMIN_KEY:?export OMINULL_ADMIN_KEY for the rollout phase}"

# Linux machines take the package over root access, not from the hub. One failure
# stops the release here, before any Windows machine is queued.
if [ "${WAIT_FOR_AGENTS}" -eq 1 ]; then
    "${ROOT_DIR}/scripts/update-linux-agents.sh" "${VERSION}" ${CANARY_IDS:+--canary "${CANARY_IDS}"}
else
    echo "[*] --no-wait: Linux machines not touched; run scripts/update-linux-agents.sh ${VERSION}."
fi

hdr() {
    hub_curl_config "${OMINULL_ADMIN_KEY}" "${HUB_URL}"
}

api() {
    local method="$1" path="$2" body="${3:-}"
    exec 3< <(hdr)
    if [ -n "${body}" ]; then
        curl -fsS --connect-timeout 5 --max-time 20 -X "${method}" \
            -K /dev/fd/3 -H 'Content-Type: application/json' \
            --data "${body}" "${HUB_URL}${path}"
    else
        curl -fsS --connect-timeout 5 --max-time 20 -X "${method}" \
            -K /dev/fd/3 "${HUB_URL}${path}"
    fi
}


. "${ROOT_DIR}/scripts/hub-request.sh"
hub_url_safe "${HUB_URL}" || exit 1

target_json() {
    jq -cn --arg ids "${1}" '$ids | split(",") | map(gsub("^[[:space:]]+|[[:space:]]+$"; "")) | map(select(length > 0))'
}

queue() {
    local ids="$1" canary="${2:-}" body
    if [ -n "${canary}" ]; then
        # One request for the release: the hub queues the canaries and holds
        # the rest until the canaries are healthy (or halts the rollout).
        body="$(jq -cn --arg version "${VERSION}" --argjson canary "$(target_json "${canary}")" \
            '{all:true,version:$version,canary:$canary}')"
    elif [ -n "${ids}" ]; then
        body="$(jq -cn --arg version "${VERSION}" --argjson ids "$(target_json "${ids}")" \
            '{endpoint_ids:$ids,version:$version}')"
    else
        body="$(jq -cn --arg version "${VERSION}" '{all:true,version:$version}')"
    fi
    # The hub authorizes the agent update itself.
    hub_post "${HUB_URL}" OMINULL_ADMIN_KEY /api/v1/agents/update "${body}"
}

validate_status() {
    jq -e --arg version "${VERSION}" '
        def identifier: type == "string" and length > 0;
        type == "object" and .latest_version == $version and
        (.endpoints | type == "array" and length > 0) and
        all(.endpoints[];
            type == "object" and (.endpoint_id | identifier) and
            (.driver_version | identifier) and (.status == "online" or .status == "offline")) and
        ([.endpoints[].endpoint_id] | length == (unique | length)) and
        (. as $status | all(["outdated", "provenance_issues", "retired", "pending"][];
            . as $key | $status | has($key) and
            (.[$key] | . == null or (type == "array" and all(.[];
                type == "object" and (.endpoint_id | identifier))))))
    ' >/dev/null
}

wait_for() {
    local ids="$1" status remaining native unavailable
    status='{}'
    local ids_json="${COHORT_IDS_JSON}"
    if [ -n "${ids}" ]; then ids_json="$(target_json "${ids}")"; fi
    local scope="online cohort"
    if [ -n "${ids}" ]; then scope="canary endpoints"; fi
    echo "[*] Waiting for ${scope} to report v${VERSION}."
    for _ in $(seq 1 60); do
        if ! status="$(api GET /api/v1/agents/update-status 2>/dev/null)"; then
            echo "    Hub did not answer; retrying."
            sleep 5
            continue
        fi
        if ! printf '%s' "${status}" | validate_status ||
           ! printf '%s' "${status}" | jq -e --argjson ids "${ids_json}" '
               [.endpoints[].endpoint_id] as $observed |
               ($ids | length > 0) and all($ids[]; . as $id | $observed | index($id) != null)
           ' >/dev/null; then
            echo "[-] Update status lacks valid requested-version or captured endpoint observations; convergence is unverified." >&2
            return 1
        fi
        remaining="$(printf '%s' "${status}" | jq -r --argjson ids "${ids_json}" --arg version "${VERSION}" '
            [.endpoints[] | select(.endpoint_id as $id | ($ids | index($id)) != null) |
             select(.driver_version != $version) | .endpoint_id] +
            [.outdated[]? | select(.endpoint_id as $id | ($ids | index($id)) != null) | .endpoint_id] |
            unique | length')"
        native="$(printf '%s' "${status}" | jq -r --argjson ids "${ids_json}" \
            '[.provenance_issues[]? | select(.endpoint_id as $id | ($ids | index($id)) != null)] | length')"
        unavailable="$(printf '%s' "${status}" | jq -r --argjson ids "${ids_json}" \
            '[.endpoints[] | select(.endpoint_id as $id | ($ids | index($id)) != null) | select(.status != "online")] | length')"
        if [ "${remaining}" = "0" ] && [ "${native}" = "0" ] && [ "${unavailable}" = "0" ]; then
            echo "[+] ${scope} converged on v${VERSION}; native provenance gate passed."
            if [ -z "${ids}" ]; then
                printf '%s' "${status}" | jq -c --argjson offline "${OFFLINE_IDS_JSON}" '
                    ([.outdated[]?.endpoint_id, .provenance_issues[]?.endpoint_id, .pending[]?.endpoint_id] | unique) as $unresolved |
                    [.endpoints[].endpoint_id] as $observed |
                    {offline_pending_count: ([$offline[] | select(. as $id | ($unresolved | index($id)) != null or ($observed | index($id)) == null)] | length),
                     offline_at_start_count: ($offline | length),
                     fleet_outdated_count: ((.outdated // []) | length),
                     fleet_provenance_issue_count: ((.provenance_issues // []) | length),
                     fleet_pending_count: ((.pending // []) | length)}'
            fi
            return 0
        fi
        echo "    ${remaining} not at requested version, ${native} provenance issue(s), ${unavailable} required endpoint(s) offline."
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

# Freeze required observations before the first queue, including the canary phase.
# Offline-at-start endpoints still receive jobs but do not extend the release wait.
INITIAL_STATUS="$(api GET /api/v1/agents/update-status)" || {
    echo "[-] Live hub did not answer; no rollout was queued." >&2
    exit 1
}
if ! printf '%s' "${INITIAL_STATUS}" | validate_status; then
    echo "[-] Invalid update-status schema or requested version; no rollout was queued." >&2
    exit 1
fi
CANARY_IDS_JSON="$(target_json "${CANARY_IDS}")"
if ! printf '%s' "${INITIAL_STATUS}" | jq -e --argjson ids "${CANARY_IDS_JSON}" '
    [.endpoints[].endpoint_id] as $observed |
    all($ids[]; . as $id | $observed | index($id) != null)
' >/dev/null || { [ -n "${CANARY_IDS}" ] && [ "${CANARY_IDS_JSON}" = "[]" ]; }; then
    echo "[-] Canary endpoints are absent or invalid; no rollout was queued." >&2
    exit 1
fi
COHORT_IDS_JSON="$(printf '%s' "${INITIAL_STATUS}" | jq -c --argjson canaries "${CANARY_IDS_JSON}" \
    '[.endpoints[] | select(.status == "online") | .endpoint_id] + $canaries | unique')"
# Linux canaries went first above, so the hub is asked for the Windows ones only.
HUB_CANARIES="$(printf '%s' "${INITIAL_STATUS}" | jq -r --argjson ids "${CANARY_IDS_JSON}" \
    '[.endpoints[] | select(.endpoint_id as $id | $ids | index($id) != null)
      | select((.os // "") | ascii_downcase | contains("linux") | not) | .endpoint_id] | join(",")')"
if [ -n "${CANARY_IDS}" ] && [ -z "${HUB_CANARIES}" ] && [ "${WAIT_FOR_AGENTS}" -eq 0 ]; then
    # The Linux canaries were not touched, so nothing has earned the rest a go.
    echo "[+] --no-wait: Linux canaries not installed; full-fleet queue deferred."
    exit 0
fi
# With every Windows machine named there is no rest to hold, and the hub refuses
# such a staged rollout.
if [ -n "${HUB_CANARIES}" ] && printf '%s' "${INITIAL_STATUS}" | jq -e --argjson ids "$(target_json "${HUB_CANARIES}")" '
    [.endpoints[] | select((.os // "") | ascii_downcase | contains("linux") | not)
     | select(.endpoint_id as $id | $ids | index($id) == null)] | length == 0' >/dev/null; then
    HUB_CANARIES=""
fi
OFFLINE_IDS_JSON="$(printf '%s' "${INITIAL_STATUS}" | jq -c --argjson required "${COHORT_IDS_JSON}" \
    '[.endpoints[] | select(.status == "offline") | .endpoint_id | select(. as $id | ($required | index($id)) == null)]')"
if [ "${WAIT_FOR_AGENTS}" -eq 1 ] && [ "${COHORT_IDS_JSON}" = "[]" ]; then
    echo "[-] No online cohort or explicit canary can be verified; no rollout was queued. Use --no-wait to queue only." >&2
    exit 1
fi

# wait_rollout follows the staged rollout the hub created (by id) until it
# releases the fleet or halts. The hub judges the canaries itself.
wait_rollout() {
    local id="$1" status state detail
    echo "[*] Waiting for the hub to release the fleet after the canaries."
    # The hub halts a rollout whose canaries are not healthy within 30 minutes.
    for _ in $(seq 1 420); do
        if ! status="$(api GET /api/v1/agents/update-status 2>/dev/null)"; then
            sleep 5
            continue
        fi
        state="$(printf '%s' "${status}" | jq -r --arg id "${id}" '[.staged_rollouts[]? | select(.id == $id)][0].state // ""')"
        detail="$(printf '%s' "${status}" | jq -r --arg id "${id}" '[.staged_rollouts[]? | select(.id == $id)][0].detail // ""')"
        case "${state}" in
            released) echo "[+] Hub released the fleet: ${detail}"; return 0 ;;
            halted|superseded) echo "[-] Rollout ${state}: ${detail}" >&2; return 1 ;;
        esac
        sleep 5
    done
    echo "[-] The hub did not release or halt the rollout within 35 minutes." >&2
    return 1
}

if [ -n "${HUB_CANARIES}" ] && printf '%s' "${INITIAL_STATUS}" | jq -e 'has("staged_rollouts")' >/dev/null; then
    STAGED="$(queue "" "${HUB_CANARIES}")" || { echo "[-] The hub refused the staged rollout." >&2; exit 1; }
    printf '%s' "${STAGED}" | jq -c '{desired_version,scheduled_count: ((.scheduled // []) | length),rollout: .rollout.id}'
    ROLLOUT_ID="$(printf '%s' "${STAGED}" | jq -r '.rollout.id // ""')"
    if [ -z "${ROLLOUT_ID}" ]; then
        echo "[-] The hub did not return a staged rollout." >&2
        exit 1
    fi
    if [ "${WAIT_FOR_AGENTS}" -eq 0 ]; then
        echo "[+] Staged rollout ${ROLLOUT_ID} queued: the hub releases the fleet once the canaries are healthy."
        exit 0
    fi
    wait_rollout "${ROLLOUT_ID}"
    wait_for ""
    exit 0
fi

if [ -n "${HUB_CANARIES}" ]; then
    # A hub without staged rollouts would ignore the canary field and update
    # everything at once, so it gets two requests instead.
    queue_report "${HUB_CANARIES}"
    if [ "${WAIT_FOR_AGENTS}" -eq 1 ]; then wait_for "${HUB_CANARIES}"; fi
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
