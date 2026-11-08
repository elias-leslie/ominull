#!/usr/bin/env bash
# release.sh batches agent releases: none when nothing the agents ship changed
# since the last "Release" commit (a hub change deploys alone through
# scripts/deploy-hub.sh), and goes out whenever something shipped changed.
# Runs release.sh in a scratch repository; a run that passes the guard goes on
# and stops at whatever the scratch repository lacks (scripts/version.sh).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/scripts/lib" "${work}/hub/pkg" "${work}/agent/tests"
cp "${ROOT_DIR}/scripts/release.sh" "${work}/scripts/release.sh"
cp "${ROOT_DIR}/scripts/lib/hub-admin-key.sh" "${work}/scripts/lib/hub-admin-key.sh"
cd "${work}"
# The batching guard runs before the hub is asked anything; placeholders keep
# release.sh from reading the production key in this scratch repository.
export OMINULL_HUB_URL=https://hub.invalid:9443 OMINULL_ADMIN_KEY=placeholder
git init -q
git config user.email test@example.invalid
git config user.name test
echo 'package pkg' > hub/pkg/a.go
echo 'int x;' > agent/tests/t.c
git add -A
git commit -qm "Release 1.0.0 (hub only): first"

failures=0
expect() {
    local want="$1"; shift
    local out
    out="$(env -u OMINULL_SIGNING_ROUTINE -u OMINULL_DEPLOY_CMD bash scripts/release.sh "$@" 2>&1 || true)"
    if ! grep -qF -- "${want}" <<<"${out}"; then
        echo "FAIL: release.sh $* should say: ${want}" >&2
        echo "${out}" | sed 's/^/    /' >&2
        failures=$((failures + 1))
    fi
}
passed="version.sh"
expect_not_batched() {
    local out
    out="$(env -u OMINULL_SIGNING_ROUTINE -u OMINULL_DEPLOY_CMD bash scripts/release.sh "$@" 2>&1 || true)"
    if grep -qE 'nothing to release' <<<"${out}"; then
        echo "FAIL: release.sh $* should not be held back:" >&2
        echo "${out}" | sed 's/^/    /' >&2
        failures=$((failures + 1))
    fi
}

expect "Nothing the agents ship has changed since Release 1.0.0; nothing to release (a hub change: scripts/deploy-hub.sh)."
echo 'int y;' >> agent/tests/t.c
echo 'package pkg // test' > hub/pkg/a_test.go
mkdir -p hub/pkg/x/testdata && echo '{}' > hub/pkg/x/testdata/f.json
git add -A && git commit -qm "tests"
expect "nothing to release" # tests ship no bytes
expect_not_batched --agents-only # rolling agents is not a hub release
echo '// changed' >> hub/pkg/a.go
expect "nothing to release" # only committed changes count
git add -A && git commit -qm "hub change"
expect "nothing to release" # a hub change deploys on its own (scripts/deploy-hub.sh)
echo 'int z;' > agent/a.c
git add -A && git commit -qm "agent change"
expect "${passed}" # an agent change goes out at once, however recent the last release
git add -A
GIT_COMMITTER_DATE="$(date -d "-2 days" -R)" git commit -q --allow-empty -m "Release 1.0.1: older"
expect "nothing to release"
mkdir -p screen/helper && echo 'fn main() {}' > screen/helper/main.rs
git add -A && git commit -qm "screen helper change"
expect "${passed}" # the screen helper ships in the Windows package

if [ "${failures}" -ne 0 ]; then
    echo "${failures} release batching check(s) failed" >&2
    exit 1
fi
echo "release batching: ok"
