#!/usr/bin/env bash
# release.sh batches hub releases: none when nothing shipped changed since the
# last "Release" commit, at most one a day unless --urgent gives a reason.
# Runs release.sh in a scratch repository; a run that passes the guard goes on
# and stops at whatever the scratch repository lacks (the deploy hook).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/scripts" "${work}/hub/pkg" "${work}/agent/tests"
cp "${ROOT_DIR}/scripts/release.sh" "${work}/scripts/release.sh"
cd "${work}"
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
passed="Deploy hook is missing"
expect_not_batched() {
    local out
    out="$(env -u OMINULL_SIGNING_ROUTINE -u OMINULL_DEPLOY_CMD bash scripts/release.sh "$@" 2>&1 || true)"
    if grep -qE 'nothing to release|batched to one a day' <<<"${out}"; then
        echo "FAIL: release.sh $* should not be held back:" >&2
        echo "${out}" | sed 's/^/    /' >&2
        failures=$((failures + 1))
    fi
}

expect "Nothing the hub or agents ship has changed since Release 1.0.0; nothing to release."
echo 'int y;' >> agent/tests/t.c
echo 'package pkg // test' > hub/pkg/a_test.go
expect "nothing to release" # tests ship no bytes
expect_not_batched --agents-only # rolling agents is not a hub release
echo '// changed' >> hub/pkg/a.go
expect "went out 0h ago; hub releases are batched to one a day."
expect "${passed}" --urgent "paging false alarm"
expect "Releasing within a day of Release 1.0.0: paging false alarm" --urgent "paging false alarm"
git add -A
GIT_COMMITTER_DATE="$(date -d '-2 days' -R)" git commit -qm "Release 1.0.1: older"
echo '// again' >> hub/pkg/a.go
expect "${passed}"

if [ "${failures}" -ne 0 ]; then
    echo "${failures} release batching check(s) failed" >&2
    exit 1
fi
echo "release batching: ok"
