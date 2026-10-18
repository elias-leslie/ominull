#!/usr/bin/env bash
# Brings the hub's package library in step with the released packages, then
# checks every synced digest is in hub/pkg/responseauth/released_packages.json.
# A library left at an older version makes every run of that package read
# "not a released package" on the owner's approval (1.8.83, windows-reboot).
# Needs OMINULL_HUB_URL, OMINULL_ADMIN_KEY and OMINULL_HUB_CA; CTL names the
# ominullctl to use (default build/ominullctl).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTL="${CTL:-${ROOT_DIR}/build/ominullctl}"
: "${OMINULL_HUB_URL:?}" "${OMINULL_ADMIN_KEY:?}"
out="$(mktemp)"
trap 'rm -f "${out}"' EXIT
for dir in windows linux; do
    "${CTL}" --url "${OMINULL_HUB_URL}" --ca "${OMINULL_HUB_CA:-}" \
        --api-key-file <(printf '%s\n' "${OMINULL_ADMIN_KEY}") --json \
        scripts sync "${ROOT_DIR}/packages/${dir}" >>"${out}"
    echo >>"${out}"
done
python3 -I - "${out}" "${ROOT_DIR}/hub/pkg/responseauth/released_packages.json" <<'PY'
import json, sys
released = json.load(open(sys.argv[2]))
bad = []
dec = json.JSONDecoder()
text = open(sys.argv[1]).read()
i = 0
while True:
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        break
    rows, i = dec.raw_decode(text, i)
    for r in rows:
        rel = released.get(r["digest"])
        print(f"  {r['name']:<26} {r['action']:<9} v{r['version']}")
        if not rel or rel["name"] != r["name"]:
            bad.append(r["name"])
if bad:
    sys.exit("[-] the hub library holds unreleased package sources: " + ", ".join(bad))
print("[+] Package library matches the released packages.")
PY
