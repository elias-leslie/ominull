#!/bin/bash
# Sync Nightshift's canary file paths to the hub, so agents skip them in the data
# inventory and the hub drops any that still arrive (docs/DATA_INVENTORY.md).
#
# Nightshift places its canaries on the workstation; every other registered
# endpoint is synced with an empty list (checked, holds none). The hub keeps
# scanning off for an endpoint until it has been synced at least once.
#
#   OMINULL_HUB_URL      hub operator API base, e.g. https://10.0.0.58:9443 (required;
#                        the key travels only over TLS checked against OMINULL_HUB_CA)
#   OMINULL_ADMIN_KEY_FILE  file whose first line is the admin key (required)
#   --endpoint ID        the workstation's endpoint id (default: matched by hostname)
#   --dry-run            print endpoint ids and path counts, send nothing
#
# Key handling: read from the file into a curl config on fd 3, never on a command
# line; paths are never printed.
set -euo pipefail
set +x

HUB_URL="${OMINULL_HUB_URL:?set OMINULL_HUB_URL to the hub operator API base}"
KEY_FILE="${OMINULL_ADMIN_KEY_FILE:?set OMINULL_ADMIN_KEY_FILE to the admin key file}"
# shellcheck source=scripts/owner-approval.sh
. "$(dirname "${BASH_SOURCE[0]}")/owner-approval.sh"
hub_url_safe "$HUB_URL" || exit 1
NIGHTSHIFT="${NIGHTSHIFT_CMD:-nightshift}"
ENDPOINT=""
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) ENDPOINT="${2:?--endpoint needs an id}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "usage: $0 [--endpoint ID] [--dry-run]" >&2; exit 2 ;;
  esac
done

hdr() {
  local ominull_admin_key
  IFS= read -r ominull_admin_key < "$KEY_FILE"
  hub_curl_config "$ominull_admin_key" "$HUB_URL"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

"$NIGHTSHIFT" canary paths --json > "$work/canaries.json"
exec 3< <(hdr)
curl -fsS --max-time 20 -K /dev/fd/3 "$HUB_URL/api/v1/endpoints" > "$work/endpoints.json"

python3 -I - "$work" "$ENDPOINT" "$(hostname)" <<'PY'
import json, sys
work, want, host = sys.argv[1], sys.argv[2], sys.argv[3].lower()
can = json.load(open(f"{work}/canaries.json"))
if can.get("schema") != "nightshift.canary-paths/1":
    sys.exit("unexpected canary list schema")
eps = json.load(open(f"{work}/endpoints.json"))
eps = eps.get("endpoints", eps) if isinstance(eps, dict) else eps
ids = [e["id"] for e in eps if isinstance(e, dict) and e.get("id")]
if not want:
    match = [e["id"] for e in eps if isinstance(e, dict) and str(e.get("hostname", "")).lower() == host]
    if len(match) != 1:
        sys.exit(f"workstation endpoint not found by hostname ({len(match)} matches); pass --endpoint ID")
    want = match[0]
if want not in ids:
    sys.exit("endpoint not registered: " + want)
bad = [str(r.get("name")) for r in can.get("canaries") or [] if r.get("unresolved") or ("unresolved" not in r and not r.get("path") and r.get("host_role"))]
if bad:
    sys.exit("canary placements name no file path (fix them in Nightshift first): " + ", ".join(bad))
paths = set()
for r in can.get("canaries") or []:
    if r.get("host_role") == "workstation":
        paths.update(p for p in (r.get("path"), r.get("real_path")) if p)
body = {"source": "nightshift", "endpoints": [{"endpoint_id": i, "paths": sorted(paths) if i == want else []} for i in ids]}
json.dump(body, open(f"{work}/body.json", "w"))
for e in body["endpoints"]:
    print(f"{e['endpoint_id']}\t{len(e['paths'])} canary path(s)")
PY

if [ "$DRY" = 1 ]; then
  echo "dry run: nothing sent"
  exit 0
fi
exec 3< <(hdr)
curl -fsS --max-time 20 -K /dev/fd/3 -H "Content-Type: application/json" --data-binary "@$work/body.json" \
  "$HUB_URL/api/v1/data/canaries" > /dev/null
echo "synced"
