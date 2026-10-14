#!/bin/bash
# Release every endpoint's isolation. The hub holds this for the owner's phone approval.
set -euo pipefail
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
: "${OMINULL_API_KEY:?export OMINULL_API_KEY with the hub admin key}"
# shellcheck source=scripts/owner-approval.sh
. "$(dirname "${BASH_SOURCE[0]}")/owner-approval.sh"
echo "[+] LIFTING NETWORK QUARANTINE ACROSS FLEET..."
owner_approved "${HUB_URL}" OMINULL_API_KEY /api/v1/endpoints/unisolate-bulk '{"scope":"all"}' | jq .
