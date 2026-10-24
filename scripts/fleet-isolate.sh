#!/bin/bash
# Isolate every endpoint. The hub authorizes it itself.
set -euo pipefail
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
: "${OMINULL_API_KEY:?export OMINULL_API_KEY with the hub admin key}"
# shellcheck source=scripts/hub-request.sh
. "$(dirname "${BASH_SOURCE[0]}")/hub-request.sh"
echo "[!] ACTIVATING EMERGENCY FLEET-WIDE NETWORK QUARANTINE..."
hub_post "${HUB_URL}" OMINULL_API_KEY /api/v1/endpoints/isolate-bulk '{"scope":"all"}' | jq .
