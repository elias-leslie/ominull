#!/bin/bash
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
API_KEY="${OMINULL_API_KEY:?export OMINULL_API_KEY with the hub admin key}"
echo "[!] ACTIVATING EMERGENCY FLEET-WIDE NETWORK QUARANTINE..."
curl -s -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"scope":"all"}' "$HUB_URL/api/v1/endpoints/isolate-bulk" | jq .
