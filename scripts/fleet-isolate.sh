#!/bin/bash
HUB_URL="http://10.0.0.58:9999"
API_KEY="<redacted-rotated-key>"
echo "[!] ACTIVATING EMERGENCY FLEET-WIDE NETWORK QUARANTINE..."
curl -s -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"scope":"all"}' "$HUB_URL/api/v1/endpoints/isolate-bulk" | jq .
