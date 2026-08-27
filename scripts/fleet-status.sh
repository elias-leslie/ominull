#!/bin/bash
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
API_KEY="${OMINULL_API_KEY:-omi_live_master}"
echo "=== OMINULL THREAT NULLIFICATION FLEET STATUS ==="
curl -s -H "X-API-Key: $API_KEY" "$HUB_URL/api/v1/endpoints" | jq -r '.[] | "[\(.status | ascii_upcase)] Host: \(.hostname) | OS: \(.os) | IP: \(.ip) | Isolated: \(.is_isolated) | Last Seen: \(.last_seen_at)"'
