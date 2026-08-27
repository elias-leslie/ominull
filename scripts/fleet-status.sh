#!/bin/bash
HUB_URL="http://10.0.0.58:9999"
API_KEY="<redacted-rotated-key>"
echo "=== OMINULL THREAT NULLIFICATION FLEET STATUS ==="
curl -s -H "X-API-Key: $API_KEY" "$HUB_URL/api/v1/endpoints" | jq -r '.[] | "[\(.status | ascii_upcase)] Host: \(.hostname) | OS: \(.os) | IP: \(.ip) | Isolated: \(.is_isolated) | Last Seen: \(.last_seen_at)"'
