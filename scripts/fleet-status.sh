#!/bin/bash
set -euo pipefail
HUB_URL="${OMINULL_HUB_URL:-http://127.0.0.1:9999}"
: "${OMINULL_API_KEY:?export OMINULL_API_KEY with the hub admin key}"
# shellcheck source=scripts/owner-approval.sh
. "$(dirname "${BASH_SOURCE[0]}")/owner-approval.sh"
hub_url_safe "${HUB_URL}"
echo "=== OMINULL THREAT NULLIFICATION FLEET STATUS ==="
# The key reaches curl on a descriptor, not in its argv.
exec 3< <(hub_curl_config "${OMINULL_API_KEY}" "${HUB_URL}")
curl -s -K /dev/fd/3 "$HUB_URL/api/v1/endpoints" | jq -r '.[] | "[\(.status | ascii_upcase)] Host: \(.hostname) | OS: \(.os) | IP: \(.ip) | Isolated: \(.is_isolated) | Last Seen: \(.last_seen_at)"'
