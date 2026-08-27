#!/usr/bin/env bash
set -euo pipefail

PROXMOX_HOST="proxmox-gem"
LXC_VMID="150"
LXC_IP="10.0.0.58"

echo "[*] 1. Building clean Linux amd64 binary..."
cd /srv/workspaces/projects/ominull/hub
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /srv/workspaces/projects/ominull/build/ominull-hub cmd/main.go
echo "[+] Build complete: /srv/workspaces/projects/ominull/build/ominull-hub"

echo "[*] 2. Running local test suite..."
go test -v ./...

echo "[*] 3. Atomically syncing binary to Proxmox LXC ${LXC_VMID} (${LXC_IP})..."
scp /srv/workspaces/projects/ominull/build/ominull-hub ${PROXMOX_HOST}:/tmp/ominull-hub
ssh ${PROXMOX_HOST} "pct push ${LXC_VMID} /tmp/ominull-hub /tmp/ominull-hub.new && pct exec ${LXC_VMID} -- bash -c 'chmod +x /tmp/ominull-hub.new && mv -f /tmp/ominull-hub.new /opt/ominull/bin/ominull-hub'"

echo "[*] 4. Restarting ominull-hub.service inside LXC..."
ssh ${PROXMOX_HOST} "pct exec ${LXC_VMID} -- systemctl restart ominull-hub.service"

echo "[*] 5. Verifying live health check..."
sleep 1
ADMIN_KEY="${OMINULL_ADMIN_KEY:-omi_live_master}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: ${ADMIN_KEY}" http://${LXC_IP}:9999/api/v1/hierarchy || true)
if [ "$STATUS" = "200" ]; then
    echo "[+] SUCCESS: Ominull Hub on LXC ${LXC_VMID} (${LXC_IP}) is healthy and online (HTTP 200)!"
else
    echo "[-] WARNING: Health check returned HTTP ${STATUS}"
    exit 1
fi
