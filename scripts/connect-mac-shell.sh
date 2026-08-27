#!/bin/bash
MAC_IP="${1:-10.0.0.63}"
MAC_USER="${2:-operator}"

echo "[*] Connecting to macOS Test System (${MAC_IP} as ${MAC_USER})..."
ssh -o StrictHostKeyChecking=no "${MAC_USER}@${MAC_IP}"
