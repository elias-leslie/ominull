#!/bin/bash
LINUX_IP="${1:-10.0.0.50}"
LINUX_USER="${2:-operator}"

echo "[*] Connecting to Linux Test System (${LINUX_IP} as ${LINUX_USER})..."
ssh -o StrictHostKeyChecking=no "${LINUX_USER}@${LINUX_IP}"
