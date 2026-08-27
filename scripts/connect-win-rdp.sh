#!/bin/bash
WIN_IP="${1:-10.0.0.29}"
WIN_USER="${2:-Administrator}"

echo "[*] Launching RDP GUI for Windows Test System (${WIN_IP} as ${WIN_USER})..."
if command -v xfreerdp3 >/dev/null 2>&1; then
    xfreerdp3 /v:"${WIN_IP}":3389 /u:"${WIN_USER}" /cert:ignore /dynamic-resolution +clipboard /sound &
elif command -v remmina >/dev/null 2>&1; then
    remmina rdp://"${WIN_USER}"@"${WIN_IP}" &
else
    echo "[-] Install xfreerdp3 or remmina to launch direct RDP."
fi
