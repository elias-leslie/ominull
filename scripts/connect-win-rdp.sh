#!/bin/bash
echo "[*] Launching RDP GUI for Windows 11 Test System (10.0.0.29)..."
if command -v xfreerdp3 >/dev/null 2>&1; then
    xfreerdp3 /v:10.0.0.29:3389 /u:Administrator /p:operator /cert:ignore /dynamic-resolution +clipboard /sound &
elif command -v remmina >/dev/null 2>&1; then
    remmina rdp://Administrator:operator@10.0.0.29 &
else
    echo "[-] Install xfreerdp3 or remmina to launch direct RDP."
fi
