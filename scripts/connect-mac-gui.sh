#!/bin/bash
MAC_IP="${1:-10.0.0.63}"

echo "[*] Launching Screen Sharing / VNC GUI for macOS (${MAC_IP})..."
if command -v remmina >/dev/null 2>&1; then
    remmina vnc://"${MAC_IP}":5900 &
elif command -v vncviewer >/dev/null 2>&1; then
    vncviewer "${MAC_IP}":5900 &
else
    echo "[*] Connect with VNC or via Hypervisor Console."
fi
