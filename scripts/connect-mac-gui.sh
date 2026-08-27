#!/bin/bash
echo "[*] Launching Screen Sharing / VNC GUI for macOS Sonoma (10.0.0.63)..."
if command -v remmina >/dev/null 2>&1; then
    remmina vnc://operator:operator@10.0.0.63:5900 &
elif command -v vncviewer >/dev/null 2>&1; then
    vncviewer 10.0.0.63:5900 &
else
    echo "[*] Open Proxmox Console for VM 114: https://10.0.0.39:8006/?console=kvm&novnc=1&vmid=114&vmname=macOS-Sonoma"
fi
