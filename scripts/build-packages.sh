#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/srv/workspaces/projects/ominull"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="1.1.0"

echo "[*] Building Cross-Platform Release Packages (v${VERSION})..."
mkdir -p "${DIST_DIR}"

# 1. Compile Linux Agent
echo "[*] Compiling Linux AMD64 binary..."
mkdir -p "${ROOT_DIR}/agent/bin"
gcc -O2 -Wall -Wextra -o "${ROOT_DIR}/agent/bin/ominull-agent" "${ROOT_DIR}/agent/linux/main.c"

# 2. Build Debian/Ubuntu .deb Package
echo "[*] Packaging Debian/Ubuntu .deb package..."
DEB_DIR="${DIST_DIR}/deb-build/ominull-agent_${VERSION}_amd64"
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/opt/ominull/bin"
mkdir -p "${DEB_DIR}/etc/systemd/system"

cp "${ROOT_DIR}/agent/bin/ominull-agent" "${DEB_DIR}/opt/ominull/bin/ominulld"
chmod 755 "${DEB_DIR}/opt/ominull/bin/ominulld"

cat << 'DEB_CONTROL' > "${DEB_DIR}/DEBIAN/control"
Package: ominull-agent
Version: 1.1.0
Section: security
Priority: optional
Architecture: amd64
Maintainer: Ominull Project <secops@example.com>
Description: Ominull Linux Kernel Threat Nullification & Flow Telemetry Agent
 Ominull provides microsecond ring-0 / eBPF network flow filtering,
 off-hours anomaly detection, and autonomous lateral threat containment.
DEB_CONTROL

cat << 'DEB_POSTINST' > "${DEB_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable ominull.service || true
    systemctl start ominull.service || true
fi
exit 0
DEB_POSTINST
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

cat << 'DEB_PRERM' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop ominull.service || true
    systemctl disable ominull.service || true
fi
exit 0
DEB_PRERM
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

cat << 'DEB_SERVICE' > "${DEB_DIR}/etc/systemd/system/ominull.service"
[Unit]
Description=Ominull Linux Native Threat Nullification Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/ominull/bin/ominulld https://omi.example.com omi_live_master
Restart=always
RestartSec=5s
KillMode=process

[Install]
WantedBy=multi-user.target
DEB_SERVICE

dpkg-deb --build "${DEB_DIR}" "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"
rm -rf "${DIST_DIR}/deb-build"
echo "  [+] Created: ${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"

# 3. Build Windows Bundle
echo "[*] Packaging Windows Agent bundle..."
WIN_DIR="${DIST_DIR}/win-build"
rm -rf "${WIN_DIR}"
mkdir -p "${WIN_DIR}"

if [ -f "${ROOT_DIR}/agent/bin/ominulld.exe" ]; then
    cp "${ROOT_DIR}/agent/bin/ominulld.exe" "${WIN_DIR}/"
fi

cat << 'WIN_INSTALL' > "${WIN_DIR}/install.ps1"
# Ominull Windows Agent Unattended Installer
param(
    [string]$HubURL = "https://omi.example.com",
    [string]$APIKey = "omi_live_master",
    [string]$Role = "workstation",
    [string]$Location = "loc-home"
)
$InstallDir = "C:\Program Files\Ominull"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item ".\ominulld.exe" -Destination "$InstallDir\ominulld.exe" -Force

# Register Windows Service
sc.exe stop OminullAgent 2>$null | Out-Null
sc.exe delete OminullAgent 2>$null | Out-Null
sc.exe create OminullAgent binPath= "\"$InstallDir\ominulld.exe\" --hub $HubURL --key $APIKey --role $Role --location $Location" start= auto DisplayName= "Ominull Threat Nullification Service"
sc.exe start OminullAgent
Write-Host "[+] Ominull Windows Agent installed and started successfully!" -ForegroundColor Green
WIN_INSTALL

(cd "${DIST_DIR}" && tar -czf "${DIST_DIR}/ominull-agent-windows-${VERSION}.tar.gz" -C "${WIN_DIR}" .)
rm -rf "${WIN_DIR}"
echo "  [+] Created: ${DIST_DIR}/ominull-agent-windows-${VERSION}.tar.gz"

# 4. Build macOS Bundle
echo "[*] Packaging macOS Agent bundle..."
MAC_DIR="${DIST_DIR}/mac-build"
rm -rf "${MAC_DIR}"
mkdir -p "${MAC_DIR}"

if [ -f "${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh" ]; then
    cp "${ROOT_DIR}/agent/macos/ominull_mac_daemon.sh" "${MAC_DIR}/"
fi

cat << 'MAC_PLIST' > "${MAC_DIR}/dev.ominull.daemon.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.ominull.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/ominull_mac_daemon.sh</string>
        <string>https://omi.example.com</string>
        <string>omi_live_master</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
MAC_PLIST

(cd "${DIST_DIR}" && tar -czf "${DIST_DIR}/ominull-agent-macos-${VERSION}.tar.gz" -C "${MAC_DIR}" .)
rm -rf "${MAC_DIR}"
echo "  [+] Created: ${DIST_DIR}/ominull-agent-macos-${VERSION}.tar.gz"

# 5. Generate Checksums
echo "[*] Generating Cryptographic SHA256 Checksums..."
(
    cd "${DIST_DIR}"
    sha256sum ominull-agent_${VERSION}_amd64.deb ominull-agent-windows-${VERSION}.tar.gz ominull-agent-macos-${VERSION}.tar.gz > SHA256SUMS.txt
)
echo "  [+] Checksums recorded in ${DIST_DIR}/SHA256SUMS.txt"

echo "[+] All cross-platform release packages built successfully in ${DIST_DIR}!"
