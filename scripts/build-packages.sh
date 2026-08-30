#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="1.7.8"

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
Version: 1.7.8
Section: security
Priority: optional
Architecture: amd64
Depends: curl, openssl
Maintainer: Ominull Project <secops@example.com>
Description: Ominull Linux Kernel Threat Nullification & Flow Telemetry Agent
 Ominull provides microsecond ring-0 / eBPF network flow filtering,
 off-hours anomaly detection, and autonomous lateral threat containment.
DEB_CONTROL

# The agent's hub URL and enrolment key live in an EnvironmentFile that the package
# creates once and never overwrites. This is what makes self-update safe: an upgrade
# replaces the binary and the unit, but an endpoint keeps the credentials it was
# enrolled with instead of reverting to placeholders and dropping off the fleet.
cat << 'DEB_POSTINST' > "${DEB_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
mkdir -p /etc/ominull

# Releases are staged here and nowhere else. It must be root-owned and closed
# to everyone else: the agent downloads a package here, verifies its signature
# and then installs it as root, so a directory any local user could write to
# would let them swap the file between the check and the install.
mkdir -p /var/lib/ominull/updates
chown root:root /var/lib/ominull /var/lib/ominull/updates
chmod 700 /var/lib/ominull/updates

if [ ! -f /etc/ominull/agent.conf ]; then
    cat << 'CONF' > /etc/ominull/agent.conf
# Ominull agent runtime arguments. Written once at install and preserved on upgrade.
OMINULL_ARGS=--hub https://omi.example.com --key <provision-via-bootstrap> --role workstation --location loc-default --ca /etc/ominull/ca.crt
CONF
    chmod 600 /etc/ominull/agent.conf
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable ominull-agent.service || true
    systemctl restart ominull-agent.service || true
fi
exit 0
DEB_POSTINST
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

cat << 'DEB_PRERM' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop ominull-agent.service || true
    # Only a full removal should disable the unit; an upgrade must leave it enabled.
    if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
        systemctl disable ominull-agent.service || true
    fi
fi
exit 0
DEB_PRERM
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

cat << 'DEB_SERVICE' > "${DEB_DIR}/etc/systemd/system/ominull-agent.service"
[Unit]
Description=Ominull Linux Native Threat Nullification Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/ominull/agent.conf
ExecStart=/opt/ominull/bin/ominulld $OMINULL_ARGS
Restart=always
RestartSec=5s
# The agent installs its own upgrades as a detached child; KillMode=process keeps
# systemd from tearing that install down along with the daemon it replaces.
KillMode=process

[Install]
WantedBy=multi-user.target
DEB_SERVICE

# Root, not the build account.
#
# dpkg-deb records whatever owns the build tree, and the build tree is owned by
# whoever ran this script. Every .deb before this one shipped /opt/ominull/bin/
# ominulld and /etc/systemd/system/ominull-agent.service owned by uid 1000, so
# on any endpoint that has a uid-1000 user - which is the first account created
# on a Debian or Ubuntu install - that user owned the root daemon's binary and
# its unit file, and the unit arrived group-writable at 0664. Rewriting
# ExecStart, or simply overwriting the binary and waiting for the next restart,
# was a local user's path to root on every Linux endpoint in the fleet.
chmod 644 "${DEB_DIR}/etc/systemd/system/ominull-agent.service"
find "${DEB_DIR}" -type d -exec chmod 755 {} +
dpkg-deb --root-owner-group --build "${DEB_DIR}" "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"

# Nothing in the package may be owned by anyone but root, or writable by anyone
# but root. A build that regresses this ships a privilege escalation, so it is
# checked here rather than discovered on an endpoint.
bad_owner="$(dpkg-deb -c "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb" | awk '$2 != "root/root"')"
if [ -n "${bad_owner}" ]; then
    echo "[-] These package members are not owned by root/root:" >&2
    echo "${bad_owner}" >&2
    exit 1
fi
bad_mode="$(dpkg-deb -c "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb" | awk '$1 ~ /^[^d].......w./')"
if [ -n "${bad_mode}" ]; then
    echo "[-] These package members are group- or world-writable:" >&2
    echo "${bad_mode}" >&2
    exit 1
fi
rm -rf "${DIST_DIR}/deb-build"
echo "  [+] Created: ${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"

# 3. Build Windows Bundle
echo "[*] Packaging Windows Agent bundle..."
WIN_DIR="${DIST_DIR}/win-build"
rm -rf "${WIN_DIR}"
mkdir -p "${WIN_DIR}"

# Build the Windows agent rather than picking up whatever happens to be lying in
# agent/bin. Shipping the bundle without the binary produced an installer with nothing
# to install, which is how the fleet ended up unable to take a Windows update at all.
# mingw-w64's swprintf follows ANSI C, where %s in a *wide* format string means a
# narrow char*. Handed a wchar_t* it reads the first byte pair as a
# one-character string and prints that. It compiles without a warning and looks
# right in review. It shipped an X-API-Key header reading "X-API-Key: T" - the
# first letter of the key - and went unnoticed for as long as the key was also
# duplicated in the query string, which is what actually authenticated every
# Windows heartbeat. %ls means wide under both conventions and is the only form
# that is correct here.
bad_wide_format=$(grep -rnE 'L"[^"]*%[-0-9.]*s' "${ROOT_DIR}/agent/src" "${ROOT_DIR}/agent/include" || true)
if [ -n "${bad_wide_format}" ]; then
    echo "[-] A wide format string uses %s. Use %ls - %s there is a narrow string to mingw:" >&2
    echo "${bad_wide_format}" >&2
    exit 1
fi

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "  [*] Cross-compiling Windows agent (mingw-w64)..."
    # -DOMINULL_WFP_EMBEDDED drops wfp_user.c's own main(); the same file is also
    # built standalone as ominull_wfp_user.exe, which stays the recovery tool for
    # a host left isolated with no agent running.
    x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -DOMINULL_WFP_EMBEDDED \
        -o "${ROOT_DIR}/agent/bin/ominulld.exe" \
        "${ROOT_DIR}/agent/src/main.c" \
        "${ROOT_DIR}/agent/src/hub_client.c" \
        "${ROOT_DIR}/agent/src/hub_tls.c" \
        "${ROOT_DIR}/agent/src/service.c" \
        "${ROOT_DIR}/agent/src/driver_client.c" \
        "${ROOT_DIR}/agent/src/updater.c" \
        "${ROOT_DIR}/agent/windows/wfp_user.c" \
        -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lfwpuclnt -lole32
    cp "${ROOT_DIR}/agent/bin/ominulld.exe" "${WIN_DIR}/"
elif [ -f "${ROOT_DIR}/agent/bin/ominulld.exe" ]; then
    echo "  [!] mingw-w64 not installed; packaging the previously built ominulld.exe"
    cp "${ROOT_DIR}/agent/bin/ominulld.exe" "${WIN_DIR}/"
else
    echo "  [-] Cannot build the Windows agent: install mingw-w64 (x86_64-w64-mingw32-gcc)." >&2
    exit 1
fi

cat << 'WIN_INSTALL' > "${WIN_DIR}/install.ps1"
# Ominull Windows Agent Unattended Installer
param(
    [string]$HubURL = "https://omi.example.com",
    [string]$APIKey = "<provision-via-bootstrap>",
    [string]$Role = "workstation",
    [string]$Location = "loc-home",
    [string]$CAPath = "C:\Program Files\Ominull\ca.crt"
)
$InstallDir = "C:\Program Files\Ominull"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item ".\ominulld.exe" -Destination "$InstallDir\ominulld.exe" -Force

# The agent verifies the hub against this file and nothing else, so an install
# that cannot find it produces a service that refuses to report rather than one
# that reports in the clear.
if (-not (Test-Path $CAPath)) {
    Write-Host "[!] No CA at $CAPath. Enrol through the hub's bootstrap script, or fetch $HubURL/api/v1/pki/ca.crt to that path first." -ForegroundColor Yellow
}

# Register through the agent's own installer. Registering the binPath by hand omits the
# --service flag the SCM entry point requires, and the service then exits immediately.
# It also stores the key in a SYSTEM-only file and registers --key-file, keeping it off
# a command line that `sc qc` shows to any logged-on user.
& "$InstallDir\ominulld.exe" --uninstall 2>$null | Out-Null
& "$InstallDir\ominulld.exe" --install --hub $HubURL --key $APIKey --role $Role --location $Location --ca $CAPath
sc.exe start ominulld
Write-Host "[+] Ominull Windows Agent installed and started successfully!" -ForegroundColor Green
WIN_INSTALL

# Root-owned and not writable by anyone else, for the same reason the .deb is.
# A tar extracted by root restores the ownership recorded in it, and these
# archives recorded the build account with group-writable modes: a launchd
# plist or a service binary that a local group can rewrite is that group's path
# to root on the endpoint. launchd refuses a group-writable plist outright, so
# this was also a latent enrolment failure.
chmod -R go-w "${WIN_DIR}"
(cd "${DIST_DIR}" && tar --owner=root --group=root --numeric-owner -czf "${DIST_DIR}/ominull-agent-windows-${VERSION}.tar.gz" -C "${WIN_DIR}" .)
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

# The daemon does not enforce anything itself: it shells out to pf_engine.sh for
# every isolation and every mesh quarantine. It was never in this archive, so a
# Mac ran a current daemon against whatever helper its original bootstrap left
# on disk - and a daemon that had learned to say "sync" was talking to a helper
# that only understood "isolate". The hub recorded the quarantine, the daemon
# announced it, and the host stayed on the network. Ship the helper with the
# thing that calls it.
if [ -f "${ROOT_DIR}/agent/macos/pf_engine.sh" ]; then
    cp "${ROOT_DIR}/agent/macos/pf_engine.sh" "${MAC_DIR}/"
else
    echo "  [-] agent/macos/pf_engine.sh is missing; the macOS agent cannot enforce anything without it." >&2
    exit 1
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
        <string><provision-via-bootstrap></string>
        <string>workstation</string>
        <string>loc-home</string>
        <string></string>
        <string>/opt/ominull/ca.crt</string>
        <string>/opt/ominull/client.crt</string>
        <string>/opt/ominull/client.key</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
MAC_PLIST

chmod -R go-w "${MAC_DIR}"
(cd "${DIST_DIR}" && tar --owner=root --group=root --numeric-owner -czf "${DIST_DIR}/ominull-agent-macos-${VERSION}.tar.gz" -C "${MAC_DIR}" .)

for archive in "${DIST_DIR}/ominull-agent-windows-${VERSION}.tar.gz" "${DIST_DIR}/ominull-agent-macos-${VERSION}.tar.gz"; do
    bad="$(tar -tvzf "${archive}" | awk '$2 != "0/0" || $1 ~ /^[^d].......w./')"
    if [ -n "${bad}" ]; then
        echo "[-] ${archive} carries members not owned by root or writable by others:" >&2
        echo "${bad}" >&2
        exit 1
    fi
done

# The macOS daemon enforces nothing on its own; every isolation and every mesh
# quarantine is a call into pf_engine.sh. An archive without it produces a host
# that reports itself quarantined and keeps routing, so it is not a release.
for required in ./ominull_mac_daemon.sh ./pf_engine.sh; do
    if ! tar -tzf "${DIST_DIR}/ominull-agent-macos-${VERSION}.tar.gz" | grep -qx "${required}"; then
        echo "[-] ominull-agent-macos-${VERSION}.tar.gz is missing ${required}; the agent could not enforce anything." >&2
        exit 1
    fi
done
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
