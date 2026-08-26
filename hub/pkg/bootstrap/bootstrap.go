package bootstrap

import (
	"fmt"
	"strings"
)

// GeneratePowerShell returns an automated, single-line unattended bootstrap script for Windows.
func GeneratePowerShell(hubURL, tenantAPIKey string) string {
	script := `
# Ominull Automated Endpoint Bootstrap (Windows)
$ErrorActionPreference = "Stop"
$HubURL = "%s"
$APIKey = "%s"
$InstallDir = "$env:ProgramFiles\Ominull"

Write-Host "[+] Initializing Ominull Endpoint Deployment..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[+] Downloading Ominull driver and agent binaries..." -ForegroundColor Gray
Invoke-WebRequest -Uri "$HubURL/download/ominull.sys" -OutFile "$InstallDir\ominull.sys"
Invoke-WebRequest -Uri "$HubURL/download/ominulld.exe" -OutFile "$InstallDir\ominulld.exe"
Invoke-WebRequest -Uri "$HubURL/download/ominullctl.exe" -OutFile "$InstallDir\ominullctl.exe"

Write-Host "[+] Installing and starting Ominull kernel driver..." -ForegroundColor Gray
& sc.exe create Ominull type= kernel binPath= "$InstallDir\ominull.sys" start= demand 2>&1 | Out-Null
& sc.exe start Ominull 2>&1 | Out-Null

Write-Host "[+] Configuring and starting Ominull Endpoint Service (ominulld)..." -ForegroundColor Gray
& sc.exe create ominulld binPath= "\"$InstallDir\ominulld.exe\" --service --hub $HubURL --key $APIKey" start= auto displayname= "Ominull Threat Nullification Service" 2>&1 | Out-Null
& sc.exe start ominulld 2>&1 | Out-Null

Write-Host "[SUCCESS] Ominull Endpoint Service deployed and actively reporting to Hub!" -ForegroundColor Green
`
	return strings.TrimSpace(fmt.Sprintf(script, hubURL, tenantAPIKey))
}

// GenerateBash returns an automated bootstrap script for Debian/Ubuntu/Linux systems.
func GenerateBash(hubURL, tenantAPIKey string) string {
	script := `#!/bin/bash
set -euo pipefail
HUB_URL="%s"
API_KEY="%s"
INSTALL_DIR="/opt/ominull"

echo -e "\033[36m[+] Initializing Ominull Linux Endpoint Deployment...\033[0m"
mkdir -p "$INSTALL_DIR"

echo -e "\033[90m[+] Downloading Ominull daemon...\033[0m"
curl -sSL "$HUB_URL/download/ominulld" -o "$INSTALL_DIR/ominulld"
chmod +x "$INSTALL_DIR/ominulld"

echo -e "\033[90m[+] Creating systemd service unit...\033[0m"
cat << 'UNIT' > /etc/systemd/system/ominulld.service
[Unit]
Description=Ominull Threat Nullification Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/ominull/ominulld --hub %s --key %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ominulld.service

echo -e "\033[32m[SUCCESS] Ominull Linux Agent deployed and connected!\033[0m"
`
	return fmt.Sprintf(script, hubURL, tenantAPIKey, hubURL, tenantAPIKey)
}
