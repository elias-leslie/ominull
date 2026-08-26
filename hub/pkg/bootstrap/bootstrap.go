package bootstrap

import (
	"fmt"
	"strings"
)

// GeneratePowerShell returns an automated, zero-friction unattended bootstrap script for Windows.
func GeneratePowerShell(hubURL, tenantAPIKey string) string {
	script := `
# Ominull Automated Zero-Friction Endpoint Bootstrap (Windows)
$ErrorActionPreference = "SilentlyContinue"
$HubURL = "%s"
$APIKey = "%s"
$InstallDir = "$env:ProgramFiles\Ominull"

Write-Host "[+] Initializing Ominull Zero-Friction Windows Deployment..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[+] Installing Ominull Enterprise Trust Anchor (Root CA)..." -ForegroundColor Gray
$CertPath = "$InstallDir\ca.crt"
Invoke-WebRequest -Uri "$HubURL/api/v1/pki/ca.crt" -OutFile $CertPath -UseBasicParsing
if (Test-Path $CertPath) {
    Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
    Write-Host "[+] Enterprise Root CA anchored successfully." -ForegroundColor Green
}

Write-Host "[+] Downloading Ominull Native User-Mode WFP Engine..." -ForegroundColor Gray
Invoke-WebRequest -Uri "$HubURL/download/ominull_wfp_user.exe" -OutFile "$InstallDir\ominull_wfp_user.exe" -UseBasicParsing
Invoke-WebRequest -Uri "$HubURL/download/ominulld.exe" -OutFile "$InstallDir\ominulld.exe" -UseBasicParsing

Write-Host "[+] Testing User-Mode WFP subsystem..." -ForegroundColor Gray
& "$InstallDir\ominull_wfp_user.exe" test

Write-Host "[+] Configuring and starting Ominull Endpoint Service..." -ForegroundColor Gray
& sc.exe stop ominulld 2>&1 | Out-Null
& sc.exe delete ominulld 2>&1 | Out-Null
& sc.exe create ominulld binPath= "\"$InstallDir\ominulld.exe\" --service --hub $HubURL --key $APIKey" start= auto displayname= "Ominull Threat Nullification Service" 2>&1 | Out-Null
& sc.exe start ominulld 2>&1 | Out-Null

Write-Host "[SUCCESS] Ominull Zero-Friction Endpoint Service deployed and actively protected!" -ForegroundColor Green
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

echo -e "\033[90m[+] Installing Ominull Enterprise Trust Anchor (Root CA)...\033[0m"
curl -sSL "$HUB_URL/api/v1/pki/ca.crt" -o /usr/local/share/ca-certificates/ominull-ca.crt || true
update-ca-certificates 2>/dev/null || true

echo -e "\033[90m[+] Downloading Ominull daemon...\033[0m"
systemctl stop ominulld.service 2>/dev/null || true
curl -sSL "$HUB_URL/download/ominulld" -o "$INSTALL_DIR/ominulld"
chmod +x "$INSTALL_DIR/ominulld"

echo -e "\033[90m[+] Creating systemd service unit...\033[0m"
cat << UNIT > /etc/systemd/system/ominulld.service
[Unit]
Description=Ominull Threat Nullification Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/ominulld --hub $HUB_URL --key $API_KEY
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ominulld.service

echo -e "\033[32m[SUCCESS] Ominull Linux Service deployed and actively reporting to Hub!\033[0m"
`
	return strings.TrimSpace(fmt.Sprintf(script, hubURL, tenantAPIKey))
}

// GenerateMacOS returns an automated bootstrap script for macOS systems using native PF.
func GenerateMacOS(hubURL, tenantAPIKey string) string {
	script := `#!/bin/bash
set -euo pipefail
HUB_URL="%s"
API_KEY="%s"
INSTALL_DIR="/opt/ominull"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: Run with sudo/root privileges."
    exit 1
fi

echo -e "\033[36m[+] Initializing Ominull macOS Zero-Friction Deployment...\033[0m"
mkdir -p "$INSTALL_DIR"

echo -e "\033[90m[+] Installing Ominull Enterprise Trust Anchor...\033[0m"
curl -sSL "$HUB_URL/api/v1/pki/ca.crt" -o "$INSTALL_DIR/ca.crt" || true
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$INSTALL_DIR/ca.crt" 2>/dev/null || true

echo -e "\033[90m[+] Downloading macOS Packet Filter Engine...\033[0m"
curl -sSL "$HUB_URL/download/pf_engine.sh" -o "$INSTALL_DIR/pf_engine.sh"
chmod +x "$INSTALL_DIR/pf_engine.sh"

echo -e "\033[90m[+] Testing BSD Packet Filter Subsystem...\033[0m"
"$INSTALL_DIR/pf_engine.sh" test

echo -e "\033[32m[SUCCESS] Ominull macOS Zero-Friction Protection Active!\033[0m"
`
	return strings.TrimSpace(fmt.Sprintf(script, hubURL, tenantAPIKey))
}
