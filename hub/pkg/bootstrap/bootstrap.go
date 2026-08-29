// Package bootstrap generates the unattended enrolment scripts the hub serves
// for each platform.
//
// Enrolment is where an endpoint learns who the hub is. The script fetches the
// hub's CA from HubURL, plants it on disk, and configures the agent to reach
// the hub at AgentHubURL - an https:// URL verified against exactly that CA.
// From then on nothing the agent does is exposed to an on-path attacker: not
// the API key, not the telemetry, not the isolation commands.
//
// The one moment that is not covered is the fetch itself. An installer that has
// no CA yet cannot verify the hub it is asking for one, so HubURL should be a
// channel that is already trusted - a public URL with a publicly-trusted
// certificate, or a LAN address on a network the operator controls at the time
// of enrolment. That is trust-on-first-use, and it is the only such moment:
// every later connection is pinned.
package bootstrap

import (
	"fmt"
	"strings"
)

// Options describes one enrolment. HubURL is the channel the installer runs
// against; AgentHubURL is what the installed agent talks to afterwards.
type Options struct {
	// HubURL is where the installer fetches the CA and the agent binaries.
	HubURL string
	// AgentHubURL is the transport the enrolled agent uses. Defaults to HubURL
	// when the hub was started without --agent-hub-url, which keeps a pre-TLS
	// deployment working unchanged.
	AgentHubURL string

	TenantAPIKey   string
	CFClientID     string
	CFClientSecret string
	LocationID     string
	RoleTag        string
	// EndpointID pins the fleet identity. Left empty, the agent derives one from
	// the hostname, and a renamed host then forks into a second record.
	EndpointID string
}

func (o Options) normalized() Options {
	if o.RoleTag == "" {
		o.RoleTag = "workstation"
	}
	if o.LocationID == "" {
		o.LocationID = "loc-home"
	}
	if o.AgentHubURL == "" {
		o.AgentHubURL = o.HubURL
	}
	return o
}

// curlAuthHeaders returns the Cloudflare Access headers the installer needs to
// reach a hub published behind a tunnel, or an empty string for a LAN hub.
func (o Options) curlAuthHeaders() string {
	if o.CFClientID == "" || o.CFClientSecret == "" {
		return ""
	}
	return fmt.Sprintf(`-H "CF-Access-Client-Id: %s" -H "CF-Access-Client-Secret: %s"`, o.CFClientID, o.CFClientSecret)
}

// GeneratePowerShell returns an automated, zero-friction unattended bootstrap script for Windows.
func GeneratePowerShell(o Options) string {
	o = o.normalized()

	cfHeadersBlock := `$Headers = @{}`
	cfArgsBlock := ""
	if o.CFClientID != "" && o.CFClientSecret != "" {
		cfHeadersBlock = fmt.Sprintf(`
$Headers = @{
    "CF-Access-Client-Id" = "%s"
    "CF-Access-Client-Secret" = "%s"
}`, o.CFClientID, o.CFClientSecret)
		cfArgsBlock = fmt.Sprintf(` --cf-id "%s" --cf-secret "%s"`, o.CFClientID, o.CFClientSecret)
	}

	// The certificate is issued to the endpoint id, and the hub compares that
	// name against the endpoint id in every later request - so the installer has
	// to pin the same id the agent will report under. Left to derive its own,
	// the agent would name itself the same way, but nothing would guarantee it.
	endpointID := o.EndpointID
	if endpointID == "" {
		endpointID = "win11-$env:COMPUTERNAME"
	}

	script := `
# Ominull Enterprise Automated Endpoint Bootstrap (Windows)
param (
    [string]$HubURL = "%s",
    [string]$AgentHubURL = "%s",
    [string]$APIKey = "%s",
    [string]$RoleTag = "%s",
    [string]$LocationID = "%s",
    [string]$EndpointID = "%s"
)
# Enrolment is not a place to carry on past a failure. A half-installed agent
# that cannot verify the hub is worse than one that never started, so anything
# unexpected here stops the script instead of being swallowed.
$ErrorActionPreference = "Stop"
%s

$InstallDir = "$env:ProgramFiles\Ominull"
Write-Host "[+] Initializing Ominull Enterprise Windows Deployment..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[+] Installing Ominull Enterprise Trust Anchor (Root CA)..." -ForegroundColor Gray
$CertPath = "$InstallDir\ca.crt"
Invoke-WebRequest -Uri "$HubURL/api/v1/pki/ca.crt" -Headers $Headers -OutFile $CertPath -UseBasicParsing
# Prove it is a certificate before trusting it. An error page saved to ca.crt
# would otherwise be imported as an anchor and then pinned by the agent.
$CaCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$CaCert.Import($CertPath)
Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
Write-Host "[+] Enterprise Root CA anchored ($($CaCert.Subject))." -ForegroundColor Green

Write-Host "[+] Downloading Ominull Native User-Mode WFP Engine & Daemon..." -ForegroundColor Gray
Invoke-WebRequest -Uri "$HubURL/download/ominull_wfp_user.exe" -Headers $Headers -OutFile "$InstallDir\ominull_wfp_user.exe" -UseBasicParsing
Invoke-WebRequest -Uri "$HubURL/download/ominulld.exe" -Headers $Headers -OutFile "$InstallDir\ominulld.exe" -UseBasicParsing

Write-Host "[+] Testing User-Mode WFP subsystem..." -ForegroundColor Gray
& "$InstallDir\ominull_wfp_user.exe" test

# This endpoint's own identity. The API key above is shared by every agent on the
# tenant: on its own it proves membership, not identity, so anyone holding it can
# report as any endpoint. The certificate issued here is what the hub tells them
# apart by.
Write-Host "[+] Enrolling endpoint identity ($EndpointID)..." -ForegroundColor Gray
$PfxPath = "$InstallDir\client.pfx"
try {
    $EnrollHeaders = @{ "X-API-Key" = $APIKey; "Content-Type" = "application/json" }
    foreach ($k in $Headers.Keys) { $EnrollHeaders[$k] = $Headers[$k] }
    $EnrollBody = @{ endpoint_id = $EndpointID; hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
    $Bundle = Invoke-RestMethod -Uri "$HubURL/api/v1/pki/enroll" -Method Post -Headers $EnrollHeaders -Body $EnrollBody -UseBasicParsing
    if (-not $Bundle.pfx_base64) { throw "the hub returned no PKCS#12 archive" }
    [IO.File]::WriteAllBytes($PfxPath, [Convert]::FromBase64String($Bundle.pfx_base64))
    # The archive carries the private key and has no password, so the file
    # permissions are the whole protection: SYSTEM and Administrators, nothing
    # inherited, nobody else. The SIDs are spelled numerically because the group
    # names differ on a localized Windows.
    & icacls.exe $PfxPath /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    Write-Host "[+] Endpoint certificate installed ($PfxPath)." -ForegroundColor Green
} catch {
    # Not fatal. The hub accepts an endpoint that presents no certificate until
    # it is started with --client-certs required, and stopping here would leave a
    # host with a trust anchor and no agent running at all.
    Remove-Item $PfxPath -Force -ErrorAction SilentlyContinue
    Write-Host "[!] Identity enrolment failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "[!] The agent will report under the API key alone. Re-run this installer once the hub's PKI is reachable." -ForegroundColor Yellow
}

Write-Host "[+] Configuring and starting Ominull Endpoint Service..." -ForegroundColor Gray
# Register through the agent's own installer: it owns the binPath, including the
# --service flag the SCM entry point requires and the --ca path the agent pins
# the hub against. It also moves the key given below into a SYSTEM-only file and
# registers --key-file instead, so the key never reaches the service command
# line, which sc qc exposes to any logged-on user.
& "$InstallDir\ominulld.exe" --uninstall 2>$null | Out-Null
& "$InstallDir\ominulld.exe" --install --hub $AgentHubURL --key $APIKey --role $RoleTag --location $LocationID --id $EndpointID --ca "$InstallDir\ca.crt" --client-pfx "$PfxPath"%s
& sc.exe start ominulld 2>&1 | Out-Null

Write-Host "[SUCCESS] Ominull Endpoint deployed; reporting to $AgentHubURL over TLS." -ForegroundColor Green
`
	return strings.TrimSpace(fmt.Sprintf(script,
		o.HubURL, o.AgentHubURL, o.TenantAPIKey, o.RoleTag, o.LocationID, endpointID,
		cfHeadersBlock, cfArgsBlock))
}

// GenerateBash returns an automated bootstrap script for Debian/Ubuntu/Linux systems.
func GenerateBash(o Options) string {
	o = o.normalized()

	cfCurlHeader := o.curlAuthHeaders()
	cfDaemonArg := ""
	if o.CFClientID != "" && o.CFClientSecret != "" {
		cfDaemonArg = fmt.Sprintf(` --cf-id %s --cf-secret %s`, o.CFClientID, o.CFClientSecret)
	}

	// Always pinned, never left to the agent to derive: the certificate below is
	// issued to this name and the hub matches it against the endpoint id in every
	// later request, so the two have to be decided in one place.
	endpointID := o.EndpointID
	if endpointID == "" {
		endpointID = "$DERIVED_ENDPOINT_ID"
	}

	script := `#!/bin/bash
set -euo pipefail
HUB_URL="%s"
AGENT_HUB_URL="%s"
API_KEY="%s"
ROLE_TAG="%s"
LOCATION_ID="%s"
INSTALL_DIR="/opt/ominull"
CA_PATH="/etc/ominull/ca.crt"
CLIENT_CERT="/etc/ominull/client.crt"
CLIENT_KEY="/etc/ominull/client.key"
DERIVED_ENDPOINT_ID="linux-$(hostname)"
ENDPOINT_ID="%s"

echo -e "\033[36m[+] Initializing Ominull Linux Endpoint Deployment...\033[0m"
mkdir -p "$INSTALL_DIR" /etc/ominull

# The trust anchor is not optional and its fetch is not allowed to fail
# quietly: the agent verifies the hub against this file and nothing else, so a
# missing or truncated one leaves an endpoint that cannot report at all. It is
# checked for being a certificate before anything is trusted, because a 401
# page written to this path would otherwise become the anchor.
echo -e "\033[90m[+] Installing Ominull Enterprise Trust Anchor (Root CA)...\033[0m"
curl -fsSL %s "$HUB_URL/api/v1/pki/ca.crt" -o "$CA_PATH"
openssl x509 -in "$CA_PATH" -noout -subject
chmod 644 "$CA_PATH"
# A copy in the system store lets curl, wget and the package tooling on this
# host reach the hub too; the agent still pins the file above explicitly.
mkdir -p /usr/local/share/ca-certificates
cp "$CA_PATH" /usr/local/share/ca-certificates/ominull-ca.crt
update-ca-certificates 2>/dev/null || true

echo -e "\033[90m[+] Downloading Ominull daemon...\033[0m"
systemctl stop ominull-agent.service 2>/dev/null || true
# Retire units from older installers so an endpoint never runs two agents at once.
systemctl disable --now ominulld.service ominull.service 2>/dev/null || true
mkdir -p "$INSTALL_DIR/bin"
curl -fsSL %s "$HUB_URL/download/ominulld" -o "$INSTALL_DIR/bin/ominulld"
chmod +x "$INSTALL_DIR/bin/ominulld"

# This endpoint's own identity. The API key is shared by every agent on the
# tenant, so it proves membership and not identity; the certificate issued here
# is what the hub tells one endpoint from another by.
#
# Failure is reported and survived rather than fatal: the hub accepts an
# endpoint that presents no certificate until it is started with
# --client-certs required, and stopping here would leave a host with a trust
# anchor, a daemon on disk and nothing running.
echo -e "\033[90m[+] Enrolling endpoint identity ($ENDPOINT_ID)...\033[0m"
json_field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }
enrol_identity() {
    local json
    json=$(curl -fsS %s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
        -d "{\"endpoint_id\":\"$ENDPOINT_ID\",\"hostname\":\"$(hostname)\"}" \
        "$HUB_URL/api/v1/pki/enroll") || return 1
    # -A because the fields are single base64 lines; without it openssl refuses
    # anything longer than a wrapped line and writes an empty file.
    printf '%%s' "$json" | json_field cert_pem | openssl base64 -d -A > "$CLIENT_CERT" || return 1
    printf '%%s' "$json" | json_field key_pem | openssl base64 -d -A > "$CLIENT_KEY" || return 1
    openssl x509 -in "$CLIENT_CERT" -noout -subject || return 1
}
if enrol_identity; then
    chmod 644 "$CLIENT_CERT"
    chmod 600 "$CLIENT_KEY"
    echo -e "\033[32m[+] Endpoint certificate installed.\033[0m"
else
    rm -f "$CLIENT_CERT" "$CLIENT_KEY"
    echo -e "\033[33m[!] Identity enrolment failed; the agent will report under the API key alone.\033[0m"
fi

# The .deb upgrade path reads this same file and leaves it untouched, so an endpoint
# enrolled here keeps its hub URL, key and CA path when it later self-updates.
echo -e "\033[90m[+] Writing enrolment config...\033[0m"
cat << CONF > /etc/ominull/agent.conf
OMINULL_ARGS=--hub $AGENT_HUB_URL --key $API_KEY --role $ROLE_TAG --location $LOCATION_ID --id $ENDPOINT_ID --ca $CA_PATH --client-cert $CLIENT_CERT --client-key $CLIENT_KEY%s
CONF
chmod 600 /etc/ominull/agent.conf

echo -e "\033[90m[+] Creating systemd service unit...\033[0m"
cat << UNIT > /etc/systemd/system/ominull-agent.service
[Unit]
Description=Ominull Threat Nullification Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/ominull/agent.conf
ExecStart=$INSTALL_DIR/bin/ominulld \$OMINULL_ARGS
Restart=always
RestartSec=5
LimitNOFILE=65535
KillMode=process

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ominull-agent.service

echo -e "\033[32m[SUCCESS] Ominull Linux Service deployed; reporting to $AGENT_HUB_URL over TLS.\033[0m"
`
	return strings.TrimSpace(fmt.Sprintf(script,
		o.HubURL, o.AgentHubURL, o.TenantAPIKey, o.RoleTag, o.LocationID, endpointID,
		cfCurlHeader, cfCurlHeader, cfCurlHeader, cfDaemonArg))
}

// GenerateMacOS returns an automated bootstrap script for macOS systems using native PF.
func GenerateMacOS(o Options) string {
	o = o.normalized()
	cfCurlHeader := o.curlAuthHeaders()

	// The daemon reads its endpoint id from the fifth argument. Pinning it here
	// rather than leaving the daemon to derive one from the hostname is what
	// keeps a renamed Mac on the fleet record it already has - and the CA path
	// that follows it sits in the sixth slot, so the id cannot be skipped.
	endpointID := o.EndpointID
	if endpointID == "" {
		endpointID = "$DERIVED_ENDPOINT_ID"
	}

	script := `#!/bin/bash
set -euo pipefail
HUB_URL="%s"
AGENT_HUB_URL="%s"
API_KEY="%s"
ROLE_TAG="%s"
LOCATION_ID="%s"
INSTALL_DIR="/opt/ominull"
CA_PATH="$INSTALL_DIR/ca.crt"
CLIENT_CERT="$INSTALL_DIR/client.crt"
CLIENT_KEY="$INSTALL_DIR/client.key"
DERIVED_ENDPOINT_ID="macos-$(hostname -s)"
ENDPOINT_ID="%s"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: Run with sudo/root privileges."
    exit 1
fi

echo -e "\033[36m[+] Initializing Ominull macOS Zero-Friction Deployment...\033[0m"
mkdir -p "$INSTALL_DIR"

# Mandatory, and verified to be a certificate before it is trusted: the daemon
# validates every hub connection against this file alone.
echo -e "\033[90m[+] Installing Ominull Enterprise Trust Anchor...\033[0m"
curl -fsSL %s "$HUB_URL/api/v1/pki/ca.crt" -o "$CA_PATH"
/usr/bin/openssl x509 -in "$CA_PATH" -noout -subject
chmod 644 "$CA_PATH"
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_PATH" 2>/dev/null || true

echo -e "\033[90m[+] Downloading macOS Packet Filter Engine and Daemon...\033[0m"
curl -fsSL %s "$HUB_URL/download/pf_engine.sh" -o "$INSTALL_DIR/pf_engine.sh"
curl -fsSL %s "$HUB_URL/download/ominull_mac_daemon.sh" -o "$INSTALL_DIR/ominull_mac_daemon.sh"
chmod +x "$INSTALL_DIR/pf_engine.sh" "$INSTALL_DIR/ominull_mac_daemon.sh"

# This endpoint's own identity. The API key is shared by every agent on the
# tenant, so it proves membership and not identity; the certificate issued here
# is what the hub tells one endpoint from another by. A failure is survived: the
# hub accepts an endpoint with no certificate until it is started with
# --client-certs required, and stopping here would leave a Mac with a trust
# anchor and no daemon.
echo -e "\033[90m[+] Enrolling endpoint identity ($ENDPOINT_ID)...\033[0m"
json_field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }
enrol_identity() {
    local json
    json=$(curl -fsS %s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
        -d "{\"endpoint_id\":\"$ENDPOINT_ID\",\"hostname\":\"$(hostname -s)\"}" \
        "$HUB_URL/api/v1/pki/enroll") || return 1
    # -A because each field is one long base64 line, which openssl otherwise
    # refuses and silently turns into an empty file.
    printf '%%s' "$json" | json_field cert_pem | /usr/bin/openssl base64 -d -A > "$CLIENT_CERT" || return 1
    printf '%%s' "$json" | json_field key_pem | /usr/bin/openssl base64 -d -A > "$CLIENT_KEY" || return 1
    /usr/bin/openssl x509 -in "$CLIENT_CERT" -noout -subject || return 1
}
if enrol_identity; then
    chmod 644 "$CLIENT_CERT"
    chmod 600 "$CLIENT_KEY"
    echo -e "\033[32m[+] Endpoint certificate installed.\033[0m"
else
    rm -f "$CLIENT_CERT" "$CLIENT_KEY"
    echo -e "\033[33m[!] Identity enrolment failed; the daemon will report under the API key alone.\033[0m"
fi

echo -e "\033[90m[+] Configuring macOS LaunchDaemon Service...\033[0m"
cat << PLIST > /Library/LaunchDaemons/dev.ominull.daemon.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.ominull.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/opt/ominull/ominull_mac_daemon.sh</string>
        <string>$AGENT_HUB_URL</string>
        <string>$API_KEY</string>
        <string>$ROLE_TAG</string>
        <string>$LOCATION_ID</string>
        <string>$ENDPOINT_ID</string>
        <string>$CA_PATH</string>
        <string>$CLIENT_CERT</string>
        <string>$CLIENT_KEY</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/ominull.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ominull.error.log</string>
</dict>
</plist>
PLIST
chmod 644 /Library/LaunchDaemons/dev.ominull.daemon.plist

launchctl unload /Library/LaunchDaemons/dev.ominull.daemon.plist 2>/dev/null || true
launchctl load -w /Library/LaunchDaemons/dev.ominull.daemon.plist

echo -e "\033[32m[SUCCESS] Ominull macOS daemon active; reporting to $AGENT_HUB_URL over TLS.\033[0m"
`
	return strings.TrimSpace(fmt.Sprintf(script,
		o.HubURL, o.AgentHubURL, o.TenantAPIKey, o.RoleTag, o.LocationID, endpointID,
		cfCurlHeader, cfCurlHeader, cfCurlHeader, cfCurlHeader))
}
