// Package bootstrap generates unattended enrolment scripts for the retained
// Linux and Windows agents.
package bootstrap

import "strings"

// Options describes one enrolment. The tenant key and one-use token are
// rendered into the script; the admin key never crosses this boundary.
type Options struct {
	HubURL          string
	AgentHubURL     string
	TenantAPIKey    string
	EnrollmentToken string
	CFClientID      string
	CFClientSecret  string
	LocationID      string
	RoleTag         string
	EndpointID      string
	AgentVersion    string
}

// Public material pinned in every released agent. The private key stays in the
// operations vault.
const releasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE71CpMPEGtyUpx3ZSuvcf+YMiwM1F
0e6k7D05y7jLxXQblk3d7ZirBH3MNJlo7aUbtmlQ2izz/u5wTG2ztJ9TBw==
-----END PUBLIC KEY-----
`

func (o Options) normalized() Options {
	if o.AgentHubURL == "" {
		o.AgentHubURL = o.HubURL
	}
	if o.RoleTag == "" {
		o.RoleTag = "workstation"
	}
	if o.LocationID == "" {
		o.LocationID = "loc-home"
	}
	if o.AgentVersion == "" {
		o.AgentVersion = "0.0.0"
	}
	return o
}

func bashQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func powershellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func render(t string, values map[string]string) string {
	for key, value := range values {
		t = strings.ReplaceAll(t, "__"+key+"__", value)
	}
	return strings.TrimSpace(t)
}

// GenerateBash installs the signed native .deb and asks the package-installed
// binary to write enrollment material. It does not copy a privileged binary or
// create a service unit.
func GenerateBash(o Options) string {
	o = o.normalized()
	endpoint := o.EndpointID
	if endpoint == "" {
		endpoint = "linux-$(hostname)"
	}
	cfBlock := ""
	if o.CFClientID != "" && o.CFClientSecret != "" {
		cfBlock = "cf_client_id=" + bashQuote(o.CFClientID) + "\ncf_client_secret=" + bashQuote(o.CFClientSecret)
	}

	template := `#!/bin/bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "[-] Run this installer as root (the one-line form uses sudo)." >&2
    exit 1
fi
command -v curl >/dev/null
command -v openssl >/dev/null
command -v dpkg >/dev/null
command -v sha256sum >/dev/null

HUB_URL=__HUB_URL__
AGENT_HUB_URL=__AGENT_HUB_URL__
API_KEY=__API_KEY__
ENROLL_TOKEN=__ENROLL_TOKEN__
ROLE_TAG=__ROLE_TAG__
LOCATION_ID=__LOCATION_ID__
ENDPOINT_ID=__ENDPOINT_ID__
VERSION=__VERSION__
PACKAGE="ominull-agent_${VERSION}_amd64.deb"
TMP=$(mktemp -d /tmp/ominull-bootstrap.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

curl_auth=()
if [ -n __CF_ID__ ] && [ -n __CF_SECRET__ ]; then
    curl_auth=(-H "CF-Access-Client-Id: __CF_ID__" -H "CF-Access-Client-Secret: __CF_SECRET__")
fi

echo "[+] Fetching and validating the Ominull CA."
curl -fsSL "${curl_auth[@]}" "$HUB_URL/api/v1/pki/ca.crt" -o "$TMP/ca.crt"
openssl x509 -in "$TMP/ca.crt" -noout -subject >/dev/null

echo "[+] Fetching native package $PACKAGE."
curl -fsSL "${curl_auth[@]}" "$HUB_URL/download/$PACKAGE" -o "$TMP/$PACKAGE"
curl -fsSL "${curl_auth[@]}" "$HUB_URL/download/$PACKAGE.sig" -o "$TMP/$PACKAGE.sig"
curl -fsSL "${curl_auth[@]}" "$HUB_URL/download/$PACKAGE.sha256" -o "$TMP/$PACKAGE.sha256"
expected=$(awk 'NF { print $1; exit }' "$TMP/$PACKAGE.sha256")
actual=$(sha256sum "$TMP/$PACKAGE" | awk '{ print $1 }')
[ "$expected" = "$actual" ]
cat > "$TMP/release.pub" <<'OMINULL_RELEASE_KEY'
__PUBLIC_KEY__OMINULL_RELEASE_KEY
openssl dgst -sha256 -verify "$TMP/release.pub" -signature "$TMP/$PACKAGE.sig" "$TMP/$PACKAGE" >/dev/null

echo "[+] Installing through dpkg."
dpkg -i "$TMP/$PACKAGE"

json_field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }
echo "[+] Enrolling endpoint $ENDPOINT_ID."
bundle=$(curl -fsSL "${curl_auth[@]}" -H "X-API-Key: $API_KEY" -H "X-Enrollment-Token: $ENROLL_TOKEN" \
    -H "Content-Type: application/json" -d "{\"endpoint_id\":\"$ENDPOINT_ID\",\"hostname\":\"$(hostname)\"}" \
    "$HUB_URL/api/v1/pki/enroll")
printf '%s' "$bundle" | json_field cert_pem | openssl base64 -d -A > "$TMP/client.crt"
printf '%s' "$bundle" | json_field key_pem | openssl base64 -d -A > "$TMP/client.key"
openssl x509 -in "$TMP/client.crt" -noout -subject >/dev/null

cat <<CONF | /opt/ominull/bin/ominulld --configure-stdin
hub_url=$AGENT_HUB_URL
api_key=$API_KEY
endpoint_id=$ENDPOINT_ID
role_tag=$ROLE_TAG
location_id=$LOCATION_ID
ca_source=$TMP/ca.crt
client_cert_source=$TMP/client.crt
client_key_source=$TMP/client.key
__CF_CONFIG__
CONF

# The unit and its ownership came from the .deb. Start the already-registered
# package unit after package-owned configuration is ready; enrollment never
# creates or edits a service definition.
systemctl start ominull-agent.service
echo "[+] Ominull Linux agent installed, enrolled, and started from $PACKAGE."
`

	return render(template, map[string]string{
		"HUB_URL":       bashQuote(o.HubURL),
		"AGENT_HUB_URL": bashQuote(o.AgentHubURL),
		"API_KEY":       bashQuote(o.TenantAPIKey),
		"ENROLL_TOKEN":  bashQuote(o.EnrollmentToken),
		"ROLE_TAG":      bashQuote(o.RoleTag),
		"LOCATION_ID":   bashQuote(o.LocationID),
		"ENDPOINT_ID":   bashQuote(endpoint),
		"VERSION":       bashQuote(o.AgentVersion),
		"CF_ID":         bashQuote(o.CFClientID),
		"CF_SECRET":     bashQuote(o.CFClientSecret),
		"CF_CONFIG":     cfBlock,
		"PUBLIC_KEY":    releasePublicKeyPEM,
	})
}

// GeneratePowerShell installs the signed native MSI and asks the
// package-installed binary to write enrollment material. It does not copy a
// privileged binary or register a service.
func GeneratePowerShell(o Options) string {
	o = o.normalized()
	endpoint := powershellQuote(o.EndpointID)
	if o.EndpointID == "" {
		endpoint = `win11-$env:COMPUTERNAME`
	}
	cfBlock := ""
	cfID, cfSecret, cfPresent := "", "", "$false"
	if o.CFClientID != "" && o.CFClientSecret != "" {
		cfID, cfSecret, cfPresent = powershellQuote(o.CFClientID), powershellQuote(o.CFClientSecret), "$true"
		cfBlock = "cf_client_id=" + o.CFClientID + "\ncf_client_secret=" + o.CFClientSecret
	}

	template := `# Ominull Windows native-package bootstrap
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell."
}
$HubURL = __HUB_URL__
$AgentHubURL = __AGENT_HUB_URL__
$APIKey = __API_KEY__
$EnrollToken = __ENROLL_TOKEN__
$RoleTag = __ROLE_TAG__
$LocationID = __LOCATION_ID__
$EndpointID = __ENDPOINT_ID__
$Version = __VERSION__
$Package = "ominull-agent-windows-$Version.msi"
$Temp = Join-Path $env:TEMP ("ominull-bootstrap-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $Headers = @{}
    if (__CF_ID_PRESENT__) {
        $Headers["CF-Access-Client-Id"] = __CF_ID__
        $Headers["CF-Access-Client-Secret"] = __CF_SECRET__
    }
    $ca = Join-Path $Temp "ca.crt"
    $msi = Join-Path $Temp $Package
    $sig = "$msi.sig"
    $digest = "$msi.sha256"
    Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$HubURL/api/v1/pki/ca.crt" -OutFile $ca
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca)
    Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$HubURL/download/$Package" -OutFile $msi
    Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$HubURL/download/$Package.sig" -OutFile $sig
    Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$HubURL/download/$Package.sha256" -OutFile $digest
    $expected = (Get-Content -LiteralPath $digest | Where-Object { $_.Trim() } | Select-Object -First 1).Split()[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
    if ($expected.ToLowerInvariant() -ne $actual) { throw "native package digest mismatch" }

    function Convert-DerEcdsaSignatureToP1363([byte[]] $der) {
        if ($der.Length -lt 8 -or $der[0] -ne 0x30) { throw "invalid release signature" }
        $offset = 2
        if ($der[1] -eq 0x81) { $offset = 3 }
        if ($offset -ge $der.Length -or $der[$offset] -ne 0x02) { throw "invalid release signature" }
        $rLength = [int]$der[$offset + 1]
        $rStart = $offset + 2
        $sTag = $rStart + $rLength
        if ($sTag + 2 -gt $der.Length -or $der[$sTag] -ne 0x02) { throw "invalid release signature" }
        $sLength = [int]$der[$sTag + 1]
        $sStart = $sTag + 2
        if ($sStart + $sLength -gt $der.Length) { throw "invalid release signature" }
        while ($rLength -gt 1 -and $der[$rStart] -eq 0) { $rStart++; $rLength-- }
        while ($sLength -gt 1 -and $der[$sStart] -eq 0) { $sStart++; $sLength-- }
        if ($rLength -gt 32 -or $sLength -gt 32) { throw "invalid release signature width" }
        $raw = New-Object byte[] 64
        [Array]::Copy($der, $rStart, $raw, 32 - $rLength, $rLength)
        [Array]::Copy($der, $sStart, $raw, 64 - $sLength, $sLength)
        return ,$raw
    }

    $releaseECDSA = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $releaseParameters = New-Object System.Security.Cryptography.ECParameters
        $releaseParameters.Curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
        $releasePoint = New-Object System.Security.Cryptography.ECPoint
        $releasePoint.X = [Convert]::FromBase64String("__PUBLIC_KEY_X__")
        $releasePoint.Y = [Convert]::FromBase64String("__PUBLIC_KEY_Y__")
        $releaseParameters.Q = $releasePoint
        $releaseECDSA.ImportParameters($releaseParameters)
        $releaseHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($msi))
        $releaseSignature = Convert-DerEcdsaSignatureToP1363 ([IO.File]::ReadAllBytes($sig))
        if (-not $releaseECDSA.VerifyHash($releaseHash, $releaseSignature)) { throw "native package signature mismatch" }
    } finally {
        $releaseECDSA.Dispose()
    }

    Write-Host "[+] Installing through Windows Installer."
    $install = Start-Process msiexec.exe -ArgumentList @('/i', $msi, '/qn', '/norestart', 'REBOOT=ReallySuppress') -Wait -PassThru
    if ($install.ExitCode -ne 0 -and $install.ExitCode -ne 3010) { throw "MSI failed with exit code $($install.ExitCode)" }

    $body = @{ endpoint_id = $EndpointID; hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
    $enrollHeaders = @{ "X-API-Key" = $APIKey; "X-Enrollment-Token" = $EnrollToken; "Content-Type" = "application/json" }
    foreach ($key in $Headers.Keys) { $enrollHeaders[$key] = $Headers[$key] }
    $bundle = Invoke-RestMethod -UseBasicParsing -Method Post -Headers $enrollHeaders -Uri "$HubURL/api/v1/pki/enroll" -Body $body
    if (-not $bundle.pfx_base64) { throw "hub returned no endpoint certificate" }
    $pfx = Join-Path $Temp "client.pfx"
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($bundle.pfx_base64))

    $config = @"
hub_url=$AgentHubURL
api_key=$APIKey
endpoint_id=$EndpointID
role_tag=$RoleTag
location_id=$LocationID
ca_source=$ca
client_pfx_source=$pfx
__CF_CONFIG__
"@
    $agent = Join-Path $env:ProgramFiles "Ominull\ominulld.exe"
    $config | & $agent --configure-stdin
    if ($LASTEXITCODE -ne 0) { throw "agent configuration failed with exit code $LASTEXITCODE" }
    Start-Service -Name ominulld
    Write-Host "[+] Ominull Windows agent installed, enrolled, and started from $Package."
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
`

	return render(template, map[string]string{
		"HUB_URL":       powershellQuote(o.HubURL),
		"AGENT_HUB_URL": powershellQuote(o.AgentHubURL),
		"API_KEY":       powershellQuote(o.TenantAPIKey),
		"ENROLL_TOKEN":  powershellQuote(o.EnrollmentToken),
		"ROLE_TAG":      powershellQuote(o.RoleTag),
		"LOCATION_ID":   powershellQuote(o.LocationID),
		"ENDPOINT_ID":   endpoint,
		"VERSION":       powershellQuote(o.AgentVersion),
		"CF_ID_PRESENT": cfPresent,
	 "CF_ID":         cfID,
	 "CF_SECRET":     cfSecret,
	 "CF_CONFIG":     cfBlock,
		"PUBLIC_KEY_X":  "71CpMPEGtyUpx3ZSuvcf+YMiwM1F0e6k7D05y7jLxXQ=",
		"PUBLIC_KEY_Y":  "G5ZN3e2YqwR9zDSZaO2lG7ZpUNos8/7ucExts7SfUwc=",
	})
}
