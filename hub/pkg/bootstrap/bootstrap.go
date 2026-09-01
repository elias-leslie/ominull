// Package bootstrap generates unattended enrollment scripts for the retained
// Linux and Windows native packages.
package bootstrap

import "strings"

// Options contains public installer parameters. EnrollmentCode is optional: an
// interactive script asks for it through the terminal, while a console-rendered
// script may carry it in the downloaded script body. It is never put in a URL,
// service argument, package property, or process argument.
type Options struct {
	HubURL         string
	AgentHubURL    string
	LocationID     string
	RoleTag        string
	EndpointID     string
	AgentVersion   string
	EnrollmentCode string
	// UseSystemCA is true when the hub URL is expected to use a public
	// certificate, such as an ACME certificate or a Cloudflare edge
	// certificate. Direct self-issued LAN deployments pin the Ominull CA.
	UseSystemCA bool
}

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
	o.HubURL = strings.TrimRight(strings.TrimSpace(o.HubURL), "/")
	o.AgentHubURL = strings.TrimRight(strings.TrimSpace(o.AgentHubURL), "/")
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

func codeBash(o Options) string {
	if o.EnrollmentCode != "" {
		return "ENROLLMENT_CODE=" + bashQuote(o.EnrollmentCode)
	}
	return `if [ -n "${OMINULL_ENROLLMENT_CODE_FILE:-}" ]; then
    ENROLLMENT_CODE=$(cat -- "$OMINULL_ENROLLMENT_CODE_FILE")
elif [ -n "${OMINULL_ENROLLMENT_CODE:-}" ]; then
    ENROLLMENT_CODE=$OMINULL_ENROLLMENT_CODE
else
    read -r -s -p "Ominull enrollment code: " ENROLLMENT_CODE < /dev/tty
    printf '\n'
fi
ENROLLMENT_CODE=$(printf '%s' "$ENROLLMENT_CODE" | tr -d '\r\n[:space:]')
[ -n "$ENROLLMENT_CODE" ] || { echo "[-] Enrollment code is required." >&2; exit 1; }`
}

// GenerateBash installs the signed native .deb, redeems a body-only enrollment
// code, and asks the package-installed binary to write protected configuration.
func GenerateBash(o Options) string {
	o = o.normalized()
	template := `#!/bin/bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "[-] Run this installer as root (the one-line form uses sudo)." >&2
    exit 1
fi
for tool in curl openssl dpkg sha256sum base64; do
    command -v "$tool" >/dev/null || { echo "[-] Missing required tool: $tool" >&2; exit 1; }
done

HUB_URL=__HUB_URL__
AGENT_HUB_URL=__AGENT_HUB_URL__
ROLE_TAG=__ROLE_TAG__
LOCATION_ID=__LOCATION_ID__
VERSION=__VERSION__
USE_SYSTEM_CA=__USE_SYSTEM_CA__
PACKAGE="ominull-agent_${VERSION}_amd64.deb"
TMP=$(mktemp -d /tmp/ominull-bootstrap.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

` + codeBash(o) + `

if [[ "$HUB_URL" == https://* ]]; then
    CURL_TLS=()
    PIN_HUB_CA=1
    if [ "$USE_SYSTEM_CA" = 1 ]; then
        PIN_HUB_CA=0
        echo "[+] Using the operating system's public certificate trust."
    else
        echo "[+] Fetching and validating the Ominull CA."
        curl -k -fsSL --max-time 30 "$HUB_URL/api/v1/pki/ca.crt" -o "$TMP/ca.crt"
        CURL_TLS=(--cacert "$TMP/ca.crt")
        openssl x509 -in "$TMP/ca.crt" -noout -subject >/dev/null
    fi
else
    echo "[-] Enrollment requires an https hub URL." >&2
    exit 1
fi

echo "[+] Fetching native package $PACKAGE."
curl -fsSL --max-time 60 "${CURL_TLS[@]}" "$HUB_URL/download/$PACKAGE" -o "$TMP/$PACKAGE"
curl -fsSL --max-time 30 "${CURL_TLS[@]}" "$HUB_URL/download/$PACKAGE.sig" -o "$TMP/$PACKAGE.sig"
curl -fsSL --max-time 30 "${CURL_TLS[@]}" "$HUB_URL/download/$PACKAGE.sha256" -o "$TMP/$PACKAGE.sha256"
expected=$(awk 'NF { print $1; exit }' "$TMP/$PACKAGE.sha256")
actual=$(sha256sum "$TMP/$PACKAGE" | awk '{ print $1 }')
[ "$expected" = "$actual" ] || { echo "[-] Native package digest mismatch." >&2; exit 1; }
cat > "$TMP/release.pub" <<'OMINULL_RELEASE_KEY'
__PUBLIC_KEY__OMINULL_RELEASE_KEY
openssl dgst -sha256 -verify "$TMP/release.pub" -signature "$TMP/$PACKAGE.sig" "$TMP/$PACKAGE" >/dev/null

echo "[+] Installing through dpkg."
dpkg -i "$TMP/$PACKAGE"

echo "[+] Redeeming the one-use enrollment code."
form=$(printf 'code=%s&platform=linux&hostname=%s' "$ENROLLMENT_CODE" "$(hostname)")
bundle=$(printf '%s' "$form" | curl -fsSL --max-time 30 "${CURL_TLS[@]}" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$HUB_URL/api/v1/enrollment/redeem")
json_field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }
device_credential=$(printf '%s' "$bundle" | json_field device_credential)
endpoint_id=$(printf '%s' "$bundle" | json_field endpoint_id)
agent_hub_url=$(printf '%s' "$bundle" | json_field agent_hub_url)
[ -n "$device_credential" ] && [ -n "$endpoint_id" ] || { echo "[-] Hub returned no device identity." >&2; exit 1; }
printf '%s' "$bundle" | json_field cert_pem | base64 -d > "$TMP/client.crt"
printf '%s' "$bundle" | json_field key_pem | base64 -d > "$TMP/client.key"
openssl x509 -in "$TMP/client.crt" -noout -subject >/dev/null

cat <<CONF | /opt/ominull/bin/ominulld --configure-stdin
hub_url=$agent_hub_url
device_credential=$device_credential
endpoint_id=$endpoint_id
role_tag=$ROLE_TAG
location_id=$LOCATION_ID
ca_source=$TMP/ca.crt
pin_hub_ca=$PIN_HUB_CA
client_cert_source=$TMP/client.crt
client_key_source=$TMP/client.key
CONF

systemctl start ominull-agent.service
echo "[+] Ominull Linux agent installed, enrolled, and started from $PACKAGE."
`
	return render(template, map[string]string{
		"HUB_URL":       bashQuote(o.HubURL),
		"AGENT_HUB_URL": bashQuote(o.AgentHubURL),
		"ROLE_TAG":      bashQuote(o.RoleTag),
		"LOCATION_ID":   bashQuote(o.LocationID),
		"VERSION":       bashQuote(o.AgentVersion),
		"USE_SYSTEM_CA": func() string {
			if o.UseSystemCA {
				return "1"
			}
			return "0"
		}(),
		"PUBLIC_KEY": releasePublicKeyPEM,
	})
}

func codePowerShell(o Options) string {
	if o.EnrollmentCode != "" {
		return "$EnrollmentCode = " + powershellQuote(o.EnrollmentCode)
	}
	return `$EnrollmentCode = $null
if ($env:OMINULL_ENROLLMENT_CODE_FILE) {
    $EnrollmentCode = (Get-Content -LiteralPath $env:OMINULL_ENROLLMENT_CODE_FILE -Raw).Trim()
} elseif ($env:OMINULL_ENROLLMENT_CODE) {
    $EnrollmentCode = $env:OMINULL_ENROLLMENT_CODE.Trim()
} else {
    $EnrollmentCode = (Read-Host "Ominull enrollment code").Trim()
}
if (-not $EnrollmentCode) { throw "Enrollment code is required." }`
}

// GeneratePowerShell installs the signed native MSI and configures the package
// through its stdin enrollment writer. It contains no Cloudflare service-token
// headers and never places the device credential in an MSI property or service
// argument.
func GeneratePowerShell(o Options) string {
	o = o.normalized()
	endpoint := powershellQuote(o.EndpointID)
	if o.EndpointID == "" {
		endpoint = "''"
	}
	template := `# Ominull Windows native-package bootstrap
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this installer from an elevated PowerShell." }
$HubURL = __HUB_URL__
$AgentHubURL = __AGENT_HUB_URL__
$RoleTag = __ROLE_TAG__
$LocationID = __LOCATION_ID__
$EndpointID = __ENDPOINT_ID__
$Version = __VERSION__
$UseSystemCA = __USE_SYSTEM_CA__
$Package = "ominull-agent-windows-$Version.msi"
$Temp = Join-Path $env:TEMP ("ominull-bootstrap-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Temp | Out-Null
` + codePowerShell(o) + `
try {
    $ca = Join-Path $Temp "ca.crt"
    $CurlTLS = @()
    $PinHubCA = 1
    $msi = Join-Path $Temp $Package
    $sig = "$msi.sig"
    $digest = "$msi.sha256"
    if ($UseSystemCA) {
        $PinHubCA = 0
        $CurlTLS = @('--ssl-no-revoke')
        Write-Host "[+] Using the operating system's public certificate trust."
    } else {
        Write-Host "[+] Fetching and validating the Ominull CA."
        curl.exe -k --ssl-no-revoke -fsSL --max-time 30 "$HubURL/api/v1/pki/ca.crt" -o $ca
        $CurlTLS = @('--cacert', $ca, '--ssl-no-revoke')
    }
    curl.exe @CurlTLS -fsSL --max-time 60 "$HubURL/download/$Package" -o $msi
    curl.exe @CurlTLS -fsSL --max-time 30 "$HubURL/download/$Package.sig" -o $sig
    curl.exe @CurlTLS -fsSL --max-time 30 "$HubURL/download/$Package.sha256" -o $digest
    $expected = (Get-Content -LiteralPath $digest | Where-Object { $_.Trim() } | Select-Object -First 1).Split()[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
    if ($expected.ToLowerInvariant() -ne $actual) { throw "native package digest mismatch" }
    $publicKeyPem = @'
__PUBLIC_KEY__'@
    function Parse-DerSig([byte[]]$sigBytes) {
        if ($sigBytes.Length -lt 8 -or $sigBytes[0] -ne 0x30) { throw "invalid release signature" }
        $pos = 1
        if ($sigBytes[$pos] -ge 128) {
            $lenBytes = $sigBytes[$pos] -band 0x7f
            $pos += 1 + $lenBytes
        } else {
            $pos += 1
        }
        if ($sigBytes[$pos] -ne 0x02) { throw "invalid release signature integer" }
        $pos += 1
        $rLen = [int]$sigBytes[$pos]
        $pos += 1
        $rBytes = New-Object byte[] $rLen
        [Array]::Copy($sigBytes, $pos, $rBytes, 0, $rLen)
        $pos += $rLen

        if ($sigBytes[$pos] -ne 0x02) { throw "invalid release signature integer" }
        $pos += 1
        $sLen = [int]$sigBytes[$pos]
        $pos += 1
        $sBytes = New-Object byte[] $sLen
        [Array]::Copy($sigBytes, $pos, $sBytes, 0, $sLen)

        $r32 = New-Object byte[] 32
        $s32 = New-Object byte[] 32
        $rStart = 0
        $rTake = $rLen
        if ($rTake -gt 32) { $rStart = $rTake - 32; $rTake = 32 }
        [Array]::Copy($rBytes, $rStart, $r32, 32 - $rTake, $rTake)
        $sStart = 0
        $sTake = $sLen
        if ($sTake -gt 32) { $sStart = $sTake - 32; $sTake = 32 }
        [Array]::Copy($sBytes, $sStart, $s32, 32 - $sTake, $sTake)

        $raw = New-Object byte[] 64
        [Array]::Copy($r32, 0, $raw, 0, 32)
        [Array]::Copy($s32, 0, $raw, 32, 32)
        return $raw
    }
    $spki = [Convert]::FromBase64String(($publicKeyPem -replace '-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s', ''))
    if ($spki.Length -lt 65 -or $spki[$spki.Length - 65] -ne 0x04) { throw "invalid pinned release public key" }
    $cngBlob = New-Object byte[] 72
    $cngBlob[0] = 0x45; $cngBlob[1] = 0x43; $cngBlob[2] = 0x53; $cngBlob[3] = 0x31; $cngBlob[4] = 32
    [Array]::Copy($spki, $spki.Length - 64, $cngBlob, 8, 64)
    $cngKey = [System.Security.Cryptography.CngKey]::Import($cngBlob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($cngKey)
    try {
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($msi))
        $rawSignature = Parse-DerSig ([IO.File]::ReadAllBytes($sig))
        if (-not $ecdsa.VerifyHash($hash, $rawSignature)) { throw "native package signature mismatch" }
    } finally { $ecdsa.Dispose(); $cngKey.Dispose() }
    Write-Host "[+] Installing through Windows Installer."
    $install = Start-Process msiexec.exe -ArgumentList @('/i', $msi, '/qn', '/norestart', 'REBOOT=ReallySuppress') -Wait -PassThru
    if ($install.ExitCode -ne 0 -and $install.ExitCode -ne 3010) { throw "MSI failed with exit code $($install.ExitCode)" }

    $form = "code=$([uri]::EscapeDataString($EnrollmentCode))&platform=windows&hostname=$([uri]::EscapeDataString($env:COMPUTERNAME))"
    $bundlePath = Join-Path $Temp "bundle.json"
    $form | curl.exe @CurlTLS -fsSL --max-time 30 -H "Content-Type: application/x-www-form-urlencoded" --data-binary '@-' "$HubURL/api/v1/enrollment/redeem" -o $bundlePath
    $bundle = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json
    if (-not $bundle.device_credential -or -not $bundle.pfx_base64) { throw "hub returned no device identity" }
    $pfx = Join-Path $Temp "client.pfx"
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($bundle.pfx_base64))
    $caSource = if ($PinHubCA -eq 1) { $ca } else { "" }
    $config = @"
hub_url=$($bundle.agent_hub_url)
device_credential=$($bundle.device_credential)
endpoint_id=$($bundle.endpoint_id)
role_tag=$RoleTag
location_id=$LocationID
ca_source=$caSource
pin_hub_ca=$PinHubCA
client_pfx_source=$pfx
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
		"ROLE_TAG":      powershellQuote(o.RoleTag),
		"LOCATION_ID":   powershellQuote(o.LocationID),
		"ENDPOINT_ID":   endpoint,
		"VERSION":       powershellQuote(o.AgentVersion),
		"USE_SYSTEM_CA": func() string {
			if o.UseSystemCA {
				return "$true"
			}
			return "$false"
		}(),
		"PUBLIC_KEY": releasePublicKeyPEM,
	})
}
