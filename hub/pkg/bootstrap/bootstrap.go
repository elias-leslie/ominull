// Package bootstrap generates unattended enrollment scripts for the retained
// Linux and Windows native packages.
package bootstrap

import (
	"strconv"
	"strings"

	"ominull/hub/pkg/response"
)

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
	// certificate, such as an operator-supplied or a Cloudflare edge
	// certificate. Direct self-issued LAN deployments pin the Ominull CA.
	UseSystemCA bool
	// RoutineFloor is the epoch of the routine key list the hub holds (0 when
	// none): the script refuses an older list than that.
	RoutineFloor int64
}

const releasePublicKeyPEM = response.ReleasePublicKeyPEM

// The package check both scripts run before installing anything. It is the
// check agents make on an update (agent_trust.h): a package signed by the
// release key the script embeds installs; otherwise it installs only when the
// hub's routine key list ({epoch, keys, sig}, the heartbeat's routine_keys)
// is strictly formed, signed by that same embedded key, not older than the
// list the hub held when it rendered the script (RoutineFloor) and not empty,
// and one listed key signed both the package and its OMINULL-RELEASE-V1
// statement. The embedded release key stays the only root of trust. Tests
// cut each block out of a rendered script by its markers and run it alone.
const (
	VerifyBlockStart = "# >>> ominull-verify"
	VerifyBlockEnd   = "# <<< ominull-verify"
)

const bashVerify = `# >>> ominull-verify
# ominull_verify_package DIR PACKAGE VERSION FLOOR: DIR holds PACKAGE, its .sig,
# release.pub (the embedded release key) and, when the hub has them,
# PACKAGE.release.sig and routine-keys.json.
ominull_hex_bin() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
ominull_verify_package() {
    local LC_ALL=C dir="$1" pkg="$2" version="$3" floor="$4"
    local raw epoch keys sig sha entry id xy prev=""
    local list_re='^\{"epoch":([1-9][0-9]{0,17}),"keys":"([0-9a-f:,]*)","sig":"([A-Za-z0-9+/]+={0,2})"\}$'
    local keys_re='^[0-9a-f]{16}:[0-9a-f]{128}(,[0-9a-f]{16}:[0-9a-f]{128}){0,3}$'
    if openssl dgst -sha256 -verify "$dir/release.pub" -signature "$dir/$pkg.sig" "$dir/$pkg" >/dev/null 2>&1; then
        echo "[+] $pkg is signed by the release key."
        return 0
    fi
    if [ ! -s "$dir/routine-keys.json" ]; then
        echo "[-] $pkg is not signed by the release key, and the hub offers no routine key list. Refused." >&2
        return 1
    fi
    raw=$(tr -d '\r\n' < "$dir/routine-keys.json")
    if ! [[ "$raw" =~ $list_re ]]; then
        echo "[-] The hub's routine key list is malformed. Refused." >&2
        return 1
    fi
    epoch=${BASH_REMATCH[1]} keys=${BASH_REMATCH[2]} sig=${BASH_REMATCH[3]}
    if [ -n "$keys" ] && ! [[ "$keys" =~ $keys_re ]]; then
        echo "[-] The hub's routine key list is malformed. Refused." >&2
        return 1
    fi
    for entry in ${keys//,/ }; do
        id=${entry%%:*}
        if [ -n "$prev" ] && ! [[ "$prev" < "$id" ]]; then
            echo "[-] The hub's routine key list is not sorted by id. Refused." >&2
            return 1
        fi
        prev=$id
    done
    printf 'OMINULL-ROUTINE-KEYS-V1\nepoch=%s\nkeys=%s\n' "$epoch" "$keys" > "$dir/routine-keys.stmt"
    if ! printf '%s' "$sig" | base64 -d > "$dir/routine-keys.sig" 2>/dev/null ||
       ! openssl dgst -sha256 -verify "$dir/release.pub" -signature "$dir/routine-keys.sig" "$dir/routine-keys.stmt" >/dev/null 2>&1; then
        echo "[-] The hub's routine key list is not signed by the release key. Refused." >&2
        return 1
    fi
    if [ "$epoch" -lt "$floor" ]; then
        echo "[-] The hub's routine key list (epoch $epoch) is older than the one the hub holds (epoch $floor). Refused." >&2
        return 1
    fi
    if [ -z "$keys" ]; then
        echo "[-] Every routine key is retired (epoch $epoch), and $pkg is not signed by the release key. Refused." >&2
        return 1
    fi
    if [ ! -s "$dir/$pkg.release.sig" ]; then
        echo "[-] $pkg has no release statement signature. Refused." >&2
        return 1
    fi
    sha=$(sha256sum "$dir/$pkg" | awk '{ print $1 }')
    printf 'OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n' "$pkg" "$version" "$sha" > "$dir/release.stmt"
    for entry in ${keys//,/ }; do
        id=${entry%%:*} xy=${entry#*:}
        ominull_hex_bin "3059301306072a8648ce3d020106082a8648ce3d03010703420004$xy" > "$dir/routine-$id.der"
        if openssl dgst -sha256 -verify "$dir/routine-$id.der" -keyform DER -signature "$dir/$pkg.release.sig" "$dir/release.stmt" >/dev/null 2>&1 &&
           openssl dgst -sha256 -verify "$dir/routine-$id.der" -keyform DER -signature "$dir/$pkg.sig" "$dir/$pkg" >/dev/null 2>&1; then
            echo "[+] $pkg is signed by routine key $id, which the release key lists (epoch $epoch)."
            return 0
        fi
    done
    echo "[-] $pkg is signed neither by the release key nor by a routine key it lists. Refused." >&2
    return 1
}
# <<< ominull-verify`

const powershellVerify = `# >>> ominull-verify
# Confirm-OminullPackage: Dir holds Package, its .sig and, when the hub has
# them, Package.release.sig and routine-keys.json; ReleaseKeyPem is the
# embedded release key. CNG on Windows; ECParameters where CNG is missing.
function ConvertFrom-OminullDerSig([byte[]]$sigBytes) {
    if ($sigBytes.Length -lt 8 -or $sigBytes[0] -ne 0x30) { throw "invalid release signature" }
    $pos = 1
    if ($sigBytes[$pos] -ge 128) { $pos += 1 + ($sigBytes[$pos] -band 0x7f) } else { $pos += 1 }
    $parts = @()
    foreach ($n in 0, 1) {
        if ($pos + 2 -gt $sigBytes.Length -or $sigBytes[$pos] -ne 0x02) { throw "invalid release signature integer" }
        $len = [int]$sigBytes[$pos + 1]
        $pos += 2
        if ($len -lt 1 -or $pos + $len -gt $sigBytes.Length) { throw "invalid release signature integer" }
        $take = [Math]::Min($len, 32)
        $part = New-Object byte[] 32
        [Array]::Copy($sigBytes, $pos + $len - $take, $part, 32 - $take, $take)
        $parts += , $part
        $pos += $len
    }
    $raw = New-Object byte[] 64
    [Array]::Copy($parts[0], 0, $raw, 0, 32)
    [Array]::Copy($parts[1], 0, $raw, 32, 32)
    return , $raw
}
function Test-OminullP256([byte[]]$XY, [byte[]]$Data, [byte[]]$DerSig) {
    $ecdsa = $null
    $cngKey = $null
    try {
        $raw = ConvertFrom-OminullDerSig $DerSig
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($Data)
        try {
            $blob = New-Object byte[] 72
            $blob[0] = 0x45; $blob[1] = 0x43; $blob[2] = 0x53; $blob[3] = 0x31; $blob[4] = 32
            [Array]::Copy($XY, 0, $blob, 8, 64)
            $cngKey = [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
            $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($cngKey)
        } catch {
            $p = New-Object System.Security.Cryptography.ECParameters
            $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
            $q = New-Object System.Security.Cryptography.ECPoint
            $q.X = [byte[]]$XY[0..31]
            $q.Y = [byte[]]$XY[32..63]
            $p.Q = $q
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create($p)
        }
        return [bool]$ecdsa.VerifyHash($hash, $raw)
    } catch {
        return $false
    } finally {
        if ($ecdsa) { $ecdsa.Dispose() }
        if ($cngKey) { $cngKey.Dispose() }
    }
}
function ConvertFrom-OminullHex([string]$hex) {
    $out = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) { $out[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
    return , $out
}
function Confirm-OminullPackage([string]$Dir, [string]$Package, [string]$Version, [long]$Floor, [string]$ReleaseKeyPem) {
    $spki = [Convert]::FromBase64String(($ReleaseKeyPem -replace '-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s', ''))
    if ($spki.Length -lt 65 -or $spki[$spki.Length - 65] -ne 0x04) { throw "invalid pinned release public key" }
    $releaseXY = New-Object byte[] 64
    [Array]::Copy($spki, $spki.Length - 64, $releaseXY, 0, 64)
    $pkgPath = Join-Path $Dir $Package
    $data = [IO.File]::ReadAllBytes($pkgPath)
    $sig = [IO.File]::ReadAllBytes("$pkgPath.sig")
    if (Test-OminullP256 $releaseXY $data $sig) {
        Write-Host "[+] $Package is signed by the release key."
        return $true
    }
    $listPath = Join-Path $Dir "routine-keys.json"
    if (-not (Test-Path -LiteralPath $listPath) -or (Get-Item -LiteralPath $listPath).Length -eq 0) {
        Write-Host "[-] $Package is not signed by the release key, and the hub offers no routine key list. Refused."
        return $false
    }
    $raw = ([IO.File]::ReadAllText($listPath)) -replace "[\r\n]", ""
    $m = [regex]::Match($raw, '^\{"epoch":([1-9][0-9]{0,17}),"keys":"([0-9a-f:,]*)","sig":"([A-Za-z0-9+/]+={0,2})"\}$')
    if (-not $m.Success) { Write-Host "[-] The hub's routine key list is malformed. Refused."; return $false }
    $epoch = [long]$m.Groups[1].Value
    $keys = $m.Groups[2].Value
    if ($keys -and -not [regex]::IsMatch($keys, '^[0-9a-f]{16}:[0-9a-f]{128}(,[0-9a-f]{16}:[0-9a-f]{128}){0,3}$')) {
        Write-Host "[-] The hub's routine key list is malformed. Refused."
        return $false
    }
    $entries = @()
    if ($keys) { $entries = $keys.Split(',') }
    $prev = $null
    foreach ($e in $entries) {
        $id = $e.Substring(0, 16)
        if ($null -ne $prev -and [string]::CompareOrdinal($prev, $id) -ge 0) {
            Write-Host "[-] The hub's routine key list is not sorted by id. Refused."
            return $false
        }
        $prev = $id
    }
    $stmt = [Text.Encoding]::ASCII.GetBytes("OMINULL-ROUTINE-KEYS-V1` + "`n" + `epoch=$epoch` + "`n" + `keys=$keys` + "`n" + `")
    $listSig = $null
    try { $listSig = [Convert]::FromBase64String($m.Groups[3].Value) } catch { }
    if (-not $listSig -or -not (Test-OminullP256 $releaseXY $stmt $listSig)) {
        Write-Host "[-] The hub's routine key list is not signed by the release key. Refused."
        return $false
    }
    if ($epoch -lt $Floor) {
        Write-Host "[-] The hub's routine key list (epoch $epoch) is older than the one the hub holds (epoch $Floor). Refused."
        return $false
    }
    if ($entries.Count -eq 0) {
        Write-Host "[-] Every routine key is retired (epoch $epoch), and $Package is not signed by the release key. Refused."
        return $false
    }
    $relPath = "$pkgPath.release.sig"
    if (-not (Test-Path -LiteralPath $relPath) -or (Get-Item -LiteralPath $relPath).Length -eq 0) {
        Write-Host "[-] $Package has no release statement signature. Refused."
        return $false
    }
    $relSig = [IO.File]::ReadAllBytes($relPath)
    $sha = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($data) | ForEach-Object { $_.ToString("x2") })
    $release = [Text.Encoding]::ASCII.GetBytes("OMINULL-RELEASE-V1` + "`n" + `package=$Package` + "`n" + `version=$Version` + "`n" + `sha256=$sha` + "`n" + `")
    foreach ($e in $entries) {
        $xy = ConvertFrom-OminullHex $e.Substring(17)
        if ((Test-OminullP256 $xy $release $relSig) -and (Test-OminullP256 $xy $data $sig)) {
            Write-Host "[+] $Package is signed by routine key $($e.Substring(0, 16)), which the release key lists (epoch $epoch)."
            return $true
        }
    }
    Write-Host "[-] $Package is signed neither by the release key nor by a routine key it lists. Refused."
    return $false
}
# <<< ominull-verify`

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
ROUTINE_FLOOR=__ROUTINE_FLOOR__
USE_SYSTEM_CA=__USE_SYSTEM_CA__
PACKAGE="ominull-agent_${VERSION}_amd64.deb"
TMP=$(mktemp -d /tmp/ominull-bootstrap.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

` + codeBash(o) + `

` + bashVerify + `

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
# Only needed for a package a routine key signed; a hub without them answers 404.
curl -fsL --max-time 30 "${CURL_TLS[@]}" "$HUB_URL/download/$PACKAGE.release.sig" -o "$TMP/$PACKAGE.release.sig" || rm -f "$TMP/$PACKAGE.release.sig"
curl -fsL --max-time 30 "${CURL_TLS[@]}" "$HUB_URL/download/routine-keys.json" -o "$TMP/routine-keys.json" || rm -f "$TMP/routine-keys.json"
expected=$(awk 'NF { print $1; exit }' "$TMP/$PACKAGE.sha256")
actual=$(sha256sum "$TMP/$PACKAGE" | awk '{ print $1 }')
[ "$expected" = "$actual" ] || { echo "[-] Native package digest mismatch." >&2; exit 1; }
cat > "$TMP/release.pub" <<'OMINULL_RELEASE_KEY'
__PUBLIC_KEY__OMINULL_RELEASE_KEY
ominull_verify_package "$TMP" "$PACKAGE" "$VERSION" "$ROUTINE_FLOOR" || exit 1

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
		"ROUTINE_FLOOR": strconv.FormatInt(o.RoutineFloor, 10),
		"PUBLIC_KEY":    releasePublicKeyPEM,
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
$RoutineFloor = __ROUTINE_FLOOR__
$UseSystemCA = __USE_SYSTEM_CA__
$Package = "ominull-agent-windows-$Version.msi"
$Temp = Join-Path $env:TEMP ("ominull-bootstrap-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Temp | Out-Null
` + codePowerShell(o) + `
` + powershellVerify + `
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
        certutil.exe -addstore -f Root $ca | Out-Null
    }
    curl.exe @CurlTLS -fsSL --max-time 60 "$HubURL/download/$Package" -o $msi
    curl.exe @CurlTLS -fsSL --max-time 30 "$HubURL/download/$Package.sig" -o $sig
    curl.exe @CurlTLS -fsSL --max-time 30 "$HubURL/download/$Package.sha256" -o $digest
    $expected = (Get-Content -LiteralPath $digest | Where-Object { $_.Trim() } | Select-Object -First 1).Split()[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
    if ($expected.ToLowerInvariant() -ne $actual) { throw "native package digest mismatch" }
    # Only needed for a package a routine key signed; a hub without them answers 404.
    curl.exe @CurlTLS -fsL --max-time 30 "$HubURL/download/$Package.release.sig" -o "$msi.release.sig"
    if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath "$msi.release.sig" -Force -ErrorAction SilentlyContinue }
    curl.exe @CurlTLS -fsL --max-time 30 "$HubURL/download/routine-keys.json" -o (Join-Path $Temp "routine-keys.json")
    if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath (Join-Path $Temp "routine-keys.json") -Force -ErrorAction SilentlyContinue }
    $publicKeyPem = @'
__PUBLIC_KEY__'@
    if (-not (Confirm-OminullPackage -Dir $Temp -Package $Package -Version $Version -Floor $RoutineFloor -ReleaseKeyPem $publicKeyPem)) { throw "native package signature mismatch" }
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
    Restart-Service -Name ominulld -Force -ErrorAction SilentlyContinue
    if ((Get-Service -Name ominulld -ErrorAction SilentlyContinue).Status -ne 'Running') {
        Start-Service -Name ominulld -ErrorAction SilentlyContinue
    }
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
		"ROUTINE_FLOOR": strconv.FormatInt(o.RoutineFloor, 10),
		"PUBLIC_KEY":    releasePublicKeyPEM,
	})
}
