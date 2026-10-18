# Installs the OmniNull screen viewer for the current user (no admin):
# copies ominull-screen.exe to %LOCALAPPDATA%\OmniNull, registers the
# ominull-screen:// link handler under HKCU, and adds the hub to
# %APPDATA%\ominull\screen.json.
#
#   .\install-screen-viewer.ps1 -Binary .\ominull-screen.exe [-Hub https://HUB:PORT -Ca .\ca.pem]
#   .\install-screen-viewer.ps1 -Uninstall
param(
    [string]$Binary,
    [string]$Hub,
    [string]$Ca,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:LOCALAPPDATA 'OmniNull'
$exe = Join-Path $dir 'ominull-screen.exe'
$key = 'HKCU:\Software\Classes\ominull-screen'
$confDir = Join-Path $env:APPDATA 'ominull'
$conf = Join-Path $confDir 'screen.json'

if ($Uninstall) {
    Remove-Item -Recurse -Force $key -ErrorAction SilentlyContinue
    Remove-Item -Force $exe -ErrorAction SilentlyContinue
    Write-Output "Removed the viewer and its link handler. Hub settings stay in $conf."
    exit 0
}
if (-not $Binary -or -not (Test-Path $Binary)) { throw '-Binary must point at ominull-screen.exe' }
if (($Hub -and -not $Ca) -or ($Ca -and -not $Hub)) { throw '-Hub and -Ca go together' }

New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item -Force $Binary $exe

New-Item -Force $key | Out-Null
Set-ItemProperty $key '(default)' 'URL:OmniNull screen'
Set-ItemProperty $key 'URL Protocol' ''
New-Item -Force "$key\shell\open\command" | Out-Null
Set-ItemProperty "$key\shell\open\command" '(default)' "`"$exe`" `"%1`""

if ($Hub) {
    if ($Hub -notmatch '^https://') { throw '-Hub must be an https:// origin' }
    $pem = Get-Content -Raw $Ca
    if ($pem -notmatch '-----BEGIN CERTIFICATE-----') { throw "$Ca is not a PEM certificate" }
    $origin = $Hub.TrimEnd('/')
    $hubs = @()
    if (Test-Path $conf) {
        $hubs = @((Get-Content -Raw $conf | ConvertFrom-Json).hubs | Where-Object { $_.origin.TrimEnd('/') -ne $origin })
    }
    $hubs += [pscustomobject]@{ origin = $origin; ca_pem = $pem }
    New-Item -ItemType Directory -Force $confDir | Out-Null
    ConvertTo-Json -Depth 4 @{ hubs = @($hubs) } | Set-Content -Encoding UTF8 $conf
    Write-Output "The viewer trusts $origin ($conf)."
}
Write-Output "Installed $exe; ominull-screen:// links open it."
