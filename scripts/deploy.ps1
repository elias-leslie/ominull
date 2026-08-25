# PowerShell deployment and test execution script
param (
    [Parameter(Mandatory=$true)]
    [string]$TargetHost,
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$ServiceName = "wfpsentinel"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Deploying wfpsentinel to target $TargetHost ===" -ForegroundColor Cyan

$sysPath = Join-Path $PSScriptRoot "..\bin\$Platform\$Configuration\wfpsentinel.sys"
$cerPath = Join-Path $PSScriptRoot "..\bin\$Platform\$Configuration\wfpsentinel.cer"

if (-not (Test-Path $sysPath)) { throw "Missing $sysPath" }
if (-not (Test-Path $cerPath)) { throw "Missing $cerPath" }

# 1. Copy files to target C:\drv via administrative SMB share
$targetDrv = "\\$TargetHost\C$\drv"
if (-not (Test-Path $targetDrv)) {
    New-Item -Path $targetDrv -ItemType Directory -Force | Out-Null
}

Copy-Item -Path $sysPath -Destination "$targetDrv\wfpsentinel.sys" -Force
Copy-Item -Path $cerPath -Destination "$targetDrv\wfpsentinel.cer" -Force
Write-Host "Files copied to $targetDrv" -ForegroundColor Green

Write-Host "`nInstructions on Target VM:" -ForegroundColor Yellow
Write-Host "1. Import Cert: certutil -addstore -f Root C:\drv\wfpsentinel.cer"
Write-Host "                certutil -addstore -f TrustedPublisher C:\drv\wfpsentinel.cer"
Write-Host "2. Create Service: sc.exe create $ServiceName type= kernel binPath= C:\drv\wfpsentinel.sys"
Write-Host "3. Start Service:  sc.exe start $ServiceName"
Write-Host "4. Stop Service:   sc.exe stop $ServiceName"
Write-Host "5. Delete Service: sc.exe delete $ServiceName"
