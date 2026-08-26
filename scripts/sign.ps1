# PowerShell test-signing script for ominull.sys
param (
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$CertSubject = "CN=OminullTestCert"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Test Signing ominull.sys ===" -ForegroundColor Cyan

$sysPath = Join-Path $PSScriptRoot "..\bin\$Platform\$Configuration\ominull.sys"
if (-not (Test-Path $sysPath)) {
    throw "Driver binary not found at $sysPath. Run scripts\build.ps1 first."
}

# Check for existing test certificate or create one
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating new self-signed code signing certificate ($CertSubject)..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject -CertStoreLocation Cert:\CurrentUser\My -HashAlgorithm SHA256
    Write-Host "Created certificate with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "Found existing certificate: $($cert.Thumbprint)"
}

# Export public certificate (.cer) for installation on test target
$cerPath = Join-Path $PSScriptRoot "..\bin\$Platform\$Configuration\ominull.cer"
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
Write-Host "Exported public cert: $cerPath" -ForegroundColor Green

# Locate signtool.exe from Windows SDK
$sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$signtool = Get-ChildItem -Path $sdkRoot -Filter "signtool.exe" -Recurse | Where-Object { $_.FullName -like "*x64*" } | Select-Object -First 1

if (-not $signtool) {
    throw "signtool.exe not found in $sdkRoot. Ensure Windows SDK is installed."
}

Write-Host "Signing $sysPath with $($signtool.FullName)..."
& $signtool.FullName sign /v /s My /n "OminullTestCert" /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 $sysPath

# If timestamping fails (e.g. offline), fallback to sign without timestamp
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Timestamping failed, signing without timestamp..."
    & $signtool.FullName sign /v /s My /n "OminullTestCert" /fd SHA256 $sysPath
}

Write-Host "Verifying signature on $sysPath..."
& $signtool.FullName verify /v /pa $sysPath

Write-Host "Signing SUCCESS." -ForegroundColor Green
