# PowerShell build script for ominull
param (
    [string]$Configuration = "Debug",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Building ominull.sys ($Configuration | $Platform) ===" -ForegroundColor Cyan

# Locate MSBuild via vswhere
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found. Ensure Visual Studio 2022 is installed."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) {
    throw "Visual Studio installation with MSBuild not found."
}

$msBuildPath = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msBuildPath)) {
    throw "MSBuild.exe not found at $msBuildPath"
}

$projectPath = Join-Path $PSScriptRoot "..\driver\ominull.vcxproj"

Write-Host "Invoking MSBuild on $projectPath..."
& $msBuildPath $projectPath /p:Configuration=$Configuration /p:Platform=$Platform /t:Rebuild

if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

$outputSys = Join-Path $PSScriptRoot "..\bin\$Platform\$Configuration\ominull.sys"
if (Test-Path $outputSys) {
    Write-Host "Build SUCCESS: $outputSys" -ForegroundColor Green
} else {
    Write-Warning "Build completed but $outputSys not found at expected path."
}
