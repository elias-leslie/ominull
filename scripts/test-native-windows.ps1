# Run only fixture APIs: no service installation or real WFP engine changes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) {
    throw 'These tests require a native Windows runner.'
}
$Build = Join-Path (Split-Path -Parent $PSScriptRoot) 'build'
$JsonOutput = & (Join-Path $Build 'test_windows_telemetry_json.exe')
if ($LASTEXITCODE -ne 0) {
    throw "Windows serializer fixture failed: $LASTEXITCODE"
}
$Batch = ($JsonOutput -join "`n") | ConvertFrom-Json
$Caps = $Batch.response_capabilities
# The fixture runs without pinned response authority keys, so the agent says
# so and offers only what needs no grant.
if (-not $Caps.isolate -or $Caps.response_key -ne $false -or $Caps.PSObject.Properties.Name -contains 'collect') {
    throw "Expected isolate with response_key:false and no collect, got $($Caps | ConvertTo-Json -Compress)"
}
if (-not ($Batch.PSObject.Properties.Name -contains 'trust')) {
    throw 'Expected the trust report field in the telemetry batch.'
}
if ($Batch.events.Count -ne 64) {
    throw "Expected 64 serialized events, got $($Batch.events.Count)"
}
foreach ($Event in $Batch.events) {
    if ($Event.process_path.Length -ne 250 -or
        $Event.process_path[10] -ne "`n" -or
        $Event.process_path[11] -ne '"' -or
        $Event.command_line.Length -ne 1000) {
        throw 'Windows serializer lost long fields or escaped characters.'
    }
}
Write-Output 'Windows serializer: 64 records with preserved long fields and controls.'
foreach ($Fixture in @('test_agent_trust', 'test_windows_ipv6_json', 'test_windows_adapter', 'test_wfp_transaction')) {
    & (Join-Path $Build "$Fixture.exe")
    if ($LASTEXITCODE -ne 0) {
        throw "$Fixture failed: $LASTEXITCODE"
    }
}
