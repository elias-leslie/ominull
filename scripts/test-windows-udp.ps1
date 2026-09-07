param([Parameter(Mandatory=$true)][string]$BinaryDirectory)
$ErrorActionPreference='Stop'
$udp=Join-Path $BinaryDirectory 'test_udp_windows_live.exe'
$lifecycle=Join-Path $BinaryDirectory 'test_udp_windows_lifecycle.exe'
$jsonBinary=Join-Path $BinaryDirectory 'test_windows_telemetry_json.exe'
foreach($binary in @($udp,$lifecycle,$jsonBinary)) {
    if(!(Test-Path -LiteralPath $binary -PathType Leaf)){throw "Missing native fixture: $binary"}
}
$ownerPath='SOFTWARE\Ominull\UDPTrace-LifecycleProbe'
$crash=& $lifecycle crash
if($LASTEXITCODE -ne 0){throw 'Crash fixture did not start'}
$crash
$old=($crash -split 'session=')[1].Trim()
if(!(logman query -ets | Select-String -SimpleMatch $old)){throw 'Crash fixture left no session to recover'}
# A stale ownership record must not authorize deleting a different session.
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ownerPath,$true)
$original=[byte[]]$key.GetValue('Session')
try {
    $changed=[byte[]]$original.Clone()
    $changed[16]=$changed[16] -bxor 1 # GUID starts after DWORD version/PID and UINT64 creation time.
    $key.SetValue('Session',$changed,[Microsoft.Win32.RegistryValueKind]::Binary)
    & $lifecycle
    if($LASTEXITCODE -eq 0){throw 'Mismatched session GUID was accepted'}
    if(!(logman query -ets | Select-String -SimpleMatch $old)){throw 'Mismatched session was stopped'}
} finally {
    $key.SetValue('Session',$original,[Microsoft.Win32.RegistryValueKind]::Binary)
    $key.Dispose()
}
& $lifecycle
if($LASTEXITCODE -ne 0){throw 'Owned session recovery failed'}
if(logman query -ets | Select-String -SimpleMatch $old){throw 'Abandoned session survived recovery'}
Write-Output 'Crash recovery and mismatched-session protection passed'
& $udp pressure
if($LASTEXITCODE -ne 0){throw 'Native UDP pressure fixture failed'}
$document=& $jsonBinary
if($LASTEXITCODE -ne 0){throw 'Native JSON fixture failed'}
$json=$document | ConvertFrom-Json
if($json.events.Count -ne 64 -or $json.events[0].src_ip -ne 'fd00::1' -or
    $json.events[0].dst_ip -ne 'fd00::2' -or $json.events[0].process_path[10] -ne [char]10 -or
    $json.events[0].process_path[11] -ne [char]34){throw 'Serialization mismatch'}
Write-Output '64 native JSON records, IPv6 peers and escaped paths passed'
