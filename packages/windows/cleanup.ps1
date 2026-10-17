# ominull-package: {"name":"windows-cleanup","title":"Cleanup","description":"Deletes old Windows temp files, crash dumps, error reports and update caches, then compacts the component store.","risk":"safe","reboot":true,"timeout":3600}
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-cleanup'
# --- prelude begin (identical in every package; tests compare) ---
# Runs as LocalSystem under the OmniNull agent: stripped environment, TEMP is the
# agent's own folder (never touched). Stdout carries only the final JSON line.
function Initialize-Env {
    $sr = $env:SystemRoot; if (-not $sr) { $sr = 'C:\Windows'; $env:SystemRoot = $sr }
    if (-not $env:windir) { $env:windir = $sr }
    $pd = [Environment]::GetFolderPath('CommonApplicationData'); if (-not $pd) { $pd = "$($env:SystemDrive)\ProgramData" }
    if (-not $env:ProgramData) { $env:ProgramData = $pd }
    if (-not $env:ALLUSERSPROFILE) { $env:ALLUSERSPROFILE = $pd }
    $pf = [Environment]::GetFolderPath('ProgramFiles')
    if (-not $env:ProgramFiles) { $env:ProgramFiles = $pf }
    if (-not ${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} = [Environment]::GetFolderPath('ProgramFilesX86') }
    if (-not $env:COMPUTERNAME) { $env:COMPUTERNAME = [Environment]::MachineName }
    if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData') }
    if (-not $env:APPDATA) { $env:APPDATA = [Environment]::GetFolderPath('ApplicationData') }
    if (-not $env:USERPROFILE) { $env:USERPROFILE = [Environment]::GetFolderPath('UserProfile') }
    if (-not $env:PSModulePath) { $env:PSModulePath = "$pf\WindowsPowerShell\Modules;$sr\system32\WindowsPowerShell\v1.0\Modules" }
    $script:Root = Join-Path $pd 'OminullMaintenance'
}
function Get-Mode([string]$Primary, [string]$Fallback) {
    $v = $Primary; if (-not $v) { $v = $Fallback }
    if ($v -and $v.Trim() -eq 'enforce') { 'enforce' } else { 'audit' }
}
function Start-Log {
    $d = Join-Path $script:Root 'logs'; New-Item -ItemType Directory -Force -Path $d | Out-Null
    Get-ChildItem -LiteralPath $d -Filter "$Pkg-*.log" | Sort-Object Name -Descending | Select-Object -Skip 19 |
        Remove-Item -Force -ErrorAction SilentlyContinue
    $script:LogFile = Join-Path $d ('{0}-{1}.log' -f $Pkg, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
function Write-Log([string]$Message) {
    if ($script:LogFile) { try { Add-Content -LiteralPath $script:LogFile -Value ('{0} {1}' -f (Get-Date -Format s), $Message) -Encoding UTF8 } catch {} }
}
# First-seen values only: a later run never overwrites what the machine had before.
function Save-Original($Values) {
    try {
        $f = Join-Path $script:Root "state\$Pkg-original.json"; $cur = [ordered]@{}; $add = $false
        if (Test-Path -LiteralPath $f) { (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cur[$_.Name] = $_.Value } }
        foreach ($k in $Values.Keys) { if (-not $cur.Contains($k)) { $cur[$k] = $Values[$k]; $add = $true } }
        if ($add) {
            New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null
            ConvertTo-Json $cur -Depth 5 | Set-Content -LiteralPath $f -Encoding UTF8
        }
    } catch { Write-Log "original-values save failed: $_" }
}
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return @{ code = -1; out = @() } }
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    @{ code = $c; out = $o }
}
# quser IDLE TIME: "." / "none" = active now, "5" minutes, "1:05" h:mm, "2+03:04" d+h:mm.
function ConvertFrom-QuserIdle([string]$Idle) {
    if ($Idle -match '^(\d+)\+(\d+):(\d+)$') { return [int]$matches[1] * 1440 + [int]$matches[2] * 60 + [int]$matches[3] }
    if ($Idle -match '^(\d+):(\d+)$') { return [int]$matches[1] * 60 + [int]$matches[2] }
    if ($Idle -match '^\d+$') { return [int]$Idle }
    0
}
function Test-UserActive([string[]]$Lines) {
    foreach ($l in $Lines) { if ($l -match '\sActive\s+(\S+)\s' -and (ConvertFrom-QuserIdle $matches[1]) -lt 15) { return $true } }
    $false
}
# Game install folders. Launchers that sit in the tray (Steam, Epic, Riot Client,
# Battle.net, EA app) live elsewhere and do not count.
function Test-GamePath([string]$Path) {
    if (-not $Path) { return $false }
    $rules = '\\steamapps\\common\\', '\\Epic Games\\(?!Launcher\\)', '\\Riot Games\\(?!Riot Client\\)', '\\XboxGames\\',
        '\\EA Games\\', '\\Ubisoft Game Launcher\\games\\', '\\GOG Galaxy\\Games\\', '\\WindowsApps\\Microsoft\.Minecraft',
        '\\(Overwatch|World of Warcraft|Diablo IV|Diablo III|Hearthstone|StarCraft II|Call of Duty)\\'
    foreach ($r in $rules) { if ($Path -match $r) { return $true } }
    $false
}
function Test-OnBattery($Batteries) {
    foreach ($b in @($Batteries)) { if ($b -and [int]$b.BatteryStatus -eq 1) { return $true } }
    $false
}
function Get-PreflightReason([bool]$CheckUpdates) {
    $q = Invoke-Native 'quser.exe' @()
    if ($q.code -ge 0 -and (Test-UserActive $q.out)) { return 'someone is using the computer' }
    foreach ($p in @(Get-CimInstance Win32_Process -Property ExecutablePath -ErrorAction SilentlyContinue)) {
        if (Test-GamePath $p.ExecutablePath) { return "a game is running ($(Split-Path -Leaf $p.ExecutablePath))" }
    }
    if (Test-OnBattery (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)) { return 'running on battery' }
    if ($CheckUpdates) {
        if (Get-Process TiWorker -ErrorAction SilentlyContinue) { return 'Windows Update is installing' }
        try { if ((New-Object -ComObject Microsoft.Update.Installer).IsBusy) { return 'Windows Update is installing' } } catch {}
    }
    $null
}
function Test-PendingReboot {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}
function Get-Reg([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}
# The Default user's hive: what every new profile starts from.
function Mount-DefaultHive {
    $root = 'Registry::HKEY_USERS\OminullDefault'
    if (Test-Path $root) { Dismount-DefaultHive }
    $dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').Default
    $r = Invoke-Native 'reg.exe' @('load', 'HKU\OminullDefault', (Join-Path $dir 'NTUSER.DAT'))
    if ($r.code -ne 0) { throw "could not load the Default user hive: $($r.out -join ' ')" }
    $root
}
# A hive left loaded would lock the Default profile, so unloading is retried.
function Dismount-DefaultHive {
    for ($i = 0; $i -lt 5; $i++) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        $r = Invoke-Native 'reg.exe' @('unload', 'HKU\OminullDefault')
        if ($r.code -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw "the Default user hive could not be unloaded: $($r.out -join ' ')"
}
function Format-Result([string]$State, [bool]$Reboot, [string[]]$Changed, $Detail) {
    if (@('ok', 'fixed', 'drift', 'failed', 'skipped') -notcontains $State) { $State = 'failed' }
    if ($null -eq $Changed) { $Changed = @() }
    $j = ConvertTo-Json ([ordered]@{ v = 1; state = $State; reboot = $Reboot; changed = $Changed; detail = $Detail }) -Compress -Depth 6
    if ($j.Length -gt 12000) { $j = ConvertTo-Json ([ordered]@{ v = 1; state = $State; reboot = $Reboot; changed = $Changed; detail = @{ truncated = $true } }) -Compress -Depth 3 }
    $j -replace "[`r`n]", ' '
}
# --- prelude end ---
# The only places this package deletes from. Nothing under Users, the Recycle Bin,
# the agent's TEMP folder or ProgramData\Ominull is ever listed.
function Get-Targets {
    $sr = $env:SystemRoot; $pd = $env:ProgramData
    @(
        @{ id = 'windows_temp'; path = "$sr\Temp"; days = 7 },
        @{ id = 'minidumps'; path = "$sr\Minidump"; days = 14 },
        @{ id = 'memory_dump'; path = "$sr\MEMORY.DMP"; days = 7 },
        @{ id = 'error_reports_archive'; path = "$pd\Microsoft\Windows\WER\ReportArchive"; days = 30 },
        @{ id = 'error_reports_queue'; path = "$pd\Microsoft\Windows\WER\ReportQueue"; days = 30 },
        @{ id = 'update_downloads'; path = "$sr\SoftwareDistribution\Download"; days = 0 }
    )
}
function Test-Allowed([string]$Path) {
    $p = $Path.TrimEnd('\') + '\'
    if ($p -match '\\Users\\|\\Ominull\\|\$Recycle\.Bin') { return $false }
    $p.StartsWith("$($env:SystemRoot)\", 'OrdinalIgnoreCase') -or $p.StartsWith("$($env:ProgramData)\Microsoft\Windows\WER\", 'OrdinalIgnoreCase')
}
# Files older than the cutoff. Junctions and symlinks are never followed.
function Get-OldFiles([string]$Path, [datetime]$Cutoff) {
    $out = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    if (-not (Test-Allowed $Path)) { return ,$out }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $f = [System.IO.FileInfo]$Path; if ($f.LastWriteTime -lt $Cutoff) { $out.Add($f) }; return ,$out
    }
    $root = [System.IO.DirectoryInfo]$Path
    if (-not $root.Exists -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return ,$out }
    $stack = New-Object System.Collections.Stack; $stack.Push($root)
    while ($stack.Count) {
        $d = $stack.Pop()
        try { $items = $d.GetFileSystemInfos() } catch { continue }
        foreach ($i in $items) {
            if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($i -is [System.IO.DirectoryInfo]) { $stack.Push($i) } elseif ($i.LastWriteTime -lt $Cutoff) { $out.Add($i) }
        }
    }
    ,$out
}
function Measure-Targets {
    $m = [ordered]@{}
    foreach ($t in Get-Targets) {
        $files = Get-OldFiles $t.path (Get-Date).AddDays(-$t.days)
        $sum = 0; foreach ($f in $files) { $sum += $f.Length }
        $m[$t.id] = $sum
    }
    $do = "$($env:SystemRoot)\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
    $sum = 0; if (Test-Path -LiteralPath $do) { foreach ($f in (Get-OldFiles $do (Get-Date).AddDays(1))) { $sum += $f.Length } }
    $m['delivery_optimization'] = $sum
    $m
}
function Test-ComponentCleanup {
    $r = Invoke-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore', '/English')
    Write-Log "dism analyze exit $($r.code)"
    [bool]($r.out | Where-Object { $_ -match 'Component Store Cleanup Recommended\s*:\s*Yes' })
}
function Remove-Old($Target) {
    $freed = 0
    foreach ($f in (Get-OldFiles $Target.path (Get-Date).AddDays(-$Target.days))) {
        $len = $f.Length
        try { Remove-Item -LiteralPath $f.FullName -Force; $freed += $len } catch { Write-Log "kept (in use): $($f.FullName)" }
    }
    $freed
}
function Invoke-Package {
    $before = Measure-Targets; $total = 0; foreach ($v in $before.Values) { $total += $v }
    $dism = Test-ComponentCleanup
    $Detail.reclaimable_bytes = $before; $Detail.component_cleanup_recommended = $dism
    Write-Log "reclaimable=$total component_cleanup=$dism"
    if ($total -lt 100MB -and -not $dism) { $script:State = 'ok'; return }
    if ($Mode -ne 'enforce') { $script:State = 'drift'; return }
    $why = Get-PreflightReason $true
    if ($why) { $script:State = 'skipped'; $Detail.reason = $why; return }

    $freed = [ordered]@{}; $errors = @()
    foreach ($t in Get-Targets) {
        if ($before[$t.id] -le 0) { continue }
        if ($t.id -eq 'update_downloads') {
            $svc = Get-Service wuauserv; $wasRunning = $svc.Status -eq 'Running'
            try {
                if ($wasRunning) { Stop-Service wuauserv -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
                $freed[$t.id] = Remove-Old $t
            } catch { $errors += "update downloads: $_" }
            finally { if ($wasRunning) { Start-Service wuauserv -ErrorAction SilentlyContinue } }
        } else { $freed[$t.id] = Remove-Old $t }
        if ($freed[$t.id] -gt 0) { $Changed.Add("$($t.id) $([math]::Round($freed[$t.id] / 1MB)) MB") }
    }
    if ($before['delivery_optimization'] -gt 0 -and (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue)) {
        try { Delete-DeliveryOptimizationCache -Force | Out-Null; $freed['delivery_optimization'] = $before['delivery_optimization']; $Changed.Add('delivery_optimization') }
        catch { $errors += "delivery optimization: $_" }
    }
    if ($dism) {
        Write-Log 'dism StartComponentCleanup'
        $r = Invoke-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/StartComponentCleanup', '/Quiet', '/NoRestart')
        $Detail.component_cleanup_exit = $r.code
        if ($r.code -eq 0 -or $r.code -eq 3010) { $Changed.Add('component_store') } else { $errors += "DISM exit $($r.code)" }
        if ($r.code -eq 3010) { $script:Reboot = $true }
    }
    $Detail.freed_bytes = $freed
    $Detail.remaining_bytes = Measure-Targets
    if ($errors.Count) { $Detail.errors = $errors; $script:State = 'failed' } else { $script:State = 'fixed' }
}
$Changed = New-Object 'System.Collections.Generic.List[string]'; $Detail = [ordered]@{}; $State = 'failed'; $Reboot = $false
try {
    Initialize-Env; Start-Log
    $Mode = Get-Mode $env:OMINULL_PARAM_MODE $env:mode; $Detail.mode = $Mode; Write-Log "start $Pkg mode=$Mode"
    Invoke-Package
} catch {
    $State = 'failed'; $m = "$_"; if ($m.Length -gt 400) { $m = $m.Substring(0, 400) }
    $Detail.error = $m; Write-Log "error: $_ $($_.ScriptStackTrace)"
}
try { $json = Format-Result $State $Reboot $Changed.ToArray() $Detail }
catch { $State = 'failed'; $json = '{"v":1,"state":"failed","reboot":false,"changed":[],"detail":{"error":"result could not be encoded"}}' }
Write-Log "result $json"
[Console]::Out.WriteLine($json)
if ($State -eq 'failed') { exit 1 }
exit 0
