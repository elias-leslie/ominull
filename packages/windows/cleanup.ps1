# ominull-package: {"name":"windows-cleanup","title":"Cleanup","description":"Deletes old Windows temp files, crash dumps, error reports and update caches, then compacts the component store.","category":"maintenance","risk":"safe","reboot":true,"timeout":3600,"interval":"weekly","params":[{"name":"temp_days","type":"int","default":7,"min":1,"max":3650,"description":"Delete Windows Temp files older than this many days"},{"name":"minidump_days","type":"int","default":14,"min":1,"max":3650,"description":"Delete crash minidumps older than this many days"},{"name":"memory_dump_days","type":"int","default":7,"min":1,"max":3650,"description":"Delete the full memory dump once it is this many days old"},{"name":"error_report_days","type":"int","default":30,"min":1,"max":3650,"description":"Delete Windows error reports older than this many days"},{"name":"update_download_days","type":"int","default":0,"min":0,"max":3650,"description":"Delete Windows Update download cache files older than this many days"},{"name":"min_reclaim_mb","type":"int","default":100,"min":0,"max":1048576,"description":"Clean only when at least this many MB can be freed (or the component store needs it)"},{"name":"component_store","type":"bool","default":true,"description":"Compact the component store when Windows recommends it"},{"name":"dism_analyze_minutes","type":"int","default":15,"min":1,"max":60,"description":"Give up checking the component store after this many minutes (DISM can hang)"},{"name":"dism_cleanup_minutes","type":"int","default":45,"min":1,"max":60,"description":"Give up compacting the component store after this many minutes (DISM can hang)"},{"name":"service_stop_seconds","type":"int","default":60,"min":5,"max":600,"description":"How long to wait for Windows Update to stop before clearing its download cache"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":1440,"description":"Enforce waits if someone used the computer within this many minutes"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-cleanup'
# --- prelude begin (identical in every package; tests compare) ---
# Runs as SYSTEM with a stripped environment; TEMP is the agent's. Stdout: one JSON line.
# The agent's environment block can carry a broken PATH (1.8.81 and older: a long PATH came through as
# PATH=<cmd.exe>), which hides shutdown.exe, quser and the rest: put the system folders back first.
function Repair-Path([string]$Path, [string]$Sys) {
  if (-not $Sys) { return $Path }
  $parts = @("$Path" -split ';' | Where-Object { $_ }); $sr = $Sys -replace '[\\/][^\\/]+$', ''
  $need = @($Sys, $sr, "$Sys\Wbem", "$Sys\WindowsPowerShell\v1.0") | Where-Object { $parts -notcontains $_ }
  (@($need) + $parts) -join ';'
}
function Initialize-Env {
  $sys = [Environment]::SystemDirectory; $sr = Split-Path $sys; $f = { [Environment]::GetFolderPath($args[0]) }; $pd = & $f 'CommonApplicationData'; $pf = & $f 'ProgramFiles'
  $want = [ordered]@{ SystemRoot = $sr; windir = $sr; SystemDrive = (Split-Path -Qualifier $sys); ProgramData = $pd; ALLUSERSPROFILE = $pd
    ProgramFiles = $pf; 'ProgramFiles(x86)' = (& $f 'ProgramFilesX86'); COMPUTERNAME = [Environment]::MachineName
    LOCALAPPDATA = (& $f 'LocalApplicationData'); APPDATA = (& $f 'ApplicationData'); USERPROFILE = (& $f 'UserProfile')
    PSModulePath = "$pf\WindowsPowerShell\Modules;$sr\system32\WindowsPowerShell\v1.0\Modules" }
  foreach ($k in $want.Keys) { if (-not [Environment]::GetEnvironmentVariable($k)) { [Environment]::SetEnvironmentVariable($k, $want[$k]) } }
  $env:PATH = Repair-Path $env:PATH $sys
  $script:Root = Join-Path $pd 'OminullMaintenance'
}
# audit reports, enforce changes, revert restores first-seen values.
function Get-Mode([string]$Primary, [string]$Fallback) {
  $v = "$Primary".Trim(); if (-not $v) { $v = "$Fallback".Trim() }
  if ('enforce', 'revert' -ccontains $v) { $v } else { 'audit' }
}
# Params are declared on line 1, set as OMINULL_PARAM_<NAME>; a bad value fails the run.
function ConvertFrom-PkgParam($Def, [string]$V) {
  $n = "param $($Def.name)"; $x = 0L
  switch ($Def.type) {
    'int' { if ($V -match '^-?\d{1,18}\z' -and [int64]::TryParse($V, [ref]$x) -and "$x" -ceq $V -and $x -ge $Def.min -and $x -le $Def.max) { return $x } }
    'bool' { if ('true', 'false' -ccontains $V) { return $V -ceq 'true' } }
    'enum' { if (@($Def.values) -ccontains $V) { return $V } }
    'list' {
      $l = [string[]]@(); if ($V -cne '-') { $l = [string[]]($V -split ',') }; $seen = @{}
      foreach ($i in $l) { if ($i -cnotmatch '^[A-Za-z0-9*][A-Za-z0-9 ._*+()\-]{0,127}\z' -or $i.Trim() -cne $i -or $seen[$i.ToLower()]) { throw "$n has a bad or repeated item '$i'" }; $seen[$i.ToLower()] = 1 }
      if ($l.Count -le $Def.max_items -and $V.Length -le 1024) { return , $l }
    }
    'catalog' { if ($V.Length -le 12288) { try { return , @((ConvertFrom-Json $V) | % { $_ }) } catch {} } }
  }
  throw "$n is not a valid $($Def.type)"
}
function Get-PkgParams([string]$Path) {
  $o = @{}; $h = (Get-Content -LiteralPath $Path -TotalCount 1) -replace '^# ominull-package:' | ConvertFrom-Json; $script:PkgTimeout = [int]$h.timeout
  foreach ($d in @($h.params)) {
    $v = [Environment]::GetEnvironmentVariable('OMINULL_PARAM_' + $d.name.ToUpper())
    # The agent cuts a variable at 2047 bytes; a catalog comes whole in the signed parameters file.
    if ($d.type -eq 'catalog') { $v = $(if ($env:OMINULL_PARAMS_FILE) { (Get-Content -LiteralPath $env:OMINULL_PARAMS_FILE -Raw | ConvertFrom-Json).($d.name) }) }
    if (-not $v) { $v = if ($d.type -eq 'list') { (@($d.default) -join ',') -replace '^$', '-' } elseif ($d.type -eq 'bool') { "$($d.default)".ToLower() } elseif ($d.type -eq 'catalog') { '[]' } else { "$($d.default)" } }
    $o[$d.name] = ConvertFrom-PkgParam $d $v
  }
  $o
}
function Start-Log([int]$Keep) {
  $d = "$($script:Root)\logs"; New-Item -ItemType Directory -Force -Path $d | Out-Null
  Get-ChildItem -LiteralPath $d -Filter "$Pkg-*.log" | Sort-Object Name -Descending | Select-Object -Skip ([math]::Max(0, $Keep - 1)) | Remove-Item -Force -ErrorAction SilentlyContinue
  $script:LogFile = "$d\$Pkg-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}
function Write-Log([string]$Message) { if ($script:LogFile) { try { Add-Content -LiteralPath $script:LogFile -Value "$(Get-Date -Format s) $Message" -Encoding UTF8 } catch {} } }
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
  if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { $full = if ([Environment]::SystemDirectory) { Join-Path ([Environment]::SystemDirectory) $Exe }; if ($full -and (Test-Path -LiteralPath $full)) { $Exe = $full } else { return @{ code = -1; out = @("$Exe was not found") } } }
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { $o = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
  @{ code = $c; out = $o }
}
# quser IDLE TIME: ./none (active), 5 (min), 1:05 (h:mm), 2+03:04 (d+h:mm).
function ConvertFrom-QuserIdle([string]$Idle) {
  if ($Idle -match '^(?:(\d+)\+)?(?:(\d+):)?(\d+)$') { [int]$matches[1] * 1440 + [int]$matches[2] * 60 + [int]$matches[3] } else { 0 }
}
function Test-UserActive([string[]]$Lines, [int]$IdleMinutes) {
  foreach ($l in $Lines) { if ($l -match '\sActive\s+(\S+)\s' -and (ConvertFrom-QuserIdle $matches[1]) -lt $IdleMinutes) { return $true } }
  $false
}
# Game folders; tray launchers (Steam, Epic, Riot Client, Battle.net, EA app) do not count.
function Test-GamePath([string]$Path) {
  $Path -and ($Path -match '\\steamapps\\common\\|\\Epic Games\\(?!Launcher\\|Epic Online Services\\)|\\Riot Games\\(?!Riot Client\\)|\\XboxGames\\|\\EA Games\\|\\Ubisoft Game Launcher\\games\\|\\GOG Galaxy\\Games\\|\\WindowsApps\\Microsoft\.Minecraft|\\(Overwatch|World of Warcraft|Diablo IV|Diablo III|Hearthstone|StarCraft II|Call of Duty)\\')
}
function Test-OnBattery($Batteries) { [bool](@($Batteries) | Where-Object { $_ -and [int]$_.BatteryStatus -eq 1 }) }
function Get-PeopleReason([int]$IdleMinutes) {
  $q = Invoke-Native 'quser.exe' @()
  if ($q.code -ge 0 -and (Test-UserActive $q.out $IdleMinutes)) { return 'someone is using the computer' }
  foreach ($p in @(Get-CimInstance Win32_Process -Property ExecutablePath -ErrorAction SilentlyContinue)) {
    if (Test-GamePath $p.ExecutablePath) { return "a game is running ($(Split-Path -Leaf $p.ExecutablePath))" }
  }
}
# Maintenance window: 1-4 "HH:MM-HH:MM" ranges, comma separated, in machine time, or in UTC with a trailing Z; a
# range may cross midnight.
function Test-WindowText([string]$W) {
  $W -cmatch '^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d(,([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d){0,3}Z?\z'
}
function Test-InWindow([string]$Window, [datetime]$Now) {
  if (-not (Test-WindowText $Window)) { return $false }
  if ($Window.EndsWith('Z')) { $Now = $Now.ToUniversalTime(); $Window = $Window.TrimEnd('Z') }
  $n = $Now.Hour * 60 + $Now.Minute
  foreach ($r in $Window.Split(',')) {
    $s = [int]$r.Substring(0, 2) * 60 + [int]$r.Substring(3, 2); $e = [int]$r.Substring(6, 2) * 60 + [int]$r.Substring(9, 2)
    if (($s -le $e -and $n -ge $s -and $n -lt $e) -or ($s -gt $e -and ($n -ge $s -or $n -lt $e))) { return $true }
  }
  $false
}
# Run options from the hub: when_busy skip (default) | wait (up to half the timeout) | run (no people checks);
# inside the window people do not count. Battery and Windows Update always do.
function Get-RunOptions {
  $b = "$env:OMINULL_PARAM_WHEN_BUSY"; if (-not $b) { $b = 'skip' }; $w = "$env:OMINULL_PARAM_WINDOW"
  if ('skip', 'wait', 'run' -cnotcontains $b) { throw 'param when_busy is not skip, wait or run' }
  if ($w -and -not (Test-WindowText $w)) { throw 'param window is not 1-4 HH:MM-HH:MM ranges (comma separated, Z for UTC)' }
  @{ busy = $b; window = $w }
}
function Get-PreflightReason([bool]$CheckUpdates, [int]$IdleMinutes) {
  $o = Get-RunOptions; $until = (Get-Date).AddSeconds([math]::Max(0, $script:PkgTimeout) / 2)
  while ($o.busy -cne 'run' -and -not (Test-InWindow $o.window (Get-Date))) {
    $why = Get-PeopleReason $IdleMinutes
    if (-not $why) { break }
    if ($o.busy -cne 'wait' -or (Get-Date).AddSeconds(60) -gt $until) { return $why }
    Write-Log "waiting: $why"; Start-Sleep -Seconds 60
  }
  if (Test-OnBattery (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)) { return 'running on battery' }
  if ($CheckUpdates) {
    if (Get-Process TiWorker -ErrorAction SilentlyContinue) { return 'Windows Update is installing' }
    try { if ((New-Object -ComObject Microsoft.Update.Installer).IsBusy) { return 'Windows Update is installing' } } catch {}
  }
}
function Format-Result([string]$State, [bool]$Reboot, [string[]]$Changed, $Detail) {
  if ('ok', 'fixed', 'drift', 'failed', 'skipped', 'na' -notcontains $State) { $State = 'failed' }
  $r = [ordered]@{ v = 1; state = $State; reboot = $Reboot; changed = @($Changed | Where-Object { $_ }); detail = $Detail }
  $j = ConvertTo-Json $r -Compress -Depth 6
  if ($j.Length -gt 12000) { $r.detail = @{ truncated = $true }; $j = ConvertTo-Json $r -Compress -Depth 3 }
  $j -replace "[`r`n]", ' '
}
# --- prelude end ---
# --- package temp begin (shared; tests compare) ---
# DISM and Appx calls failed with "The system cannot find the path specified" for every package while
# the after-test was clean; the agent's TEMP is the likely cause. They get a package-owned folder,
# set only around the call; the agent's own folder is never touched.
function Invoke-InPkgTemp([scriptblock]$Block) {
  $t = "$($script:Root)\tmp"; New-Item -ItemType Directory -Force -Path $t | Out-Null
  $old = @{}; foreach ($v in 'TEMP', 'TMP') { $old[$v] = [Environment]::GetEnvironmentVariable($v); [Environment]::SetEnvironmentVariable($v, $t) }
  try { & $Block } finally { foreach ($v in 'TEMP', 'TMP') { [Environment]::SetEnvironmentVariable($v, $old[$v]) } }
}
# --- package temp end ---
# The only places this package deletes from. Nothing under Users, the Recycle Bin,
# the agent's TEMP folder or ProgramData\Ominull is ever listed.
function Get-Targets {
  $sr = $env:SystemRoot; $pd = $env:ProgramData
  @(
    @{ id = 'windows_temp'; path = "$sr\Temp"; days = $Opt.temp_days },
    @{ id = 'minidumps'; path = "$sr\Minidump"; days = $Opt.minidump_days },
    @{ id = 'memory_dump'; path = "$sr\MEMORY.DMP"; days = $Opt.memory_dump_days },
    @{ id = 'error_reports_archive'; path = "$pd\Microsoft\Windows\WER\ReportArchive"; days = $Opt.error_report_days },
    @{ id = 'error_reports_queue'; path = "$pd\Microsoft\Windows\WER\ReportQueue"; days = $Opt.error_report_days },
    @{ id = 'update_downloads'; path = "$sr\SoftwareDistribution\Download"; days = $Opt.update_download_days }
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
# DISM can hang for hours at no CPU (seen on two laptops, worse with a DISM left from an earlier run).
# A leftover Dism.exe is ended before starting, and every DISM call is time-boxed: on the limit its whole
# process tree is killed and the component cleanup is reported skipped, not failed.
function Stop-StaleDism {
  foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='Dism.exe'" -ErrorAction SilentlyContinue)) {
    Write-Log "ending leftover Dism.exe pid $($p.ProcessId) from an earlier run"
    $null = Invoke-Native 'taskkill.exe' @('/PID', "$($p.ProcessId)", '/T', '/F')
    $script:Detail.dism_leftover_ended = 1 + [int]$script:Detail.dism_leftover_ended
  }
}
$DismExe = 'dism.exe'
# Seconds a DISM call may take: its param, never past the package time limit (less 3 minutes to report).
function Get-DismSeconds([int]$Minutes) {
  if (-not $script:Started) { $script:Started = Get-Date }
  $left = $script:PkgTimeout - ((Get-Date) - $script:Started).TotalSeconds - 180
  [int][math]::Max(0, [math]::Min($Minutes * 60, $left))
}
function Invoke-Dism([string[]]$Arguments, [int]$Seconds) {
  if ($Seconds -le 0) { return @{ code = -2; out = @(); timed_out = $true } }
  if (-not (Get-Command $DismExe -ErrorAction SilentlyContinue)) { return @{ code = -1; out = @(); timed_out = $false } }
  $dir = "$($script:Root)\tmp"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $out = Join-Path $dir 'dism.out'; $err = Join-Path $dir 'dism.err'
  $p = Start-Process -FilePath $DismExe -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  $null = $p.Handle   # keeps the exit code readable after the process ends
  if (-not $p.WaitForExit($Seconds * 1000)) {
    if ((Invoke-Native 'taskkill.exe' @('/PID', "$($p.Id)", '/T', '/F')).code -eq -1) { try { $p.Kill() } catch {} }
    try { $null = $p.WaitForExit(30000) } catch {}
    Write-Log "dism timed out after $Seconds s, process tree ended: $($Arguments -join ' ')"
    return @{ code = -2; out = @(); timed_out = $true }
  }
  $p.WaitForExit()   # exited; this also waits for its output to be written out
  @{ code = $p.ExitCode; out = @(Get-Content -LiteralPath $out -ErrorAction SilentlyContinue); timed_out = $false }
}
function Send-ProgressLine([string]$Text) { [Console]::Error.WriteLine("::progress:: $Text") }
function Test-ComponentCleanup {
  Send-ProgressLine "checking the component store (up to $($Opt.dism_analyze_minutes) min)"
  $r = Invoke-InPkgTemp { Invoke-Dism @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore', '/English') (Get-DismSeconds $Opt.dism_analyze_minutes) }
  Write-Log "dism analyze exit $($r.code) timed_out=$($r.timed_out)"
  @{ timed_out = $r.timed_out; recommended = [bool]($r.out | Where-Object { $_ -match 'Component Store Cleanup Recommended\s*:\s*Yes' }) }
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
  if ($Mode -eq 'revert') { $script:State = 'na'; $Detail.reason = 'cleanup only deletes files'; return }
  $before = Measure-Targets; $total = 0; foreach ($v in $before.Values) { $total += $v }
  $dism = $false
  if ($Opt.component_store) {
    Stop-StaleDism
    $a = Test-ComponentCleanup
    if ($a.timed_out) { $Detail.component_cleanup = 'skipped: timed out' } else { $dism = $a.recommended }
  }
  $Detail.reclaimable_bytes = $before; $Detail.component_cleanup_recommended = $dism
  Write-Log "reclaimable=$total component_cleanup=$dism"
  if ($total -lt $Opt.min_reclaim_mb * 1MB -and -not $dism) { $script:State = 'ok'; return }
  if ($Mode -ne 'enforce') { $script:State = 'drift'; return }
  $why = Get-PreflightReason $true $Opt.idle_minutes
  if ($why) { $script:State = 'skipped'; $Detail.reason = $why; return }

  $freed = [ordered]@{}; $errors = @()
  foreach ($t in Get-Targets) {
    if ($before[$t.id] -le 0) { continue }
    if ($t.id -eq 'update_downloads') {
      $svc = Get-Service wuauserv; $wasRunning = $svc.Status -eq 'Running'
      try {
        if ($wasRunning) { Stop-Service wuauserv -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($Opt.service_stop_seconds)) }
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
    Send-ProgressLine "compacting the component store (up to $($Opt.dism_cleanup_minutes) min)"
    $r = Invoke-InPkgTemp { Invoke-Dism @('/Online', '/Cleanup-Image', '/StartComponentCleanup', '/Quiet', '/NoRestart') (Get-DismSeconds $Opt.dism_cleanup_minutes) }
    if ($r.timed_out) { $Detail.component_cleanup = 'skipped: timed out' }
    else {
      $Detail.component_cleanup_exit = $r.code
      if ($r.code -eq 0 -or $r.code -eq 3010) { $Changed.Add('component_store') } else { $errors += "DISM exit $($r.code)" }
      if ($r.code -eq 3010) { $script:Reboot = $true }
    }
  }
  $Detail.freed_bytes = $freed
  $Detail.remaining_bytes = Measure-Targets
  if ($errors.Count) { $Detail.errors = $errors; $script:State = 'failed' } else { $script:State = 'fixed' }
}
$Changed = New-Object 'System.Collections.Generic.List[string]'; $Detail = [ordered]@{}; $State = 'failed'; $Reboot = $false; $script:Started = Get-Date
try {
  Initialize-Env; $Opt = Get-PkgParams $PSCommandPath; Start-Log $Opt.log_keep
  $Mode = Get-Mode $env:OMINULL_PARAM_MODE $env:mode; $Detail.mode = $Mode; Write-Log "start $Pkg mode=$Mode"
  Invoke-Package
} catch { $State = 'failed'; $Detail.error = "$_".Substring(0, [math]::Min(400, "$_".Length)); Write-Log "error: $_ $($_.ScriptStackTrace)" }
try { $json = Format-Result $State $Reboot $Changed.ToArray() $Detail }
catch { $State = 'failed'; $json = '{"v":1,"state":"failed","reboot":false,"changed":[],"detail":{"error":"result could not be encoded"}}' }
Write-Log "result $json"
[Console]::Out.WriteLine($json)
if ($State -eq 'failed') { exit 1 }
exit 0
