# ominull-package: {"name":"windows-performance","title":"Gaming performance","description":"Turns on Game Mode and GPU scheduling where supported and turns off background game recording.","category":"maintenance","risk":"safe","reboot":true,"timeout":300,"interval":"weekly","params":[{"name":"game_mode","type":"bool","default":true,"description":"Turn on Game Mode for new user profiles"},{"name":"gpu_scheduling","type":"bool","default":false,"careful":true,"description":"Careful: turn on hardware-accelerated GPU scheduling where the driver supports it (needs a restart; some games and capture tools misbehave)"},{"name":"block_game_recording","type":"bool","default":true,"description":"Turn off background game recording (Game DVR) by policy"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":1440,"description":"Enforce waits if someone used the computer within this many minutes"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-performance'
# --- prelude begin (identical in every package; tests compare) ---
# Runs as SYSTEM with a stripped environment; TEMP is the agent's. Stdout: one JSON line.
function Initialize-Env {
  $sys = [Environment]::SystemDirectory; $sr = Split-Path $sys; $f = { [Environment]::GetFolderPath($args[0]) }; $pd = & $f 'CommonApplicationData'; $pf = & $f 'ProgramFiles'
  $want = [ordered]@{ SystemRoot = $sr; windir = $sr; SystemDrive = (Split-Path -Qualifier $sys); ProgramData = $pd; ALLUSERSPROFILE = $pd
    ProgramFiles = $pf; 'ProgramFiles(x86)' = (& $f 'ProgramFilesX86'); COMPUTERNAME = [Environment]::MachineName
    LOCALAPPDATA = (& $f 'LocalApplicationData'); APPDATA = (& $f 'ApplicationData'); USERPROFILE = (& $f 'UserProfile')
    PSModulePath = "$pf\WindowsPowerShell\Modules;$sr\system32\WindowsPowerShell\v1.0\Modules" }
  foreach ($k in $want.Keys) { if (-not [Environment]::GetEnvironmentVariable($k)) { [Environment]::SetEnvironmentVariable($k, $want[$k]) } }
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
  $o = @{}
  foreach ($d in @(((Get-Content -LiteralPath $Path -TotalCount 1) -replace '^# ominull-package:' | ConvertFrom-Json).params)) {
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
  if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return @{ code = -1; out = @() } }
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
function Get-PreflightReason([bool]$CheckUpdates, [int]$IdleMinutes) {
  $q = Invoke-Native 'quser.exe' @()
  if ($q.code -ge 0 -and (Test-UserActive $q.out $IdleMinutes)) { return 'someone is using the computer' }
  foreach ($p in @(Get-CimInstance Win32_Process -Property ExecutablePath -ErrorAction SilentlyContinue)) {
    if (Test-GamePath $p.ExecutablePath) { return "a game is running ($(Split-Path -Leaf $p.ExecutablePath))" }
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
# --- original values begin (shared; tests compare) ---
# First-seen values, recorded before enforce changes them, never overwritten.
function Get-Original {
  $o = [ordered]@{}; $f = "$($script:Root)\state\$Pkg-original.json"
  if (Test-Path -LiteralPath $f) { (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $o[$_.Name] = $_.Value } }
  $o
}
function Save-Original($Values) {
  $o = Get-Original; $n = $o.Count; foreach ($k in $Values.Keys) { if (-not $o.Contains($k)) { $o[$k] = $Values[$k] } }
  if ($o.Count -gt $n) { New-Item -ItemType Directory -Force -Path "$($script:Root)\state" | Out-Null; ConvertTo-Json $o -Depth 5 | Set-Content -LiteralPath "$($script:Root)\state\$Pkg-original.json" -Encoding UTF8 }
}
# revert: HKLM:|DefaultUser\key\name = DWORD ($null: absent), service:<name> = StartMode/State; others are kept.
function Invoke-Revert([string]$HiveRoot) {
  $done = @(); $keep = @(); $err = @()
  foreach ($e in (Get-Original).GetEnumerator()) {
    $k = $e.Key
    try {
      if ($k -match '^service:(.+)$') {
        $n = $matches[1]; $m, $r = "$($e.Value)" -split '/'
        Set-Service -Name $n -StartupType ($m -replace '^Auto$', 'Automatic'); if ($r -eq 'Running') { Start-Service -Name $n }
      } elseif ($k -match '^(HKLM:|DefaultUser)\\') { Restore-Reg $k $e.Value $HiveRoot } else { $keep += $k; continue }
      $done += $k; $Changed.Add("restored $k")
    } catch { $err += "$k : $_" }
  }
  $Detail.restored = $done; $Detail.not_restorable = $keep
  $script:State = $(if ($err) { $Detail.errors = $err; 'failed' } elseif ($done) { 'fixed' } else { 'ok' })
}
# --- original values end ---
# --- registry helpers begin (shared; tests compare) ---
function New-Control([string]$Id, $Expected, $Actual, [string]$State, [string]$Risk) {
  [ordered]@{ id = $Id; expected = "$Expected"; actual = "$Actual"; state = $State; risk = $(if ($Risk) { $Risk } else { 'safe' }) }
}
function Get-Reg([string]$Path, [string]$Name) { try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null } }
function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
  New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}
function Restore-Reg([string]$Key, $Value, [string]$HiveRoot) {
  $null = $Key -match '^(.+)\\([^\\]+)$'; $p = $matches[1] -replace '^DefaultUser', $HiveRoot
  if ($null -eq $Value) { Remove-ItemProperty -LiteralPath $p -Name $matches[2] -ErrorAction SilentlyContinue } else { Set-RegDword $p $matches[2] $Value }
}
# Default user hive (new profiles): one run at a time, mutex held load to unload; never unloads one it didn't load.
function Mount-DefaultHive([int]$WaitMs = 120000) {
  $m = New-Object Threading.Mutex($false, 'Global\OminullDefaultHive')
  try { $got = $m.WaitOne($WaitMs) } catch [Threading.AbandonedMutexException] { $got = $true }
  if (!$got) { $m.Dispose(); $script:State = 'skipped'; $Detail.reason = 'another package is using the Default user hive'; return }
  $script:HiveLock = $m; $h = 'Registry::HKEY_USERS\OminullDefault'
  if (Test-Path $h) { $Detail.hive_preloaded = $true; return $h }
  $r = Invoke-Native 'reg.exe' @('load', 'HKU\OminullDefault', "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').Default)\NTUSER.DAT")
  if ($r.code) { Dismount-DefaultHive; throw "could not load the Default user hive: $($r.out)" }
  $script:HiveMine = $true; $h
}
function Dismount-DefaultHive {
  if (!($m = $script:HiveLock)) { return }
  try {
    for ($i = 0; $script:HiveMine -and $i -lt 5; $i++) {
      [gc]::Collect(); [gc]::WaitForPendingFinalizers(); $r = Invoke-Native 'reg.exe' @('unload', 'HKU\OminullDefault')
      if ($r.code) { Start-Sleep 2 } else { $script:HiveMine = $false }
    }
    if ($script:HiveMine) { throw "the Default user hive could not be unloaded: $($r.out)" }
  } finally { $script:HiveMine = $false; $script:HiveLock = $null; $m.ReleaseMutex(); $m.Dispose() }
}
# A setting is (path, name, DWORD[, 'careful']); its key names it in originals and controls.
function Get-Key($s) { "$($s[0])\$($s[1])" -replace '^Registry::HKEY_USERS\\OminullDefault', 'DefaultUser' }
function Get-Drift($Settings) {
  $d = [ordered]@{}; foreach ($s in $Settings) { $c = Get-Reg $s[0] $s[1]; if ("$c" -ne "$($s[2])") { $d[(Get-Key $s)] = $c } }; $d
}
# Preflight, record originals, apply; the check after decides the state. One control per setting.
function Invoke-Settings($Settings) {
  $after = $drift = Get-Drift $Settings; $fixed = @{}; Write-Log "drift: $($drift.Keys -join ', ')"
  $script:State = $(if (-not $drift.Count) { 'ok' } elseif ($Mode -ne 'enforce') { 'drift' } elseif ($why = Get-PreflightReason $false $Opt.idle_minutes) { $Detail.reason = $why; 'skipped' } else { 'fixed' })
  if ($State -eq 'fixed') {
    Save-Original $drift; $w = @()
    foreach ($s in $Settings) { if ($drift.Contains(($k = Get-Key $s))) { try { Set-RegDword $s[0] $s[1] $s[2]; $fixed[$k] = 1; $Changed.Add("$k=$($s[2])") } catch { $w += "$k : $_" } } }
    if (($after = Get-Drift $Settings).Count) { $script:State = 'failed' }; if ($w) { $Detail.warnings = $w }
  }
  $Detail.controls = @(foreach ($s in $Settings) {
    $k = Get-Key $s; $a = $after.Contains($k)
    New-Control $k $s[2] $(if ($a) { $after[$k] } else { $s[2] }) $(if ($a) { 'fail' } elseif ($fixed[$k]) { 'fixed' } else { 'pass' }) $s[3] })
}
# --- registry helpers end ---
$GraphicsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
$DisplayClass = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
# Hardware-accelerated GPU scheduling needs Windows 10 2004+ and a WDDM 2.7+ driver; the
# driver version's first field is the WDDM version (27 = 2.7, 31 = 3.1).
function Test-HagsSupported([int]$Build, [string[]]$DriverVersions) {
  if ($Build -lt 19041) { return $false }
  foreach ($v in $DriverVersions) { if ($v -match '^(\d+)\.' -and [int]$matches[1] -ge 27) { return $true } }
  $false
}
function Get-DriverVersions {
  @(Get-ChildItem -LiteralPath $DisplayClass -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' } |
    ForEach-Object { $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
      if ($p.DriverVersion -and $p.DriverDesc -notmatch 'Basic Display|Remote|Virtual') { "$($p.DriverVersion)" } })
}
function Get-Settings($HiveRoot, [bool]$Hags) {
  $s = @()
  if ($Opt.block_game_recording) { $s += , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR', 'AllowGameDVR', 0) }
  if ($Opt.game_mode) { $s += , @("$HiveRoot\Software\Microsoft\GameBar", 'AutoGameModeEnabled', 1) }
  if ($Hags -and $Opt.gpu_scheduling) { $s += , @($GraphicsKey, 'HwSchMode', 2, 'careful') }
  , $s
}
function Invoke-Package {
  if (-not ($hive = Mount-DefaultHive)) { return }
  try {
    if ($Mode -eq 'revert') { Invoke-Revert $hive } else {
      $build = [int](Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuildNumber')
      $drivers = @(Get-DriverVersions); $hags = Test-HagsSupported $build $drivers
      $Detail.gpu_drivers = $drivers; $Detail.hags_supported = $hags
      if (-not $hags) { $Detail.hags_note = 'GPU scheduling left alone: needs Windows 10 2004+ and a WDDM 2.7+ driver' }
      elseif (-not $Opt.gpu_scheduling) { $Detail.hags_note = 'GPU scheduling is a careful step, left alone unless gpu_scheduling is on' }
      $plan = Invoke-Native 'powercfg.exe' @('/getactivescheme')
      $Detail.power_plan = ($plan.out -join ' ') -replace '^.*\(([^)]*)\).*$', '$1'
      Invoke-Settings (Get-Settings $hive $hags)
    }
    if ($Changed -match 'HwSchMode') { $script:Reboot = $true }
  } finally { Dismount-DefaultHive }
}
$Changed = New-Object 'System.Collections.Generic.List[string]'; $Detail = [ordered]@{}; $State = 'failed'; $Reboot = $false
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
