# ominull-package: {"name":"windows-audit","title":"Standards check","description":"Checks BitLocker, Defender, firewall, update age, free disk space, TPM and Secure Boot without changing anything.","category":"maintenance","risk":"safe","reboot":false,"timeout":300,"interval":"daily","params":[{"name":"signature_max_days","type":"int","default":3,"min":1,"max":60,"description":"Drift once Defender signatures are this many days old"},{"name":"update_max_days","type":"int","default":35,"min":1,"max":365,"description":"Drift once the last successful Windows Update install is this many days ago"},{"name":"disk_min_free_pct","type":"int","default":15,"min":1,"max":90,"description":"System drive is fine with at least this percent free (or the GB below)"},{"name":"disk_min_free_gb","type":"int","default":20,"min":1,"max":10000,"description":"System drive is fine with at least this many GB free (or the percent above)"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-audit'
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
# --- reboot check begin (shared; tests compare) ---
function Test-PendingReboot {
  (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
  (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}
# --- reboot check end ---
# Read-only. One control per check: pass, fail, or na (does not apply here).
function New-Control($Id, $Expected, $Actual, $State, $Risk = 'safe') { [ordered]@{ id = $Id; expected = "$Expected"; actual = "$Actual"; state = $State; risk = $Risk } }
function Test-Control([string]$Id, [string]$Expected, [scriptblock]$Block) {
  try { $a, $ok = & $Block; New-Control $Id $Expected $a $(if ($null -eq $ok) { 'na' } elseif ($ok) { 'pass' } else { 'fail' }) }
  catch { New-Control $Id $Expected "check failed: $("$_".Substring(0, [math]::Min(160, "$_".Length)))" 'fail' }
}
function Get-CheckState($Controls) { if (@($Controls | Where-Object { $_.state -eq 'fail' }).Count) { 'drift' } else { 'ok' } }
function Invoke-Package {
  if ($Mode -eq 'revert') { $script:State = 'na'; $Detail.reason = 'audit changes nothing'; return }
  $Detail.controls = $c = @(
    Test-Control 'bitlocker' 'system drive protected' {
      $v = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($env:SystemDrive)'" -ErrorAction SilentlyContinue
      if (-not $v) { 'not available on this edition', $null } else { "protection status $($v.ProtectionStatus)", ([int]$v.ProtectionStatus -eq 1) }
    }
    Test-Control 'defender' "antivirus and real-time on, signatures under $($Opt.signature_max_days) days old" {
      $m = Get-MpComputerStatus; $age = [int]((Get-Date) - $m.AntivirusSignatureLastUpdated).TotalDays
      "antivirus $($m.AntivirusEnabled), real-time $($m.RealTimeProtectionEnabled), signatures $age days old", [bool]($m.AntivirusEnabled -and $m.RealTimeProtectionEnabled -and $age -lt $Opt.signature_max_days)
    }
    Test-Control 'firewall' 'all profiles on' {
      $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
      $(if ($off.Count) { "off: $($off -join ', ')" } else { 'all profiles on' }), ($off.Count -eq 0)
    }
    Test-Control 'updates' "last install under $($Opt.update_max_days) days ago" {
      $days = [int]((Get-Date) - [datetime](New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate).TotalDays
      "last successful install $days days ago", ($days -lt $Opt.update_max_days)
    }
    Test-Control 'disk' "at least $($Opt.disk_min_free_pct)% or $($Opt.disk_min_free_gb) GB free" {
      $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
      $pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1); $gb = [math]::Round($d.FreeSpace / 1GB, 1)
      "$gb GB free ($pct%)", ($pct -ge $Opt.disk_min_free_pct -or $gb -ge $Opt.disk_min_free_gb)
    }
    Test-Control 'tpm' 'present and ready' { $t = Get-Tpm; "present $($t.TpmPresent), ready $($t.TpmReady)", [bool]($t.TpmPresent -and $t.TpmReady) }
    Test-Control 'secure_boot' 'on' { $on = $false; try { $on = [bool](Confirm-SecureBootUEFI) } catch {}; $(if ($on) { 'on' } else { 'off or not UEFI' }), $on }
  )
  $script:Reboot = $Detail.reboot_pending = Test-PendingReboot
  $script:State = Get-CheckState $c
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
