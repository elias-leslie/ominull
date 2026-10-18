# ominull-package: {"name":"windows-maintenance-mode","title":"Maintenance mode","description":"Keeps the computer awake while maintenance runs: sleep and hibernate after idle are off until the end time, then the machine's own settings come back by themselves.","category":"maintenance","risk":"safe","reboot":false,"timeout":120,"interval":"daily","params":[{"name":"hours","type":"int","default":6,"min":1,"max":24,"description":"How long maintenance mode lasts before the machine's own sleep settings come back"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}],"role":"maintenance_mode"}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-maintenance-mode'
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
# --- maintenance mode ---
# enforce: sleep and hibernate after idle off (AC and DC) until now + hours; the values in force
# before are saved once and a one-off SYSTEM task puts them back at the end (or at the next start
# if the machine was off then). Enforce again extends the end. revert: put them back now.
# audit: report. No preflight: keeping the machine awake is the point.
$SleepGroup = '238c9fa8-0aad-41ed-83f4-97be242c8f20'
$PowerSettings = [ordered]@{ standby = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'; hibernate = '9d7815a6-7ee4-497e-8888-515a05f02364' }
$TaskName = 'OminullMaintenanceModeEnd'
function Get-StateFile { "$($script:Root)\state\$Pkg.json" }
# The last two hex values of a setting's block are its current AC and DC index (locale-proof).
function ConvertFrom-PowerQuery([string]$Text) {
  $v = @([regex]::Matches($Text, ':\s*0x([0-9a-fA-F]{1,8})\b') | ForEach-Object { [Convert]::ToInt64($_.Groups[1].Value, 16) })
  if ($v.Count -ge 2) { , @($v[-2], $v[-1]) } else { $null }
}
# A saved powercfg /query (the operator's power-before.txt) split by setting GUID.
function ConvertFrom-PowerDump([string]$Text) {
  $o = [ordered]@{}
  foreach ($k in $PowerSettings.Keys) {
    $i = $Text.IndexOf($PowerSettings[$k], [StringComparison]::OrdinalIgnoreCase); if ($i -lt 0) { return $null }
    $part = $Text.Substring($i + 36); $j = $part.IndexOf('GUID', [StringComparison]::OrdinalIgnoreCase); if ($j -gt 0) { $part = $part.Substring(0, $j) }
    $v = ConvertFrom-PowerQuery $part; if (-not $v) { return $null }
    $o["$k.ac"] = $v[0]; $o["$k.dc"] = $v[1]
  }
  $o
}
function Get-ActiveScheme {
  $r = Invoke-Native 'powercfg.exe' @('/getactivescheme')
  if (($r.out -join ' ') -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $matches[1] } else { throw 'powercfg did not name the active power plan' }
}
function Get-PowerValues([string]$Scheme) {
  $o = [ordered]@{}
  foreach ($k in $PowerSettings.Keys) {
    $r = Invoke-Native 'powercfg.exe' @('/query', $Scheme, $SleepGroup, $PowerSettings[$k])
    $v = ConvertFrom-PowerQuery ($r.out -join "`n"); if ($r.code -or -not $v) { throw "powercfg could not read the $k timeout" }
    $o["$k.ac"] = $v[0]; $o["$k.dc"] = $v[1]
  }
  $o
}
function Set-PowerValues([string]$Scheme, $Values) {
  foreach ($e in $Values.GetEnumerator()) {
    $k, $w = $e.Key -split '\.'
    $r = Invoke-Native 'powercfg.exe' @("/set$($w)valueindex", $Scheme, $SleepGroup, $PowerSettings[$k], "$($e.Value)")
    if ($r.code) { throw "powercfg could not set $($e.Key): $($r.out)" }
  }
  $null = Invoke-Native 'powercfg.exe' @('/setactive', 'SCHEME_CURRENT')
}
# Self-contained: also the scheduled task's whole command. Values are checked again here because
# the state file sits under ProgramData.
function Restore-Power {
  $f = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'OminullMaintenance\state\windows-maintenance-mode.json'
  $g = @{ standby = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'; hibernate = '9d7815a6-7ee4-497e-8888-515a05f02364' }; $done = @()
  if (Test-Path -LiteralPath $f) {
    $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
    if ("$($s.scheme)" -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
      foreach ($p in @($s.saved.PSObject.Properties)) {
        $k, $w = $p.Name -split '\.'; $v = "$($p.Value)"
        if ($g[$k] -and ('ac', 'dc' -ccontains $w) -and $v -match '^\d{1,10}$') {
          & powercfg.exe "/set$($w)valueindex" $s.scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 $g[$k] $v 2>&1 | Out-Null
          if (-not $LASTEXITCODE) { $done += "$($p.Name)=$v" }
        }
      }
      & powercfg.exe /setactive SCHEME_CURRENT 2>&1 | Out-Null
    }
    Remove-Item -LiteralPath $f -Force
  }
  try { Unregister-ScheduledTask -TaskName OminullMaintenanceModeEnd -TaskPath '\Ominull\' -Confirm:$false -ErrorAction Stop } catch {}
  , $done
}
function Register-EndTask([datetime]$Until) {
  $cmd = "function Restore-Power {$((Get-Item function:Restore-Power).Definition)}`n`$null = Restore-Power"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
  $a = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc"
  $t = New-ScheduledTaskTrigger -Once -At $Until.ToLocalTime()
  $st = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
  $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -TaskPath '\Ominull\' -Action $a -Trigger $t -Settings $st -Principal $p -Force | Out-Null
}
function Get-ModeState {
  $f = Get-StateFile; if (-not (Test-Path -LiteralPath $f)) { return $null }
  $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
  $u = $(if ($s.until -is [datetime]) { $s.until } else { [datetime]::Parse("$($s.until)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) })
  @{ until = $u.ToUniversalTime(); since = "$($s.since)"; raw = $s }
}
function Invoke-Package {
  $now = [datetime]::UtcNow; $cur = Get-ModeState
  if ($cur -and $cur.until -le $now -and $Mode -ne 'audit') { $r = Restore-Power; $Changed.Add("ended an expired maintenance mode ($($r -join ', '))"); $cur = $null }
  if ($Mode -eq 'audit') {
    $on = $cur -and $cur.until -gt $now
    $Detail.maintenance_mode = [ordered]@{ on = [bool]$on; until = $(if ($cur) { $cur.until.ToString('o') }); since = $(if ($cur) { $cur.since }) }
    $script:State = $(if ($cur -and -not $on) { $Detail.reason = 'maintenance mode ended but the sleep settings were not put back yet'; 'drift' } else { 'ok' })
  } elseif ($Mode -eq 'revert') {
    if ($cur) { $r = Restore-Power; $Changed.Add("sleep settings back: $($r -join ', ')"); $script:State = 'fixed' } else { $script:State = 'ok' }
    $Detail.maintenance_mode = [ordered]@{ on = $false }
  } else {
    $until = $now.AddHours($Opt.hours)
    New-Item -ItemType Directory -Force -Path "$($script:Root)\state" | Out-Null
    if ($cur) {
      $s = $cur.raw; $s.until = $until.ToString('o'); $Changed.Add("extended to $($s.until)")
    } else {
      $scheme = Get-ActiveScheme; $saved = Get-PowerValues $scheme
      $legacy = "$($script:Root)\state\power-before.txt"
      if (Test-Path -LiteralPath $legacy) { if ($d = ConvertFrom-PowerDump (Get-Content -LiteralPath $legacy -Raw)) { $saved = $d; $Detail.saved_from = 'power-before.txt'; Move-Item -LiteralPath $legacy -Destination "$legacy.imported" -Force } }
      if (-not (@($saved.Values) | Where-Object { $_ -gt 0 })) { $Detail.warning = 'sleep was already off before maintenance mode; ending it leaves it off' }
      $s = [ordered]@{ scheme = $scheme; saved = $saved; since = $now.ToString('o'); until = $until.ToString('o') }
      $Changed.Add("sleep and hibernate after idle off (was $(@($saved.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)s" }) -join ', '))")
    }
    ConvertTo-Json $s -Depth 4 | Set-Content -LiteralPath (Get-StateFile) -Encoding UTF8
    try {
      Register-EndTask $until
      $zero = [ordered]@{}; foreach ($k in $PowerSettings.Keys) { $zero["$k.ac"] = 0; $zero["$k.dc"] = 0 }
      Set-PowerValues $s.scheme $zero
      $left = @((Get-PowerValues $s.scheme).Values | Where-Object { $_ -ne 0 })
      $script:State = $(if ($left) { 'failed' } else { 'fixed' })
    } catch { $null = Restore-Power; throw }
    $Detail.maintenance_mode = [ordered]@{ on = $State -eq 'fixed'; until = $s.until; since = $s.since }
  }
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
