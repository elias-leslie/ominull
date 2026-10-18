# ominull-package: {"name":"windows-debloat","title":"Remove bundled apps","description":"Removes a listed set of bundled Microsoft extras and stops sponsored apps from installing for new users; never touches the Store, Xbox, drivers or OEM tools.","category":"maintenance","risk":"careful","reboot":false,"timeout":900,"interval":"weekly","params":[{"name":"remove_apps","type":"list","default":["Clipchamp.Clipchamp","Microsoft.BingNews","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.MicrosoftSolitaireCollection","Microsoft.People","Microsoft.WindowsFeedbackHub","Microsoft.ZuneMusic","Microsoft.ZuneVideo","MicrosoftTeams","Microsoft.Todos","Microsoft.MixedReality.Portal","Microsoft.SkypeApp","Microsoft.Microsoft3DViewer","Microsoft.MicrosoftOfficeHub","Microsoft.549981C3F5F10","Microsoft.BingSearch"],"max_items":64,"description":"Bundled apps removed for every user and from the image new profiles get (package names; * matches any text)"},{"name":"deprovision_apps","type":"list","default":["7EE7776C.LinkedInforWindows","SpotifyAB.SpotifyMusic","BytedancePte.Ltd.TikTok","Disney.37853FC22B2CE","king.com.CandyCrushSaga","king.com.CandyCrushSodaSaga","king.com.CandyCrushFriends","Facebook.Facebook","AmazonVideo.PrimeVideo","MSTeams"],"max_items":64,"description":"Sponsored apps dropped from the image; copies someone installed are reported, not removed"},{"name":"services","type":"list","default":["RetailDemo","MapsBroker","Fax","WMPNetworkSvc"],"max_items":32,"description":"Services disabled and stopped"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":1440,"description":"Enforce waits if someone used the computer within this many minutes"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-debloat'
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
    PSModulePath = "$pf\WindowsPowerShell\Modules;$sr\system32\WindowsPowerShell\v1.0\Modules"
    PATHEXT = '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC' }
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
# Native tools run as plain processes: no PowerShell pipeline, so a missing PATHEXT (the agent's
# environment) cannot turn shutdown.exe into a "document", and a failure to start is a result.
function ConvertTo-NativeArg([string]$A) {
  if ($A -and $A -notmatch '[\s"]') { return $A }
  '"' + (($A -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}
function Resolve-Native([string]$Exe) {
  if ([IO.Path]::IsPathRooted($Exe)) { if (Test-Path -LiteralPath $Exe) { return $Exe }; return $null }
  $s = if ([Environment]::SystemDirectory) { Join-Path ([Environment]::SystemDirectory) $Exe }
  if ($s -and (Test-Path -LiteralPath $s)) { return $s }
  $c = @(Get-Command $Exe -CommandType Application -ErrorAction SilentlyContinue)[0]
  if ($c) { return $c.Source }; $null
}
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
  $path = Resolve-Native $Exe
  if (-not $path) { return @{ code = -1; out = @("$Exe was not found") } }
  try {
    $si = New-Object Diagnostics.ProcessStartInfo $path
    $si.Arguments = (@($Arguments) | ForEach-Object { ConvertTo-NativeArg $_ }) -join ' '
    $si.UseShellExecute = $false; $si.RedirectStandardOutput = $true; $si.RedirectStandardError = $true; $si.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($si); $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync(); $p.WaitForExit()
    @{ code = $p.ExitCode; out = @("$($o.Result)`n$($e.Result)" -split "`r?`n" | Where-Object { $_ -ne '' }) }
  } catch { @{ code = -1; out = @("$Exe could not be started: $($_.Exception.Message)") } }
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
# --- protected services begin (shared; tests compare) ---
# Never disabled, whatever a list says: Defender, firewall, Windows Update, Store, Xbox,
# GPU/OEM and audio services, core Windows services and the OmniNull agent.
function Test-ProtectedService([string]$Name) {
  $Name -match 'WinDefend|WdNis|WdFilter|WdBoot|Sense|SecurityHealth|wscsvc|MDCore|mpssvc|BFE|wuauserv|UsoSvc|WaaSMedic|BITS|DoSvc|TrustedInstaller|msiserver|CryptSvc|InstallService|ClipSVC|AppXSvc|LicenseManager|StorSvc|Xbl|Xbox|Gaming|GameInput|NVIDIA|NVDisplay|AMD|Radeon|Intel|Realtek|ASUS|Armoury|Lenovo|Dell|\bHP|Omen|Razer|Dolby|Nahimic|Audio|RpcSs|RpcEptMapper|DcomLaunch|EventLog|Winmgmt|Dhcp|Dnscache|LanmanWorkstation|PlugPlay|Power|ProfSvc|Schedule|SamSs|LSM|gpsvc|nsi|NlaSvc|netprofm|Ominull|OmniNull'
}
# --- protected services end ---
# The lists are params. Never removed, whatever a list says: Store, Xbox and gaming,
# drivers' and OEM tools, runtimes.
function Test-Protected([string]$Name) {
  $Name -match 'Store|Xbox|Gaming|DesktopAppInstaller|Terminal|VCLibs|UI\.Xaml|NET\.Native|WindowsAppRuntime|SecHealth|NVIDIA|AMD|Radeon|Intel|Realtek|ASUS|Armoury|ROG\b|Lenovo|Vantage|MSI|MICRO-STAR|Dell|\bHP|Omen|Acer|Predator|Razer|Alienware|Dolby|Nahimic|DTS'
}
function Get-State {
  # Names may hold * (needs 4+ other characters); every matched name is checked again.
  $prov = @(Get-AppxProvisionedPackage -Online); $inst = @(Get-AppxPackage -AllUsers)
  $s = [ordered]@{ remove = @(); deprovision = @(); kept_user_installed = @(); services = [ordered]@{}; refused = @() }
  foreach ($n in @(@($Opt.remove_apps) + @($Opt.deprovision_apps) | Sort-Object -Unique)) {
    if ((Test-Protected $n) -or ($n -replace '\*').Length -lt 4) { $s.refused += $n; continue }
    $rm = @($Opt.remove_apps) -contains $n
    foreach ($p in @($inst | Where-Object { $_.Name -like $n })) {
      if (Test-Protected $p.Name) { $s.refused += $p.Name } elseif ($rm) { $s.remove += $p.PackageFullName } else { $s.kept_user_installed += $p.Name }
    }
    foreach ($p in @($prov | Where-Object { $_.DisplayName -like $n })) { if (Test-Protected $p.DisplayName) { $s.refused += $p.DisplayName } else { $s.deprovision += $p.PackageName } }
  }
  foreach ($k in 'remove', 'deprovision', 'kept_user_installed', 'refused') { $s[$k] = @($s[$k] | Sort-Object -Unique) }
  foreach ($n in $Opt.services) {
    if (Test-ProtectedService $n) { $s.refused += "service:$n"; continue }
    $svc = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
    if ($svc -and ($svc.StartMode -ne 'Disabled' -or $svc.State -ne 'Stopped')) { $s.services[$n] = "$($svc.StartMode)/$($svc.State)" }
  }
  $s
}
function Get-DriftCount($State) { $State.remove.Count + $State.deprovision.Count + $State.services.Count }
function Invoke-Package {
  if ($Mode -eq 'revert') { Invoke-Revert ''; return }
  $st = Get-State
  $Detail.found = $st
  Write-Log "remove=$($st.remove -join ',') deprovision=$($st.deprovision -join ',') services=$($st.services.Keys -join ',')"
  if ((Get-DriftCount $st) -eq 0) { $script:State = 'ok'; return }
  if ($Mode -ne 'enforce') { $script:State = 'drift'; return }
  $why = Get-PreflightReason $false $Opt.idle_minutes
  if ($why) { $script:State = 'skipped'; $Detail.reason = $why; return }
  $prior = [ordered]@{}
  foreach ($f in $st.remove) { $prior["appx:$f"] = 'installed' }
  foreach ($f in $st.deprovision) { $prior["provisioned:$f"] = 'provisioned' }
  foreach ($k in $st.services.Keys) { $prior["service:$k"] = $st.services[$k] }
  Save-Original $prior
  $errors = New-Object 'System.Collections.Generic.List[string]'
  Invoke-InPkgTemp {
    foreach ($f in $st.remove) { try { Remove-AppxPackage -Package $f -AllUsers; $Changed.Add("removed $f") } catch { $errors.Add("$f : $_") } }
    foreach ($f in $st.deprovision) { try { Remove-AppxProvisionedPackage -Online -PackageName $f | Out-Null; $Changed.Add("deprovisioned $f") } catch { $errors.Add("$f : $_") } }
  }
  foreach ($n in $st.services.Keys) {
    try { Set-Service -Name $n -StartupType Disabled; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; $Changed.Add("service:$n=Disabled") }
    catch { $errors.Add("service $n : $_") }
  }
  # The after-test decides: errors with nothing left over are warnings.
  $after = Get-State
  $Detail.after = $after
  if ($errors.Count) { $Detail.warnings = @($errors | ForEach-Object { "$_".Substring(0, [math]::Min(200, "$_".Length)) }) }
  $script:State = $(if ((Get-DriftCount $after) -gt 0) { 'failed' } else { 'fixed' })
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
