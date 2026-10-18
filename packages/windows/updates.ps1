# ominull-package: {"name":"windows-updates","title":"Windows updates","description":"Installs pending Windows and driver updates, skipping previews, optional and feature updates and firmware unless told otherwise, and reports whether a restart is needed.","category":"maintenance","risk":"safe","reboot":true,"timeout":3600,"interval":"daily","params":[{"name":"exclude","type":"list","default":["firmware","preview","feature_update","optional"],"max_items":5,"description":"Kinds of update never installed; any of: firmware, preview, feature_update, optional, driver"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":1440,"description":"Enforce waits if someone used the computer within this many minutes"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-updates'
# --- prelude begin (identical in every package; tests compare) ---
# SYSTEM, a stripped environment, the agent's TEMP. Stdout: one JSON line.
# Old agents could pass PATH=<cmd.exe>: the system folders go back first.
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
# Native tools run as plain processes: no PATHEXT needed, and a failure to start is a result.
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
# Presence without quser (not on Home): WTS sessions; WTS has no console idle, the agent passes it; locked = LogonUI.
$script:WtsSource = @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct WtsInfo {
  public int State, Id, A, B, C, D, E, F;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Station;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
  public long ConnectTime, DisconnectTime, LastInputTime, LogonTime, CurrentTime; }
[DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSEnumerateSessionsW(IntPtr s, int r, int v, out IntPtr p, out int n);
[DllImport("wtsapi32.dll")] public static extern bool WTSQuerySessionInformationW(IntPtr s, int id, int c, out IntPtr p, out int n);
[DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr p);
'@
function Get-WtsType { if (-not ('OmniNull.Wts' -as [type])) { Add-Type -Namespace OmniNull -Name Wts -MemberDefinition $script:WtsSource }; [OmniNull.Wts] }
function Get-Sessions {
  $t = Get-WtsType; $m = [Runtime.InteropServices.Marshal]; $p = [IntPtr]::Zero; $n = 0
  if (-not $t::WTSEnumerateSessionsW([IntPtr]::Zero, 0, 1, [ref]$p, [ref]$n)) { throw "WTSEnumerateSessions failed ($($m::GetLastWin32Error()))" }
  $locked = @(Get-Process LogonUI -ErrorAction SilentlyContinue | ForEach-Object { $_.SessionId })
  try {
    for ($i = 0; $i -lt $n; $i++) {
      $id = $m::ReadInt32($p, $i * 3 * [IntPtr]::Size); $b = [IntPtr]::Zero; $len = 0
      if ($id -eq 0 -or -not $t::WTSQuerySessionInformationW([IntPtr]::Zero, $id, 24, [ref]$b, [ref]$len)) { continue }
      try { $w = $m::PtrToStructure($b, [type][OmniNull.Wts+WtsInfo]) } finally { $t::WTSFreeMemory($b) }
      $idle = $null; if ($w.LastInputTime -gt 0 -and $w.CurrentTime -ge $w.LastInputTime) { $idle = [int][math]::Floor(($w.CurrentTime - $w.LastInputTime) / 6e8) }
      $c = $env:OMINULL_CONSOLE_IDLE_SECONDS; if ($null -eq $idle -and "$id" -eq $env:OMINULL_CONSOLE_SESSION -and $c -match '^\d+$') { $idle = [int][math]::Floor([int]$c / 60) }
      @{ id = $id; state = $w.State; user = "$($w.User)"; idle = $idle; locked = $locked -contains $id }
    }
  } finally { $t::WTSFreeMemory($p) }
}
# In use: an active, unlocked session with a user, idle under the threshold or not reported.
function Test-SessionsActive($Sessions, [int]$IdleMinutes) {
  [bool](@($Sessions) | Where-Object { $_ -and $_.state -eq 0 -and $_.user -and -not $_.locked -and ($null -eq $_.idle -or $_.idle -lt $IdleMinutes) })
}
function Get-SessionReason([int]$IdleMinutes) {
  try { $s = @(Get-Sessions) } catch { return "it cannot tell whether someone is using the computer ($($_.Exception.Message))" }
  if (Test-SessionsActive $s $IdleMinutes) { 'someone is using the computer' }
}
# Game folders; tray launchers (Steam, Epic, Riot Client, Battle.net, EA app) do not count.
function Test-GamePath([string]$Path) {
  $Path -and ($Path -match '\\steamapps\\common\\|\\Epic Games\\(?!Launcher\\|Epic Online Services\\)|\\Riot Games\\(?!Riot Client\\)|\\XboxGames\\|\\EA Games\\|\\Ubisoft Game Launcher\\games\\|\\GOG Galaxy\\Games\\|\\WindowsApps\\Microsoft\.Minecraft|\\(Overwatch|World of Warcraft|Diablo IV|Diablo III|Hearthstone|StarCraft II|Call of Duty)\\')
}
function Test-OnBattery($Batteries) { [bool](@($Batteries) | Where-Object { $_ -and [int]$_.BatteryStatus -eq 1 }) }
function Get-PeopleReason([int]$IdleMinutes) {
  $why = Get-SessionReason $IdleMinutes
  if ($why) { return $why }
  foreach ($p in @(Get-CimInstance Win32_Process -Property ExecutablePath -ErrorAction SilentlyContinue)) {
    if (Test-GamePath $p.ExecutablePath) { return "a game is running ($(Split-Path -Leaf $p.ExecutablePath))" }
  }
}
# Window: 1-4 "HH:MM-HH:MM" ranges, machine time or UTC with a trailing Z; may cross midnight.
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
# when_busy skip (default) | wait (half the timeout) | run; people don't count in the window, battery and updates do.
function Get-RunOptions {
  $b = "$env:OMINULL_PARAM_WHEN_BUSY"; if (-not $b) { $b = 'skip' }; $w = "$env:OMINULL_PARAM_WINDOW"
  if ('skip', 'wait', 'run' -cnotcontains $b) { throw 'param when_busy is not skip, wait or run' }
  if ($w -and -not (Test-WindowText $w)) { throw 'param window is not 1-4 HH:MM-HH:MM ranges (comma separated, Z for UTC)' }
  @{ busy = $b; window = $w }
}
# TiWorker idles for minutes after any update scan, ours included: it counts only while using CPU.
function Get-TiCpu { [double](@(Get-Process TiWorker -ErrorAction SilentlyContinue) | ForEach-Object { $_.TotalProcessorTime.TotalSeconds } | Measure-Object -Sum).Sum }
function Test-ServicingBusy { if (-not (Get-Process TiWorker -ErrorAction SilentlyContinue)) { return $false }; $a = Get-TiCpu; Start-Sleep -Seconds 10; (Get-TiCpu) - $a -gt 1 }
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
    try { if ((New-Object -ComObject Microsoft.Update.Installer).IsBusy) { return 'Windows Update is installing' } } catch {}
    if (Test-ServicingBusy) { return 'Windows servicing is busy (TiWorker working)' }
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
# Kinds an exclude list may name. Skipped updates are listed under not_offered for the owner.
$Kinds = 'firmware', 'preview', 'feature_update', 'optional', 'driver'
function Test-Wanted($Update) {
  $x = @($Opt.exclude); foreach ($k in $x) { if ($Kinds -notcontains $k) { throw "unknown update kind '$k'" } }
  if ($x -contains 'preview' -and $Update.Title -match 'Preview') { return $false }
  if ($x -contains 'optional' -and $Update.BrowseOnly) { return $false }
  if ($x -contains 'driver' -and $Update.Type -eq 2) { return $false }
  # Firmware: BIOS/EC flashes.
  if ($x -contains 'firmware' -and $Update.Type -eq 2 -and $Update.DriverClass -eq 'Firmware') { return $false }
  # Feature updates (category Upgrades) move Windows to a new version.
  if ($x -contains 'feature_update') {
    if ($Update.Title -match 'Feature update') { return $false }
    foreach ($c in $Update.Categories) { if ($c.Name -eq 'Upgrades' -or $c.CategoryID -eq 'e6cf1350-c01b-414d-a61f-263d14d133b4') { return $false } }
  }
  $true
}
function Get-UpdateLabel($Update) {
  $kb = @($Update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
  $t = $Update.Title; if ($t.Length -gt 120) { $t = $t.Substring(0, 120) }
  if ($kb) { "$kb $t" } else { $t }
}
function Invoke-Package {
  if ($Mode -eq 'revert') { $script:State = 'na'; $Detail.reason = 'installed updates are not removed here'; return }
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'OmniNull maintenance'
  $base = 'IsInstalled=0 and IsHidden=0'; if (@($Opt.exclude) -contains 'optional') { $base += ' and BrowseOnly=0' }
  $types = @('Software'); if (@($Opt.exclude) -notcontains 'driver') { $types += 'Driver' }
  $crit = @($types | ForEach-Object { "$base and Type='$_'" }) -join ' or '
  # Busy check first: the search itself starts TiWorker, which then looked like an install in progress.
  $why = $(if ($Mode -eq 'enforce') { Get-PreflightReason $true $Opt.idle_minutes })
  Write-Log "searching: $crit"
  $found = $session.CreateUpdateSearcher().Search($crit)
  $wanted = @(); $skipped = @()
  foreach ($u in $found.Updates) { if (Test-Wanted $u) { $wanted += $u } else { $skipped += (Get-UpdateLabel $u) } }
  $Detail.available = @($wanted | ForEach-Object { Get-UpdateLabel $_ })
  $Detail.not_offered = $skipped
  $pending = Test-PendingReboot
  $Detail.reboot_pending_before = $pending
  Write-Log "wanted=$($wanted.Count) skipped=$($skipped.Count) reboot_pending=$pending"
  if ($wanted.Count -eq 0) { $script:State = 'ok'; $script:Reboot = $pending; return }
  if ($Mode -ne 'enforce') { $script:State = 'drift'; $script:Reboot = $pending; return }
  if ($why) { $script:State = 'skipped'; $Detail.reason = $why; $script:Reboot = $pending; return }

  $coll = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $wanted) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; $coll.Add($u) | Out-Null }
  $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll
  Write-Log 'downloading'
  $dr = $dl.Download()
  $Detail.download_result = [int]$dr.ResultCode
  $inst = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $wanted) { if ($u.IsDownloaded) { $inst.Add($u) | Out-Null } }
  if ($inst.Count -eq 0) { $script:State = 'failed'; $Detail.error = 'no update finished downloading'; return }
  $installer = $session.CreateUpdateInstaller(); $installer.Updates = $inst
  Write-Log "installing $($inst.Count)"
  $ir = $installer.Install()
  # OperationResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted.
  $results = @(); $failed = 0
  for ($i = 0; $i -lt $inst.Count; $i++) {
    $rc = [int]$ir.GetUpdateResult($i).ResultCode; $label = Get-UpdateLabel $inst.Item($i)
    if ($rc -eq 2 -or $rc -eq 3) { $Changed.Add($label) } else { $failed++ }
    $results += [ordered]@{ update = $label; result = $rc }
  }
  $Detail.installed = $results
  $Detail.not_downloaded = $wanted.Count - $inst.Count
  $script:Reboot = [bool]$ir.RebootRequired -or (Test-PendingReboot)
  if ($failed -gt 0 -or $inst.Count -lt $wanted.Count) { $script:State = 'failed' } else { $script:State = 'fixed' }
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
