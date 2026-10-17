# ominull-package: {"name":"windows-software-removal","title":"Software removal","description":"Uninstalls programs in the hub's software catalog with their official uninstallers, silent and time-boxed; what needs someone at the screen is reported.","category":"maintenance","risk":"careful","reboot":true,"timeout":3600,"interval":"weekly","params":[{"name":"categories","type":"list","default":["adware","oem_bloat","trialware"],"max_items":8,"description":"Catalog categories to remove (games, game_addons, oem_bloat, trialware, adware)"},{"name":"keep","type":"list","default":[],"max_items":32,"description":"Catalog ids or name wildcards never removed here"},{"name":"close_running","type":"enum","values":["never","idle","always"],"default":"idle","description":"Close a running program first: never, when nobody is using the computer, or always"},{"name":"uninstall_timeout","type":"int","default":600,"min":60,"max":1800,"description":"Seconds one uninstaller may run before it is stopped"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":240,"description":"Minutes without input before the computer counts as idle"},{"name":"catalog","type":"catalog","default":[],"description":"The software catalog, filled in by the hub"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"Run logs of this package kept on the machine"}]}
$ErrorActionPreference = 'Stop'; $ProgressPreference = $WarningPreference = $VerbosePreference = $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-software-removal'
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
# --- software removal ---
# msi: msiexec /x with the machine's product code; registry: the program's own uninstall string plus
# one known flag; appx: Remove-AppxPackage. Time-boxed; a timeout or leftover is reported for the owner.
$Flags = '/S', '/SILENT', '/VERYSILENT /NORESTART', '/quiet', '/quiet /norestart', '/uninstall /quiet', '-uninstall', '--uninstall', '--force-uninstall'
$Methods = @{ program = 'msi', 'registry', 'manual'; appx = 'appx', 'manual' }
$KeepNames = '*Ominull*', '*OmniNull*', 'Microsoft *', 'Windows *', '*Visual C++*', '*.NET*', '*Driver*', '*WebView2*', '*NVIDIA*', '*Intel(R)*', '*Realtek*', 'AMD *', '*Defender*'
$KeepAppx = 'Microsoft.*', 'MicrosoftWindows.*', 'Windows.*', '*Ominull*', '*NVIDIA*', '*Realtek*', 'AppUp.*'
$Shells = '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$'
function Get-Installed {
  $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  foreach ($u in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) { $keys += "Registry::HKEY_USERS\$($u.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
  foreach ($e in @(Get-ItemProperty $keys -ErrorAction SilentlyContinue)) {
    $n = "$($e.DisplayName)".Trim(); if (-not $n -or $e.SystemComponent -eq 1 -or $e.ParentKeyName) { continue }
    [pscustomobject]@{ kind = 'program'; name = $n; publisher = "$($e.Publisher)".Trim(); version = "$($e.DisplayVersion)"; key = $e.PSChildName; msi = ($e.WindowsInstaller -eq 1 -and $e.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$'); quiet = "$($e.QuietUninstallString)"; uninstall = "$($e.UninstallString)"; location = "$($e.InstallLocation)" }
  }
  foreach ($a in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)) { [pscustomobject]@{ kind = 'appx'; name = $a.Name; publisher = ''; version = "$($a.Version)"; key = $a.PackageFullName; location = "$($a.InstallLocation)" } }
}
function Test-Entry($c) {
  ($Methods["$($c.kind)"] -ccontains $c.method) -and "$($c.match)" -cmatch "^[A-Za-z0-9*][A-Za-z0-9 ._*+()&'!-]{2,99}\z" -and (-not $c.flag -or ($c.method -eq 'registry' -and $Flags -ccontains $c.flag))
}
function Find-Wanted($Inv, $Cat) {
  foreach ($c in $Cat) {
    if (-not (Test-Entry $c)) { throw "catalog entry $($c.id) is not valid" }
    foreach ($i in $Inv) { if ($i.kind -eq $c.kind -and $i.name -like $c.match -and (-not $c.publisher -or $i.publisher -like $c.publisher)) { [pscustomobject]@{ c = $c; i = $i } } }
  }
}
function Test-Like([string]$s, $pats) { foreach ($p in $pats) { if ($s -like $p) { return $true } }; $false }
function Get-Command4($c, $i) {
  $msiexec = "$env:SystemRoot\System32\msiexec.exe"
  if ($c.method -eq 'appx') { return @{ appx = $i.key } }
  if ($c.method -eq 'manual') { return @{ owner = 'the catalog says it needs someone at the screen' } }
  $s = $(if ($c.method -eq 'msi') { '' } elseif ($i.quiet) { $i.quiet } else { $i.uninstall })
  $code = $(if ($i.msi) { $i.key } elseif ("$($i.uninstall) $s" -match '(?i)msiexec(?:\.exe)?"?\s+/[IX]\s*(\{[0-9A-F-]{36}\})') { $matches[1] })
  if ($code -and ($c.method -eq 'msi' -or $s -match '(?i)msiexec')) { return @{ exe = $msiexec; args = "/x $code /qn /norestart" } }
  if ($c.method -eq 'msi') { return @{ owner = 'not a Windows Installer product on this machine' } }
  if (-not $s) { return @{ owner = 'it lists no uninstall command' } }
  if ($s -match '^\s*"([^"]+)"\s*(.*)$' -or $s -match '^\s*(.+?\.exe)\s*(.*)$') { $exe = $matches[1]; $a = $matches[2].Trim() } else { return @{ owner = 'its uninstall command is not understood' } }
  if ((Split-Path -Leaf $exe) -match $Shells) { return @{ owner = 'its uninstall command runs a shell' } }
  if (-not [IO.Path]::IsPathRooted($exe) -or -not (Test-Path -LiteralPath $exe)) { return @{ owner = 'its uninstaller file is missing' } }
  if ($c.flag -and -not $i.quiet) { $a = "$a $($c.flag)".Trim() }
  @{ exe = $exe; args = $a }
}
function Stop-Tree([int]$Id) { foreach ($k in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$Id" -ErrorAction SilentlyContinue)) { Stop-Tree $k.ProcessId }; Stop-Process -Id $Id -Force -ErrorAction SilentlyContinue }
function Invoke-Uninstaller($Cmd, [int]$Sec) {
  $sp = @{ FilePath = $Cmd.exe; PassThru = $true; WindowStyle = 'Hidden' }; if ($Cmd.args) { $sp.ArgumentList = $Cmd.args }
  $p = Start-Process @sp
  if ($p.WaitForExit($Sec * 1000)) { return $p.ExitCode }
  Stop-Tree $p.Id; $null
}
function Get-Running($i) {
  if ("$($i.location)".Length -lt 8) { return @() }; $loc = $i.location.TrimEnd('\') + '\'
  @(Get-CimInstance Win32_Process -Property ProcessId, ExecutablePath -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($loc, [StringComparison]::OrdinalIgnoreCase) })
}
function Add-Owner($id, $n, [string]$r) { $script:owner += [ordered]@{ id = $id; name = $n; reason = $r.Substring(0, [math]::Min(160, $r.Length)) } }
function Invoke-Package {
  if ($Mode -eq 'revert') { $script:State = 'na'; $Detail.reason = 'uninstalled software cannot be put back; reinstall it'; return }
  $found = @(); $script:owner = @(); $kept = @(); $refused = @(); $other = [ordered]@{}; $deferred = @(); $removed = @()
  foreach ($w in @(Find-Wanted @(Get-Installed) $Opt.catalog)) {
    $c = $w.c; $i = $w.i
    if (Test-Like $i.name $(if ($i.kind -eq 'appx') { $KeepAppx } else { $KeepNames })) { $refused += $i.name; continue }
    if ($i.kind -eq 'program' -and $i.publisher -like 'Microsoft*') { $refused += $i.name; continue }
    if ((Test-Like $i.name $Opt.keep) -or $Opt.keep -contains $c.id) { $kept += $i.name; continue }
    if ($Opt.categories -notcontains $c.category) { $other[$c.category] = 1 + [int]$other[$c.category]; continue }
    $found += [pscustomobject]@{ id = $c.id; name = $i.name; version = $i.version; category = $c.category; method = $c.method; w = $w }
  }
  $Detail.found = @($found | Select-Object id, name, version, category, method)
  if ($kept) { $Detail.kept = $kept }; if ($refused) { $Detail.refused = $refused }; if ($other.Count) { $Detail.other_categories = $other }
  if ($Mode -eq 'audit') { $script:State = $(if ($found) { 'drift' } else { 'ok' }); return }
  $deadline = [datetime]::UtcNow.AddSeconds(3600 - 120); $active = $null
  foreach ($f in $found) {
    $c = $f.w.c; $i = $f.w.i; $sec = $(if ($c.timeout) { [int]$c.timeout } else { [int]$Opt.uninstall_timeout })
    if ([datetime]::UtcNow.AddSeconds($sec) -gt $deadline) { $deferred += $i.name; continue }
    $cmd = Get-Command4 $c $i
    if ($cmd.owner) { Add-Owner $c.id $i.name $cmd.owner; continue }
    $run = @(Get-Running $i)
    if ($run) {
      if ($Opt.close_running -eq 'idle' -and $null -eq $active) { $q = Invoke-Native 'quser.exe' @(); $active = $q.code -ge 0 -and (Test-UserActive $q.out $Opt.idle_minutes) }
      if ($Opt.close_running -eq 'never' -or ($Opt.close_running -eq 'idle' -and $active)) { Add-Owner $c.id $i.name 'it is running and was left open'; continue }
      $run | ForEach-Object { Stop-Tree $_.ProcessId }
    }
    Write-Log "uninstall $($c.id) '$($i.name)' via $($c.method)"
    try {
      if ($cmd.appx) { Remove-AppxPackage -Package $cmd.appx -AllUsers -ErrorAction Stop; $code = 0
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -eq $i.name | ForEach-Object { $null = Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName } }
      else { $code = Invoke-Uninstaller $cmd $sec }
    } catch { Add-Owner $c.id $i.name "$_"; continue }
    Write-Log "  exit $code"
    if ($null -eq $code) { Add-Owner $c.id $i.name "its uninstaller did not finish in $sec s; it may be waiting for someone at the screen"; continue }
    if (3010, 1641 -contains $code) { $script:Reboot = $true }
    $f | Add-Member -NotePropertyName code -NotePropertyValue $code
  }
  $left = @(Get-Installed)
  foreach ($f in $found | Where-Object { $null -ne $_.code }) {
    if ($left | Where-Object { $_.kind -eq $f.w.i.kind -and $_.key -eq $f.w.i.key -and $_.name -eq $f.w.i.name }) { Add-Owner $f.id $f.name "still installed after its uninstaller (exit $($f.code))" }
    else { $removed += $f.name; $Changed.Add("removed $($f.name)") }
  }
  $Detail.removed = $removed; if ($deferred) { $Detail.deferred = $deferred }; if ($script:owner) { $Detail.needs_owner = $script:owner }
  $script:State = $(if ($script:owner -or $deferred) { 'drift' } elseif ($removed) { 'fixed' } else { 'ok' })
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
