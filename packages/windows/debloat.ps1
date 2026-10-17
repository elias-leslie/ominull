# ominull-package: {"name":"windows-debloat","title":"Remove bundled apps","description":"Removes a fixed list of bundled Microsoft extras and stops sponsored apps from installing for new users; never touches the Store, Xbox, drivers or OEM tools.","risk":"careful","reboot":false,"timeout":900}
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'
$Pkg = 'windows-debloat'
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
# Microsoft's bundled extras: removed for every user and from the image new profiles get.
function Get-RemoveList {
    'Clipchamp.Clipchamp', 'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
    'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People', 'Microsoft.WindowsFeedbackHub', 'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo', 'MicrosoftTeams', 'Microsoft.Todos', 'Microsoft.MixedReality.Portal', 'Microsoft.SkypeApp',
    'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftOfficeHub', 'Microsoft.549981C3F5F10', 'Microsoft.BingSearch'
}
# Sponsored third-party apps: dropped from the image so new profiles never get them, but a
# copy someone installed and may use (Spotify, new Teams for school) is reported, not removed.
function Get-DeprovisionList {
    '7EE7776C.LinkedInforWindows', 'SpotifyAB.SpotifyMusic', 'BytedancePte.Ltd.TikTok', 'Disney.37853FC22B2CE',
    'king.com.CandyCrushSaga', 'king.com.CandyCrushSodaSaga', 'king.com.CandyCrushFriends', 'Facebook.Facebook',
    'AmazonVideo.PrimeVideo', 'MSTeams'
}
# Never removed, whatever a list says: Store, Xbox and gaming, drivers' and OEM tools, runtimes.
function Test-Protected([string]$Name) {
    $Name -match 'Store|Xbox|Gaming|DesktopAppInstaller|Terminal|VCLibs|UI\.Xaml|NET\.Native|WindowsAppRuntime|SecHealth|NVIDIA|AMD|Radeon|Intel|Realtek|ASUS|Armoury|ROG\b|Lenovo|Vantage|MSI|MICRO-STAR|Dell|\bHP|Omen|Acer|Predator|Razer|Alienware|Dolby|Nahimic|DTS'
}
$ServiceNames = 'RetailDemo', 'MapsBroker', 'Fax', 'WMPNetworkSvc'
function Get-State {
    $prov = @(Get-AppxProvisionedPackage -Online)
    $s = [ordered]@{ remove = @(); deprovision = @(); kept_user_installed = @(); services = [ordered]@{} }
    foreach ($n in Get-RemoveList) {
        if (Test-Protected $n) { continue }
        foreach ($p in @(Get-AppxPackage -AllUsers -Name $n)) { $s.remove += $p.PackageFullName }
        foreach ($p in @($prov | Where-Object { $_.DisplayName -eq $n })) { $s.deprovision += $p.PackageName }
    }
    foreach ($n in Get-DeprovisionList) {
        if (Test-Protected $n) { continue }
        foreach ($p in @($prov | Where-Object { $_.DisplayName -eq $n })) { $s.deprovision += $p.PackageName }
        foreach ($p in @(Get-AppxPackage -AllUsers -Name $n)) { $s.kept_user_installed += $p.Name }
    }
    foreach ($n in $ServiceNames) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        if ($svc -and ($svc.StartMode -ne 'Disabled' -or $svc.State -ne 'Stopped')) { $s.services[$n] = "$($svc.StartMode)/$($svc.State)" }
    }
    $s
}
function Get-DriftCount($State) { $State.remove.Count + $State.deprovision.Count + $State.services.Count }
function Invoke-Package {
    $st = Get-State
    $Detail.found = $st
    Write-Log "remove=$($st.remove -join ',') deprovision=$($st.deprovision -join ',') services=$($st.services.Keys -join ',')"
    if ((Get-DriftCount $st) -eq 0) { $script:State = 'ok'; return }
    if ($Mode -ne 'enforce') { $script:State = 'drift'; return }
    $why = Get-PreflightReason $false
    if ($why) { $script:State = 'skipped'; $Detail.reason = $why; return }
    $prior = [ordered]@{}
    foreach ($f in $st.remove) { $prior["appx:$f"] = 'installed' }
    foreach ($f in $st.deprovision) { $prior["provisioned:$f"] = 'provisioned' }
    foreach ($k in $st.services.Keys) { $prior["service:$k"] = $st.services[$k] }
    Save-Original $prior
    $errors = @()
    foreach ($f in $st.remove) {
        try { Remove-AppxPackage -Package $f -AllUsers; $Changed.Add("removed $f") } catch { $errors += "$f : $_" }
    }
    foreach ($f in $st.deprovision) {
        try { Remove-AppxProvisionedPackage -Online -PackageName $f | Out-Null; $Changed.Add("deprovisioned $f") } catch { $errors += "$f : $_" }
    }
    foreach ($n in $st.services.Keys) {
        try { Set-Service -Name $n -StartupType Disabled; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; $Changed.Add("service:$n=Disabled") }
        catch { $errors += "service $n : $_" }
    }
    $after = Get-State
    $Detail.after = $after
    if ($errors.Count -or (Get-DriftCount $after) -gt 0) { $script:State = 'failed'; $Detail.errors = @($errors | ForEach-Object { "$_".Substring(0, [math]::Min(200, "$_".Length)) }) }
    else { $script:State = 'fixed' }
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
