# Static and unit checks for the Windows maintenance packages. Runs under pwsh on
# Linux or Windows: packages/windows/tests/run.sh, or pwsh -File this script.
# Unit checks load only the packages' function definitions (nothing at top level
# runs) and replace the system calls with stand-ins.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$Dir = Split-Path -Parent $PSScriptRoot
$Names = 'updates', 'cleanup', 'privacy', 'debloat', 'performance', 'audit'
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Passed = 0
function Check([string]$What, [bool]$Ok) {
    if ($Ok) { $script:Passed++ } else { $script:Failures.Add($What); Write-Host "FAIL $What" }
}
function Get-Defs([string]$Path) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        ForEach-Object { $_.Extent.Text }) -join "`n"
}

# ---------------------------------------------------------------- static checks
$preludes = @{}
$forbidden = @{
    'reboots the machine'          = 'Restart-Computer|Stop-Computer|shutdown(\.exe)?\s+/[rs]'
    'irreversible DISM /ResetBase' = '/ResetBase'
    'boot configuration'           = 'bcdedit'
    'Defender settings'            = 'Set-MpPreference|Add-MpPreference|DisableAntiSpyware|DisableRealtimeMonitoring'
    'firewall changes'             = 'Set-NetFirewallProfile|netsh\s+advfirewall'
    'disk/partition operations'    = 'Format-Volume|Clear-Disk|Remove-Partition|diskpart|Initialize-Disk'
    'Recycle Bin'                  = 'Clear-RecycleBin'
    'agent TEMP folder'            = '\$env:(TEMP|TMP)\b'
    'hosts file'                   = 'drivers\\etc\\hosts'
    'VBS / memory integrity'       = 'HypervisorEnforcedCodeIntegrity|EnableVirtualizationBasedSecurity|DeviceGuard'
    'SmartScreen'                  = 'SmartScreen'
    'stdout noise'                 = 'Write-Host|Write-Output|Out-Host|Write-Information|Out-Default'
    'winget as SYSTEM'             = 'winget'
    'PS 7-only switch'             = '-AsHashtable'
}
foreach ($n in $Names) {
    $path = Join-Path $Dir "$n.ps1"
    $bytes = [System.IO.File]::ReadAllBytes($path)
    Check "$n size < 16384 bytes ($($bytes.Length))" ($bytes.Length -lt 16384)
    Check "$n is ASCII without BOM" (-not ($bytes | Where-Object { $_ -gt 127 }))
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $lines = $text -split "`n"
    $meta = $null
    if ($lines[0] -match '^# ominull-package: (\{.*\})$') { try { $meta = $matches[1] | ConvertFrom-Json } catch {} }
    Check "$n header line is JSON" ($null -ne $meta)
    if ($meta) {
        Check "$n header name" ($meta.name -eq "windows-$n")
        Check "$n header title/description" ([bool]$meta.title -and [bool]$meta.description)
        Check "$n header risk" (@('safe', 'careful') -contains $meta.risk)
        Check "$n header reboot is bool" ($meta.reboot -is [bool])
        Check "$n header timeout 1..3600" (($meta.timeout -is [long] -or $meta.timeout -is [int]) -and $meta.timeout -ge 1 -and $meta.timeout -le 3600)
        Check "$n `$Pkg matches header" ($text -match "(?m)^\`$Pkg = '$([regex]::Escape($meta.name))'")
    }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Check "$n parses ($(@($errors | ForEach-Object { $_.Message }) -join '; '))" ($errors.Count -eq 0)
    $ps7 = @($ast.FindAll({ param($x) $x.GetType().Name -in 'TernaryExpressionAst', 'PipelineChainAst' }, $true))
    $ps7 += @($tokens | Where-Object { $_.Kind -in 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr' })
    Check "$n uses no PowerShell 7-only syntax" ($ps7.Count -eq 0)
    foreach ($k in $forbidden.Keys) { Check "$n never touches $k" ($text -notmatch $forbidden[$k]) }
    Check "$n writes stdout once" (([regex]::Matches($text, '\[Console\]::Out\.WriteLine')).Count -eq 1)
    if ($text -match '(?s)# --- prelude begin.*?# --- prelude end ---') { $preludes[$n] = $matches[0] }
    Check "$n has the shared prelude" ($preludes.ContainsKey($n))
}
Check 'prelude identical in every package' (@($preludes.Values | Sort-Object -Unique).Count -eq 1)

# ------------------------------------------------------- unit checks: prelude
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'audit.ps1'))))
    Check 'mode: enforce from OMINULL_PARAM_MODE' ((Get-Mode 'enforce' '') -eq 'enforce')
    Check 'mode: enforce from bare mode' ((Get-Mode '' 'enforce') -eq 'enforce')
    Check 'mode: padded value' ((Get-Mode ' enforce ' '') -eq 'enforce')
    Check 'mode: missing is audit' ((Get-Mode '' '') -eq 'audit')
    Check 'mode: unknown is audit' ((Get-Mode 'delete-everything' 'enforce') -eq 'audit')
    Check 'quser idle .' ((ConvertFrom-QuserIdle '.') -eq 0)
    Check 'quser idle none' ((ConvertFrom-QuserIdle 'none') -eq 0)
    Check 'quser idle minutes' ((ConvertFrom-QuserIdle '5') -eq 5)
    Check 'quser idle h:mm' ((ConvertFrom-QuserIdle '1:05') -eq 65)
    Check 'quser idle d+h:mm' ((ConvertFrom-QuserIdle '2+03:04') -eq 3064)
    $hdr = ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME'
    Check 'quser: active console user' (Test-UserActive @($hdr, '>nadia                 console             1  Active      none   10/17/2026 9:00 AM'))
    Check 'quser: idle 45 min is not active' (-not (Test-UserActive @($hdr, ' nadia                 console             1  Active        45   10/17/2026 9:00 AM')))
    Check 'quser: idle 14 min is active' (Test-UserActive @($hdr, ' nadia                 console             1  Active        14   10/17/2026 9:00 AM'))
    Check 'quser: disconnected is not active' (-not (Test-UserActive @($hdr, ' bob                                       2  Disc          1:00  10/17/2026 9:00 AM')))
    Check 'quser: no sessions' (-not (Test-UserActive @()))
    foreach ($p in 'C:\Program Files (x86)\Steam\steamapps\common\Elden Ring\Game\eldenring.exe', 'D:\Epic Games\Fortnite\FortniteClient.exe',
        'C:\Riot Games\VALORANT\live\VALORANT.exe', 'C:\XboxGames\Halo Infinite\Content\HaloInfinite.exe', 'E:\GOG Galaxy\Games\Witcher 3\bin\witcher3.exe') {
        Check "game path: $p" (Test-GamePath $p)
    }
    foreach ($p in 'C:\Program Files (x86)\Steam\steam.exe', 'C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe',
        'C:\Riot Games\Riot Client\RiotClientServices.exe', 'C:\Windows\explorer.exe', '') {
        Check "not a game: '$p'" (-not (Test-GamePath $p))
    }
    Check 'not a game: null' (-not (Test-GamePath $null))
    Check 'battery discharging' (Test-OnBattery @([pscustomobject]@{ BatteryStatus = 1 }))
    Check 'battery on AC' (-not (Test-OnBattery @([pscustomobject]@{ BatteryStatus = 2 })))
    Check 'no battery' (-not (Test-OnBattery $null))

    $o = Format-Result 'fixed' $true @('a') ([ordered]@{ prior = @{ x = 1 } }) | ConvertFrom-Json
    Check 'result v=1' ($o.v -eq 1)
    Check 'result state' ($o.state -eq 'fixed')
    Check 'result reboot bool' ($o.reboot -is [bool] -and $o.reboot)
    Check 'result one change stays an array' ((Format-Result 'fixed' $false @('a') @{}) -match '"changed":\["a"\]')
    Check 'result no changes is []' ((Format-Result 'ok' $false @() @{}) -match '"changed":\[\]')
    Check 'result null changes is []' ((Format-Result 'ok' $false $null @{}) -match '"changed":\[\]')
    Check 'result unknown state becomes failed' (((Format-Result 'weird' $false @() @{}) | ConvertFrom-Json).state -eq 'failed')
    Check 'result is one line' (-not ((Format-Result 'ok' $false @() @{ note = "a`r`nb" }) -match "[`r`n]"))
    $big = Format-Result 'drift' $false @() @{ blob = ('x' * 20000) }
    Check 'result oversized detail is truncated' ($big.Length -lt 1000 -and ($big | ConvertFrom-Json).detail.truncated)
    Check 'result field order' ((Format-Result 'ok' $false @() @{}) -match '^\{"v":1,"state":"ok","reboot":false,"changed":\[\],"detail":')

    # Preflight with stand-ins for every system call.
    $script:Quser = @{ code = -1; out = @() }; $script:Procs = @(); $script:Batt = $null; $script:Busy = $false; $script:Ti = $null
    function Invoke-Native { $script:Quser }
    function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName, $Property, $Filter)
        if ($ClassName -eq 'Win32_Process') { $script:Procs } else { $script:Batt } }
    function Get-Process { [CmdletBinding()] param([Parameter(Position = 0)]$Name) $script:Ti }
    function New-Object { [pscustomobject]@{ IsBusy = $script:Busy } }
    Check 'preflight: nothing blocks' ($null -eq (Get-PreflightReason $true))
    $script:Quser = @{ code = 0; out = @($hdr, '>nadia  console  1  Active  none  10/17/2026 9:00 AM') }
    Check 'preflight: user active' ((Get-PreflightReason $false) -match 'using the computer')
    $script:Quser = @{ code = 1; out = @('No User exists for *') }
    $script:Procs = @([pscustomobject]@{ ExecutablePath = 'C:\Riot Games\VALORANT\live\VALORANT.exe' })
    Check 'preflight: game running' ((Get-PreflightReason $false) -match 'game is running \(VALORANT.exe\)')
    $script:Procs = @([pscustomobject]@{ ExecutablePath = $null }); $script:Batt = [pscustomobject]@{ BatteryStatus = 1 }
    Check 'preflight: on battery' ((Get-PreflightReason $false) -match 'battery')
    $script:Batt = $null; $script:Busy = $true
    Check 'preflight: update installing' ((Get-PreflightReason $true) -match 'Windows Update')
    Check 'preflight: update check only when asked' ($null -eq (Get-PreflightReason $false))
    $script:Busy = $false; $script:Ti = [pscustomobject]@{ Name = 'TiWorker' }
    Check 'preflight: TiWorker running' ((Get-PreflightReason $true) -match 'Windows Update')
}

# --------------------------------------------------- unit checks: per package
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'updates.ps1'))))
    $cat = { param($n, $id) [pscustomobject]@{ Name = $n; CategoryID = $id } }
    $u = { param($t, $c, $b) [pscustomobject]@{ Title = $t; Categories = @($c); BrowseOnly = $b; KBArticleIDs = @('5031354') } }
    Check 'updates: cumulative update wanted' (Test-Wanted (& $u '2026-10 Cumulative Update for Windows 11 (KB5031354)' (& $cat 'Security Updates' 'x') $false))
    Check 'updates: driver wanted' (Test-Wanted (& $u 'NVIDIA - Display - 31.0.15.5222' (& $cat 'Drivers' 'y') $false))
    Check 'updates: preview skipped' (-not (Test-Wanted (& $u '2026-10 Cumulative Update Preview for Windows 11' (& $cat 'Updates' 'x') $false)))
    Check 'updates: feature update skipped' (-not (Test-Wanted (& $u 'Feature update to Windows 11, version 25H2' (& $cat 'Upgrades' 'x') $false)))
    Check 'updates: Upgrades category skipped' (-not (Test-Wanted (& $u 'Windows 11' (& $cat 'Other' 'e6cf1350-c01b-414d-a61f-263d14d133b4') $false)))
    Check 'updates: optional (browse-only) skipped' (-not (Test-Wanted (& $u 'Some optional driver' (& $cat 'Drivers' 'y') $true)))
    Check 'updates: label has KB' ((Get-UpdateLabel (& $u 'Title' (& $cat 'x' 'x') $false)) -eq 'KB5031354 Title')
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'cleanup.ps1'))))
    $oldRoot = $env:SystemRoot; $oldPd = $env:ProgramData
    $env:SystemRoot = 'C:\Windows'; $env:ProgramData = 'C:\ProgramData'
    foreach ($t in Get-Targets) { Check "cleanup: target allowed $($t.path)" (Test-Allowed $t.path) }
    foreach ($p in 'C:\Users\nadia\AppData\Local\Temp', 'C:\ProgramData\Ominull', 'C:\Windows\Temp\..\..\Users\x', 'C:\$Recycle.Bin',
        'D:\Windows\Temp', 'C:\ProgramData\Microsoft\Windows\Start Menu', 'C:\ProgramData', 'C:\Program Files\Steam') {
        Check "cleanup: refuses $p" (-not (Test-Allowed $p))
    }
    Check 'cleanup: no ResetBase, recycle bin or user path in targets' (-not ((Get-Targets | ForEach-Object { $_.path }) -match 'Users|Recycle|Ominull'))
    $env:SystemRoot = $oldRoot; $env:ProgramData = $oldPd
    # Age filter and link handling on a real tree, with the path guard stood in.
    function Test-Allowed { $true }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("omt-" + [guid]::NewGuid().ToString('N'))
    $outside = Join-Path ([IO.Path]::GetTempPath()) ("omt-out-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force (Join-Path $tmp 'sub'), $outside | Out-Null
    $old = (Get-Date).AddDays(-30)
    foreach ($f in 'old.txt', 'sub\old2.txt' -replace '\\', [IO.Path]::DirectorySeparatorChar) { $p = Join-Path $tmp $f; Set-Content $p 'x'; (Get-Item $p).LastWriteTime = $old }
    Set-Content (Join-Path $tmp 'new.txt') 'x'
    Set-Content (Join-Path $outside 'precious.txt') 'x'; (Get-Item (Join-Path $outside 'precious.txt')).LastWriteTime = $old
    $linked = $true; try { New-Item -ItemType SymbolicLink -Path (Join-Path $tmp 'link') -Target $outside -ErrorAction Stop | Out-Null } catch { $linked = $false }
    $found = @((Get-OldFiles $tmp (Get-Date).AddDays(-7)) | ForEach-Object { $_.Name } | Sort-Object)
    Check "cleanup: age filter finds only old files ($($found -join ','))" (($found -join ',') -eq 'old.txt,old2.txt')
    if ($linked) { Check 'cleanup: links are not followed' ($found -notcontains 'precious.txt') }
    Remove-Item -Recurse -Force $tmp, $outside
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'debloat.ps1'))))
    foreach ($n in @(Get-RemoveList) + @(Get-DeprovisionList)) { Check "debloat: list entry not protected $n" (-not (Test-Protected $n)) }
    foreach ($n in 'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
        'Microsoft.GamingApp', 'Microsoft.GamingServices', 'Microsoft.DesktopAppInstaller', 'Microsoft.WindowsTerminal', 'Microsoft.VCLibs.140.00',
        'Microsoft.UI.Xaml.2.8', 'NVIDIACorp.NVIDIAControlPanel', 'AdvancedMicroDevicesInc-2.AMDRadeonSoftware', 'AppUp.IntelGraphicsExperience',
        'RealtekSemiconductorCorp.RealtekAudioControl', 'B9ECED6F.ArmouryCrate', 'E046963F.LenovoCompanion', 'AD2F1837.HPSystemEventUtility',
        'AD2F1837.OMENCommandCenter', 'DellInc.DellPowerManager', 'AcerIncorporated.PredatorSense', 'RazerInc.RazerSynapse', 'Microsoft.SecHealthUI') {
        Check "debloat: protects $n" (Test-Protected $n)
    }
    Check 'debloat: remove and deprovision lists are disjoint' (-not (@(Get-RemoveList) | Where-Object { @(Get-DeprovisionList) -contains $_ }))
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'privacy.ps1'))))
    Check 'privacy: Home floor 1' ((Get-TelemetryFloor 'Core') -eq 1)
    Check 'privacy: Pro floor 1' ((Get-TelemetryFloor 'Professional') -eq 1)
    Check 'privacy: Enterprise floor 0' ((Get-TelemetryFloor 'Enterprise') -eq 0)
    Check 'privacy: Education floor 0' ((Get-TelemetryFloor 'Education') -eq 0)
    $all = @(Get-MachineSettings 1) + @(Get-UserSettings) | ForEach-Object { "$($_[0])\$($_[1])" }
    Check 'privacy: never touches Defender, firewall, Windows Update, SmartScreen or location' (-not ($all -match 'Defender|Firewall|WindowsUpdate|SmartScreen|LocationAndSensors|DeviceGuard'))
    Check 'privacy: telemetry follows the floor' (@(Get-MachineSettings 1 | Where-Object { $_[1] -eq 'AllowTelemetry' -and $_[2] -eq 1 }).Count -eq 1)
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'performance.ps1'))))
    Check 'performance: HAGS on WDDM 3.1, Win11' (Test-HagsSupported 22631 @('31.0.15.5222'))
    Check 'performance: no HAGS on WDDM 2.6' (-not (Test-HagsSupported 22631 @('26.20.100.7')))
    Check 'performance: no HAGS before 2004' (-not (Test-HagsSupported 18363 @('31.0.15.5222')))
    Check 'performance: no HAGS without a driver' (-not (Test-HagsSupported 22631 @()))
    $GraphicsKey = 'HKLM:\G'
    Check 'performance: HAGS setting only when supported' (@(Get-Settings 'Registry::X' $false | Where-Object { $_[1] -eq 'HwSchMode' }).Count -eq 0 -and @(Get-Settings 'Registry::X' $true | Where-Object { $_[1] -eq 'HwSchMode' }).Count -eq 1)
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'audit.ps1'))))
    Check 'audit: all ok' ((Get-CheckState ([ordered]@{ a = @{ ok = $true }; b = @{ ok = $null } })) -eq 'ok')
    Check 'audit: one failing check is drift' ((Get-CheckState ([ordered]@{ a = @{ ok = $true }; b = @{ ok = $false } })) -eq 'drift')
}

# ------------------------------------------- end to end: the one-line contract
# Off Windows every package fails early (no Windows APIs) and must still print exactly
# one JSON line and exit 1. On Windows only the read-only standards check is run.
$isWin = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
$isRoot = (-not $isWin) -and ((& id -u) -eq '0')
$pwshExe = (Get-Process -Id $PID).Path
$run = if ($isWin) { @('audit') } elseif ($isRoot) { @() } else { $Names }
foreach ($n in $run) {
    $env:OMINULL_PARAM_MODE = 'audit'
    $out = @(& $pwshExe -NoProfile -NonInteractive -File (Join-Path $Dir "$n.ps1") 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $o = $null; if ($out.Count -eq 1) { try { $o = $out[0] | ConvertFrom-Json } catch {} }
    Check "e2e $n prints one JSON line ($($out -join ' | '))" ($null -ne $o -and $o.v -eq 1)
    if ($o) { Check "e2e $n exit code matches state" (($o.state -eq 'failed') -eq ($code -ne 0)) }
}
Remove-Item Env:OMINULL_PARAM_MODE -ErrorAction SilentlyContinue

Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failures.Count)
if ($script:Failures.Count) { exit 1 }
exit 0
