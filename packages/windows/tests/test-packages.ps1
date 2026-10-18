# Static and unit checks for the Windows maintenance packages. Runs under pwsh on
# Linux or Windows: packages/windows/tests/run.sh, or pwsh -File this script.
# Unit checks load only the packages' function definitions (nothing at top level
# runs) and replace the system calls with stand-ins.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$Dir = Split-Path -Parent $PSScriptRoot
$Names = 'updates', 'cleanup', 'privacy', 'debloat', 'performance', 'audit', 'maintenance-mode', 'software-removal', 'reboot'
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Passed = 0
function Check([string]$What, [bool]$Ok) {
    if ($Ok) { $script:Passed++ } else { $script:Failures.Add($What); Write-Host "FAIL $What" }
}
Get-ChildItem Env: | Where-Object { $_.Name -like 'OMINULL_PARAM_*' } | ForEach-Object { Remove-Item "Env:$($_.Name)" }
# Function definitions plus the package's top-level tables ($Kinds, $Machine, ...),
# without the preference settings and the run itself.
function Get-Defs([string]$Path) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $skip = 'ErrorActionPreference', 'ProgressPreference', 'WarningPreference', 'VerbosePreference', 'InformationPreference', 'Changed', 'Detail', 'State', 'Reboot', 'json'
    $tables = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $skip -notcontains $_.Left.VariablePath.UserPath } | ForEach-Object { $_.Extent.Text })
    (@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text }) + $tables) -join "`n"
}

# ---------------------------------------------------------------- static checks
$preludes = @{}
$headers = @{}
$blocks = @{}
# Names a param may not take (payload fields, mode, environment variables scripts rely on).
$reserved = 'mode', 'script_id', 'script_version', 'script_digest', 'interpreter', 'source', 'parameters', 'timeout_seconds', 'max_output_bytes',
    'path', 'pathext', 'temp', 'tmp', 'windir', 'systemroot', 'systemdrive', 'comspec', 'psmodulepath', 'programdata', 'programfiles',
    'allusersprofile', 'userprofile', 'appdata', 'localappdata', 'public', 'username', 'userdomain', 'computername', 'os'
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
    Check "$n size < 24576 bytes ($($bytes.Length))" ($bytes.Length -lt 24576)
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
        Check "$n header key order" ((@($meta.PSObject.Properties.Name) -join ',') -match '^name,title,description,category,risk,reboot,timeout,interval,params(,platform)?(,role)?$')
        if ($meta.PSObject.Properties.Name -contains 'platform') { Check "$n header platform" ($meta.platform -ceq 'windows') }
        if ($meta.PSObject.Properties.Name -contains 'role') { Check "$n header role" (($meta.role -ceq 'maintenance_mode' -and $n -eq 'maintenance-mode') -or ($meta.role -ceq 'reboot' -and $n -eq 'reboot')) }
        Check "$n header category" (@('maintenance', 'security') -contains $meta.category)
        Check "$n header interval" (@('hourly', 'daily', 'weekly') -contains $meta.interval)
        $headers[$n] = $meta
        $pn = @{}
        foreach ($p in @($meta.params)) {
            $keys = @($p.PSObject.Properties.Name)
            Check "$n param $($p.name) name" ($p.name -cmatch '^[a-z][a-z0-9_]{1,31}$' -and $reserved -notcontains $p.name -and -not $pn[$p.name])
            $pn[$p.name] = 1
            Check "$n param $($p.name) description" ([bool]$p.description -and $p.description.Length -le 200)
            Check "$n param $($p.name) known type" (@('int', 'bool', 'enum', 'list', 'catalog') -contains $p.type)
            Check "$n param $($p.name) has a default" ($keys -contains 'default')
            if ($p.type -eq 'int') { Check "$n param $($p.name) int bounds" ($p.default -is [ValueType] -and $p.min -le $p.default -and $p.default -le $p.max) }
            if ($p.type -eq 'bool') { Check "$n param $($p.name) bool default" ($p.default -is [bool]) }
            if ($p.type -eq 'enum') { Check "$n param $($p.name) enum default" (@($p.values) -ccontains $p.default) }
            if ($p.type -eq 'list') { Check "$n param $($p.name) list bounds" ($p.max_items -ge 1 -and $p.max_items -le 64 -and @($p.default).Count -le $p.max_items) }
            $extra = @($keys | Where-Object { @('name', 'type', 'default', 'min', 'max', 'values', 'max_items', 'description', 'careful') -notcontains $_ })
            Check "$n param $($p.name) has no unknown keys" ($extra.Count -eq 0)
            if ($keys -contains 'careful') { Check "$n param $($p.name) careful only on an off-by-default bool" ($p.careful -eq $true -and $p.type -eq 'bool' -and $p.default -eq $false) }
        }
        Check "$n declares log_keep" ($pn['log_keep'] -eq 1)
        Check "$n `$Pkg matches header" ($text -match "(?m)^\`$Pkg = '$([regex]::Escape($meta.name))'")
    }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Check "$n parses ($(@($errors | ForEach-Object { $_.Message }) -join '; '))" ($errors.Count -eq 0)
    $ps7 = @($ast.FindAll({ param($x) $x.GetType().Name -in 'TernaryExpressionAst', 'PipelineChainAst' }, $true))
    $ps7 += @($tokens | Where-Object { $_.Kind -in 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr' })
    Check "$n uses no PowerShell 7-only syntax" ($ps7.Count -eq 0)
    # Only the restart package may restart the machine.
    foreach ($k in $forbidden.Keys) { if ($n -eq 'reboot' -and $k -eq 'reboots the machine') { continue }; Check "$n never touches $k" ($text -notmatch $forbidden[$k]) }
    Check "$n writes stdout once" (([regex]::Matches($text, '\[Console\]::Out\.WriteLine')).Count -eq 1)
    if ($text -match '(?s)# --- prelude begin.*?# --- prelude end ---') { $preludes[$n] = $matches[0] }
    Check "$n has the shared prelude" ($preludes.ContainsKey($n))
    foreach ($b in 'original values', 'registry helpers', 'protected services', 'reboot check', 'package temp') {
        if ($text -match "(?s)# --- $b begin.*?# --- $b end ---") { if (-not $blocks[$b]) { $blocks[$b] = @() }; $blocks[$b] += $matches[0] }
    }
    Check "$n reads every tunable from its params" ($text -match '\$Opt = Get-PkgParams \$PSCommandPath; Start-Log \$Opt\.log_keep')
}
Check 'prelude identical in every package' (@($preludes.Values | Sort-Object -Unique).Count -eq 1)
foreach ($b in $blocks.Keys) { Check "block '$b' identical wherever present" (@($blocks[$b] | Sort-Object -Unique).Count -eq 1) }
Check 'debloat and privacy share the registry/original-value helpers' ($blocks['original values'].Count -eq 3 -and $blocks['registry helpers'].Count -eq 2 -and $blocks['reboot check'].Count -eq 3 -and $blocks['package temp'].Count -eq 2)

# ------------------------------------------------------- unit checks: prelude
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'audit.ps1'))))
    Check 'mode: enforce from OMINULL_PARAM_MODE' ((Get-Mode 'enforce' '') -eq 'enforce')
    Check 'mode: enforce from bare mode' ((Get-Mode '' 'enforce') -eq 'enforce')
    Check 'mode: padded value' ((Get-Mode ' enforce ' '') -eq 'enforce')
    Check 'mode: missing is audit' ((Get-Mode '' '') -eq 'audit')
    Check 'mode: unknown is audit' ((Get-Mode 'delete-everything' 'enforce') -eq 'audit')
    Check 'mode: revert' ((Get-Mode 'revert' '') -eq 'revert')
    Check 'mode: Revert is not revert' ((Get-Mode 'Revert' '') -eq 'audit')
    Check 'quser idle .' ((ConvertFrom-QuserIdle '.') -eq 0)
    Check 'quser idle none' ((ConvertFrom-QuserIdle 'none') -eq 0)
    Check 'quser idle minutes' ((ConvertFrom-QuserIdle '5') -eq 5)
    Check 'quser idle h:mm' ((ConvertFrom-QuserIdle '1:05') -eq 65)
    Check 'quser idle d+h:mm' ((ConvertFrom-QuserIdle '2+03:04') -eq 3064)
    $hdr = ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME'
    Check 'quser: active console user' (Test-UserActive @($hdr, '>nadia                 console             1  Active      none   10/17/2026 9:00 AM') 15)
    Check 'quser: idle 45 min is not active' (-not (Test-UserActive @($hdr, ' nadia                 console             1  Active        45   10/17/2026 9:00 AM') 15))
    Check 'quser: idle 14 min is active' (Test-UserActive @($hdr, ' nadia                 console             1  Active        14   10/17/2026 9:00 AM') 15)
    Check 'quser: idle 45 min is active under a 60 min threshold' (Test-UserActive @($hdr, ' nadia                 console             1  Active        45   10/17/2026 9:00 AM') 60)
    Check 'quser: disconnected is not active' (-not (Test-UserActive @($hdr, ' bob                                       2  Disc          1:00  10/17/2026 9:00 AM') 15))
    Check 'quser: no sessions' (-not (Test-UserActive @() 15))

    # Params: defaults come from line 1, a run overrides them, bad values fail.
    $tmpPkg = Join-Path ([IO.Path]::GetTempPath()) ("omp-" + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -LiteralPath $tmpPkg -Value ('# ominull-package: {"name":"t","params":[{"name":"age_days","type":"int","default":7,"min":1,"max":30,"description":"d"},' +
        '{"name":"deep","type":"bool","default":false,"description":"d"},{"name":"level","type":"enum","values":["low","high"],"default":"low","description":"d"},' +
        '{"name":"apps","type":"list","default":["A.One","B Two"],"max_items":3,"description":"d"},{"name":"none","type":"list","default":[],"max_items":2,"description":"d"},' +
        '{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"d"}]}')
    $p = Get-PkgParams $tmpPkg
    Check 'params: int default' ($p.age_days -eq 7 -and $p.age_days -is [long])
    Check 'params: bool default' ($p.deep -is [bool] -and -not $p.deep)
    Check 'params: enum default' ($p.level -ceq 'low')
    Check 'params: list default stays an array' ($p.apps -is [array] -and $p.apps.Count -eq 2 -and $p.apps[1] -ceq 'B Two')
    Check 'params: empty list default' ($p.none -is [array] -and $p.none.Count -eq 0)
    $env:OMINULL_PARAM_AGE_DAYS = '30'; $env:OMINULL_PARAM_DEEP = 'true'; $env:OMINULL_PARAM_LEVEL = 'high'; $env:OMINULL_PARAM_APPS = '-'; $env:OMINULL_PARAM_NONE = 'X.Y'
    $p = Get-PkgParams $tmpPkg
    Check 'params: env overrides' ($p.age_days -eq 30 -and $p.deep -and $p.level -ceq 'high' -and $p.apps.Count -eq 0 -and $p.none.Count -eq 1 -and $p.none[0] -ceq 'X.Y')
    foreach ($bad in @(@('AGE_DAYS', '31'), @('AGE_DAYS', '0'), @('AGE_DAYS', '07'), @('AGE_DAYS', '+7'), @('AGE_DAYS', '7.5'), @('AGE_DAYS', '99999999999999999999'),
            @('DEEP', 'True'), @('DEEP', '1'), @('LEVEL', 'HIGH'), @('LEVEL', 'medium'), @('APPS', 'A,B,C,D'), @('APPS', 'A,a'), @('APPS', 'A;rm'),
            @('APPS', 'C:\Windows'), @('APPS', ',A'), @('APPS', 'A '), @('APPS', 'say"hi'), @('APPS', ('x' * 1025)))) {
        Remove-Item Env:OMINULL_PARAM_* -ErrorAction SilentlyContinue
        Set-Item "Env:OMINULL_PARAM_$($bad[0])" $bad[1]
        $threw = $false; try { Get-PkgParams $tmpPkg | Out-Null } catch { $threw = $true }
        Check "params: refuses $($bad[0])=$($bad[1].Substring(0, [math]::Min(20, $bad[1].Length)))" $threw
    }
    Remove-Item Env:OMINULL_PARAM_* -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpPkg
    foreach ($n in $Names) {
        $ok = $true; try { $d = Get-PkgParams (Join-Path $Dir "$n.ps1") } catch { $ok = $false }
        Check "params: $n defaults are valid" ($ok -and $d.log_keep -ge 1)
    }
    foreach ($p in 'C:\Program Files (x86)\Steam\steamapps\common\Elden Ring\Game\eldenring.exe', 'D:\Epic Games\Fortnite\FortniteClient.exe',
        'C:\Riot Games\VALORANT\live\VALORANT.exe', 'C:\XboxGames\Halo Infinite\Content\HaloInfinite.exe', 'E:\GOG Galaxy\Games\Witcher 3\bin\witcher3.exe') {
        Check "game path: $p" (Test-GamePath $p)
    }
    foreach ($p in 'C:\Program Files (x86)\Steam\steam.exe', 'C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe',
        'C:\Program Files (x86)\Epic Games\Epic Online Services\service\EpicOnlineServicesUserHelper.exe',
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
    Check 'result na is kept' (((Format-Result 'na' $false @() @{}) | ConvertFrom-Json).state -eq 'na')
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
    Check 'preflight: nothing blocks' ($null -eq (Get-PreflightReason $true 15))
    $script:Quser = @{ code = 0; out = @($hdr, '>nadia  console  1  Active  none  10/17/2026 9:00 AM') }
    Check 'preflight: user active' ((Get-PreflightReason $false 15) -match 'using the computer')
    $script:Quser = @{ code = 1; out = @('No User exists for *') }
    $script:Procs = @([pscustomobject]@{ ExecutablePath = 'C:\Riot Games\VALORANT\live\VALORANT.exe' })
    Check 'preflight: game running' ((Get-PreflightReason $false 15) -match 'game is running \(VALORANT.exe\)')
    $script:Procs = @([pscustomobject]@{ ExecutablePath = $null }); $script:Batt = [pscustomobject]@{ BatteryStatus = 1 }
    Check 'preflight: on battery' ((Get-PreflightReason $false 15) -match 'battery')
    $script:Batt = $null; $script:Busy = $true
    Check 'preflight: update installing' ((Get-PreflightReason $true 15) -match 'Windows Update')
    Check 'preflight: update check only when asked' ($null -eq (Get-PreflightReason $false 15))
    $script:Busy = $false; $script:Ti = [pscustomobject]@{ Name = 'TiWorker' }
    Check 'preflight: TiWorker running' ((Get-PreflightReason $true 15) -match 'Windows Update')
    $script:Ti = $null
    # Run options: the window (may cross midnight), wait and run.
    Check 'window: inside' (Test-InWindow '01:00-05:00' ([datetime]'2026-10-17 03:30'))
    Check 'window: end is outside' (-not (Test-InWindow '01:00-05:00' ([datetime]'2026-10-17 05:00')))
    Check 'window: across midnight, late' (Test-InWindow '22:00-06:00' ([datetime]'2026-10-17 23:10'))
    Check 'window: across midnight, early' (Test-InWindow '22:00-06:00' ([datetime]'2026-10-17 05:59'))
    Check 'window: across midnight, day' (-not (Test-InWindow '22:00-06:00' ([datetime]'2026-10-17 12:00')))
    Check 'window: none' (-not (Test-InWindow '' ([datetime]'2026-10-17 03:30')))
    Check 'window: bad text' (-not (Test-InWindow '1:00-5:00' ([datetime]'2026-10-17 03:30')))
    $script:Quser = @{ code = 0; out = @($hdr, '>nadia  console  1  Active  none  10/17/2026 9:00 AM') }
    $env:OMINULL_PARAM_WHEN_BUSY = 'run'
    Check 'when_busy run: people do not count' ($null -eq (Get-PreflightReason $false 15))
    $script:Batt = [pscustomobject]@{ BatteryStatus = 1 }
    Check 'when_busy run: battery still counts' ((Get-PreflightReason $false 15) -match 'battery')
    $script:Batt = $null
    $env:OMINULL_PARAM_WHEN_BUSY = 'skip'; $env:OMINULL_PARAM_WINDOW = '00:00-23:59'
    Check 'inside the window people do not count' ($null -eq (Get-PreflightReason $false 15))
    $env:OMINULL_PARAM_WINDOW = ''
    Check 'skip: someone using it skips' ((Get-PreflightReason $false 15) -match 'using the computer')
    $env:OMINULL_PARAM_WHEN_BUSY = 'wait'; $script:PkgTimeout = 600; $script:Slept = 0
    function Start-Sleep { param($Seconds) $script:Slept++; if ($script:Slept -ge 2) { $script:Quser = @{ code = 1; out = @() } } }
    Check 'wait: runs once nobody is using it' ($null -eq (Get-PreflightReason $false 15) -and $script:Slept -eq 2)
    $script:Quser = @{ code = 0; out = @($hdr, '>nadia  console  1  Active  none  10/17/2026 9:00 AM') }; $script:PkgTimeout = 60
    Check 'wait: gives up within half the timeout' ((Get-PreflightReason $false 15) -match 'using the computer')
    $env:OMINULL_PARAM_WHEN_BUSY = 'sometimes'
    Check 'when_busy: a bad value fails' ($(try { Get-PreflightReason $false 15; $false } catch { "$_" -match 'when_busy' }))
    $env:OMINULL_PARAM_WHEN_BUSY = ''; $env:OMINULL_PARAM_WINDOW = '25:00-01:00'
    Check 'window: a bad value fails' ($(try { Get-PreflightReason $false 15; $false } catch { "$_" -match 'window' }))
    Remove-Item Env:OMINULL_PARAM_WHEN_BUSY, Env:OMINULL_PARAM_WINDOW -ErrorAction SilentlyContinue
}

# --------------------------------------------------- unit checks: per package
# $Opt is each package's params at their defaults unless a check says otherwise.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'updates.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'updates.ps1')
    $cat = { param($n, $id) [pscustomobject]@{ Name = $n; CategoryID = $id } }
    $u = { param($t, $c, $b) [pscustomobject]@{ Title = $t; Categories = @($c); BrowseOnly = $b; KBArticleIDs = @('5031354') } }
    $fw = [pscustomobject]@{ Title = 'Lenovo - Firmware - 1.2'; Categories = @(& $cat 'Drivers' 'y'); BrowseOnly = $false; Type = 2; DriverClass = 'Firmware'; KBArticleIDs = @() }
    Check 'updates: cumulative update wanted' (Test-Wanted (& $u '2026-10 Cumulative Update for Windows 11 (KB5031354)' (& $cat 'Security Updates' 'x') $false))
    Check 'updates: driver wanted' (Test-Wanted (& $u 'NVIDIA - Display - 31.0.15.5222' (& $cat 'Drivers' 'y') $false))
    Check 'updates: preview skipped' (-not (Test-Wanted (& $u '2026-10 Cumulative Update Preview for Windows 11' (& $cat 'Updates' 'x') $false)))
    Check 'updates: feature update skipped' (-not (Test-Wanted (& $u 'Feature update to Windows 11, version 25H2' (& $cat 'Upgrades' 'x') $false)))
    Check 'updates: Upgrades category skipped' (-not (Test-Wanted (& $u 'Windows 11' (& $cat 'Other' 'e6cf1350-c01b-414d-a61f-263d14d133b4') $false)))
    Check 'updates: optional (browse-only) skipped' (-not (Test-Wanted (& $u 'Some optional driver' (& $cat 'Drivers' 'y') $true)))
    Check 'updates: firmware skipped by default' (-not (Test-Wanted $fw))
    Check 'updates: label has KB' ((Get-UpdateLabel (& $u 'Title' (& $cat 'x' 'x') $false)) -eq 'KB5031354 Title')
    $Opt = @{ exclude = [string[]]@('preview') }
    Check 'updates: firmware wanted when not excluded' (Test-Wanted $fw)
    Check 'updates: preview still skipped' (-not (Test-Wanted (& $u 'Cumulative Update Preview' (& $cat 'Updates' 'x') $false)))
    $Opt = @{ exclude = [string[]]@('firmware', 'driver') }
    Check 'updates: drivers skipped when excluded' (-not (Test-Wanted (& $u 'NVIDIA - Display' (& $cat 'Drivers' 'y') $false | ForEach-Object { $_ | Add-Member Type 2 -PassThru })))
    $Opt = @{ exclude = [string[]]@('everything') }
    $threw = $false; try { Test-Wanted $fw | Out-Null } catch { $threw = $true }
    Check 'updates: unknown exclude kind fails the run' $threw
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'cleanup.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'cleanup.ps1')
    $oldRoot = $env:SystemRoot; $oldPd = $env:ProgramData
    $env:SystemRoot = 'C:\Windows'; $env:ProgramData = 'C:\ProgramData'
    foreach ($t in Get-Targets) { Check "cleanup: target allowed $($t.path)" (Test-Allowed $t.path) }
    foreach ($p in 'C:\Users\nadia\AppData\Local\Temp', 'C:\ProgramData\Ominull', 'C:\Windows\Temp\..\..\Users\x', 'C:\$Recycle.Bin',
        'D:\Windows\Temp', 'C:\ProgramData\Microsoft\Windows\Start Menu', 'C:\ProgramData', 'C:\Program Files\Steam') {
        Check "cleanup: refuses $p" (-not (Test-Allowed $p))
    }
    Check 'cleanup: no ResetBase, recycle bin or user path in targets' (-not ((Get-Targets | ForEach-Object { $_.path }) -match 'Users|Recycle|Ominull'))
    $days = @{}; foreach ($t in Get-Targets) { $days[$t.id] = $t.days }
    Check 'cleanup: target ages come from params' ($days.windows_temp -eq 7 -and $days.minidumps -eq 14 -and $days.memory_dump -eq 7 -and $days.error_reports_queue -eq 30 -and $days.update_downloads -eq 0)
    $Opt.temp_days = 3
    Check 'cleanup: changed temp age is used' (@(Get-Targets | Where-Object { $_.id -eq 'windows_temp' -and $_.days -eq 3 }).Count -eq 1)
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
    # DISM time box (it hung for hours on two laptops): a hung DISM is killed at its limit and reported timed out.
    $script:Root = Join-Path ([IO.Path]::GetTempPath()) ("omt-dism-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $script:Root | Out-Null
    function Write-Log { }
    if (-not $IsWindows) {
        $DismExe = Join-Path $script:Root 'fake-dism'
        Set-Content -LiteralPath $DismExe "#!/bin/sh`nsleep 30`n"; chmod +x $DismExe
        $t0 = Get-Date; $r = Invoke-Dism @('/Online') 1; $took = ((Get-Date) - $t0).TotalSeconds
        Check "cleanup: a hung DISM is cut at its limit ($([math]::Round($took, 1)) s)" ($r.timed_out -and $took -lt 15)
        Set-Content -LiteralPath $DismExe "#!/bin/sh`necho 'Component Store Cleanup Recommended : Yes'`n"
        $a = Test-ComponentCleanup
        Check 'cleanup: analyze reads the recommendation' ($a.recommended -and -not $a.timed_out)
        Set-Content -LiteralPath $DismExe "#!/bin/sh`nsleep 30`n"
        $Opt.dism_analyze_minutes = 1; $script:PkgTimeout = 185; $script:Started = Get-Date
        $t0 = Get-Date; $a = Test-ComponentCleanup; $took = ((Get-Date) - $t0).TotalSeconds
        Check "cleanup: the time box never runs past the package limit ($([math]::Round($took, 1)) s)" ($a.timed_out -and $took -lt 15)
    }
    $script:PkgTimeout = 3600; $script:Started = (Get-Date).AddSeconds(-3500)
    Check 'cleanup: no time left means no DISM call' ((Get-DismSeconds 15) -eq 0 -and (Invoke-Dism @('/Online') 0).timed_out)
    $script:Started = Get-Date
    Check 'cleanup: DISM limits come from params' ((Get-DismSeconds $Opt.dism_cleanup_minutes) -eq 45 * 60 -and (Get-PkgParams (Join-Path $Dir 'cleanup.ps1')).dism_analyze_minutes -eq 15)
    Remove-Item -Recurse -Force $script:Root
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'debloat.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'debloat.ps1')
    foreach ($n in @($Opt.remove_apps) + @($Opt.deprovision_apps)) { Check "debloat: default list entry not protected $n" (-not (Test-Protected $n)) }
    $protectedApps = 'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
        'Microsoft.GamingApp', 'Microsoft.GamingServices', 'Microsoft.DesktopAppInstaller', 'Microsoft.WindowsTerminal', 'Microsoft.VCLibs.140.00',
        'Microsoft.UI.Xaml.2.8', 'NVIDIACorp.NVIDIAControlPanel', 'AdvancedMicroDevicesInc-2.AMDRadeonSoftware', 'AppUp.IntelGraphicsExperience',
        'RealtekSemiconductorCorp.RealtekAudioControl', 'B9ECED6F.ArmouryCrate', 'E046963F.LenovoCompanion', 'AD2F1837.HPSystemEventUtility',
        'AD2F1837.OMENCommandCenter', 'DellInc.DellPowerManager', 'AcerIncorporated.PredatorSense', 'RazerInc.RazerSynapse', 'Microsoft.SecHealthUI'
    foreach ($n in $protectedApps) { Check "debloat: protects $n" (Test-Protected $n) }
    foreach ($n in @($Opt.services)) { Check "debloat: default service not protected $n" (-not (Test-ProtectedService $n)) }
    $protectedSvcs = 'WinDefend', 'WdNisSvc', 'SecurityHealthService', 'Sense', 'mpssvc', 'BFE', 'wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'BITS', 'DoSvc',
        'TrustedInstaller', 'InstallService', 'ClipSVC', 'AppXSvc', 'XblAuthManager', 'XboxNetApiSvc', 'GamingServices', 'NVDisplay.ContainerLocalSystem',
        'AMD External Events Utility', 'RtkAudioUniversalService', 'Audiosrv', 'RpcSs', 'EventLog', 'Winmgmt', 'Dnscache', 'OminullAgent'
    foreach ($n in $protectedSvcs) { Check "debloat: protects service $n" (Test-ProtectedService $n) }
    Check 'debloat: default remove and deprovision lists are disjoint' (-not (@($Opt.remove_apps) | Where-Object { @($Opt.deprovision_apps) -contains $_ }))
    # A list that names protected apps, a bare wildcard or protected services removes and disables none of them.
    function Get-AppxProvisionedPackage { [CmdletBinding()] param([switch]$Online)
        @($protectedApps + 'Microsoft.BingNews', 'king.com.CandyCrushSaga' | ForEach-Object { [pscustomobject]@{ DisplayName = $_; PackageName = "$($_)_1.0_neutral_~_8wekyb3d8bbwe" } }) }
    function Get-AppxPackage { [CmdletBinding()] param([switch]$AllUsers)
        @($protectedApps + 'Microsoft.BingNews' | ForEach-Object { [pscustomobject]@{ Name = $_; PackageFullName = "$($_)_1.0_x64__8wekyb3d8bbwe" } }) }
    function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName, $Filter)
        if ($Filter -match "Name='([^']+)'") { [pscustomobject]@{ Name = $matches[1]; StartMode = 'Auto'; State = 'Running' } } }
    $Opt.remove_apps = [string[]](@($protectedApps) + 'Microsoft.BingNews', '*Xbox*', '*', '*.*', 'Microsoft*')
    $Opt.deprovision_apps = [string[]]@('*CandyCrush*', '*Store*')
    $Opt.services = [string[]]@('WinDefend', 'mpssvc', 'wuauserv', 'XblGameSave', 'Fax')
    $st = Get-State
    $touched = @($st.remove) + @($st.deprovision) + @($st.services.Keys)
    Check "debloat: protected apps never removed ($($st.remove -join ','))" (-not ($touched | Where-Object { Test-Protected ($_ -replace '_.*$') }))
    Check 'debloat: BingNews still removed' (@($st.remove | Where-Object { $_ -like 'Microsoft.BingNews_*' }).Count -eq 1)
    Check 'debloat: wildcard deprovisions CandyCrush' (@($st.deprovision | Where-Object { $_ -like 'king.com.CandyCrushSaga_*' }).Count -eq 1)
    Check 'debloat: bare wildcards are refused' (@($st.refused) -contains '*' -and @($st.refused) -contains '*.*')
    Check "debloat: protected services never disabled ($($st.services.Keys -join ','))" ((@($st.services.Keys) -join ',') -eq 'Fax')
    Check 'debloat: refusals are reported' (@($st.refused) -contains 'service:WinDefend' -and @($st.refused) -contains 'Microsoft.WindowsStore')
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'privacy.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'privacy.ps1')
    Check 'privacy: Home floor 1' ((Get-TelemetryFloor 'Core') -eq 1)
    Check 'privacy: Pro floor 1' ((Get-TelemetryFloor 'Professional') -eq 1)
    Check 'privacy: Enterprise floor 0' ((Get-TelemetryFloor 'Enterprise') -eq 0)
    Check 'privacy: Education floor 0' ((Get-TelemetryFloor 'Education') -eq 0)
    $m = @(Get-Settings $Machine 'HKLM:\P' 1 $Opt.turn_off); $u = @(Get-Settings $User 'HKU:\D' 1 $Opt.turn_off)
    Check "privacy: default groups give every setting ($($m.Count)+$($u.Count))" ($m.Count -eq 16 -and $u.Count -eq 11)
    Check 'privacy: default groups cover every group' (@(@($Machine.Keys) + @($User.Keys) + @($Svc.Keys) | Where-Object { @($Opt.turn_off) -notcontains $_ }).Count -eq 0)
    $all = @($m) + @($u) | ForEach-Object { "$($_[0])\$($_[1])" }
    Check 'privacy: never touches Defender, firewall, Windows Update, SmartScreen or location' (-not ($all -match 'Defender|Firewall|WindowsUpdate|SmartScreen|LocationAndSensors|DeviceGuard'))
    Check 'privacy: telemetry follows the floor' (@($m | Where-Object { $_[1] -eq 'AllowTelemetry' -and $_[2] -eq 1 }).Count -eq 1 -and
        @(Get-Settings $Machine 'HKLM:\P' 0 $Opt.turn_off | Where-Object { $_[1] -eq 'AllowTelemetry' -and $_[2] -eq 0 }).Count -eq 1)
    $c = @(Get-Settings $Machine 'HKLM:\P' 1 ([string[]]@('copilot')))
    Check 'privacy: one group gives only its settings' ($c.Count -eq 1 -and $c[0][1] -eq 'TurnOffWindowsCopilot')
    Check 'privacy: no groups, no settings' (@(Get-Settings $Machine 'HKLM:\P' 1 ([string[]]@())).Count -eq 0)
    $threw = $false; try { Get-Settings $Machine 'HKLM:\P' 1 ([string[]]@('defender')) | Out-Null } catch { $threw = $true }
    Check 'privacy: unknown group fails the run' $threw
    $sv = @(Get-Settings $Svc 'HKLM:\S' 1 $Opt.turn_off)
    Check 'privacy: only telemetry services are ever disabled' ((@($sv | ForEach-Object { "$($_[0])\$($_[1])=$($_[2])" }) -join ',') -eq 'HKLM:\S\DiagTrack\Start=4,HKLM:\S\dmwappushservice\Start=4')
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'performance.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'performance.ps1')
    Check 'performance: HAGS on WDDM 3.1, Win11' (Test-HagsSupported 22631 @('31.0.15.5222'))
    Check 'performance: no HAGS on WDDM 2.6' (-not (Test-HagsSupported 22631 @('26.20.100.7')))
    Check 'performance: no HAGS before 2004' (-not (Test-HagsSupported 18363 @('31.0.15.5222')))
    Check 'performance: no HAGS without a driver' (-not (Test-HagsSupported 22631 @()))
    $GraphicsKey = 'HKLM:\G'
    $off = Get-Settings 'Registry::X' $false; $on = Get-Settings 'Registry::X' $true
    Check 'performance: careful HAGS is off by default' ($Opt.gpu_scheduling -eq $false -and @($on).Count -eq 2 -and -not @($on | Where-Object { $_[1] -eq 'HwSchMode' }).Count)
    $Opt.gpu_scheduling = $true
    $off = Get-Settings 'Registry::X' $false; $on = Get-Settings 'Registry::X' $true
    $h = @($on | Where-Object { $_[1] -eq 'HwSchMode' })
    Check 'performance: HAGS setting only when supported' (@($off | Where-Object { $_[1] -eq 'HwSchMode' }).Count -eq 0 -and $h.Count -eq 1)
    Check 'performance: HAGS step is marked careful' ($h[0][3] -eq 'careful' -and @($on).Count -eq 3)
    $Opt.gpu_scheduling = $false; $Opt.block_game_recording = $false
    $one = Get-Settings 'Registry::X' $true
    Check 'performance: switched-off settings are left alone' (@($one).Count -eq 1 -and $one[0][1] -eq 'AutoGameModeEnabled')
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'audit.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'audit.ps1')
    $c = @((Test-Control 'a' 'x' { 'fine', $true }), (Test-Control 'b' 'x' { 'no edition', $null }), (Test-Control 'c' 'x' { throw 'boom' }))
    Check 'audit: control states pass, na, fail on error' ((@($c | ForEach-Object { $_.state }) -join ',') -eq 'pass,na,fail' -and $c[2].actual -match 'check failed: boom')
    Check 'audit: na and pass are ok' ((Get-CheckState @($c[0], $c[1])) -eq 'ok')
    Check 'audit: one failing control is drift' ((Get-CheckState $c) -eq 'drift')
    Check 'audit: control shape' ((@($c[0].Keys) -join ',') -eq 'id,expected,actual,state,risk' -and $c[0].risk -eq 'safe')
    $Detail = [ordered]@{}; $Mode = 'revert'; Invoke-Package
    Check 'audit: revert does not apply' ($script:State -eq 'na' -and $Detail.reason)
}
foreach ($n in 'cleanup', 'updates') {
    & {
        . ([scriptblock]::Create((Get-Defs (Join-Path $Dir "$n.ps1"))))
        $Detail = [ordered]@{}; $Mode = 'revert'; $script:State = 'failed'; Invoke-Package
        Check "${n}: revert does not apply" ($script:State -eq 'na' -and $Detail.reason)
    }
}
# Enforce records first-seen values once; revert puts them back. Registry and services are stand-ins.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'privacy.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'privacy.ps1')
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ominull-test-$PID"; $script:Root = $tmp; $Pkg = 'windows-test'
    $reg = @{ 'HKLM:\A\x' = 0; 'HKLM:\A\y' = 1 }; $svc = New-Object System.Collections.Generic.List[string]
    function Get-Reg($Path, $Name) { $reg["$Path\$Name"] }
    function Set-RegDword($Path, $Name, $Value) { $reg["$Path\$Name"] = $Value }
    function Remove-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name) $reg.Remove("$LiteralPath\$Name") }
    function Set-Service { [CmdletBinding()] param($Name, $StartupType) $svc.Add("$Name=$StartupType") }
    function Start-Service { [CmdletBinding()] param($Name) $svc.Add("$Name started") }
    function Get-PreflightReason { $null }
    try {
        $Changed = New-Object System.Collections.Generic.List[string]; $Detail = [ordered]@{}; $Mode = 'audit'
        $set = @(, @('HKLM:\A', 'x', 1)) + @(, @('HKLM:\A', 'y', 1)) + @(, @('HKLM:\A', 'z', 1, 'careful'))
        Invoke-Settings $set
        Check 'revert test: audit only reports drift' ($script:State -eq 'drift' -and $reg['HKLM:\A\x'] -eq 0 -and -not $Changed.Count)
        $Mode = 'enforce'; Invoke-Settings $set
        Check 'revert test: enforce fixes' ($script:State -eq 'fixed' -and $reg['HKLM:\A\x'] -eq 1 -and $reg['HKLM:\A\z'] -eq 1)
        $ctl = @($Detail.controls)
        Check 'controls: one per setting with the contract keys' ($ctl.Count -eq 3 -and -not @($ctl | Where-Object { (@($_.Keys) -join ',') -ne 'id,expected,actual,state,risk' }).Count)
        Check 'controls: states and risk' ((@($ctl | ForEach-Object { "$($_.state)/$($_.risk)" }) -join ',') -eq 'fixed/safe,pass/safe,fixed/careful')
        $o = Get-Original
        Check 'revert test: first-seen values recorded' ($o.Count -eq 2 -and $o['HKLM:\A\x'] -eq 0 -and $o.Contains('HKLM:\A\z') -and $null -eq $o['HKLM:\A\z'])
        $reg['HKLM:\A\x'] = 7; Invoke-Settings $set; Save-Original ([ordered]@{ 'service:Fax' = 'Manual/Running'; 'appx:Foo' = 'installed' })
        $o = Get-Original
        Check 'revert test: recorded values never overwritten' ($o['HKLM:\A\x'] -eq 0 -and $o['service:Fax'] -eq 'Manual/Running')
        $Changed.Clear(); Invoke-Revert ''
        Check 'revert test: registry restored, absent value removed' ($reg['HKLM:\A\x'] -eq 0 -and -not $reg.ContainsKey('HKLM:\A\z') -and $reg['HKLM:\A\y'] -eq 1)
        Check 'revert test: service restored and started' ((@($svc) -join ',') -eq 'Fax=Manual,Fax started')
        Check 'revert test: reports restored and not restorable' ($script:State -eq 'fixed' -and @($Detail.restored).Count -eq 3 -and (@($Detail.not_restorable) -join ',') -eq 'appx:Foo')
        $Mode = 'enforce'; $reg['HKLM:\A\x'] = 0; function Get-PreflightReason { 'someone is using the computer' }; Invoke-Settings $set
        Check 'revert test: busy machine is skipped, not changed' ($script:State -eq 'skipped' -and $reg['HKLM:\A\x'] -eq 0)
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# Default hive: one run at a time; a hive this run did not load is never unloaded.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'performance.ps1'))))
    $Detail = [ordered]@{}; $script:State = 'failed'; $calls = New-Object System.Collections.Generic.List[string]
    function Invoke-Native($Exe, $Arguments) { $calls.Add($Arguments[0]); @{ code = 0; out = @() } }
    function Get-ItemProperty { [CmdletBinding()] param([Parameter(Position = 0)]$Path) [pscustomobject]@{ Default = 'C:\Users\Default' } }
    # Another holder on another thread; returns whether it could take the lock within $ms.
    function Test-LockFree([int]$ms) {
        $ps = [powershell]::Create().AddScript({ param($ms) $m = New-Object Threading.Mutex($false, 'Global\OminullDefaultHive')
            try { $g = $m.WaitOne($ms) } catch [Threading.AbandonedMutexException] { $g = $true }; if ($g) { $m.ReleaseMutex() }; $m.Dispose(); $g }).AddArgument($ms)
        try { [bool]($ps.Invoke() | Select-Object -Last 1) } finally { $ps.Dispose() }
    }
    $hold = [powershell]::Create().AddScript({ $m = New-Object Threading.Mutex($false, 'Global\OminullDefaultHive'); [void]$m.WaitOne(); Start-Sleep -Milliseconds 1500; $m.ReleaseMutex(); $m.Dispose() })
    $h = $hold.BeginInvoke(); Start-Sleep -Milliseconds 300
    $r = Mount-DefaultHive 200
    Check 'hive: lock timeout skips with a reason' ($null -eq $r -and $script:State -eq 'skipped' -and $Detail.reason -match 'Default user hive' -and -not $calls.Count)
    [void]$hold.EndInvoke($h); $hold.Dispose()
    function Test-Path { param([Parameter(Position = 0)]$Path) $true }
    $r = Mount-DefaultHive 1000
    Check 'hive: one already loaded is used' ($r -eq 'Registry::HKEY_USERS\OminullDefault' -and $Detail.hive_preloaded -and -not $calls.Count)
    Check 'hive: lock held while in use' (-not (Test-LockFree 100))
    Dismount-DefaultHive
    Check 'hive: a hive this run did not load is never unloaded' (-not ($calls -contains 'unload'))
    Check 'hive: lock released after use' (Test-LockFree 100)
    function Test-Path { param([Parameter(Position = 0)]$Path) $false }
    $r = Mount-DefaultHive 1000; Dismount-DefaultHive
    Check 'hive: a hive this run loaded is unloaded' ((@($calls) -join ',') -eq 'load,unload' -and (Test-LockFree 100))
    function Invoke-Native($Exe, $Arguments) { $calls.Add($Arguments[0]); @{ code = 1; out = @('denied') } }
    $calls.Clear(); $threw = $false; try { Mount-DefaultHive 1000 } catch { $threw = $true }
    Check 'hive: a failed load releases the lock and unloads nothing' ($threw -and (@($calls) -join ',') -eq 'load' -and (Test-LockFree 100))
}
# The after-test decides the state: errors with nothing left over are warnings.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'privacy.ps1'))))
    $Opt = Get-PkgParams (Join-Path $Dir 'privacy.ps1')
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ominull-test-a-$PID"; $script:Root = $tmp; $Pkg = 'windows-test'
    $reg = @{}; function Get-Reg($Path, $Name) { $reg["$Path\$Name"] }; function Get-PreflightReason { $null }
    try {
        $Changed = New-Object System.Collections.Generic.List[string]; $Detail = [ordered]@{}; $Mode = 'enforce'
        function Set-RegDword($Path, $Name, $Value) { $reg["$Path\$Name"] = $Value; throw 'access denied' }
        Invoke-Settings @(, @('HKLM:\A', 'x', 1))
        Check 'after-test clean with errors is fixed with warnings' ($script:State -eq 'fixed' -and @($Detail.warnings).Count -eq 1 -and $Detail.controls[0].state -eq 'pass')
        function Set-RegDword($Path, $Name, $Value) { throw 'access denied' }
        $Detail = [ordered]@{}; Invoke-Settings @(, @('HKLM:\A', 'y', 1))
        Check 'after-test drift is failed' ($script:State -eq 'failed' -and $Detail.controls[0].state -eq 'fail')
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'debloat.ps1'))))
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ominull-test-d-$PID"; $script:Root = $tmp; $Opt = @{ idle_minutes = 15 }
    $script:states = @(); $script:seen = @()
    function Get-State { $x, $script:states = $script:states; $x }
    function Save-Original($Values) {}
    function Get-PreflightReason { $null }
    function Remove-AppxPackage { [CmdletBinding()] param($Package, [switch]$AllUsers) $script:seen += [Environment]::GetEnvironmentVariable('TEMP') }
    function Remove-AppxProvisionedPackage { [CmdletBinding()] param([switch]$Online, $PackageName) throw 'The system cannot find the path specified.' }
    $dirty = [ordered]@{ remove = @('A_1'); deprovision = @('B_1'); services = [ordered]@{} }
    $clean = [ordered]@{ remove = @(); deprovision = @(); services = [ordered]@{} }
    $oldTemp = [Environment]::GetEnvironmentVariable('TEMP')
    try {
        $Changed = New-Object System.Collections.Generic.List[string]; $Detail = [ordered]@{}; $Mode = 'enforce'
        $script:states = @($dirty, $clean); Invoke-Package
        Check 'debloat: clean after-test with errors is fixed with warnings' ($script:State -eq 'fixed' -and @($Detail.warnings).Count -eq 1 -and $Detail.warnings[0] -match 'cannot find the path')
        Check 'debloat: Appx calls run with the package TEMP, restored after' ($script:seen[0] -eq "$tmp\tmp" -and [Environment]::GetEnvironmentVariable('TEMP') -eq $oldTemp)
        $Detail = [ordered]@{}; $script:states = @($dirty, $dirty); Invoke-Package
        Check 'debloat: drift after the test is failed' ($script:State -eq 'failed')
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# Maintenance mode: powercfg parsing, enforce/extend/revert/audit with stand-ins.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'maintenance-mode.ps1'))))
    $q = "Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)`n  Minimum Possible Setting: 0x00000000`n  Maximum Possible Setting: 0xffffffff`n" +
        "  Possible Settings increment: 0x00000001`n  Possible Settings units: Seconds`nCurrent AC Power Setting Index: 0x00000708`nCurrent DC Power Setting Index: 0x0000012c"
    $v = ConvertFrom-PowerQuery $q
    Check 'mm: query gives AC then DC' ($v.Count -eq 2 -and $v[0] -eq 1800 -and $v[1] -eq 300)
    Check 'mm: query without values is null' ($null -eq (ConvertFrom-PowerQuery 'Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da'))
    $h = $q.Replace('29f6c1db-86da-48c5-9fdb-f2b67b1f44da', '9d7815a6-7ee4-497e-8888-515a05f02364').Replace('0x00000708', '0x00002a30').Replace('0x0000012c', '0x00000e10')
    $d = ConvertFrom-PowerDump ("Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)`n" + $q + "`n" + $h)
    Check 'mm: saved dump split by setting' ($d['standby.ac'] -eq 1800 -and $d['standby.dc'] -eq 300 -and $d['hibernate.ac'] -eq 10800 -and $d['hibernate.dc'] -eq 3600)
    Check 'mm: dump missing a setting is null' ($null -eq (ConvertFrom-PowerDump $q))
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ominull-test-mm-$PID"; $script:Root = $tmp; $Pkg = 'windows-maintenance-mode'; $Opt = @{ hours = 6 }
    New-Item -ItemType Directory -Force -Path "$tmp\state" | Out-Null
    $script:pw = [ordered]@{ 'standby.ac' = 1800; 'standby.dc' = 300; 'hibernate.ac' = 10800; 'hibernate.dc' = 3600 }; $script:task = $null; $script:restored = 0
    function Get-ActiveScheme { '381b4222-f694-41f0-9685-ff5bb260df2e' }
    function Get-PowerValues($Scheme) { $o = [ordered]@{}; foreach ($k in $script:pw.Keys) { $o[$k] = $script:pw[$k] }; $o }
    function Set-PowerValues($Scheme, $Values) { foreach ($e in $Values.GetEnumerator()) { $script:pw[$e.Key] = $e.Value } }
    function Register-EndTask([datetime]$Until) { $script:task = $Until }
    function Restore-Power { $script:restored++; $s = Get-Content -LiteralPath (Get-StateFile) -Raw | ConvertFrom-Json
        foreach ($p in $s.saved.PSObject.Properties) { $script:pw[$p.Name] = $p.Value }; Remove-Item -LiteralPath (Get-StateFile); $script:task = $null; , @('x') }
    try {
        $Changed = New-Object System.Collections.Generic.List[string]; $Detail = [ordered]@{}; $Mode = 'enforce'
        Invoke-Package
        $st = Get-Content -LiteralPath (Get-StateFile) -Raw | ConvertFrom-Json
        Check 'mm: enforce turns sleep off' ($script:State -eq 'fixed' -and -not (@($script:pw.Values) | Where-Object { $_ -ne 0 }) -and $Detail.maintenance_mode.on)
        Check 'mm: enforce saves the values before' ($st.saved.'standby.ac' -eq 1800 -and $st.saved.'hibernate.dc' -eq 3600)
        Check 'mm: end task at now + hours' ($script:task -and [math]::Abs(($script:task - [datetime]::UtcNow.AddHours(6)).TotalMinutes) -lt 1)
        $Opt = @{ hours = 12 }; $Changed.Clear(); $Detail = [ordered]@{}; Invoke-Package
        $st = Get-Content -LiteralPath (Get-StateFile) -Raw | ConvertFrom-Json
        Check 'mm: enforce again extends and keeps the first saved values' ($script:State -eq 'fixed' -and $st.saved.'standby.ac' -eq 1800 -and $Changed[0] -match '^extended' -and
            [math]::Abs(($script:task - [datetime]::UtcNow.AddHours(12)).TotalMinutes) -lt 1)
        $Mode = 'audit'; $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: audit reports on and until' ($script:State -eq 'ok' -and $Detail.maintenance_mode.on -and [bool]$Detail.maintenance_mode.until)
        $Mode = 'revert'; $Changed.Clear(); $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: revert puts the values back' ($script:State -eq 'fixed' -and $script:pw['standby.ac'] -eq 1800 -and $script:pw['hibernate.dc'] -eq 3600 -and -not (Test-Path -LiteralPath (Get-StateFile)))
        $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: revert when off is ok' ($script:State -eq 'ok' -and -not $Detail.maintenance_mode.on)
        $Mode = 'audit'; $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: audit when off' ($script:State -eq 'ok' -and -not $Detail.maintenance_mode.on)
        # An end that passed while the machine was off: audit flags it, enforce ends it first.
        @{ scheme = 'x'; saved = @{ 'standby.ac' = 900 }; since = '2026-10-01T00:00:00.0000000Z'; until = '2026-10-01T06:00:00.0000000Z' } | ConvertTo-Json | Set-Content -LiteralPath (Get-StateFile)
        $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: audit flags an expired mode not yet ended' ($script:State -eq 'drift' -and -not $Detail.maintenance_mode.on)
        $Mode = 'enforce'; $Opt = @{ hours = 6 }; $Changed.Clear(); $Detail = [ordered]@{}; $n0 = $script:restored; Invoke-Package
        Check 'mm: enforce ends an expired mode, then starts afresh' ($script:restored -eq $n0 + 1 -and $Changed[0] -match 'expired' -and $script:State -eq 'fixed')
        $Mode = 'revert'; $Detail = [ordered]@{}; Invoke-Package
        # The operator's earlier power-before.txt wins over the current (already zero) values.
        $script:pw = [ordered]@{ 'standby.ac' = 0; 'standby.dc' = 0; 'hibernate.ac' = 0; 'hibernate.dc' = 0 }
        Set-Content -LiteralPath "$tmp\state\power-before.txt" -Value ("Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20`n" + $q + "`n" + $h)
        $Mode = 'enforce'; $Changed.Clear(); $Detail = [ordered]@{}; Invoke-Package
        $st = Get-Content -LiteralPath (Get-StateFile) -Raw | ConvertFrom-Json
        Check 'mm: saved power-before.txt is imported once' ($Detail.saved_from -eq 'power-before.txt' -and $st.saved.'standby.ac' -eq 1800 -and
            -not (Test-Path -LiteralPath "$tmp\state\power-before.txt") -and (Test-Path -LiteralPath "$tmp\state\power-before.txt.imported"))
        $Mode = 'revert'; $Detail = [ordered]@{}; Invoke-Package
        Check 'mm: revert after import restores the operator values' ($script:pw['standby.ac'] -eq 1800 -and $script:pw['hibernate.ac'] -eq 10800)
        function Set-PowerValues($Scheme, $Values) { throw 'denied' }
        $Mode = 'enforce'; $Detail = [ordered]@{}; $threw = $false; try { Invoke-Package } catch { $threw = $true }
        Check 'mm: a failed enforce restores and leaves no state' ($threw -and -not (Test-Path -LiteralPath (Get-StateFile)) -and $null -eq $script:task)
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# Software removal: catalog from the parameters file, matching, keep and protected names,
# official commands only, time-boxing and what is left for the owner.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'software-removal.ps1'))))
    $cat = '[{"id":"app-explorer","name":"App Explorer","kind":"program","match":"App Explorer*","category":"adware","method":"registry","flag":"/S","risk":"safe"},' +
        '{"id":"epic","name":"Epic","kind":"program","match":"Epic Games Launcher","category":"game_addons","method":"msi","risk":"safe"},' +
        '{"id":"fake-ms","name":"Edge","kind":"program","match":"Microsoft Edge*","category":"adware","method":"registry","risk":"safe"},' +
        '{"id":"hang","name":"Hang","kind":"program","match":"Hang Tool","category":"adware","method":"registry","timeout":60,"risk":"safe"},' +
        '{"id":"kept","name":"Kept","kind":"program","match":"Kept Tool","category":"adware","method":"msi","risk":"safe"},' +
        '{"id":"manual","name":"Manual","kind":"program","match":"Manual Game","category":"adware","method":"manual","risk":"safe"},' +
        '{"id":"roblox-store","name":"Roblox","kind":"appx","match":"ROBLOXCORPORATION.ROBLOX","category":"games","method":"appx","risk":"safe"},' +
        '{"id":"shell","name":"Shell","kind":"program","match":"Shell Tool","category":"adware","method":"registry","risk":"safe"},' +
        '{"id":"wave","name":"Wave","kind":"program","match":"WaveBrowser*","category":"adware","method":"registry","flag":"--force-uninstall","risk":"careful"}]'
    $pf = Join-Path ([IO.Path]::GetTempPath()) "ominull-params-$PID.json"
    Set-Content -LiteralPath $pf -Value (@{ mode = 'enforce'; catalog = $cat; categories = 'adware' } | ConvertTo-Json -Compress)
    $env:OMINULL_PARAMS_FILE = $pf; $env:OMINULL_PARAM_CATALOG = $cat.Substring(0, 100)
    $Opt = Get-PkgParams (Join-Path $Dir 'software-removal.ps1')
    Check 'sr: catalog read whole from the parameters file' (@($Opt.catalog).Count -eq 9 -and $Opt.catalog[8].id -eq 'wave')
    Remove-Item Env:OMINULL_PARAMS_FILE, Env:OMINULL_PARAM_CATALOG
    Check 'sr: no parameters file is an empty catalog' (@((Get-PkgParams (Join-Path $Dir 'software-removal.ps1')).catalog).Count -eq 0)
    Remove-Item -LiteralPath $pf
    $Opt.categories = @('adware'); $Opt.keep = @('Kept*'); $Opt.close_running = 'idle'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "ominull-sr-$PID"; New-Item -ItemType Directory -Force -Path "$tmp\x" | Out-Null
    'x' | Set-Content "$tmp\x\uninst.exe"; 'x' | Set-Content "$tmp\x\wave.exe"
    $script:inv = @(
        [pscustomobject]@{ kind = 'program'; name = 'App Explorer'; publisher = 'Host App'; version = '1'; key = 'AppEx'; msi = $false; quiet = ''; uninstall = "`"$tmp\x\uninst.exe`""; location = "$tmp\x" },
        [pscustomobject]@{ kind = 'program'; name = 'Epic Games Launcher'; publisher = 'Epic'; version = '1'; key = '{11111111-2222-3333-4444-555555555555}'; msi = $true; quiet = ''; uninstall = ''; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'Microsoft Edge'; publisher = 'Microsoft Corporation'; version = '1'; key = 'Edge'; msi = $false; quiet = ''; uninstall = 'x'; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'Hang Tool'; publisher = ''; version = '1'; key = 'Hang'; msi = $false; quiet = "`"$tmp\x\uninst.exe`" /hang"; uninstall = ''; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'Kept Tool'; publisher = ''; version = '1'; key = '{K}'; msi = $true; quiet = ''; uninstall = ''; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'Manual Game'; publisher = ''; version = '1'; key = 'M'; msi = $false; quiet = ''; uninstall = 'x'; location = '' },
        [pscustomobject]@{ kind = 'appx'; name = 'ROBLOXCORPORATION.ROBLOX'; publisher = ''; version = '1'; key = 'ROBLOX_1'; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'Shell Tool'; publisher = ''; version = '1'; key = 'S'; msi = $false; quiet = ''; uninstall = 'C:\Windows\System32\cmd.exe /c del x'; location = '' },
        [pscustomobject]@{ kind = 'program'; name = 'WaveBrowser'; publisher = 'Wave'; version = '1'; key = 'W'; msi = $false; quiet = ''; uninstall = "$tmp\x\wave.exe --uninstall"; location = '' })
    $script:calls = @(); $script:gone = @('AppEx', 'W')
    function Get-Installed { $script:inv | Where-Object { $script:phase -ne 'after' -or $script:gone -notcontains $_.key } }
    function Invoke-Uninstaller($Cmd, [int]$Sec) { $script:calls += "$($Cmd.exe)|$($Cmd.args)|$Sec"; if ($Cmd.args -match 'hang') { $null } else { 0 } }
    function Get-Running($i) { if ($i.key -eq 'AppEx') { @([pscustomobject]@{ ProcessId = 42 }) } else { @() } }
    function Invoke-Native { @{ code = 0; out = @(' USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME', '>nadia console 1 Active none 10/17/2026 9:00 AM') } }
    function Stop-Tree([int]$Id) { $script:calls += "kill $Id" }
    function Write-Log {}
    try {
        $script:phase = ''; $Changed = New-Object System.Collections.Generic.List[string]; $Detail = [ordered]@{}; $Mode = 'audit'
        Invoke-Package
        $ids = @($Detail.found | ForEach-Object { $_.id }) -join ','
        Check "sr: audit finds what the categories name ($ids)" ($script:State -eq 'drift' -and $ids -eq 'app-explorer,hang,manual,shell,wave' -and -not $script:calls)
        Check 'sr: Microsoft programs are never removed' (@($Detail.refused) -contains 'Microsoft Edge')
        Check 'sr: keep list honoured' (@($Detail.kept) -contains 'Kept Tool')
        Check 'sr: other categories only counted' ($Detail.other_categories.game_addons -eq 1 -and $Detail.other_categories.games -eq 1)
        $Mode = 'enforce'; $Detail = [ordered]@{}
        function Get-Installed { $script:inv | Where-Object { $script:phase -ne 'after' -or $script:gone -notcontains $_.key } }
        $orig = ${function:Get-Installed}; $script:n = 0
        function Get-Installed { $script:n++; if ($script:n -gt 1) { $script:phase = 'after' }; & $orig }
        Invoke-Package
        $owner = @{}; foreach ($o in @($Detail.needs_owner)) { $owner[$o.id] = $o.reason }
        Check 'sr: a running program is left open while someone uses the computer' ($owner['app-explorer'] -match 'running' -and -not ($script:calls -match 'kill'))
        Check 'sr: manual entries go to the owner' ($owner['manual'] -match 'someone at the screen')
        Check 'sr: every owner item offers the keep list' (@($Detail.needs_owner | Where-Object { $_.keep -cne 'keep' }).Count -eq 0)
        Check 'sr: an uninstall string that runs a shell is refused' ($owner['shell'] -match 'shell' -and -not ($script:calls -match 'cmd.exe'))
        Check 'sr: a hung uninstaller is stopped and reported' ($owner['hang'] -match 'did not finish in 60 s' -and ($script:calls -match '/hang\|60$'))
        Check 'sr: registry uses the machine string plus its flag' ($script:calls -contains "$tmp\x\wave.exe|--uninstall --force-uninstall|600")
        Check 'sr: removed only what is gone after' (@($Detail.removed) -join ',' -eq 'WaveBrowser' -and $script:State -eq 'drift' -and $Changed[0] -eq 'removed WaveBrowser')
        # Nobody at the computer: close it and uninstall.
        function Invoke-Native { @{ code = 1; out = @() } }
        $script:calls = @(); $script:n = 0; $script:phase = ''; $Changed.Clear(); $Detail = [ordered]@{}; Invoke-Package
        Check 'sr: idle computer: running program closed, then removed' (($script:calls -contains 'kill 42') -and ($script:calls -match 'uninst.exe\|/S\|600') -and @($Detail.removed) -contains 'App Explorer')
        # msi uses the product code the machine lists, never a command.
        $Opt.categories = @('game_addons'); $script:calls = @(); $script:n = 0; $script:phase = ''; $Detail = [ordered]@{}; Invoke-Package
        Check 'sr: msi runs msiexec /x with the listed product code' ($script:calls[0] -match 'msiexec.exe\|/x \{11111111-2222-3333-4444-555555555555\} /qn /norestart\|600' -and @($Detail.needs_owner)[0].reason -match 'still installed')
        $Mode = 'revert'; $Detail = [ordered]@{}; Invoke-Package
        Check 'sr: revert is not applicable' ($script:State -eq 'na')
        $Mode = 'audit'; $Opt.catalog = @([pscustomobject]@{ id = 'bad'; kind = 'program'; match = '*'; category = 'adware'; method = 'registry' })
        $threw = $false; try { Invoke-Package } catch { $threw = $true }
        Check 'sr: an invalid catalog entry fails the run' $threw
        $Opt.catalog = @([pscustomobject]@{ id = 'bad'; kind = 'program'; match = 'Wave Tool'; category = 'adware'; method = 'registry'; flag = '/S & calc' })
        $threw = $false; try { Invoke-Package } catch { $threw = $true }
        Check 'sr: a flag outside the list fails the run' $threw
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# Restart: audit flags a pending restart; enforce warns and schedules; revert cancels only its own.
& {
    . ([scriptblock]::Create((Get-Defs (Join-Path $Dir 'reboot.ps1'))))
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ominull-test-rb-$PID"; $script:Root = $tmp; $Pkg = 'windows-reboot'
    $script:pending = $false; $script:calls = @(); $script:code = 0; $script:why = $null
    function Test-PendingReboot { $script:pending }
    function Get-LastBoot { [datetime]::UtcNow.AddDays(-1) }
    function Get-PreflightReason { $script:why }
    function Invoke-Native([string]$Exe, [string[]]$Arguments) { $script:calls += , (@($Exe) + $Arguments); @{ code = $script:code; out = @() } }
    function Run([string]$M) { $script:Mode = $M; $script:Changed = New-Object System.Collections.Generic.List[string]; $script:Detail = [ordered]@{}; $script:State = 'failed'; Invoke-Package }
    try {
        $Opt = @{ only_if_needed = $true; warn_minutes = 10; idle_minutes = 15 }
        Run 'audit'; Check 'rb: audit without a pending restart is ok' ($script:State -eq 'ok' -and -not $script:calls.Count)
        $script:pending = $true; Run 'audit'; Check 'rb: audit with a pending restart is drift' ($script:State -eq 'drift')
        $script:pending = $false; Run 'enforce'; Check 'rb: only_if_needed and nothing pending: no restart' ($script:State -eq 'ok' -and -not $script:calls.Count)
        $script:pending = $true; $script:why = 'someone is using the computer'; Run 'enforce'
        Check 'rb: preflight skips' ($script:State -eq 'skipped' -and -not $script:calls.Count)
        $script:why = $null; Run 'enforce'; $c = $script:calls[-1]
        Check 'rb: enforce schedules a warned restart' ($script:State -eq 'fixed' -and $c[0] -eq 'shutdown.exe' -and ($c -join ' ') -match '^shutdown\.exe /r /t 600 /d p:4:1 /c OmniNull maintenance: this computer restarts in 10 minutes' -and $Detail.restart_in_seconds -eq 600)
        Check 'rb: enforce writes the marker' (Test-Path -LiteralPath (Get-MarkerFile))
        $n = $script:calls.Count; Run 'enforce'; Check 'rb: a second enforce leaves the scheduled restart' ($script:State -eq 'ok' -and $script:calls.Count -eq $n)
        Run 'revert'; Check 'rb: revert cancels its own restart' ($script:State -eq 'fixed' -and ($script:calls[-1] -join ' ') -eq 'shutdown.exe /a' -and -not (Test-Path -LiteralPath (Get-MarkerFile)))
        $n = $script:calls.Count; Run 'revert'; Check 'rb: revert without its own restart touches nothing' ($script:State -eq 'ok' -and $script:calls.Count -eq $n)
        $Opt.only_if_needed = $false; $script:pending = $false; $script:code = 1190; Run 'enforce'
        Check 'rb: a shutdown already scheduled elsewhere is left be' ($script:State -eq 'ok' -and -not (Test-Path -LiteralPath (Get-MarkerFile)))
        $script:code = 5; $threw = $false; try { Run 'enforce' } catch { $threw = $true }; Check 'rb: a shutdown.exe error fails' $threw
        $script:code = 0; @{ at = [datetime]::UtcNow.AddDays(-2).ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Get-MarkerFile)
        Run 'revert'; Check 'rb: a restart that already happened is forgotten' ($script:State -eq 'ok' -and -not (Test-Path -LiteralPath (Get-MarkerFile)))
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
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
