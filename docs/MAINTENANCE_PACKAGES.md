# Maintenance packages

Deterministic, re-runnable maintenance, optimization, cleanup and standards
checks for enrolled endpoints, in the spirit of ImmyBot's software and task
packages but small: a handful of machines, one owner, no new stores.

## Model

- **Catalog = the script library.** The source of truth is
  `packages/windows/*.ps1` and `packages/linux/*.sh` in this repository.
  `ominullctl scripts sync packages/windows` (and `packages/linux`) makes the
  hub's library match it: a package is created on
  first sync, gets a new immutable version only when its source (sha256) or
  parameter schema changed, and its description and metadata are updated in
  place. Re-running the sync is free.
- **Metadata** lives in one JSON column on `scripts` (`metadata_json`, added
  in place on existing libraries): `package`, `title`, `category`
  (`maintenance` or `security`), `risk` (`safe` or `careful`), `reboot` (the
  package may need one), `timeout` (seconds, at most 3600) and `interval`
  (the default schedule: `hourly`, `daily` or `weekly`). The sync reads it from
  line 1 of each script:
  `# ominull-package: {"name","title","description","category","risk","reboot","timeout","interval","params"}`,
  optionally followed by `"platform"` (`windows`, the default, run by
  `powershell.exe`; or `linux`, run by `/bin/sh` as root, file extension
  `.sh`) and `"role"` (`maintenance_mode` or `reboot`, below). A package runs only on
  hosts of its platform.
  Security compliance packages are the same system with `category:
  "security"`; none ship yet.
- **Execution = an ordinary `script_exec` job**, authorized like any other
  script run: from the console, from `ominullctl maint run` or from the
  schedule, the hub asks the response authority, which signs the grants on the
  first request and nobody is asked (see "Authorizing a package run").
- **State = the latest job.** Nothing is stored per (host, package); the hub
  derives the current state from the newest job of each package on read.

## Package contract

- **Modes.** `mode` = `audit` (default), `enforce` or `revert`, delivered as
  `$env:OMINULL_PARAM_MODE`. Audit only tests and reports. Enforce tests, and
  only if something drifted, changes what is needed and tests again. Revert
  puts back the first-seen values recorded in
  `C:\ProgramData\OminullMaintenance\state\<name>-original.json` (the record
  is written once and never overwritten, so a later enforce keeps the very
  first values). Packages with nothing to restore (audit, cleanup, updates)
  answer revert with `na`; debloat restores services and lists removed apps
  under `not_restorable`. If saving the first-seen values fails, enforce fails
  rather than make a change it could not undo.
- **Parameters.** Every tunable is declared in the header's `params`:
  `{"name","type","default","description"}` plus, by type, `min`/`max`
  (`int`, required), `values` (`enum`), `max_items` (`list`, required) and
  `careful` (`bool` only, default must be `false`). Types are `int`, `bool`,
  `enum`, `list` and `catalog` (see Software removal; its default is `[]`
  and the hub fills it on every run, so it has no setting). A run sets each one as `OMINULL_PARAM_<NAME>`; on the
  wire an int is decimal, a bool `true`/`false`, a list is its items joined
  by `,` (`-` for an empty list), each item matching
  `^[A-Za-z0-9*][A-Za-z0-9 ._*+()\-]{0,127}$`, no duplicates. Scripts read
  the header themselves, fall back to the default when a value is unset and
  fail the run on a bad value. Names that collide with payload fields, `mode`
  or agent environment variables are refused. The hub derives each script's
  parameter schema from the header, so the console, `ominullctl` and the
  authority all check the same rules.
- **Safety stays literal.** The deny lists (protected apps and services,
  cleanup's allowed paths, forbidden operations, game folders) are code, not
  parameters, and no parameter can loosen them. A list item that matches a
  protected rule is refused and reported under `detail.found.refused`.
- **Careful steps.** A step that carries more risk than its package is gated
  by a `bool` parameter marked `careful` (default off), e.g. performance's
  `gpu_scheduling`. Turning one on makes that run careful.
- **Result line.** The last stdout line is
  `{"v":1,"state":"ok|fixed|drift|failed|skipped|na","reboot":bool,"changed":[...],"detail":{...}}`.
  Exit code 0 unless failed. A missing or unparseable line counts as failed.
  `na` (not applicable: the package or mode does not apply here) is a result,
  not a failure. Stdout stays one line (the agent keeps the head of long
  output and merges stderr); the verbose log goes to
  `C:\ProgramData\OminullMaintenance\logs\<name>-<time>.log` (`log_keep`
  newest kept).
- **Controls.** A standards check reports `detail.controls`:
  `[{"id","cis","expected","actual","state","risk"}]` with state `pass`,
  `fail`, `fixed` or `na`. `cis` is a reference id only (`CIS WIN11 1.1.4`),
  never benchmark text. Compliance is pass / (pass + fail); `na` and `fixed`
  rows do not count against it. Audit, privacy and performance report
  controls today.
- Enforce runs return `skipped` (with `detail.reason`) when someone is using
  the machine (an active, unlocked Windows session with a user whose last
  input is within `idle_minutes`, read through the WTS API so it works on
  Windows Home, which has no `quser`; a session whose idle time Windows
  does not report counts as in use, and a failed session query counts as
  "cannot tell", never as nobody there), a game is
  running (process paths under the usual game library folders; launchers and
  always-on helpers such as Epic Online Services are not games), the machine
  is on battery, or, for updates and cleanup, Windows Update is installing
  (the update installer says it is busy) or Windows servicing is working
  (TiWorker using CPU over a 10 s sample; an idle TiWorker, which lingers
  after any update scan, does not count). The updates package checks this
  before it searches, since its own search starts TiWorker.
- Windows reports no last-input time for the local console session to a
  SYSTEM service (WTS returns 0 there, also through WTSSessionInfoEx and
  WinStationQueryInformation), so a signed-in console read as in use even
  when nobody had touched it for hours. Agents from 1.8.88 measure it inside
  the session: before each script job the agent starts its own exe there as
  the signed-in user (`ominulld.exe --console-idle`, no window), which exits
  with `GetLastInputInfo`'s idle seconds, and the script gets
  `OMINULL_CONSOLE_SESSION` and `OMINULL_CONSOLE_IDLE_SECONDS` when that
  worked. The prelude uses them for that session only when WTS reports
  nothing; without them (older agents, nobody signed in, the probe failed) an
  unreported console still counts as in use.
- Packages start native tools as plain processes, never with
  `Start-Process -Redirect*/-NoNewWindow`: in Windows PowerShell that copies
  the environment into a case-insensitive map, which throws on names that
  differ only by case (agents before 1.8.87 sent `OMINULL_PARAM_mode` and
  `OMINULL_PARAM_MODE`).
  Audit runs are never skipped.
- **Run options** (`when_busy`, `window`) are set by the hub, never declared
  in a header, and gate the people checks (someone using the machine, a game)
  of enforce and revert runs; battery and Windows Update always count. The
  authority's audit statement names them.
  - `when_busy`: `skip` (the default: report `skipped`), `wait` (check again
    every minute for up to half the package's time limit, then skip) or `run`
    (do not wait for open apps or games). Playbook steps that change
    something use `wait`, or `run` when the run is started with "Don't wait
    for open apps".
  - `window`: the machine's maintenance window, 1-4 `HH:MM-HH:MM` ranges
    joined by commas, in the machine's own time, or in UTC with a trailing
    `Z` (a range may cross midnight). Inside it people do not count. The hub
    adds it to every enforce and revert run (console, schedule, playbook),
    maintenance mode excepted. Changing a window changes those runs'
    payloads (and so their digests).
- **Maintenance windows** (`GET/PUT /api/v1/maintenance/windows[?endpoint_id=]`):
  a fleet default plus per-machine windows, stored as data (settings row
  `maintenance.windows`). Body `{"ranges":["01:00-05:00"],"clock":"machine"|"utc"}`
  for the fleet or, with `endpoint_id`, one machine; `{"reset":true}` drops a
  machine's own window (it follows the fleet) or the fleet default. Unset, the
  default is 01:00-05:00 machine time (or the older single fleet window, which
  `PUT /api/v1/maintenance/settings {"window":..}` still sets). Audited as
  `MAINTENANCE_WINDOWS_SET`. One run covers only machines whose
  windows match ("run them separately" otherwise). Agents from 1.8.82 report
  their clock's UTC offset (trust report `utc_offset_minutes`); with it the
  hub shows whether the window is open and its next start, and the schedule
  starts enforce runs only inside the window. Without it (machine time, older
  agent) the package's own window check decides.
  CLI: `ominullctl maint window show [EP]`, `maint window set EP|--default
  01:00-05:00[,..] [--clock machine|utc]`, `maint window reset EP|--default`.
- Packages never restart the machine themselves; they report `reboot`.
  Only the Restart package (below) restarts, with a warning on screen.
- Each script stays under 32 KiB (the library and agents take 64 KiB) and runs on Windows PowerShell 5.1.

## Windows safety rules

- Packages run as LocalSystem with the agent's stripped environment and
  `TEMP=C:\ProgramData\Ominull`. They never touch `$env:TEMP`,
  `ProgramData\Ominull`, user folders or Downloads. Cleanup deletes from an
  explicit path list with age filters and never follows links. Its one
  Recycle Bin exception: `$I`/`$R` item pairs under `<fixed drive>:\$Recycle.Bin\<SID>\`,
  aged by the deletion time stored in `$I` (not the file time).
- Per-user settings go through HKLM policy and the Default-user hive only, so
  they reach new profiles; machine-wide policies cover everyone.
- Never: disable Defender, the firewall, Windows Update, SmartScreen or
  VBS/Memory Integrity; hosts-file blocking; bcdedit; disk or partition work;
  removing Store, Xbox, Gaming Services, GPU or OEM tools; DISM `/ResetBase`.
- Debloat removes a named list of bundled Appx packages and refuses anything
  matching its never-list even if the list names it.

## Packages

The seven Windows packages below are `maintenance`. Every package but audit also takes `idle_minutes`
(15) and all take `log_keep` (20).

| Package | Risk | Timeout | Every | What enforce does | Parameters |
|---|---|---|---|---|---|
| `windows-updates` | safe | 3600 s | daily | Installs pending software and driver updates through the Windows Update API; reports reboot. | `exclude` (firmware, preview, feature_update, optional; `driver` allowed) |
| `windows-cleanup` | safe | 3600 s | weekly | Clears Windows\Temp, update downloads (Windows Update idle), Delivery Optimization cache, crash dumps, old error reports, Recycle Bin items (every user, every fixed drive); DISM `/StartComponentCleanup`. Each DISM call is time-boxed and its process tree ended at the limit; a DISM left over from an earlier run is ended first; a timed-out step reports `component_cleanup: skipped: timed out` and the run carries on. | age per kind (`temp_days` 7, `minidump_days` 14, `memory_dump_days` 7, `error_report_days` 30, `update_download_days` 0, `recycle_bin_days` 30, 0 empties it fully), `min_reclaim_mb`, `component_store`, `dism_analyze_minutes` 15, `dism_cleanup_minutes` 45, `service_stop_seconds` |
| `windows-privacy` | safe | 300 s | daily | Turns off the groups in `turn_off`: telemetry at the edition's minimum (DiagTrack and dmwappushservice disabled), advertising ID, tailored experiences, activity history, consumer suggestions, web results in Start, Copilot, Recall. Location is left alone. | `turn_off` (all 9 groups by default) |
| `windows-debloat` | careful | 900 s | weekly | Removes the listed bundled apps for all users and from the image; drops sponsored apps from the image; disables the listed services. Xbox, Store, GPU and OEM tools stay. | `remove_apps`, `deprovision_apps`, `services` |
| `windows-performance` | safe | 300 s | weekly | Game Mode on, background game recording off by policy; hardware-accelerated GPU scheduling only when its careful step is on (reboot). | `game_mode`, `block_game_recording`, `gpu_scheduling` (careful, off) |
| `windows-audit` | safe | 300 s | daily | Read-only controls: BitLocker, Defender, firewall, update age, free disk, TPM, Secure Boot, pending reboot; `ok` or `drift`. | `signature_max_days`, `update_max_days`, `disk_min_free_pct`, `disk_min_free_gb` |
| `windows-software-removal` | careful | 3600 s | weekly | Uninstalls programs and Store apps in the hub's software catalog with their official uninstallers; see below. | `categories`, `keep`, `close_running`, `uninstall_timeout`, `catalog` |

### Maintenance mode

`windows-maintenance-mode` and `linux-maintenance-mode` (role
`maintenance_mode`, safe, parameter `hours` 1-24, default 6) keep a machine
awake while maintenance runs. The role means the hub never schedules them and
the asset card shows them as one line ("Maintenance mode: On, kept awake
until ... / Turn off", or "Off / Turn on for 6 hours") instead of a package
row. The state is the latest run: its result carries
`detail.maintenance_mode {on, until}`, and an end time already past reads as
off. How long it lasts is the package's `hours` setting (fleet default and
per-machine override, as for any package; "How long..." on the card).

- **Windows**: enforce saves the active plan's sleep-after and
  hibernate-after values (AC and DC) once in
  `ProgramData\OminullMaintenance\state\windows-maintenance-mode.json`, sets
  them to 0 and registers a one-off SYSTEM task (`\Ominull\OminullMaintenanceModeEnd`,
  start when available) that puts them back at the end time, or at the next
  start if the machine was off then. Enforce again moves the end time and
  keeps the first saved values. Revert puts them back now; audit reports and
  reads `drift` if an end time passed without the values coming back. If the
  operator saved a `powercfg /query` dump at `state\power-before.txt` earlier,
  its values are the ones saved (once; the file is renamed `.imported`).
- **Linux**: enforce starts a transient systemd unit
  (`ominull-maintenance-mode`, `RuntimeMaxSec` = hours) holding a
  `systemd-inhibit --what=sleep:idle` lock, so systemd itself lets go at the
  end time. Enforce again replaces it with the new end; revert stops it.
  Hosts without systemd answer `na`.

Turning it on or off from the card is an ordinary run (enforce / revert),
authorized on the first request like any other.

### Restart

`windows-reboot` and `linux-reboot` (role `reboot`, careful, time limit 60
minutes) restart a machine after a warning. The role means the hub never
schedules them; they run as a playbook step or as a direct run from a
machine's page, and both are authorized on the first request. Parameters: `only_if_needed`
(true: restart only when the system says a restart is pending),
`warn_minutes` (10, 1-60) and `idle_minutes` (15).

- **Audit** reads a pending restart as `drift` (Windows: the Component Based
  Servicing and Windows Update reboot keys; Linux: `/var/run/reboot-required`
  or `needs-restarting -r`).
- **Enforce** runs the preflight with the run options, then
  `shutdown.exe /r /t N /d p:4:1 /c "OmniNull maintenance: this computer
  restarts in N minutes ... Save your work now."` on Windows or
  `shutdown -r +N` with the same message on Linux (sent to logged-in users).
  It returns `fixed` with `detail.restart_in_seconds` and leaves a marker with
  the restart time. A restart already scheduled (its own, or someone else's)
  is left alone and reads `ok`. On Linux, someone using the machine means an
  active local `loginctl` session not idle for `idle_minutes`.
- **Revert** cancels a restart this package scheduled that has not happened
  yet (`shutdown /a`, `shutdown -c`); it never cancels anyone else's.

### Upkeep packages (Linux)

`linux-cleanup` (safe, no role) is routine upkeep for a Linux machine. It is a
plain `/bin/sh` script that reads `OMINULL_PARAM_*`, so the same bytes run
from the hub, from `ominullctl host-script run` and, with the hub down, by hand
as root (`env -i OMINULL_PARAM_MODE=enforce sh cleanup.sh`).
`scripts/package-manifest.py` prints the Linux packages (file, sha256,
interval, timeout, parameter defaults as environment values); a tool that runs
them without the hub is generated from that output and never kept by hand.
`packages/linux/` is the only source.

**Btrfs scrubs and NVMe self-tests are not OmniNull packages.** On the owner's
workstation, Nightshift owns them through its own systemd timers
(`nightshift-btrfs-scrub-*.timer`, `nightshift-nvme-*-test.timer`), because
they must keep running when the hub is down. OmniNull neither schedules nor
audits them there; do not add a package for them.

- **`linux-cleanup`** (daily, 900 s). Trims the system journal to
  `journal_max_mb` (2048), empties the apt package cache above
  `apt_cache_max_mb` (100) and removes disabled Snap revisions
  (`snap_revisions`), at idle priority. Audit reports the sizes and drifts when
  one is over its limit (the journal gets a 10% allowance for the files being
  written). Deleted journal entries and caches do not come back, so revert is
  `na`. It touches no user folder; per-user caches (uv, app caches) belong to
  the tools that own them.

Space-guard stays in Nightshift: it has to work on a full disk and without the
hub.

### Software removal

`windows-software-removal` uninstalls third-party software the hub's
**software catalog** names. It is careful, so the authority's audit statement
for every run (audit too) flags it as careful and names the catalog's size.

- **Catalog.** One settings row (`maintenance.software_catalog`); a hub that
  never saved one uses the list shipped in
  `hub/pkg/scripts/software_catalog_seed.json` (games, game add-ons and
  launchers, manufacturer extras, trials, adware). An entry is `id`, `name`,
  `kind` (`program` from Apps and features, or `appx`), `match` (a wildcard
  on the display or package name, at least 4 real characters), optional
  `publisher` (programs), `category`, `method`, optional `flag` and
  `timeout` (30-1800 s), `risk` and `note`. Methods: `msi` (msiexec /x with
  the listed product code, silent), `registry` (the program's own quiet or
  uninstall string plus at most one `flag` from a fixed list such as `/S` or
  `--force-uninstall`), `appx` (Remove-AppxPackage for all users) and
  `manual` (never run; reported for someone at the screen).
- **API.** `GET /api/v1/maintenance/catalog` (any role) returns the entries,
  whether they were saved here, and the category, method and flag labels.
  `PUT {"entry":{...}}` (admin) adds or replaces one entry: adding one or
  changing what it matches or how it is removed is a loosening, which the
  authority authorizes on the same request (it writes the audit statement from
  the entry); a name or note change is not. `DELETE ?id=` removes one. All
  are audited as `SOFTWARE_CATALOG_CHANGED`.
- **Runs carry the catalog.** The hub puts the catalog in force into the
  run's `catalog` parameter at dispatch (compact JSON, notes dropped, at
  most 12 KiB), so the run's grants cover the exact entries. Agents cut
  one environment variable at 2047 bytes, so the package reads catalog
  parameters from the signed parameters file (`OMINULL_PARAMS_FILE`), not
  the environment. The hub refuses a run whose parameters would pass the
  agents' 16 KiB limit.
- **What a run does.** Lists programs (HKLM 64/32-bit and every loaded
  user hive) and Store apps, matches them against the catalog entries in
  `categories`, minus `keep` (ids or name wildcards). It refuses anything
  Microsoft-published or on its keep list (Windows, runtimes, drivers,
  Defender, GPU and audio tools, OmniNull) whatever the catalog says.
  Enforce runs each uninstaller silently and time-boxed (the entry's
  `timeout` or `uninstall_timeout`), stopping the process tree when it runs
  over. A program that is running is closed first only as `close_running`
  allows (`idle` by default: nobody active for `idle_minutes`); otherwise it
  is deferred to the next run.
- **Result.** `detail` lists `found`, `kept`, `refused`, `other_categories`
  (catalog matches outside `categories`), `removed`, `deferred` and
  `needs_owner` (manual entries, missing or unsafe uninstall commands,
  failures). Audit: `drift` if anything would be removed, else `ok`.
  Enforce: `drift` if anything was deferred or needs the owner, `fixed` if
  something was removed, else `ok`. Revert: `na` (an uninstall cannot be
  undone).

## Playbooks

A playbook is a named list of up to 8 package steps (package and mode) run
in order, optionally inside maintenance mode. Playbooks are data: one
settings row (`maintenance.playbooks`), edited from the Maintenance page or
`GET/PUT/DELETE /api/v1/maintenance/playbooks` (PUT `{"playbook":{"id",
"name","steps":[{"package","mode"}],"maintenance_mode","note"}}`, admin).
Saving checks every step against the library (a live package, not
maintenance mode itself, all on one platform) and runs nothing.
A Restart step is allowed anywhere in the list.

- **Running one.** `POST /api/v1/maintenance/playbooks/run
  {"playbook_id","endpoint_ids","dont_wait"}` (admin) is authorized once for
  every step on every machine. Steps that change something (not audits) wait
  while someone is using the machine or a game is open (`when_busy=wait`);
  `dont_wait` sends `run` instead. With maintenance mode on, the run is maintenance mode on
  (its `hours` set to the run's window), the steps, then maintenance mode
  off. Each step uses the machines' effective settings for that package, so
  machines that differ need separate runs (as for any package run).
- **Window.** Each step's time limit plus 10 minutes (and 10 minutes for
  each maintenance mode run, 75 more for each Restart step), rounded up to
  whole hours; a playbook that
  would need more than 24 hours is refused. The payload the authority signs
  (`PackageRunPayload.playbook {name, window_seconds}`, route
  `/api/v1/maintenance/playbooks/run`) carries the window, the audit statement reads
  "one step after another, all within N hours" with the steps numbered (or,
  when that does not fit the 300 characters an audit statement shows, a compact form:
  short names, the mode only when it is not enforce, options said once; a
  playbook that still does not fit is cut with an ellipsis, and the grants stay bound to the
  full payload), and
  the authority signs every grant of that run for exactly the window.
- **One step at a time.** The agent starts every job it is offered at once,
  so the hub keeps the grants and starts a machine's next step only when the
  one before it has ended (finished, failed, or quiet past its time limit
  plus 10 minutes); it checks every 30 seconds. A failed step does not stop
  the ones after it, so maintenance mode still ends. A step not started
  when the window ends is not started (`not_started`); a step still queued
  on an offline machine past the window reads `not_run`. Runs live in the
  settings row `maintenance.playbook_runs` (script payloads and unused grants
  are dropped when a run ends; the 20 newest finished runs are kept).
  Scheduled package runs leave a machine alone while a playbook runs on it.
- **After a restart.** When a Restart step returns `fixed`, the machine's
  next step waits until the restart time plus 2 minutes has passed and the
  machine has checked in since, so no step is handed to a machine going
  down.
- **Console.** The Maintenance tab's **Playbooks** card lists playbooks
  with their steps (*Run…*, *Edit…*, *Remove*) and recent runs with each
  machine's progress ("Step 2 of 5: Cleanup (enforce), running", or the
  results once done). *Run…* picks Windows or Linux machines to match the
  steps and offers "Don't wait for open apps".

## Settings

One small table, `maintenance_settings`, keyed (tenant, package, endpoint):

- The fleet row (endpoint empty) holds a package's default: enabled, mode
  (`audit` or `enforce`), interval and parameter values. An endpoint row
  overrides any of those for one machine. A NULL field inherits; built-in
  defaults are package off, mode audit, the header's interval and the
  header's parameter defaults. Revert is a one-off run mode, never a schedule.
- Package `@maintenance` / `@security` holds the category switch, at fleet and
  endpoint level (categories are on by default). A package runs on a host
  only when both it and its category are on there.
- An endpoint override needs a `reason` and may carry `expires_at` (a date or
  RFC 3339 time in the future). Once it expires the machine falls back to the
  fleet default; editing an expired override starts it fresh.
- API: `GET /api/v1/maintenance/settings[?endpoint_id=]` returns packages
  (fleet, endpoint and effective values, parameter definitions) and
  categories. `PUT` (admin) takes `{"package"|"category","endpoint_id",
  "enabled","mode","interval","on_drift","params":{name: value|null},"reason",
  "expires_at","reset"}`; `null` clears a field, `reset` clears the row.
  `PUT {"window":"22:00-06:00"}` alone sets the fleet maintenance window
  (settings row `maintenance.window`; `""` clears it); GET returns it as
  `window`. The Package settings card has the same field.
  Every change is audited (`MAINTENANCE_SETTINGS_CHANGED`) and starts a
  schedule pass.
- Saving a setting runs nothing. Every run, whatever its mode or parameters,
  is authorized on the first request when it is asked for (see below); there is
  no per-setting ask.

## Console

- **Maintenance page** (rail): Maintenance and Security tabs. Each tab has
  the category switch for the fleet and a table of its packages with the
  fleet schedule, how many settings differ from the defaults and the synced
  version. *Settings…* opens the package's fleet defaults: scheduled, mode,
  how often and each typed parameter, with where each value comes from, the
  default it would go back to, and a reset per row. Changes save as they are
  made. Under the Maintenance tab, the **Software removal catalog** card lists
  every entry (what it matches, category, how it is removed) with *Add…*,
  *Edit…* and *Remove*; adding or changing what an entry removes is authorized
  on the same request and audited.
- **Asset view, Maintenance and security card** (Windows hosts), same tabs:
  compliance for the category, the machine's category switch (an override
  asks for a reason and an optional end date), and per package the latest
  result, mode, reason, number of changes, when, reboot needed, and the
  schedule in force here with any override and its expiry. *Controls* shows
  the controls of the latest run; *Run…* runs audit, enforce or revert on
  that host; *Settings…* edits this machine's override with its reason and
  end date. An open run past its timeout plus 10 minutes shows "No result
  came back".
- **Response jobs page** names package runs ("Cleanup package") and shows
  mode, result, reason, reboot needed, what changed, compliance and a
  "Controls checked" table.
- `GET /api/v1/maintenance?endpoint_id=` returns the same data.

## Long runs

Script runs may last up to 3600 s in the hub and both agents. The grant is
checked only when the job is offered; an acknowledged job is never offered
again or reaped, and its result is accepted whenever it arrives. The Linux
agent runs each script job in a detached worker so heartbeats continue; the
Windows agent runs it on a worker thread. Agents older than the 3600 s cap
treat a larger timeout as the 60 s default.

## Authorizing a package run

`POST /api/v1/maintenance/run` (`{"endpoint_ids","packages","mode"}`, admin
key) is authorized on the first request: the hub calls the response authority
(`POST /v1/authorize`), which validates the payload, signs the grants and the
hub dispatches one job per host and package at once. Nobody is asked and there
is no 202, no `X-Approval-ID` from the caller (the hub sets it from the
authorization id) and no rule to make. The run uses each host's effective
parameters; hosts in one call must share them.

- **What is signed**: the response authority sees the exact script payload
  of every run (source, digest, interpreter, parameters, timeout, output
  bound) and the named hosts, and writes the audit text ("Run as
  SYSTEM on laptop-1: windows-cleanup (enforce), up to 60 min, settings
  temp_days=30"; at most 300 characters, cut with an ellipsis; the grants are
  bound to the full payload, not the text). Changed parameters are listed
  against the defaults. Each grant binds one host and one script payload, which
  must be exactly the bytes `json.Marshal` makes of it. A request is
  limited to 50 hosts.
- **Which scripts count as packages**: the authority ships with the digest,
  name and risk of every file in `packages/windows` and `packages/linux`
  (`hub/pkg/responseauth/released_packages.json`, kept in step by a test).
  Only those sources, run by their platform's interpreter (`powershell.exe`
  or `/bin/sh`) with `mode` plus exactly the
  parameters their (trusted) header declares, each valid, are packages; the
  hub's own copy of the header is never trusted. Anything else is audited as
  "not a released package". A changed package needs a hub release before the
  authority names it as a package.
- **Refusals**: an invalid payload, parameters outside the header's bounds,
  ambiguous or reordered fields, more than 50 hosts, or a playbook that would
  need more than 24 hours is refused with the reason (HTTP error and audit
  `ACTION_REFUSED`). The endpoint can still refuse a run its lock level or
  capability manifest forbids.
- **One-off scripts** (`POST /api/v1/maintenance/script`) are authorized the
  same way and audited as not a released package, with the script's name, shell,
  size and digest prefix.
- The old model is gone: approval rows, the "baseline" exception, "Approve all
  like this" rules, `ominullctl maint rules|forget-rule` and the Nightshift
  approval relay. Audit rows named `OWNER_APPROVAL_*` appear only in history;
  authorized runs are `ACTION_AUTHORIZED`, then `SCRIPT_RUN_DISPATCHED`.

## Schedule

Every 5 minutes (and right after a settings change) the hub walks each
package × online host of its platform with the effective settings
(maintenance mode and Restart excepted: they never run on a schedule). A package is due
on a host when it and its category are on there, the host is online (seen in
the last 30 s), no run of it is open there, its last success (`ok`, `fixed`,
`drift`) is older than the interval and its last attempt is at least an hour
old. A laptop that was off simply catches up the next time it is online.
Hosts whose run would be the identical payload are grouped into one request.

The schedule asks the authority like `maint run` and dispatches at once
(at most 50 hosts per run; the rest wait for the next pass). A run the
authority will not sign, or an authority that is not available, shows up as a
schedule block (console and Nightshift feed) with its reason and is tried again
on the next pass.

**Audit-then-enforce.** A safe package (not careful, not maintenance mode or Restart) may set `on_drift` to
`"enforce"` at fleet or machine level (`null` clears it; it applies only while mode is audit). It keeps auditing on
its interval. When a host's newest run of it is a scheduled audit that finished with `drift`, the next pass requests one
enforce run on that host, inside its maintenance window, the same way as any enforce run: the authority signs it and
it is dispatched at once ("PACKAGE (enforce: the scheduled audit found drift)"). Nothing more is requested until the
next scheduled audit; a hand-run audit's drift never triggers it. Careful packages (and any with a role) are
refused when you set `on_drift` (`400`): auto-enforce is only for safe packages, so run a careful package's enforce by hand.

## Nightshift feed

The existing findings feed (`/api/v1/integrations/nightshift/findings`) carries these records:

- `ominull.maintenance`: critical (pushes) when the latest run of any package
  on any host failed or returned no result line, with counts in the message
  and the failures in `unmapped`; otherwise informational and resolved, with
  the latest runs, hosts that need changes, hosts that need a reboot and
  compliance per category.
- `ominull.maintenance.schedule`: medium (board only) while a scheduled run is
  blocked (the authority refused it or was not available), resolved otherwise.
  The message text still says "approval or a declined ask"; read it as a block.
- `ominull.decisions.<run>`: one per run with items waiting for the owner
  (below), medium (board only), listing each item; resolved for a week once
  every item of the run is answered.
- `ominull.run.<endpoint>.<package>`: one per run that needs someone: `needs_hands` (waiting on a window) and
  `stalled` at low severity, `failed` (finished in the last day) at medium. `unmapped` carries `endpoint_id`,
  `endpoint`, `package`, `state`, `reason`, `window` (title, process, pid, session), `mode`, `job_id`, `since` and
  `next_move` (needs_hands: take a steward remote-screen session for the run and click the dialog). At most 20, the
  neediest first. When the run clears, the record reads resolved for a day, then drops (the raised set is the
  settings row `maintenance.run_records`).

**Escalation.** `POST /api/v1/maintenance/escalate {"job_id","reason"}` (admin) hands a run to the owner: it becomes
one decision (group `job:<id>`, answer `handled`) on the decisions card and the Nightshift feed, audited
`MAINTENANCE_ESCALATED`. `404` unknown job, `400` no reason or not a script run. Escalating the same job again
replaces the reason; the newest 50 are kept (settings row `maintenance.escalations`).

## Owner decisions

A package result may list what it could not settle by itself in
`detail.needs_owner`: `[{"id","name","reason","keep"}]` (software removal
does: manual entries, unsafe or missing uninstallers, programs left open,
uninstallers that hung or left the program behind). `keep`, when present,
names a list setting of the package that a "keep" answer adds `id` to. The
hub reads these from each machine's latest runs (text cut short, control
characters dropped, at most 40 per run, a `keep` that is not a setting name
ignored) and groups the open ones by run: a playbook run, or one package's
latest runs (`ominull.decisions.playbook.<id>`,
`ominull.decisions.package.<name>`).

- **Answers.** `GET /api/v1/maintenance/decisions` returns `open` (key,
  machine, package, item, the answers it allows) and the 20 latest
  `answered`. `POST {"key","answer","reason"}` (admin): `keep` adds the item
  to that machine's override of the named list setting (software removal:
  `keep`), with "keeps NAME: reason" added to the override's reason, so later
  runs skip it there (a reason is required); `handled` just closes it.
  Answers are audited (`MAINTENANCE_DECISION`) and kept in the settings row
  `maintenance.decisions` (the newest 500).
- **Nightshift inbox (removed).** Nightshift no longer relays decisions:
  `/api/v1/integrations/nightshift/decisions` and `/decisions/answer` are gone.
  The feed records still carry `"answer_in":"Nightshift inbox or OmniNull console"`;
  read it as the console (or `POST /api/v1/maintenance/decisions` with the admin key).
- **Coming back.** An answered item opens again only if a run that finished
  after the answer reports it again.
- **Console.** A *Decisions for you* card at the top of the Maintenance page,
  shown only while something is open, lists the items by run with *Keep…*
  (asks why) and *Handled*.

## Running a package

1. Sync: `ominullctl scripts sync packages/windows` and
   `ominullctl scripts sync packages/linux` (admin key).
2. `ominullctl maint run HOST PKG... --mode audit|enforce|revert` runs with
   the host's effective settings, waits for each
   job and prints one line per package: `HOST PKG {result line}`.
   `--no-wait` returns after the jobs are created. `ominullctl maint status
   HOST` prints where each package stands, with controls passed.
3. Settings: `ominullctl maint settings [HOST]` prints the effective values;
   `ominullctl maint set PKG|@CATEGORY [--endpoint HOST] [--on|--off] [--mode
   M] [--every R] [NAME=VALUE|NAME=default ...] [--inherit enabled,mode,every]
   [--reason TEXT] [--until YYYY-MM-DD|never] [--reset]` changes them (a host
   override needs `--reason`).
4. Or from the console: Maintenance page for fleet defaults, the host's asset
   view → Maintenance and security for one machine.
5. Pick `audit` first; run `enforce` when the changes are wanted.

## Tests

- `ominullctl` tests check every package header and size.
- `packages/windows/tests/run.sh` (pwsh from `PATH` or `$OMINULL_PWSH`) parses
  each script, rejects PowerShell 7-only syntax and forbidden operations, and
  unit-tests parameters, the result line, controls, `na`, careful gating,
  revert recording and restoring, the preflight rules and run options
  (window across midnight, wait, run), Restart, and maintenance mode
  (powercfg parsing, enforce/extend/revert/audit, expiry, the saved dump);
  the Windows CI job runs it.
- `ominullctl` tests also run each `packages/linux/*.sh` under `sh -n`, a
  read-only audit (one result line, exit code matching the state) and a bad
  parameter (fails before changing anything).
- `packages/linux/tests/run.sh` runs a copy of each Linux package under
  `/bin/sh` with its fixed paths moved to a temp folder and stand-in
  `loginctl`, `shutdown` and `sleep` first in `PATH`: Restart's audit, warned
  enforce, `only_if_needed`, skip / wait / run, the window, battery, revert of
  its own restart only, bad parameters. The Linux CI job runs it.
- `hub/pkg/server/maintenance_decisions_test.go`: needs_owner items cleaned,
  one feed record per run and its resolved form, keep writing the machine's
  override with the reason, handled, and an item reopening on a later run.
- `hub/pkg/server/playbooks_test.go`: saving, one step at a time, the window
  and its end, "Don't wait", the hold after a restart, the maintenance window
  setting and the schedule never restarting a machine.
- `hub/pkg/server/maintenance_mode_test.go`: each platform gets its own
  package, the card state from the latest run, expiry, a Linux audit and the schedule never running maintenance mode.
- `hub/pkg/scripts/package_params_test.go`: header parsing, parameter checks,
  change summaries and settings resolution including expiry.
- `hub/pkg/responseauth/package_run_test.go`: per-script grants, careful
  steps named, playbook windows, forged, tampered, reordered or ambiguous
  payloads, runs too long to show whole being cut.
- `hub/pkg/server/maintenance_run_test.go`: the run route authorized on the
  first request, settings validation and overrides, the schedule's dispatch,
  the feed records.

## Later (not built)

Tagging detector events raised while a package runs ("during maintenance"):
the agent has to mark the job's process tree, which needs an agent release.
