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
  `.sh`) and `"role"` (`maintenance_mode`, below). A package runs only on
  hosts of its platform.
  Security compliance packages are the same system with `category:
  "security"`; none ship yet.
- **Execution = an ordinary `script_exec` job**, signed and approved like any
  other script run: from the console (browser session plus passkey), or from
  `ominullctl maint run` and the schedule through the owner's Nightshift tap
  (see "Owner approval and the package rule").
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
  `enum` and `list`. A run sets each one as `OMINULL_PARAM_<NAME>`; on the
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
  the machine (a `quser` session active within `idle_minutes`), a game is
  running (process paths under the usual game library folders; launchers and
  always-on helpers such as Epic Online Services are not games), the machine
  is on battery, or, for updates and cleanup, Windows Update is installing.
  Audit runs are never skipped.
- Packages never reboot; they report `reboot` and Windows active hours handle it.
- Each script stays under 16 KiB and runs on Windows PowerShell 5.1.

## Windows safety rules

- Packages run as LocalSystem with the agent's stripped environment and
  `TEMP=C:\ProgramData\Ominull`. They never touch `$env:TEMP`,
  `ProgramData\Ominull`, user folders, Downloads or the Recycle Bin. Cleanup
  deletes from an explicit path list with age filters and never follows links.
- Per-user settings go through HKLM policy and the Default-user hive only, so
  they reach new profiles; machine-wide policies cover everyone.
- Never: disable Defender, the firewall, Windows Update, SmartScreen or
  VBS/Memory Integrity; hosts-file blocking; bcdedit; disk or partition work;
  removing Store, Xbox, Gaming Services, GPU or OEM tools; DISM `/ResetBase`.
- Debloat removes a named list of bundled Appx packages and refuses anything
  matching its never-list even if the list names it.

## Packages

All six are `maintenance`. Every package but audit also takes `idle_minutes`
(15) and all take `log_keep` (20).

| Package | Risk | Timeout | Every | What enforce does | Parameters |
|---|---|---|---|---|---|
| `windows-updates` | safe | 3600 s | daily | Installs pending software and driver updates through the Windows Update API; reports reboot. | `exclude` (firmware, preview, feature_update, optional; `driver` allowed) |
| `windows-cleanup` | safe | 3600 s | weekly | Clears Windows\Temp, update downloads (Windows Update idle), Delivery Optimization cache, crash dumps, old error reports; DISM `/StartComponentCleanup`. | age per kind (`temp_days` 7, `minidump_days` 14, `memory_dump_days` 7, `error_report_days` 30, `update_download_days` 0), `min_reclaim_mb`, `component_store`, `service_stop_seconds` |
| `windows-privacy` | safe | 300 s | daily | Turns off the groups in `turn_off`: telemetry at the edition's minimum (DiagTrack and dmwappushservice disabled), advertising ID, tailored experiences, activity history, consumer suggestions, web results in Start, Copilot, Recall. Location is left alone. | `turn_off` (all 9 groups by default) |
| `windows-debloat` | careful | 900 s | weekly | Removes the listed bundled apps for all users and from the image; drops sponsored apps from the image; disables the listed services. Xbox, Store, GPU and OEM tools stay. | `remove_apps`, `deprovision_apps`, `services` |
| `windows-performance` | safe | 300 s | weekly | Game Mode on, background game recording off by policy; hardware-accelerated GPU scheduling only when its careful step is on (reboot). | `game_mode`, `block_game_recording`, `gpu_scheduling` (careful, off) |
| `windows-audit` | safe | 300 s | daily | Read-only controls: BitLocker, Defender, firewall, update age, free disk, TPM, Secure Boot, pending reboot; `ok` or `drift`. | `signature_max_days`, `update_max_days`, `disk_min_free_pct`, `disk_min_free_gb` |

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
so it asks on the phone; an audit does not.

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
  "enabled","mode","interval","params":{name: value|null},"reason",
  "expires_at","reset"}`; `null` clears a field, `reset` clears the row.
  Every change is audited (`MAINTENANCE_SETTINGS_CHANGED`) and starts a
  schedule pass.
- Saving a setting runs nothing and needs no tap. What needs the owner is
  decided when a run is asked for (see below): switching to enforce, turning
  on a careful package or step, or changing parameters asks once; turning a
  package off or back to audit never asks.

## Console

- **Maintenance page** (rail): Maintenance and Security tabs. Each tab has
  the category switch for the fleet and a table of its packages with the
  fleet schedule, how many settings differ from the defaults and the synced
  version. *Settings…* opens the package's fleet defaults: scheduled, mode,
  how often and each typed parameter, with where each value comes from, the
  default it would go back to, and a reset per row. Changes save as they are
  made.
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

## Owner approval and the package rule

`POST /api/v1/maintenance/run` (`{"endpoint_ids","packages","mode"}`, admin
key) goes through the hub's owner-approval gate like rollouts. The run uses
each host's effective parameters; hosts in one call must share them. If the
owner is needed the first call answers 202 with an approval id, the owner
gets a Nightshift push and taps once, and the repeated call (with
`X-Approval-ID`) creates one job per host and package.

- **What is approved**: the response authority sees the exact script payload
  of every run (source, digest, interpreter, parameters, timeout, output
  bound) and the named hosts, and writes the text the owner sees ("Run as
  SYSTEM on laptop-1: windows-cleanup (enforce), up to 60 min, settings
  temp_days=30"). Changed parameters are listed against the defaults. Each
  grant binds one host and one script payload, which must be exactly the
  bytes `json.Marshal` makes of it.
- **Which scripts count as packages**: the authority ships with the digest,
  name and risk of every file in `packages/windows` and `packages/linux`
  (`hub/pkg/responseauth/released_packages.json`, kept in step by a test).
  Only those sources, run by their platform's interpreter (`powershell.exe`
  or `/bin/sh`) with `mode` plus exactly the
  parameters their (trusted) header declares, each valid, are packages; the
  hub's own copy of the header is never trusted. Anything else is shown as
  "not a released package", asks every time and never gets a rule. So a
  changed package needs a hub release before a rule can cover it. A run too
  long to show whole in one ask is refused (split it).
- **Baseline**: a run of only `safe` released packages in `audit` with every
  parameter at its default changes nothing, so the authority approves it
  without asking (method `baseline`, audited) and without the hourly limit.
- **"Approve all like this"** is offered only when every item is `safe` with
  no careful step on. It records the payload digests and hosts, plus the
  audit twin of each enforce item (same parameters, mode audit); later runs
  of exactly those payloads (or a subset) on those hosts (or a subset) go
  through with no tap and are not held to the hourly limit. A new package
  version, other parameters, timeout or host is a new digest or target and
  asks again. Revert is treated like enforce: never a baseline, never an
  audit twin, covered only by a rule made for that revert run.
- **Careful** packages, and any run with a careful step on, never get a rule:
  every run asks. A rule ends after 90 days unused; `ominullctl maint rules`
  lists them and `maint forget-rule [ID]` removes one or all.
- Nightshift accepts these statements (kind `script_exec`, offer `packages`)
  from executor release 5d4e7248bcba on.

## Schedule

Every 5 minutes (and right after a settings change) the hub walks each
package × online host of its platform with the effective settings
(maintenance mode excepted: it never runs on a schedule). A package is due
on a host when it and its category are on there, the host is online (seen in
the last 30 s), no run of it is open there, its last success (`ok`, `fixed`,
`drift`) is older than the interval and its last attempt is at least an hour
old. A laptop that was off simply catches up the next time it is online.
Hosts whose run would be the identical payload are grouped into one request.

The schedule requests approval like `maint run`: a baseline or rule-covered
run dispatches at once; anything else files one ask on the owner's phone and
waits for it (a host dropping offline keeps the same ask). Once approved the
run is dispatched to the hosts still due and online. A declined or expired
ask is not asked again for 24 hours, or until the settings change.

## Nightshift feed

The existing findings feed (`/api/v1/integrations/nightshift/findings`) carries two records:

- `ominull.maintenance`: critical (pushes) when the latest run of any package
  on any host failed or returned no result line, with counts in the message
  and the failures in `unmapped`; otherwise informational and resolved, with
  the latest runs, hosts that need changes, hosts that need a reboot and
  compliance per category.
- `ominull.maintenance.schedule`: medium (board only) while a scheduled run is
  waiting for the owner or was declined, resolved otherwise.

## Running a package

1. Sync: `ominullctl scripts sync packages/windows` and
   `ominullctl scripts sync packages/linux` (admin key).
2. `ominullctl maint run HOST PKG... --mode audit|enforce|revert` runs with
   the host's effective settings, asks the owner when needed, waits for each
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
  revert recording and restoring, the preflight rules and maintenance mode
  (powercfg parsing, enforce/extend/revert/audit, expiry, the saved dump);
  the Windows CI job runs it.
- `ominullctl` tests also run each `packages/linux/*.sh` under `sh -n`, a
  read-only audit (one result line, exit code matching the state) and a bad
  parameter (fails before changing anything).
- `hub/pkg/server/maintenance_mode_test.go`: each platform gets its own
  package, the card state from the latest run, expiry, a Linux audit without a
  tap and the schedule never running maintenance mode.
- `hub/pkg/scripts/package_params_test.go`: header parsing, parameter checks,
  change summaries and settings resolution including expiry.
- `hub/pkg/responseauth/package_rule_test.go`: baseline, rule coverage and
  audit twins, careful packages and steps, revert, per-script grants,
  forged, tampered or ambiguous payloads.
- `hub/pkg/server/maintenance_run_test.go`: the run route under approval and
  rule, settings validation and overrides, the schedule's asks and dispatch,
  the feed records.

## Later (not built)

Tagging detector events raised while a package runs ("during maintenance"):
the agent has to mark the job's process tree, which needs an agent release.
