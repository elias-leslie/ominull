# Maintenance packages

Deterministic, re-runnable maintenance, optimization, cleanup and standards
checks for enrolled endpoints, in the spirit of ImmyBot's software and task
packages but small: a handful of machines, one owner, no new stores.

## Model

- **Catalog = the script library.** The source of truth is
  `packages/windows/*.ps1` in this repository. `ominullctl scripts sync
  packages/windows` makes the hub's library match it: a package is created on
  first sync, gets a new immutable version only when its source (sha256) or
  parameter schema changed, and its description and metadata are updated in
  place. Re-running the sync is free.
- **Metadata** lives in one JSON column on `scripts` (`metadata_json`, added
  in place on existing libraries): `package`, `title`, `risk` (`safe` or
  `careful`), `reboot` (the package may need one) and `timeout` (seconds, at
  most 3600). The sync reads it from line 1 of each script:
  `# ominull-package: {"name","title","description","risk","reboot","timeout"}`.
- **Execution = an ordinary `script_exec` job**, signed and approved like any
  other script run: from the console (browser session plus passkey), or from
  `ominullctl maint run` and the schedule through the owner's Nightshift tap
  (see "Owner approval and the package rule").
- **State = the latest job.** Nothing is stored per (host, package); the hub
  derives the current state from the newest job of each package on read.

## Package contract

- One parameter, `mode` = `audit` (default) or `enforce`, delivered as
  `$env:OMINULL_PARAM_MODE`. Each package tests; in enforce mode, and only if
  something drifted, it changes what is needed and tests again.
- The last stdout line is
  `{"v":1,"state":"ok|fixed|drift|failed|skipped","reboot":bool,"changed":[...],"detail":{...}}`.
  Exit code 0 unless failed. A missing or unparseable line counts as failed.
  Stdout stays one line (the agent keeps the head of long output and merges
  stderr); the verbose log goes to
  `C:\ProgramData\OminullMaintenance\logs\<name>-<time>.log` (newest 20 kept).
- `detail` records the prior values of what a run changed, and
  `C:\ProgramData\OminullMaintenance\state\<name>-original.json` keeps the
  first value ever seen for each setting, so a change can be reverted by hand.
- Enforce runs return `skipped` (with `detail.reason`) when someone is using
  the machine (a `quser` session active within 15 minutes), a game is running
  (process paths under the usual game library folders), the machine is on
  battery, or, for updates and cleanup, Windows Update is installing. Audit runs
  are never skipped.
- Packages never reboot; they report `reboot` and Windows active hours handle it.
- Each script stays under 16 KiB.

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

| Package | Risk | Timeout | What enforce does |
|---|---|---|---|
| `windows-updates` | safe | 3600 s | Installs pending software and driver updates through the Windows Update API, skipping previews, optional and feature updates; reports reboot. |
| `windows-cleanup` | safe | 3600 s | Clears Windows\Temp (>7 days), update downloads (Windows Update idle), Delivery Optimization cache, crash dumps, old error reports; DISM `/StartComponentCleanup`. |
| `windows-privacy` | safe | 300 s | Telemetry at the edition's minimum, advertising ID, tailored experiences, activity history, consumer suggestions, web results in Start, Copilot and Recall off; DiagTrack and dmwappushservice disabled. Location is left alone. |
| `windows-debloat` | careful | 900 s | Removes the named bundled apps for all users and from the image; drops sponsored apps from the image; disables RetailDemo, MapsBroker, Fax, WMPNetworkSvc. Xbox services stay. |
| `windows-performance` | safe | 300 s | Game Mode on, hardware-accelerated GPU scheduling where supported (reboot), background game recording off by policy. Power plan, SysMain and Search are left alone. |
| `windows-audit` | safe | 300 s | Read-only: BitLocker, Defender, firewall, recent updates, free disk, TPM, Secure Boot, pending reboot; `ok` or `drift`. |

## Console

- **Asset view, Maintenance card** (Windows hosts): each package with its
  latest result, mode, reason, number of changes, when, and whether a reboot is
  needed; *Run…* opens the run sheet on that host with the package's timeout.
  An open run past its timeout plus 10 minutes shows "No result came back".
- **Response jobs page** names package runs ("Cleanup package") and shows mode,
  result, reason, reboot needed and what changed.
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
key) goes through the hub's owner-approval gate like rollouts: the first call
answers 202 with an approval id, the owner gets a Nightshift push and taps
once, and the repeated call (with `X-Approval-ID`) creates one job per host
and package.

- **What is approved**: the response authority sees the exact script payload
  of every run (source, digest, interpreter, parameters, timeout, output
  bound) and the named hosts, and writes the text the owner sees ("Run as
  SYSTEM on laptop-1: windows-audit (audit), up to 5 min"). Each grant binds
  one host and one script payload, which must be exactly the bytes
  `json.Marshal` makes of it.
- **Which scripts count as packages**: the authority ships with the digest,
  name and risk of every file in `packages/windows`
  (`hub/pkg/responseauth/released_packages.json`, kept in step by a test).
  Only those sources, run by `powershell.exe` with no parameter but `mode`,
  are packages; the hub's own copy of the header is never trusted. Anything
  else is shown as "not a released package", asks every time and never gets
  a rule. So a changed package needs a hub release before a rule can cover it.
  A run too long to show whole in one ask is refused (split it).
- **"Approve all like this"** is offered only when every package in the run is
  `safe`. It records the payload digests and hosts; later runs of exactly
  those scripts (or a subset) on those hosts (or a subset) go through with no
  tap and are not held to the hourly approval limit. A new package version,
  another mode, timeout or host is a new digest or target and asks again.
  `careful` packages never get a rule: every run asks. A rule ends after 90
  days unused; `ominullctl maint rules` lists them and `maint forget-rule
  [ID]` removes one or all.
- Nightshift accepts these statements (kind `script_exec`, offer `packages`)
  from executor release 5d4e7248bcba on.

## Schedule

`ominullctl maint schedule HOST[,HOST] PKG --every hourly|daily|weekly
[--mode audit|enforce]` adds a `script_schedules` row with the same timeout
and output bound as `maint run`, so the scheduled run is the same payload a
rule covers. Every 5 minutes the hub walks active schedules of package
scripts: a package is due on a host when the host is online (seen in the last
30 s), no run of it is open there, its last success (`ok`, `fixed`, `drift`)
is older than the interval and its last attempt is at least an hour old. A
laptop that was off simply catches up the next time it is online. Grants are
signed at dispatch for the due, online hosts only.

The schedule asks the authority rule-only: a run no rule covers is refused
without filing an ask, so nothing pushes from the schedule. It waits and is
listed in the Nightshift feed instead.

## Nightshift feed

The existing findings feed (`/api/v1/nightshift/feed`) carries two records:

- `ominull.maintenance`: critical (pushes) when the latest run of any package
  on any host failed or returned no result line, with counts in the message
  and the failures in `unmapped`; otherwise informational and resolved, with
  the latest runs, hosts that need changes and hosts that need a reboot.
- `ominull.maintenance.schedule`: medium (board only) while a schedule is
  waiting for a rule, resolved otherwise.

## Running a package

1. Sync: `ominullctl scripts sync packages/windows` (admin key).
2. `ominullctl maint run HOST PKG... --mode audit` asks the owner (or runs at
   once under a rule), waits for each job and prints one line per package:
   `HOST PKG {result line}`. `--no-wait` returns after the jobs are created.
   `ominullctl maint status HOST` prints where each package stands.
3. Or from the console: the host's asset view → Maintenance → *Run…*.
4. Pick `audit` first; run `enforce` when the changes are wanted.

## Tests

- `ominullctl` tests check every package header and size.
- `packages/windows/tests/run.sh` (pwsh from `PATH` or `$OMINULL_PWSH`) parses
  each script, rejects PowerShell 7-only syntax and forbidden operations, and
  unit-tests the result line and preflight rules; the Windows CI job runs it.
- `hub/pkg/responseauth/package_rule_test.go`: rule coverage, careful
  packages, per-script grants, tampered or ambiguous payloads.
- `hub/pkg/server/maintenance_run_test.go`: the run route under approval and
  rule, the schedule's due logic and rule-only dispatch, the feed records.

## Later (not built)

Tagging detector events raised while a package runs ("during maintenance"):
the agent has to mark the job's process tree, which needs an agent release.
