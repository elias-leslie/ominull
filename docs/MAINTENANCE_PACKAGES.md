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
  other script run (browser session plus passkey).
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

## Running a package

1. Sync: `ominullctl scripts sync packages/windows` (admin key).
2. Console → the host's asset view → Maintenance → *Run…* on a package.
3. Pick `audit` first; review the result on the jobs page; run `enforce` when
   the changes are wanted. Each run asks for the passkey.

## Tests

- `ominullctl` tests check every package header and size.
- `packages/windows/tests/run.sh` (pwsh from `PATH` or `$OMINULL_PWSH`) parses
  each script, rejects PowerShell 7-only syntax and forbidden operations, and
  unit-tests the result line and preflight rules; the Windows CI job runs it.

## Later (not built)

Approval rules covering a batch of package runs, a schedule loop over
`script_schedules`, a Nightshift findings record, and tagging detector events
raised during a run.
