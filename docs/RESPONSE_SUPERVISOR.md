# Supervised script runs

Every `script_exec` job (maintenance packages, playbook steps, one-off scripts) runs under a supervisor on the
endpoint. Nobody has to keep asking whether a run is done: the endpoint reports how it is going, the hub derives a
live state, and `ominullctl maint wait` blocks until something worth reacting to happens.

Code: `agent/include/script_supervisor.h` (platform-neutral: progress parsing, activity clock, phase, heartbeat
body), `agent/include/script_exec_linux.h` (`ScriptExec_RunSupervised`), `agent/include/script_exec_windows.h`
(`ScriptExec_RunSupervisedWin`), the hub's `hub/pkg/response/supervision.go` and
`hub/pkg/server/maintenance_supervise.go`.

## Heartbeat

`POST /api/v1/response/jobs/progress`, device-authenticated like `jobs/ack` and `jobs/result`:

```json
{"job_id":"..","lease_id":"..","phase":"running|stalled|needs_hands",
 "progress_pct":40,"message":"removing Wave Tool",
 "cpu_ms":1200,"io_bytes":0,"idle_seconds":0,"processes":2,
 "window":{"title":"Wave Tool Setup","process":"msiexec.exe","pid":1234,"session":1}}
```

- Sent when the child starts, every 30 s, and at most every 5 s when the phase or progress line changes.
- `window` only with `needs_hands`. Text is capped at 200 bytes; the hub strips control characters again.
- The reply is `{"ok":true,"cancel":false|true}`. A pending cancel makes the endpoint kill the whole process tree
  and report `state: cancelled`, `error_code: CANCELLED`.
- A failed heartbeat never fails the job. A heartbeat after the result is answered 409 and ignored.
- The lease must match; its two-minute offer expiry does not apply once the job was acknowledged.

## Progress lines

A line of output starting with `::progress::` is a progress line: `::progress:: 40% removing Wave Tool` or
`::progress:: checking updates`. An optional leading `NN%` sets the percent; a line without one keeps the last
percent. Lines stay in the captured output. Packages that must keep one stdout line write progress to stderr (the
agent reads both from one pipe).

## Phases

The tree is sampled every 5 s. Activity is new output, CPU time up by 200 ms, or storage IO up by 64 KiB.

- `running`: activity within the last 180 s.
- `stalled`: no activity for 180 s and no visible window from the tree.
- `needs_hands`: no activity for 180 s and a visible top-level window owned by a process in the tree (a dialog
  waiting for a click). The heartbeat names its title, process and session.

Stalled and needs_hands never kill a run; only its time limit or a cancel does. The hub also reads a run as stalled
when it had heartbeats and then none for 3 minutes (the machine went quiet).

## Cleanup

- Linux: the child runs in its own process group. When the main process exits, or on timeout or cancel, the group
  gets SIGTERM, then SIGKILL after 250 ms; the pipe drain has a 1 s deadline, so a script that closes its output
  cannot escape the time limit. A process that calls `setsid` leaves the group and is out of reach.
- Windows: the child runs in a job object (kill on close). On exit, timeout or cancel the job is terminated before a
  final drain that never blocks (1 s deadline). If the agent cannot put the child in a job object (it logs this), only
  the main process is supervised and killed.
- Output honours the payload's `max_output_bytes` (5 MiB at most); the result says `"truncated":true` when it was cut.

## Limits

- Windows window detection sees the desktop the child inherited (the agent's, session 0). Windows a run opens in a
  signed-in user's session are not visible to it; the run then reads stalled, not needs_hands.
- Linux has no window detection: runs are running or stalled.
- CPU on Linux counts live processes and their reaped children; IO counts storage bytes only (pipe writes show up as
  output instead).

## Live state and waiting

The hub's run states: `waiting`, `running`, `stalled`, `needs_hands`, `no_result`, and the final ones (`ok`,
`fixed`, `drift`, `skipped`, `na`, `failed`, `cancelled`, `not_run`). Stalled, needs_hands and no_result need
attention.

`GET /api/v1/maintenance/wait?ids=ID[,ID...]&wait=25[&all=1]` takes job ids, run ids (a maintenance run's or one-off
script's owner approval) and playbook run ids. It is a long-poll woken by job events (ack, heartbeat change, result,
cancel) and answers once any run ends or one needs attention (`all=1`: once all have ended, or one needs attention).

`ominullctl maint wait ID... [--all] [--timeout D]` prints one line per run and exits 0 (ok), 3 (a run failed), 4 (a
run needs attention), 5 (timeout). `maint run` and `maint script` print `run <id>` and `job <id> <endpoint> <name>`
lines and, without `--no-wait`, wait the same way. Agents run `maint wait` as a background task.
