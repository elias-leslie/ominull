# Agent self-update

All three agents update themselves, and none of them installs anything it has
not cryptographically verified first.

Before v1.3.0 only Linux self-updated, and the way it did so was not safe to
copy. Windows and macOS needed a binary pushed over SSH by hand.

## The trust model

An auto-updater is a remote code execution channel by design, so the question is
not "did the file arrive intact" but "who authorised these bytes".

**Every release carries a detached ECDSA P-256 signature over the package, and
every agent verifies it against a public key compiled into the agent itself.**
The key is in `agent/include/release_key.h`. The private half lives in the
operations vault and never touches this repo, the hub, or CI.

Trust deliberately does not route through the hub. A compromised hub, or anyone
on the plain-HTTP LAN path to one, can serve whatever bytes they like and no
agent will install them. This is why a digest alone is not enough: a digest
served by the same party that serves the package proves only that the download
was not corrupted in transit, and an attacker who can replace the package can
replace the digest beside it just as easily.

The digest is still checked first, because it is cheap and it separates
"corrupted download" from "someone signed this with a key we do not trust" in
the logs.

The scheme was chosen so that no agent gains a dependency to verify it:

| platform | verifies with | ships with the OS |
|---|---|---|
| Linux | `openssl dgst -sha256 -verify` | yes (declared in the `.deb`) |
| macOS | `/usr/bin/openssl` | yes |
| Windows | BCrypt CNG (`BCRYPT_ECDSA_P256_ALGORITHM`) | yes |

`scripts/sign-release.sh` signs the built packages and refuses to run if the key
it is given is not the one pinned in the agents — signing with an unrecognised
key would produce a release the whole fleet silently rejects. `release.sh` calls
it, so an unsigned release is not something that can accidentally ship.

## What the hub does

- The `agent_update` descriptor on a telemetry response carries `version`,
  `package`, `url`, `signature` and `sha256`.
- **The hub fails closed.** `agentUpdateDescriptor` produces nothing unless the
  package, its `.sha256` and its `.sig` are all present in `--binary-dir`. An
  unsigned release is never advertised, and an operator push reports it as
  "no signed package on the hub" rather than queueing a job that could never
  complete. Agents would reject it anyway; this turns a fleet of failed installs
  into one clear answer in one place.
- Eligibility comes from what the agent says it can install, not from its OS
  string. Agents report `update_capability` — `deb`, `pkg`, or `exe` — and the
  hub gates on that. The OS string is a display label: v1.2.0 changed the
  Windows one from a hardcoded literal to a detected value, and matching on it
  was one release away from misrouting a fleet-wide update.
- An agent that reports no capability is offered nothing, with one deliberate
  exception: an endpoint that has never reported the field is running a
  pre-1.3.0 agent, and the only pre-1.3.0 agent that can install anything is the
  Linux one. So the legacy fallback covers exactly that case. A pre-1.3.0
  Windows or macOS endpoint is honestly reported as needing the push-deployer.

## What the agents do

All three follow the same sequence, and any failure leaves the running agent
untouched:

1. Take **only the path** from the descriptor URL, require it to start
   `/download/`, and fetch it from the hub the agent is already configured to
   talk to. The advertised host is ignored: behind a reverse proxy the hub
   legitimately advertises a host the agent does not dial, and ignoring it means
   no hub response can redirect a download somewhere else.
2. Stage into a **root-only directory**, never `/tmp` (see below).
3. Check the digest.
4. Verify the signature against the pinned key. No signature, no install —
   there is no degraded mode, because an unverified root install is the thing
   being prevented.
5. Install, then restart into the new build.

### The `/tmp` escalation this replaced

The pre-1.3.0 Linux path did this:

```c
snprintf(debPath, sizeof(debPath), "/tmp/ominull-agent_%s_amd64.deb", version);
"setsid nohup sh -c 'curl -fsSL -m 300 -o \"%s\" \"%s\" && dpkg -i \"%s\"; ...'"
```

A fully predictable filename in a world-writable directory, downloaded as root
and installed with `dpkg`, whose maintainer scripts also run as root. Two local
privilege escalations fall out of that: a local user can plant a malicious
`.deb` at that path, or win the race between the download completing and `dpkg`
opening it. Separately, `curl -o` onto a pre-planted symlink writes root-owned
content wherever the symlink points.

Adding a signature check would **not** have closed it. Verifying a file and then
installing it from a world-writable path leaves the time-of-check/time-of-use
window wide open. The fix is both: verify, and stage somewhere unprivileged
users cannot reach.

Staging is now `/var/lib/ominull/updates` (`0700`, root-owned) on Linux,
`/opt/ominull/updates` on macOS, and the install directory on Windows. The Linux
agent re-checks the directory's owner and mode every time and refuses to use one
that is group- or world-writable rather than trying to correct it: if something
else created it, the safe response is to stop.

### Linux

The updater is written to a script in the staging directory and run detached —
detached because `dpkg`'s `prerm` stops the very daemon issuing the command, so
a child of the current process would be torn down mid-install. `set -e` means a
failed download, a wrong digest or a bad signature stops before `dpkg` is ever
reached. Steps are logged to `/var/log/ominull-update.log`.

`/etc/ominull/agent.conf` is created once and never overwritten, so an upgrade
keeps the credentials the endpoint enrolled with.

### macOS

The package is a script, not an installer, so two things matter:

- **Only the daemon script is replaced.** The installed LaunchDaemon plist
  carries the host's pinned endpoint id, hub URL and API key; the packaged one
  carries placeholders. Overwriting it would change the host's identity and
  break its auth.
- **The running script is never written in place.** `bash` reads a script
  incrementally as it executes, so rewriting the file underneath a running shell
  splices new bytes into the current run. The new script is written beside it
  and `mv`d over: rename swaps the directory entry while the running process
  keeps its original inode.

The agent then exits 0 and `launchd` restarts it under `KeepAlive`.

### Windows

The running image is locked against write and delete but can be renamed, so:

1. Download and verify in the install directory — administrator-only, and the
   same volume as the target, which is what makes the final rename atomic.
2. `MoveFileEx(current -> ominulld.old, MOVEFILE_REPLACE_EXISTING)`.
3. `MoveFileEx(new -> current, MOVEFILE_REPLACE_EXISTING)`.
4. Spawn `ominulld.exe --restart-service` detached, then exit non-zero.
5. The new build deletes `ominulld.old` on its first successful start, falling
   back to `MOVEFILE_DELAY_UNTIL_REBOOT` if it is somehow still held.

A service cannot synchronously stop and start itself; that, not the file lock,
is the real reason this was never built before. The process that would issue the
start is the one exiting.

#### Why a helper process and not the SCM (v1.4.2)

Through v1.4.1 step 4 was just the non-zero exit, and the restart was left to the
SCM's recovery actions. That was the wrong mechanism, and it failed in the field
on both the 1.3.3 → 1.4.0 and the 1.4.0 → 1.4.1 rolls: the Windows endpoint
installed its update, stopped, and stayed stopped until someone ran `sc start`.

The recovery actions are a *list*, and which entry runs is chosen by a
per-service failure counter. That counter is not scoped to this update — it
counts every abnormal exit on the host inside the reset period, including
crashes and any `taskkill` — and once it runs past the end of the list the SCM
repeats the last entry rather than starting over. On an endpoint with any
earlier failure that day, the update's own exit therefore landed on the last
action, which was the rollback command, not on a restart. Two things about the
diagnosis are worth writing down because they look like the cause and are not:
the service does abort correctly (`sc query` shows `WIN32_EXIT_CODE : 1067`),
and `FAILURE_ACTIONS_ON_NONCRASH_FAILURES` is `TRUE`. Both are necessary; the
counter is what decides the outcome.

So the restart is explicit now. `Service_SpawnRestart` launches a detached copy
of the installed binary — the path comes from the running module, so after the
swap that is the *new* build — with `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
| CREATE_BREAKAWAY_FROM_JOB`, falling back without the breakaway flag when a job
object forbids it. That helper outlives the service process, polls the SCM until
the service reads `SERVICE_STOPPED`, and calls `StartService`. It treats
`ERROR_SERVICE_ALREADY_RUNNING` as success, because that means the SCM's own
recovery restart won the race, which is the outcome either way.

An earlier design note in this file argued the opposite — that a detached
restarter "makes the update depend on a process that is about to be killed". It
does not: `CreateProcess` children are not killed when the parent exits, only
when a job object says so, and that is precisely what the breakaway flag and its
fallback are for. The SCM's failure counter turned out to be the far less
predictable dependency.

The exit stays non-zero, so the recovery actions remain as a fallback for the one
case the helper cannot cover: a binary too broken to run `--restart-service` at
all.

**`Service_EnsureRecovery` runs on every start, not just at install.**
`CreateService` returns `ERROR_SERVICE_EXISTS` on an already-registered service,
so configuring recovery only at install time leaves every in-place upgrade
without it — an agent that installs updates but can never restart into them.

Rollback has two layers, because a broken build fails in two different ways:

- A build that starts but cannot work: a marker file records the attempt, the
  new build clears it once running, and after three failures the previous binary
  is restored.
- A build so broken the SCM cannot launch it: no code of ours ever runs, so the
  last recovery action restores the file from outside the process. Since v1.4.2
  that action runs `ominull-recover.bat`, written into the install directory on
  every start:

  ```bat
  if exist "<dir>\update.pending" if exist "<dir>\ominulld.old" (
    move /y "<dir>\ominulld.old" "<dir>\ominulld.exe"
    del /q "<dir>\update.pending"
  )
  "%SystemRoot%\System32\sc.exe" start ominulld
  ```

  Both guards matter. This is the action the SCM *repeats* once the counter runs
  off the end of the list, so it has to be safe to run when nothing is wrong; the
  unconditional `move` that shipped through v1.4.1 turned any unrelated failure
  into a silent downgrade. The trailing `sc start` is what makes the repeat
  useful rather than merely harmless. The script and the interpreter are both
  named by absolute path because the SCM runs this as LocalSystem.

  The reset period dropped from 86400s to 900s at the same time, so the action
  list is only ever walked by a service that is failing *now*. A binary that
  cannot start still walks all three actions in about seventy seconds.

## Traps

- **`SC_ACTION_RESTART` needs `SERVICE_START` on the service handle**, not just
  `SERVICE_CHANGE_CONFIG`. Without it `ChangeServiceConfig2` fails with
  `ERROR_ACCESS_DENIED` even for LocalSystem — and `OpenService` still returns a
  perfectly valid handle, so the failure appears only at the point of use. This
  shipped in v1.3.1 and left the Windows agent able to install an update but not
  restart into it. Nothing but running it against a real service catches this.
- **The SCM failure counter is not yours.** It is per-service but not per-cause:
  crashes, `taskkill`, and a self-update's own deliberate non-zero exit all
  increment the same number, and past the end of the action list the SCM repeats
  the last action instead of restarting. Anything that must happen after a
  service exits has to happen without consulting it. This is what made the
  Windows self-update need a manual `sc start`, twice, before v1.4.2.
- **Test an update from the previous release forward.** Installing the new build
  directly proves nothing: the interesting failure is an old agent meeting a new
  descriptor. The v1.2.0 → v1.3.0 roll was performed entirely by the *old*
  unverified code path; only v1.3.0 → v1.3.1 exercised the new one. It is also
  why the v1.4.2 restart fix could only be proved by the v1.4.2 → v1.4.3 roll:
  the 1.4.1 → 1.4.2 hop is executed by the code being replaced.
- **Never put the signing key, real hostnames, or the launchd label in a tracked
  file.** They belong in the vault.
- The fleet has one host per platform, so a bad Windows or macOS update means an
  SSH repair hop.

## Verification

```
cd hub && go test -race ./...
gcc -O2 -Wall -Wextra -o /tmp/t agent/tests/test_dpi.c && /tmp/t
gcc -O2 -Wall -Wextra -o /tmp/d agent/tests/test_der_sig.c && /tmp/d
gcc -O2 -Wall -Wextra -o /tmp/a agent/linux/main.c            # must be warning-free
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -DOMINULL_WFP_EMBEDDED -o /tmp/w.exe \
  agent/src/{main,hub_client,hub_tls,service,driver_client,updater}.c \
  agent/windows/wfp_user.c \
  -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lfwpuclnt -lole32
bash -n agent/macos/ominull_mac_daemon.sh
scripts/version.sh check
gitleaks detect --source .
```

`test_der_sig.c` covers the one piece of hand-written parsing in the trust path:
the DER-to-`r||s` conversion the Windows agent feeds to CNG. It is checked
against signatures openssl actually produced, and against malformed structures
that must be refused rather than falling through as a zeroed — and therefore
attacker-chosen — signature.

Build and tests are not runtime evidence. The acceptance test is a real release
converging the real fleet unattended, plus a deliberately tampered package —
correct digest, signature from a different key — refused on every platform with
the running agent left untouched.

"Unattended" is the part that has to be checked deliberately on Windows, because
the failure it catches looks like success from the hub: the endpoint reports the
new version only *after* someone starts it. Push the service's failure counter
past the end of the recovery list first (three `taskkill /f` of `ominulld.exe`
inside the reset period), then roll the release and touch nothing.

## Still open

- ~~**Transport is plain HTTP** between agents and the hub on the LAN.~~ Done in
  v1.4.0: the hub serves HTTPS on a leaf signed by its own CA, enrolment plants
  that CA on every endpoint, and all three agents pin it and refuse rather than
  fall back to HTTP. The signature is still what makes a package safe — it is
  verified against a key compiled into the agent, not against the hub — but the
  API key, the telemetry and the isolation commands are no longer in the clear.
  See `docs/AGENT_TLS.md`.
- **No platform-native signing yet.** Authenticode on Windows (`scripts/sign.ps1`
  exists) and `codesign`/notarization on macOS would add what the OS itself
  enforces, on top of the portable scheme. Neither is required for the update
  path to be safe, but both are worth having — Authenticode also keeps
  SmartScreen and AV out of the way of an update.
- **macOS ships a tarball, not a `.pkg`.** A signed, notarized `productbuild`
  package is the platform-native answer for a daemon and would replace the
  hand-rolled file placement.
