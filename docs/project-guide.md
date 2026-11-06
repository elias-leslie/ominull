# Ominull project guide

[Project overview](../README.md)

Commands and source paths are relative to the repository root unless stated otherwise.
This guide retains operating detail; dated/versioned examples do not establish current runtime acceptance.

Ominull is a Linux and Windows endpoint telemetry, detection, and containment
hub. The hub embeds the operator console and SQLite store. Agents use signed
native packages, authenticated REST heartbeats, unique per-device credentials,
and optional matching client certificates.

Agents report TCP counter observations and passive UDP socket observations.
[Collection semantics and build requirements](../docs/UDP_OBSERVATION.md) describe
timing, process attribution, byte units, and coverage limits.

Supported products:

- Linux hub `.deb`
- Linux agent `.deb`
- Windows agent `.msi`

macOS, kernel drivers, packet capture, Copilot, WebSockets, SSH deployment, and
other retired product paths are not supported.

## Install the hub

The supported hub host is a Debian-family Linux machine. Install the registered
package as root:

```bash
# Replace RELEASE_VERSION with the version of the verified package.
sudo dpkg -i ./ominull-hub_RELEASE_VERSION_amd64.deb
sudo ominullctl setup-token
```

The package creates `/opt/ominull/bin/ominull-hub`, `/usr/bin/ominullctl`,
`/etc/ominull/hub.env`, the package-owned `ominull-hub.service`, and the
root-only local setup-token file. It installs the hub service and a separate
`ominull-response-authority.service` for response authorization. The database,
device PKI, release artifacts, backups, and operator configuration survive an
upgrade, remove, reinstall, or hub purge. Purge is never a database delete.

Open `http://<hub-lan-name>:9999/setup` or the configured HTTPS console URL.
Enter the token in the page. The token is accepted in a POST body only,
exchanged for a short-lived HTTP-only setup session, and consumed once. It is
never put in a URL, service argument, package field, or log. Generate a new
break-glass token locally with:

```bash
sudo ominullctl setup-token --rotate
```

The wizard saves validated package configuration and walks through:

1. Host, package, service, storage, PKI, listener, URL, and dependency checks.
2. Local administrator identity and recovery.
3. LAN or optional-Cloudflare network mode and separate console/agent URLs.
4. DNS and self-issued or operator-supplied server certificates.
5. Client-certificate proof mode: optional during migration, or required after
   every retained agent is proven.
6. Optional native OIDC and optional Cloudflare Access console authentication.
7. Separate WAN agent access with a JSON-only, non-redirecting agent route.
8. Native Linux/Windows installation, enrollment, heartbeat, and provenance proof.

After saving a changed listener or certificate configuration, restart the one
hub service. The permanent `/status` page runs the same bounded checks and
can reopen diagnostics without reopening first-run setup. A configured upgrade
does not silently create a new setup token or reset setup state.

The package service reads `/etc/ominull/hub.env`. Normal installation needs no
manual edits. Its important paths and defaults are:

```text
OMINULL_DB=/var/lib/ominull/ominull.db
OMINULL_ADMIN_KEY_FILE=/etc/ominull/admin.key
OMINULL_BINARY_DIR=/opt/ominull/bin
OMINULL_LISTEN=:9999
OMINULL_TLS_LISTEN=:9443
OMINULL_CLIENT_CERTS=optional
```

The hub does not forward DNS or bind a DHCP listener. Router telemetry supplies
leases, DNS observations, and optional DHCPv4 fingerprints without putting the
hub in the client network path. See [router collection](../scripts/router/README.md).

## Network, TLS, and identity

Ominull works fully on a LAN. Cloudflare is an
optional adapter, not a dependency. In Cloudflare mode the operator creates an
outbound Cloudflare Tunnel route and Access application/policy in the provider
console. The hub does not change Cloudflare policy, DNS, router forwarding, or
other security boundaries.

Use separate hostnames for the console and agent transport. The console may
use OIDC or Cloudflare Access. The agent hostname must pass requests to the
hub without an interactive Access redirect. Each agent authenticates with its
own Ominull device credential; shared Cloudflare service tokens are not used.
The supported Cloudflare path uses free-tier Tunnel and Access capabilities. It
does not require Enterprise, BYOCA, Access mTLS, Workers, Spectrum, or paid
load balancing.

The hub's device CA issues a client certificate per endpoint. A device
credential is the steady-state REST proof. A directly connected native client
certificate remains an additional matching proof: its subject must match the
endpoint named by the device credential. Set client certificates to `required`
only after every retained endpoint presents one.

Native OIDC uses HTTPS discovery, authorization-code flow, state, nonce, PKCE,
issuer/audience checks, and stable issuer-plus-subject identity binding. Public
certificates are obtained and installed by the operator; Ominull does not alter
router or DNS state. See [`docs/OIDC.md`](../docs/OIDC.md).

## Enroll Linux and Windows agents

Open `/install` from a network covered by an administrator-created enrollment
window. The page offers Linux or Windows and returns a generic bootstrap command
plus a body-only enrollment code. The compatibility alias `/enrol` remains for
already distributed links.

Enrollment profiles have explicit lifetimes:

- `invitation`: one use, short-lived by default.
- `campaign`: time-boxed; unlimited uses when `max_uses` is zero, or bounded by
  the configured use count.
- `deployment`: persistent until revoked; still scoped to its tenant/site.

The bootstrap fetches the signed native package, verifies its SHA-256 digest and
detached ECDSA signature, invokes `dpkg` or Windows Installer, then sends the
enrollment code in the JSON request body. The installed package writes protected
configuration through stdin. It does not copy a daemon, create a service, or
put enrollment material in a URL, command argument, package property, or log.

Each successful redemption creates a unique `omd_...` device credential and a
matching endpoint certificate. Linux stores them under `/etc/ominull`; Windows
stores them under protected `C:\ProgramData\Ominull`. Heartbeats send the
credential in `X-Ominull-Device-Credential`. The old shared tenant-key path is
available only during an explicit migration setting for retained 1.7.x agents;
the updated native agent automatically adopts its unique credential, then the
old path can be disabled. Credential listing never returns secret material;
rotation returns the new secret once, and revocation stops the endpoint.

An administrator enrolls a Linux host directly with `scripts/enroll-linux-host.sh --role ROLE
[--monitor-only REASON] -- RUN...`, where RUN runs a command as root on the host (`ssh HOST sudo -n`, or
`ssh root@davion-gem pct exec ID --`); it needs `OMINULL_HUB_URL` and `OMINULL_ADMIN_KEY`. Agent VMs use role
`agent`; a host the hub must never isolate also gets `--monitor-only`. Aico's Status row `ominull.fleet.coverage`
(`scripts/fleet_coverage.py`, user timer from `scripts/install-fleet-coverage.sh` on the workstation, every 15
minutes) names the fleet machines in Aico Status that have no enrolled agent.

## Package lifecycle and updates

The hub package owns the hub binary, `ominullctl`, embedded web assets, bundled
signed Linux/Windows endpoint artifacts, and the hub and response-authority
systemd services. The Linux
agent package owns `/opt/ominull/bin/ominulld` and one systemd service. The MSI
owns `ominulld`, user-mode WFP recovery, the `ominulld` service registration,
and Windows Installer metadata. Package upgrades preserve enrolled identity;
downgrades are refused. Remove stops and unregisters the package service.
Purge is explicit and removes only that package's private endpoint files; hub
database, PKI, release, and backup data are preserved.

Agents self-update only after checking the package digest and the release key
pinned in the binary. Linux uses `dpkg`; Windows uses `msiexec`. A failed
download, signature, package transaction, restart, or heartbeat leaves the
current package authoritative.

## CLI and API

`ominullctl` is the local hub recovery tool:

```bash
sudo ominullctl setup-token
sudo ominullctl setup-token --rotate
sudo ominullctl setup-status
```

For fleet operations and CyberOps control, `ominullctl` reads `OMINULL_HUB_URL`
and `OMINULL_API_KEY_FILE` (or `--api-key-file /etc/ominull/admin.key`). Never commit credentials.
An https hub with its own CA takes `--ca` or `OMINULL_HUB_CA` (e.g. `/etc/ominull/ca.crt`).

### Remote commands for agents

Run commands on an enrolled endpoint through the hub's terminal session, over
the agent's existing outbound channel (no listener on the endpoint, no SSH).
Every new session is authorized on the first request (the hub asks the
response authority to sign the grant; nobody is asked), is recorded like a console
shell, and ends at the hub's remote shell limits (by default 4 hours, or 15
minutes idle; see below). Linux runs `/bin/sh`,
Windows PowerShell (as SYSTEM). Output comes back clean: the command's own
stdout and stderr, and `exec` exits with the command's exit code.

```bash
ominullctl exec [--timeout S] ENDPOINT -- 'uname -a'     # one command, session ends
ominullctl shell open [--ttl 90m] ENDPOINT               # opens a session, then reuse:
ominullctl exec ENDPOINT -- 'journalctl -u x -n 50'      #   runs in the held session
ominullctl put ENDPOINT ./fix.sh /tmp/fix.sh             #   files up to 2 MiB
ominullctl get ENDPOINT /var/log/syslog ./syslog         #   (- for stdout)
ominullctl shell end ENDPOINT
ominullctl --json exec ENDPOINT -- CMD                   # {"stdout","stderr","exit"}
```

`shell open` asks for the hub's longest session unless `--ttl` asks for less,
and holds the session until the `expires_at` the hub answers with. A one-shot
`exec` asks only for its `--timeout` plus five minutes.

The limits (longest session, idle timeout, sessions open per endpoint and in
total) are set in the console under the account menu, **Remote shell limits**,
or with `GET`/`PUT /api/v1/terminal/limits`. The hub's flags or environment
(`--terminal-max-duration`/`OMINULL_TERMINAL_MAX_DURATION`,
`--terminal-idle-timeout`, `--terminal-max-per-endpoint`,
`--terminal-max-per-tenant`) are the startup defaults; values saved from the
console win and survive restarts. Safety bounds: 5 minutes to 24 hours, idle 1
minute up to the session length, 1 to 10 per endpoint, 1 to 50 in total.
Lowering a limit applies at once; raising one is authorized by the response
authority on the same request and recorded in the audit (e.g. "Remote shell:
sessions run up to 6 hours (was 4 hours)"). Sessions already open keep the
limits they started with, and each session's authorization names its length
("recorded, up to 4 hours").

A held session lives in a background process with a private socket under
`$XDG_RUNTIME_DIR/ominull/`. `ominullctl enrol list|open|close` manages LAN
self-enrolment windows; opening one is authorized on the first request and
audited.

Protected operator routes use the admin key, a signed console session, native
OIDC session, or verified Cloudflare Access assertion. Tenant routes remain
tenant-scoped. Agent routes use a unique device credential.

Every agent holds the one admin key, so an admin-key call is recorded as
`admin` unless the caller names itself in `X-Ominull-Agent` (1 to 64 printable
ASCII characters, no `"` or `\`, no leading or trailing space; an unusable one
reads `admin`, and is a 400 on routes the authority signs). The hub records it, as a claim, as
`agent "<name>" (admin key)` wherever it records who acted: the audit,
`anomaly_resolutions.resolved_by`, tuning saves, expected rules, isolations, the
audit trail's "by". `X-Username` stays the hub's own: it is cleared on the
way in and never taken from the caller. `scripts/hub-request.sh` (`hub_post`,
`hub_curl_config`) and `ominullctl` send `$OMINULL_AGENT`, else the agent
session they run in (`cc:<id> (Aico <window>)` or `codex:<id>`); a raw curl
adds `header = "X-Ominull-Agent: <name>"` to its `-K` config. A call without
it still works and reads `admin`. Sessions an agent opens (terminal, screen)
belong to that name, so reattach with the same one.

| Route | Method | Purpose |
|---|---:|---|
| `/` | GET | operator console |
| `/status` | GET | authenticated diagnostics/status page |
| `/setup` | GET | local-token first-run/recovery wizard |
| `/api/v1/setup/session` | POST | body-only local token exchange |
| `/api/v1/setup/status` | GET | wizard diagnostics and redacted configuration |
| `/api/v1/setup/apply` | POST | CSRF-protected validated setup save |
| `/api/v1/setup/complete` | POST | CSRF-protected setup lock |
| `/api/v1/diagnostics` | GET | bounded JSON diagnostics |
| `/install` | GET/POST | self-service Linux/Windows enrollment portal |
| `/api/v1/enrollment/profiles` | GET/POST | manage invitation/campaign/deployment profiles |
| `/api/v1/enrollment/redeem` | POST | body-only enrollment profile redemption |
| `/api/v1/device-auth/credentials` | GET/POST/DELETE | list, rotate, revoke device credentials |
| `/api/v1/enrolment/script` | POST | authenticated bootstrap/profile generation |
| `/api/v1/enrolment/windows` | GET/POST/DELETE | bounded self-service window management |
| `/api/v1/events` | POST | device-authenticated telemetry heartbeat |
| `/api/v1/agent/config` | GET | device-scoped control/config response |
| `/api/v1/agents/update` | POST | queue signed native package update |
| `/api/v1/agents/update-status` | GET | convergence and package provenance |
| `/api/v1/agents/rollback` | POST | admin: `{version, reason}` retires an agent release: halts its staged rollouts, drops its queued updates and refuses to roll it again; machines already on it stay until a newer release; no authorization needed |
| `/api/v1/trust/routine-keys` | GET/POST | admin: the routine release keys the pinned release key listed, `{epoch, keys:[{id, public_key}], signature}` over `OMINULL-ROUTINE-KEYS-V1` (`/statement` returns the exact bytes; a higher epoch replaces, an empty list revokes). Agents get it in the heartbeat and accept a routine key only for agent packages and their release statements; a release signed with one rolls out canaries first |
| `/api/v1/detection/tuning` | GET/POST/DELETE | read, adjust or reset the behavioural thresholds; a save that loosens is authorized by the response authority on the same request (no second step) and recorded in the audit with a detection-policy note; a loosening the authority cannot read (invalid or over 16 KiB) is refused with the reason; the authority's audit statement opens with the floor drill run against the proposed tuning (the floor cases it would newly blind) |
| `/api/v1/detection/expected` | GET/POST/PUT/DELETE | the expected rules (below): GET returns `{rules, findings, explicit, now}`; POST or PUT upserts one rule by `id` (admin); DELETE `?id=` removes one (admin, tightens, applies at once); a write that loosens is authorized by the response authority on the same request and audited as `EXPECTED_RULE_SAVED` / `EXPECTED_RULE_DELETED` |
| `/api/v1/detection/expected/mark` | POST | admin: `{id, reason?, all_hosts?, days?}` turns a finding into a narrow expected rule (this program, this network, this host, this kind) and acknowledges the finding; audited as `EXPECTED_RULE_MARKED`; no release needed |
| `/api/v1/detection/tuning/replay` | GET/POST | what the saved tuning (GET) or a draft (POST `{"tuning": ...}`, not saved) would still raise over stored findings (`from`/`to`, default 7 days, at most 92) |
| `/api/v1/anomalies/resolve` | POST | admin: close findings with a recorded reason, by `ids` + `reason`, or `covered: true` for every open finding the saved tuning no longer raises; the console's alert detail gives the same `verdict` (Confirm benign / Confirm real) with a reason; what it closes is recorded as `FINDINGS_ACKNOWLEDGED` and counted on the health findings' detection-policy note, like an acknowledgement |
| `/api/v1/endpoints/presence` | POST | admin: `{endpoint_id, presence, reason}` with presence `always_on`, `intermittent` (quiet alerts only after 30 days) or `parked` (never alerted when quiet; `lab` is accepted as its old name); reason required unless `always_on`; moving a host toward parked is authorized by the response authority on the same request (kind `detection_policy`, target `endpoint:<id>`), back toward always on applies at once; audited |
| `/api/v1/topology/workspace` | GET | grouped communication data with stable asset IDs and observed domain/process evidence |
| `/api/v1/router/telemetry` | POST | ingest one gateway poll: DHCP leases, conntrack flows, resolver queries and the answers they returned |
| `/api/v1/router/flows` | GET | stored flow rollups, filterable by source, destination and hours |
| `/api/v1/router/talkers` | GET | which devices are talking and to whom, ranked by bytes and named where known |
| `/api/v1/router/clients` | GET | per-client daily traffic from the gateway's own counters |
| `/api/v1/router/health` | GET | the gateway's latest own-condition reading (WAN, uptime, memory, config storage, connection table, firmware and when it last changed, failed ssh logins, UPnP mappings) |
| `/api/v1/router/identity` | POST | admin: issue a gateway client certificate; reissuing revokes the previous one |
| `/api/v1/health/findings` | GET | fleet administrator: the hub's health findings as `{generated_at, findings}`, for diagnostics (what the Aico rows are built from) |
| `/api/v1/integrations/aico` | GET, POST | fleet administrator: the Aico push URL and key (see Aico push); the key itself is never returned |
| `/oidc/start` | GET | begin native OIDC authorization-code sign-in |
| `/oidc/callback` | GET | validate OIDC state, PKCE, nonce, issuer, and operator identity |

Expected rules (`expected_rules` in the tuning, one list). Everything the hub
treats as "this is expected" is a rule here: a program talking to its maker, a
browser to named networks, a backup to its storage, an interpreter running a
named script, routine admin ssh, a container bridge. Every behavioural
detector asks the same matcher (`hub/pkg/storage/expected_rules.go`) whether a
finding of its kind is expected for this flow; a rule is live data, edited
through `/api/v1/detection/expected` without a release, and the Go defaults are
only the seed a hub starts with. A rule is
`{id, name, reason, findings, programs, runtime, workload, hosts, vendor, domains,
except_domains, prefixes, networks, tenancy, port, protocol, direction,
max_hosts, expires_at}`. Every clause that is set must match; a list inside a
clause matches on any entry.

- Program: `programs` is `[{path, sha256, run_as, exact}]` (lower-cased installed path,
  `*` for one path segment such as a version number; `run_as` is `system` for
  root and the system accounts, or one account name; `exact` keeps the path as
  written, case and all, with no pattern and no ` (deleted)` allowance, as a
  migrated exclusion had it); `runtime` names an agent
  runtime from `agent_runtimes`; `workload` is an interpreter plus the script it
  runs (`python3.13 /srv/app/.venv/bin/python -m app.worker`) or an installed
  path. A program in a folder any account can write (`/tmp`, `/var/tmp`,
  `/dev/shm`) needs `sha256`; a program under `/home` does not, so a self-updating
  program stays expected after it updates, bound by `run_as`. A workload needs an
  absolute script, `-m module` or `-jar file`; inline (`-c`, `-e`), stdin and
  preloaded code make it `<interpreter> -c`, which never matches. A workload rule
  needs an `expires_at` at most 90 days out, and an interpreter workload must name
  `networks` or `prefixes` (`*` means any named network).
- Destination: `domains`, `prefixes` and `networks` (AS numbers, exact network
  names, or `*` for any named network). A name is only what a client sent, so
  `domains` must be anchored by `prefixes` or `networks`, and a rule that lists
  `domains` needs the name the client asked for under one of them as well as the
  address (a rule that names a `vendor` must list its domains; vendor prefixes no
  wider than /16 or /32). `except_domains`
  are names under the listed domains that are anyone's (Cloud Storage buckets) and
  never match. `tenancy` is `vendor` (only a published maker range), the default
  (any network that is not rented compute) or `any` (rented compute too, which
  an implant can hide in). A rule with no prefix and no network matches any
  destination.
- Narrowing: `hosts` (endpoint ids or roles), `port`, `protocol`, `direction`, and
  `max_hosts` for a lateral fan-out (at most 8; left out it means 8). A lateral
  rule names hosts, programs and one port, never a floor port (23, 135, 445,
  3389), and a window that touches a floor port is never routine.
- Effect: `findings` lists the kinds it makes expected (`NOVEL_PROCESS_EGRESS`,
  `OFF_HOURS_ACTIVITY`, `BANDWIDTH_SPIKE`, `BANDWIDTH_BURST`, `C2_BEACONING`,
  `NOVEL_DESTINATION`, `NEW_PLACE_UPLOAD`, `AGENT_NEW_DESTINATION`,
  `AGENT_UPLOAD_VOLUME`, `CLOUD_STORAGE_EGRESS`, `LATERAL_PORT_SWEEP`). Empty
  means every kind except the four that page or hide a transfer on their own
  account (`NEW_PLACE_UPLOAD`, `AGENT_UPLOAD_VOLUME`, `CLOUD_STORAGE_EGRESS`,
  `LATERAL_PORT_SWEEP`), which a rule covers only when it names them.
- Exclusions in a rule always win, and no rule reaches the floor (below).

The response authority judges every write. A rule that covers more than it did
loosens: a new rule, an added kind, program, host, domain, prefix or network, a
lifted restriction (program account, port, protocol, direction, hosts, domains),
a wider tenancy, a higher `max_hosts`, an exception removed, a later or no
expiry. It is authorized on the same request and audited; removing a rule,
narrowing one or ending it sooner tightens and applies at once. A changed name
or reason matches nothing and tightens. Past `expires_at` a rule vouches for
nothing and the next save drops it. Rules that lapse within
`policy_expiry_warn_days` (hub setting, default 30, 1 to 89), or lapsed in the
last week, make the health findings' `ominull.detection.expiring` medium (a
daily agent item) with how to renew: re-POST the rule with the same id and a
later `expires_at`. Novelty and off-hours findings fold to one per program and
counterparty per first-seen cooldown. The tuning save is a patch over what is
saved; sending `expected_rules` replaces the whole list, and the retired lists
(`quiet_processes`, `quiet_orgs`, `quiet_clients`, `quiet_pairs`,
`known_workloads`, `agent_runtime_vendors`, `admin_fanout_*`) are refused with a
400 pointing here. At upgrade the hub carried every saved entry of those lists
into rules with the reach it had and nothing wider. Check a change with the
replay route before saving it: `cut` is the best case, and `worst_cut` allows for
findings that a silenced one kept folded live and that were therefore never
recorded (`may_surface`).

Marking a finding expected (the console's Expected button, or
`/api/v1/detection/expected/mark`) writes the narrowest rule that covers it: the
finding's program (a `/home` version folder generalised to `*`, a root process
bound to `system`), its named network, its host (`all_hosts` widens), its kind
only, and an expiry only when `days` is given. It is refused for the floor, a program the
agent could not attribute, an unnamed address, rented compute and Cloud Storage.

Detection floor (`hub/pkg/detector/floor.go`). The sensitive ports
(23/135/445/3389), the bandwidth outlier and 10 MB burst bounds, the port-sweep
and lateral-sweep thresholds and the longest silence (15 min) are code. Where
the tuning holds a weaker `silence_after_minutes`, `bandwidth_min_samples`,
`bandwidth_cooldown_minutes`, `warmup_hours` or a rule's `max_hosts`, the floor value runs instead and the
feed's detection-policy note says so (`floor_clamped`); a stricter value runs
as saved. Silence cannot be switched off, and the 10 MB burst is raised with
`bandwidth_enabled` off. A workload rule's
`expires_at` is at most 90 days out when added, changed or renewed. The
threat-list match, sensitive-port egress, port sweep, lateral sweep and
resolver bypass run before the expected rules and ignore them: no rule
silences them (the infrastructure paths in code, run as their own account,
stay exempt from the sweeps), apart from the admin ssh rule that bounds a
fan-out to inventoried hosts on port 22, never one that reaches a floor port.
The 10 MB burst still yields to a rule that names it, because Windows Update and
Delivery Optimization upload tens of megabytes as svchost.exe and a backup
program's rule for its storage service exists for exactly that.

Floor drill (`hub/pkg/detector/drill.go`, `hub/pkg/server/floor_drill.go`). At
start, weekly and after every applied detection policy change, inside the hub
process, synthetic events for each floor
rule (threat-list match and its isolation, sensitive port, port sweep, lateral
sweep, bandwidth burst, resolver bypass shaped as a connection test, an agent's
ssh fan-out that reaches SMB, a host gone quiet) run through a throwaway engine
on the live tuning, expected rules included. It stores no finding and isolates nothing.
A rule that does not raise, isolate where it should, or that the feed would
explain away (`Expected`) is a CRITICAL `ominull.detection.drill` on the
health findings, as is a drill that has not run for more than eight days; a
missed drill runs again every hour until it passes. The lateral cases use the
private /24 holding the most enrolled endpoints and twice each threshold. Both
sweeps run again as each program an expected rule names (path with `*` filled
in, its pinned hash, its account or root), except a resolver or container
runtime the code already exempts; a shell or interpreter trips the lateral
sweep at a lower count, so its first sweep is recorded rather than paged and the
case only has to raise. Each rule narrowed to a host, a destination range or a
port gets the floor cases its own traffic could make, from its host, by its
program, inside its range and on its port: threat-list match, sensitive port,
port sweep, lateral sweep on SMB and, for an agent runtime or interpreter,
resolver bypass. A case it cannot match is skipped (a port sweep under a rule
for one port, a lateral sweep under a public or too small range or inside a
container network, the sweeps for a program the code exempts), and so is the
burst, which a rule may cover by design.
A loosening tuning save or rule is drilled before it is applied: the
floor cases the proposed policy would blind that the saved one does not (a case
that raises today and that the proposed policy no longer builds, such as the
resolver bypass of a removed agent runtime, counts). The authority's audit
statement opens with them ("BLINDS 2 FLOOR CASES: lateral sweep, ...",
shortened to the count when the change leaves no room) or with "floor drill:
blinds no floor case (the 10 MB burst yields to expected rules)". The drill does not block the save: the authority signs it and the
audit and the detection-policy note show what it blinds. Presence and retirement
reach no floor rule the drill runs, so their statements carry
no drill.

Detection tiers (`hub/pkg/storage/anomaly_tier.go`, `hub/pkg/detector/tier.go`).
Paging comes only from deterministic detectors: canary and decoy hits, silence
and return against presence, sweeps, threat intelligence, beaconing, volume,
sensitive ports and the agent egress rules. The behavioural detectors
(`NOVEL_DESTINATION`, `NOVEL_PROCESS_EGRESS`, `OFF_HOURS_ACTIVITY`) write hunt
leads: stored in full with `held_reason` `hunt` and `tier` in the evidence, out
of every open count, the default alert list and the Aico push summary, shown
under HUNT LEADS (`GET /api/v1/anomalies?held=hunt`, `hunt_total`) and bounded
by the anomaly retention. On agent-heavy endpoints (tuning
`agent_heavy_endpoints` by endpoint id, `agent_heavy_roles` by role tag, and,
with `agent_heavy_observed` (default on), any endpoint whose own telemetry has
shown an agent runtime; never the operating system; a console save keeps all
three) a lead is also muted to LOW, the detector's
severity kept as `detector_severity`. New-device findings from the retired
scheduled subnet sweep (`alert-disc-*`, kept until anomaly retention removes
them) share the `NOVEL_DESTINATION` type and keep paging. Discovery now runs
only on demand. Findings
recorded before the tiers were moved once at startup (setting
`anomaly_hunt_tier_backfill_v1`). The replay route reports `paging`: before
(every kept finding not held by learning) and after (kept findings of paging
detectors), by type and by host. The detectors' code stays until labelled drills
compare both tiers. The health findings carry the leads as
`ominull.anomalies.hunt` (always informational).

Agent egress (`agent_runtimes`, `agent_*` in the tuning) keeps a baseline per
AI agent runtime on each endpoint, matched by executable (Claude Code's native
build runs as its version number under `~/.local/share/claude/versions/`). For
the first `agent_baseline_days` the runtime's destinations are learned; after
that a registrable domain it has never reached (on a CDN or rented compute,
the domain together with the network owner, because the hub borrows names
from the resolver and one address there serves many sites) is
`AGENT_NEW_DESTINATION`, reported (MEDIUM, in the agent-egress digest) and
never paged on its own whoever hosts it, because agents read the web for a
living; it pages (HIGH) only when the runtime sends 1 MB or more there within
an hour of first reaching it, once, when the total crosses the line (a
connection's first report carries no bytes on Linux); an hour
of uploads above `max(agent_upload_floor_mb, agent_upload_factor x` its
14-day 95th-percentile hour`)` is `AGENT_UPLOAD_VOLUME`, and a runtime or an
interpreter resolving names through public DNS, DoT or DoH is
`AGENT_DNS_BYPASS`. When each runtime's baseline began is kept apart from its
destinations and is never pruned, so a runtime idle past retention does not
learn silently again. Registrable domains follow the whole public suffix list,
so each tenant of a shared host (`x.a.run.app`) is its own destination. Tools
an agent spawns are judged as themselves: the hub sees a parent's instance id,
not its executable. Each runtime's maker is an expected rule too
(`vendor-claude`, `vendor-antigravity`): `runtime`, `vendor`, `domains`,
`except_domains`, `prefixes`, `networks` and `tenancy: vendor`. Prefixes are the maker's
published service ranges (no wider than /16 or /32, never on a shared CDN or
rented compute). Networks are the maker's AS numbers for a maker whose
published ranges are too many to copy: an address counts when the hub's
attribution, from the maker's own published feed (not the built-in table),
places it in that AS as the maker's service, so Google's counts as goog.json
less cloud.json. Excluded domains are hosts under the maker's domains that
serve anyone's content (Cloud Storage and Firebase Storage under
`googleapis.com`) and never count as the maker. A domain that is a private
public suffix (`googleapis.com`) is accepted only on an entry with prefixes or
networks. Antigravity (`agy`) ships with Google: `googleapis.com` less the
storage hosts, on AS15169. A runtime's flow to its maker's domain inside those
ranges or networks skips the per-connection bandwidth baseline (its hourly
upload volume still judges it) and the new-place upload rule, and the maker's
domain is named as the probable cause of a new destination. Adding a domain,
prefix or network, or taking an exception away, loosens (authorized and
audited); the reverse tightens. A maker behind a shared CDN (OpenAI, Cloudflare)
has no rule, since an address any site can be fronted from proves nothing.

Unknown and removed routes return not found. The old `/api/v1/pki/enroll`
route is retained only for authenticated legacy recovery; new enrollment uses
the profile API and returns device identity in the protected response.

The hub summarises its own state as findings (an OCSF Detection Finding subset):
open alerts in the last 24 hours, agent egress findings at their worst severity,
server agents quiet for 30 minutes or more, workstation agents quiet for over 7
days, router collector freshness and certificate expiry, and so on.
`GET /api/v1/health/findings` (fleet administrator only) returns the raw list for
diagnostics; Aico's Status rows are built from it. An endpoint's presence
(`/api/v1/endpoints/presence`) changes its allowance: intermittent hosts are reported after 30 days quiet,
parked hosts never; the hub's own `ENDPOINT_SILENT` finding follows the same presence.
Device names appear only in structured fields, never in messages, except the alert summary,
which is the notice's sentence.

Resolving findings through
`POST /api/v1/anomalies/resolve` takes `verdict` (`benign`, `malicious`, or
omitted), also on a finding already acknowledged; the tuning-covered path records `benign` by method `tuning`. A plain
acknowledgement (single, batch, acknowledge-all, marking expected) records no verdict.

See [Topology workspace](../docs/TOPOLOGY_WORKSPACE.md) for grouping, selection, pins
and the limits of observed domain/process evidence.

## Aico push

The hub pushes its paging alerts and its health to Aico (the owner's Needs you and Status), once a minute. There is no pull
feed. Aico calls back on two routes behind the relay key (`X-API-Key`, `nsa_` prefix; an admin issues or rotates it with
`POST /api/v1/aico/relay-key`): `POST /api/v1/aico/alerts/verdict` and `GET /api/v1/aico/agent-builds`.

Set it up as a fleet administrator (not a tenant administrator):

```sh
curl -s -X POST -H "X-API-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"url":"http://<aico LAN IPv4>:<port>/api/ominull/push"}' https://hub/api/v1/integrations/aico
```

The URL must be `http://` with a private or loopback IPv4 address, a port and exactly the path `/api/ominull/push`.
The first save makes the push key (`onp_` plus 64 hex characters) and records `since`, so alerts older than that are
not pushed. The answer is `{url, key_name, key_sha256, since, last_push_at, last_ok_at, last_error}`; `GET` returns
the same. The key is only ever sent to Aico as `X-API-Key` and is never returned or logged. Put `key_name`
(`ominull-hub`) and `key_sha256` in Aico's `~/.config/aico/ominull-keys.json`:
`{"keys":[{"name":"ominull-hub","sha256":"<key_sha256>"}]}`. `{"rotate": true}` makes a new key; update that file
with the new `key_sha256` straight after. Every change is audited (`AICO_PUSH_URL_SET`, `AICO_PUSH_KEY_MADE`,
`AICO_PUSH_KEY_ROTATED`). A failed push keeps its notices and retries on the next pass; `last_error` says why.

What is pushed (a body of `{"notices": [...], "rows": [...]}`, at most 50 of each):

- **Notices.** Each open alert that pages (the same rule as the alert summary: a classed page, or an unclassed
  high or critical alert the hub does not explain) since the later of seven days ago and `since`. One notice per
  incident, and one more for an incident's first escalation; a repeat of an incident makes none. An alert with no
  incident asks by its own id. Sent tokens are kept 30 days (table `aico_push_sent`). Each is a critical alert,
  "Security alert on HOST", with the sentence and its time (UTC), a redacted command line, destinations and the likely
  cause. Its key is `alerts:<alert ids>`: the owner's "That was me" sends those ids to
  `/api/v1/aico/alerts/verdict`. Offers Not expected, Expected (not for threat-list and beacon
  alerts, which are closed in the console), Look into it, and Open when the hub URL is `https://`.
- **Rows.** The health findings, one Status row each (`ominull.*`, machine `ominull-hub`, project `ominull`): `ok`
  when resolved or only a note, else `warn`; never `failed`, so a row never phones the owner by itself (alerts do,
  as notices). `next_run` is five minutes ahead, so a hub that stops pushing shows late. A row the hub stops producing (a
  section that recovered, a key taken off the retired list) is sent once more as `ok`, "Resolved: the OmniNull hub no
  longer reports this", with no `next_run`, so it never shows late (setting `aico_push_rows` lists the rows Aico
  shows). `ominull.detection.health` warns while paged incidents exceed the weekly page budget. Per-item findings fold into
  one row per family (`ominull.run`, `ominull.decisions`, `ominull.compliance`) with the worst state.
- **Retired release keys.** Setting `retired_release_keys` (JSON `[{"id","clean_from"}]`, default
  `[{"id":"1932669bb5871af4","clean_from":"1.8.71"}]`) gives one row `ominull.builds.<id>` per key: `warn` naming up to
  six enrolled, not retired agents (offline ones included) whose build is older than `clean_from` or unreadable,
  else `ok`.

## Build, test, and release

```bash
scripts/version.sh check
scripts/build-packages.sh
OMINULL_SIGNING_KEY=/path/from/ops-vault scripts/sign-release.sh
scripts/test-package-lifecycle.sh
(cd hub && go test -race ./... && go vet ./...)
scripts/release.sh --version "$(scripts/version.sh show)" --canary <linux-id>,<windows-id>
```

The hub is installed through Proxmox's hub-install key (`scripts/deploy-hub.sh`,
installed on Proxmox by root with `scripts/pve/install.sh`). Every hub release,
`--hub-only` included, needs `OMINULL_HUB_URL`, `OMINULL_ADMIN_KEY` and the hub
CA, because `release.sh` asks the key which hub is installed before it builds
or signs anything. Until the key is installed, set
`OMINULL_DEPLOY_CMD=scripts/deploy_remote.sh` to deploy through the owner's
root alias as before.

The release workflow checks the isolated package lifecycle, deploys the hub
first, rolls retained Linux and Windows canaries, waits for native package
provenance, then rolls the rest. Production credentials and topology come from
the operations vault or environment and never from tracked files.

With `--canary`, the release is authorized once. The authorization covers
every endpoint; the hub queues only the canaries and holds the rest
(`agent_rollouts`). Once each canary runs the version, has a clean provenance
check and was seen in the last two minutes, the hub queues the held
endpoints. A canary that fails the provenance check, or is not healthy within
30 minutes, halts the rollout and nothing more is queued. `update-status`
lists the last rollouts under `staged_rollouts`. A hub without staged rollouts
gets the older two-request sequence.

### Releases

A hub release goes out whenever something the hub or agents ship has changed,
as often as needed. `release.sh` refuses only when nothing shipped changed since
the last `Release X.Y.Z` commit (tests, test data and Markdown do not count).
`--agents-only` rolls an already published release.

Detection thresholds, exemptions and vendor lists are tuning data on the hub
(`hub/pkg/storage/detection_tuning.go`, changed through the detection policy
API), so changing one needs no release at all.

An agent update is authorized on the first request (no rule, no tap). The
authority checks the payload and the release evidence: every agent package's
release statement should verify under the release key the authority pins (or
under a routine key that key listed), and a rollout of a routine-key release to
more than one endpoint must name canaries (otherwise it is refused). Evidence the
authority cannot verify is still signed, because agents verify the package
signature themselves before installing; the audit summary then says "release
signature not verified by the authority". The audit row is `ACTION_AUTHORIZED`.

Official protocol and provider references:

- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
- [Cloudflare Access JWT validation](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [Debian maintainer scripts](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
- [Windows service installation](https://learn.microsoft.com/en-us/windows/win32/services/service-programs)

See [`docs/AGENT_TLS.md`](../docs/AGENT_TLS.md),
[`docs/AGENT_SELFUPDATE.md`](../docs/AGENT_SELFUPDATE.md),
[`docs/TRUST_FABRIC.md`](../docs/TRUST_FABRIC.md),
[`docs/SETUP.md`](../docs/SETUP.md), and
[`docs/CLOUDFLARE.md`](../docs/CLOUDFLARE.md).

Maintenance packages (Windows updates, cleanup, privacy, debloat, performance
and a standards check, run as authorized script jobs with a Maintenance card on
the asset view) are described in
[`docs/MAINTENANCE_PACKAGES.md`](../docs/MAINTENANCE_PACKAGES.md).

Finished plans (forensics and response, the v1.8.1 hardening, the DNS and DHCP
incident) are kept in [`docs/history/`](../docs/history/README.md). They do not
describe current release behavior.

## License

See [`LICENSE`](../LICENSE).
