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

Protected operator routes use the admin key, a signed console session, native
OIDC session, or verified Cloudflare Access assertion. Tenant routes remain
tenant-scoped. Agent routes use a unique device credential.

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
| `/api/v1/detection/tuning` | GET/POST/DELETE | read, adjust or reset the behavioural thresholds |
| `/api/v1/detection/tuning/suppress` | POST | mark one finding's program/network pair expected |
| `/api/v1/detection/tuning/replay` | GET/POST | what the saved tuning (GET) or a draft (POST `{"tuning": ...}`, not saved) would still raise over stored findings (`from`/`to`, default 7 days, at most 92) |
| `/api/v1/anomalies/resolve` | POST | admin: close findings with a recorded reason, by `ids` + `reason`, or `covered: true` for every open finding the saved tuning no longer raises; the console's alert detail gives the same `verdict` (Confirm benign / Confirm real) with a reason |
| `/api/v1/endpoints/presence` | POST | admin: `{endpoint_id, presence, reason}` with presence `always_on`, `intermittent` (quiet alerts only after 30 days) or `parked` (never alerted when quiet; `lab` is accepted as its old name); reason required unless `always_on`; audited |
| `/api/v1/learning/windows` | GET/POST | list or open a learning window over a tenant, location or endpoint |
| `/api/v1/learning/windows/close` | POST | end a window as completed or cancelled |
| `/api/v1/learning/proposals` | GET | what a window observed, as candidate tuning changes with their evidence |
| `/api/v1/learning/proposals/apply` | POST | apply an explicit list of proposal ids |
| `/api/v1/topology/workspace` | GET | grouped communication data with stable asset IDs and observed domain/process evidence |
| `/api/v1/topology/views` | GET, PUT, DELETE | personal saved layouts with revision conflict checks; auditors read only |
| `/api/v1/router/telemetry` | POST | ingest one gateway poll: DHCP leases, conntrack flows, resolver queries and the answers they returned |
| `/api/v1/router/flows` | GET | stored flow rollups, filterable by source, destination and hours |
| `/api/v1/router/talkers` | GET | which devices are talking and to whom, ranked by bytes and named where known |
| `/api/v1/router/clients` | GET | per-client daily traffic from the gateway's own counters |
| `/api/v1/router/identity` | POST | admin: issue a gateway client certificate; reissuing revokes the previous one |
| `/api/v1/integrations/nightshift/findings` | GET | summarised findings for Nightshift (`nightshift.findings/v1`), with the feed key or admin |
| `/api/v1/integrations/nightshift/key` | POST | admin: issue the Nightshift feed key, shown once and kept as a hash; reissuing revokes |
| `/oidc/start` | GET | begin native OIDC authorization-code sign-in |
| `/oidc/callback` | GET | validate OIDC state, PKCE, nonce, issuer, and operator identity |

Known workloads (`known_workloads` in the tuning) name a program whose outbound
conversations are its job, as `{workload, owner, reason}`. A workload is the
lower-cased executable path for most programs (`/opt/google/chrome/chrome`)
and, for an interpreter, the interpreter plus what it runs (`python3.13
/srv/app/.venv/bin/python -m app.worker`). `*` in a pattern spans part of one
path segment of one argument, never a `/` or a space; a pattern may not start
with `*`, and an interpreter pattern must end with the program it runs, spelled
out: an absolute script path, `-m module` or `-jar file` (a name from argv[0]
alone, such as `node npm ci`, is refused). Code that is not a named program -
inline (`-c`, `-e`, `--eval`), from stdin or a `/dev/fd` pipe, preloaded
(`node -r`, `--import`, `perl -M`, `ruby -r`) - and any option the parser does
not know make the workload `<interpreter> -c`, which is never known. The
command line arrives as one string and is split on spaces, so an argument that
itself contains a space can shift what is read as the program; like the
command line being the process's own account of itself, that is an accepted
limit of the identity, not proof. Owner is a substring of the network owner, which never
covers rented compute or an unnamed address, or `*` for a program whose
destinations are arbitrary by design. For an installed program `*` covers
every destination; for an interpreter it stops at rented compute and unnamed
addresses unless the entry sets `include_rented`, because an interpreter's
workload is read from its own command line and a process can imitate one. A
reason is required. A known workload silences only the novelty findings (new
destination, interpreter egress) and, for an owner-`*` entry, off-hours;
beaconing, upload volume and threat-intelligence matches still judge it.
Novelty and off-hours findings fold to one per program and counterparty per
first-seen cooldown. Check a change with the replay route before saving it:
`cut` is the best case, and `worst_cut` allows for findings that a silenced
one kept folded live and that were therefore never recorded (`may_surface`).

Detection tiers (`hub/pkg/storage/anomaly_tier.go`, `hub/pkg/detector/tier.go`).
Paging comes only from deterministic detectors: canary and decoy hits, silence
and return against presence, sweeps, threat intelligence, beaconing, volume,
sensitive ports and the agent egress rules. The behavioural detectors
(`NOVEL_DESTINATION`, `NOVEL_PROCESS_EGRESS`, `OFF_HOURS_ACTIVITY`) write hunt
leads: stored in full with `held_reason` `hunt` and `tier` in the evidence, out
of every open count, the default alert list and the Nightshift summary, shown
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
compare both tiers. The Nightshift feed carries the leads as
`ominull.anomalies.hunt` (always informational) and, on `?contract=v4`, a `tier`
on every anomaly record (`hunt` when every finding in it is a lead).

Agent egress (`agent_runtimes`, `agent_*` in the tuning) keeps a baseline per
AI agent runtime on each endpoint, matched by executable (Claude Code's native
build runs as its version number under `~/.local/share/claude/versions/`). For
the first `agent_baseline_days` the runtime's destinations are learned; after
that a registrable domain it has never reached (on a CDN or rented compute,
the domain together with the network owner, because the hub borrows names
from the resolver and one address there serves many sites) is
`AGENT_NEW_DESTINATION`
(HIGH on rented compute, a bare address, or a first contact over 1 MB), an hour
of uploads above `max(agent_upload_floor_mb, agent_upload_factor x` its
14-day 95th-percentile hour`)` is `AGENT_UPLOAD_VOLUME`, and a runtime or an
interpreter resolving names through public DNS, DoT or DoH is
`AGENT_DNS_BYPASS`. When each runtime's baseline began is kept apart from its
destinations and is never pruned, so a runtime idle past retention does not
learn silently again. Registrable domains follow the whole public suffix list,
so each tenant of a shared host (`x.a.run.app`) is its own destination. Tools
an agent spawns are judged as themselves: the hub sees a parent's instance id,
not its executable.

Unknown and removed routes return not found. The old `/api/v1/pki/enroll`
route is retained only for authenticated legacy recovery; new enrollment uses
the profile API and returns device identity in the protected response.

The Nightshift feed key opens only the findings route and is read-only. The
document is Nightshift's contract (an OCSF Detection Finding subset, defined in
Nightshift's `docs/ingest.md`). It carries counts and states: open anomalies in
the last 24 hours, agent egress findings at their worst severity, server agents quiet for 30 minutes or more, workstation agents
quiet for over 7 days, router collector freshness, and router certificate expiry. An endpoint's presence
(`/api/v1/endpoints/presence`) changes its allowance: intermittent hosts are reported after 30 days quiet,
parked hosts never; the hub's own `ENDPOINT_SILENT` finding follows the same presence.
Device names appear only in structured fields, never in messages.

`?contract=v2` serves `nightshift.findings/v2`: the same findings plus
`anomaly_records`, one per device, kind and ISO week (`baseline_window_id`,
e.g. `2026-W42`) over the current week and the four before it, newest first,
cut at 500 records or 160 KiB, less when the v1 part is large, so the
document stays under 224 KiB (`anomaly_records_truncated`). A record is
`{device_id, kind, count, first_seen, last_seen, baseline_window_id, outcome,
verified, outcome_source}`: `device_id` is an HMAC of the endpoint id under a
hub secret created once (setting `nightshift_device_salt`; a malformed value
fails the request rather than being replaced), `kind` a fixed enum (`other`
for a type it does not list), times epoch milliseconds, and no hostname,
domain or text.

Outcomes come only from structured state. Resolving findings through
`POST /api/v1/anomalies/resolve` takes `verdict` (`benign`, `malicious`, or
omitted), also on a finding already acknowledged; the tuning-covered path records `benign` by method `tuning`. A plain
acknowledgement (single, batch, acknowledge-all, quiet pair) records no
verdict and verifies nothing. Per window: a `malicious` verdict is
`incident`/`verdict`; an `ISOLATE_HOST` or `AUTO_ISOLATE_HOST` audit (bulk
isolation writes one per endpoint after it succeeds; the guard's `_FORCED` and
`_UNVERIFIED` entries do not count) is `incident`/`isolation`; every finding
closed by tuning is `benign`/`auto_resolved`; every finding closed by tuning
or a `benign` verdict is `benign`/`acknowledged`; a kind that is not
inherently hostile (not beaconing, threat intel, lateral sweep, DNS bypass,
upload volume or `other`) seen in three earlier windows with no incident, at
least one of them verified, is `benign`/`recurrence`. A device's benign labels
before its latest incident are withdrawn, and a capped read marks every record
unverified. Everything else is `unverified`, which the learner must not train
on. The default document stays v1.

See [Topology workspace](../docs/TOPOLOGY_WORKSPACE.md) for grouping, selection, pins,
saved views and the limits of observed domain/process evidence.

## Build, test, and release

```bash
scripts/version.sh check
scripts/build-packages.sh
OMINULL_SIGNING_KEY=/path/from/ops-vault scripts/sign-release.sh
scripts/test-package-lifecycle.sh
(cd hub && go test -race ./... && go vet ./...)
scripts/release.sh --version "$(scripts/version.sh show)" --canary <linux-id>,<windows-id>
```

The release workflow checks the isolated package lifecycle, deploys the hub
first, rolls retained Linux and Windows canaries, waits for native package
provenance, then rolls the rest. Production credentials and topology come from
the operations vault or environment and never from tracked files.

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

Proposed future forensics and remote-response work is tracked in
[`docs/NEXTGEN_FORENSICS_AND_RESPONSE_PLAN.md`](../docs/NEXTGEN_FORENSICS_AND_RESPONSE_PLAN.md).
It does not describe current release behavior.

## License

See [`LICENSE`](../LICENSE).
