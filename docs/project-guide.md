# Ominull project guide

[Project overview](../README.md)

Commands and source paths are relative to the repository root unless stated otherwise.
This guide retains operating detail; dated/versioned examples do not establish current runtime acceptance.

Ominull is a Linux and Windows endpoint telemetry, detection, and containment
hub. The hub embeds the operator console and SQLite store. Agents use signed
native packages, authenticated REST heartbeats, unique per-device credentials,
and optional matching client certificates.

Agents report TCP counter observations and passive UDP socket observations.

Linux observes UDP with an embedded libbpf program: addresses, ports, direction,
payload bytes, process and time, never payload content. It needs readable kernel BTF
and permission to attach BPF, and otherwise reports `unavailable`. It sees its own
network namespace, not every container on a host. Windows reads the
Microsoft-Windows-Kernel-Network ETW provider; an unknown event layout counts as loss,
and IPv6 link-local observations are dropped and counted, since ETW gives no interface
scope. An accepted send is not proof of delivery, and neither platform claims every
offload or alternative kernel I/O path.

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
root-only local setup-token file. The database, grant keys (`/var/lib/ominull/grants`),
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
does not silently create a new setup token or reset setup state. When OIDC or
Cloudflare is down, `sudo ominullctl setup-status` and `sudo ominullctl setup-token
--rotate` still work locally; a fresh token opens a recovery session and is audited,
but clears nothing.

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
router or DNS state. The hub maps `(issuer, subject)` to an explicit operator row; an
email claim alone never grants a role. The client secret is a root-only
`oidc-client.secret` beside the environment file and is never returned.

For Cloudflare, the agent hostname must answer an unauthenticated probe with the hub's
bounded JSON, not an Access login page; the wizard checks this. Access assertions count
only for the configured team, audience and issuer, with valid time claims and a mapped
operator. The hub validates the signed JWT and does not trust an email header. If the
provider cannot keep the console and agent routes separate, use LAN mode.

The console listener (`:8443`) sends HSTS and never asks for a client certificate, so
operators stay clear of the agent listener's client-certificate rules on `:9443`. Serve it
with `OMINULL_CONSOLE_TLS_CERT` and `OMINULL_CONSOLE_TLS_KEY`, or with a leaf from the hub
CA for `OMINULL_CONSOLE_HOSTNAME`; for that one, export the root with `sudo ominullctl
console export-ca --out ca.crt` and add it to each operator machine's trust store.

Agents pin the hub CA in self-issued mode and use the operating system's trust with an
operator certificate or Cloudflare. The first CA fetch is trust-on-first-use and must use a
channel the operator trusts; afterwards an agent refuses a missing CA, unknown issuer, wrong
name, expired certificate or untrusted peer, with no cleartext fallback unless
`allow_plaintext` is set. Neither platform follows redirects to another host.

Client certificates last a year and renew over the agent's heartbeat. Within
`agent_cert_renew_days` of expiry (default 60) the hub puts a new certificate and key in the
reply, at most every `agent_cert_offer_cooldown_minutes` (default 60), until the agent presents
it. The agent proves it against the hub on a fresh connection first and otherwise keeps the
one it has. `POST /api/v1/endpoints/cert-renewal` with `{"endpoint_id"}` asks for a renewal now;
`GET` lists each endpoint's certificate. A Linux agent whose certificate expired while it was
off cannot reconnect and needs re-enrolment. Renewal is not revocation: answer a leaked key by
re-enrolling the endpoint. The `ominull.agents.certificate` health finding names what needs doing.

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
`ssh root@pve-host pct exec ID --`); it needs `OMINULL_HUB_URL` and `OMINULL_ADMIN_KEY`. Agent VMs use role
`agent`; a host the hub must never isolate also gets `--monitor-only`. The hub's Status row `ominull.fleet.coverage` names the machines that report to Aico and have no enrolled agent.

## Package lifecycle and updates

The hub package owns the hub binary, `ominullctl`, embedded web assets, bundled
signed Linux/Windows endpoint artifacts, and the hub systemd service. The Linux
agent package owns `/opt/ominull/bin/ominulld` and one systemd service. The MSI
owns `ominulld`, user-mode WFP recovery, the `ominulld` service registration,
and Windows Installer metadata. Package upgrades preserve enrolled identity;
downgrades are refused. Remove stops and unregisters the package service.
Purge is explicit and removes only that package's private endpoint files; hub
database, PKI, release, and backup data are preserved.

Windows agents self-update with `msiexec` only after checking the package digest
and the release key pinned in the binary. Linux machines take updates from
`scripts/update-linux-agents.sh`, which checks the signature first and puts the
previous binary back if the new one will not stay running. A failed download,
signature, package transaction, restart, or heartbeat leaves the current package
authoritative.

## CLI and API

`ominullctl --help` lists every command; `ominullctl help remote` and `ominullctl help screen` explain
remote commands and screen sessions. Locally on the hub, `sudo ominullctl setup-token [--rotate]` and
`setup-status` are the recovery tools. For fleet work it reads `OMINULL_HUB_URL`, `OMINULL_API_KEY_FILE`
and `OMINULL_HUB_CA`. Production values live in the private operations brief. Never commit credentials.

Protected operator routes use the admin key, a signed console session, native OIDC session, or
verified Cloudflare Access assertion. Tenant routes remain tenant-scoped. Agent routes use a unique
device credential. Unknown and removed routes return not found.

Routes: `rg -n 'HandleFunc' hub/pkg/server/server.go`; each handler's comment holds its rules.

| Topic | Rules live in |
|---|---|
| Who an admin-key call is recorded as (`X-Ominull-Agent`) | `agentLabelHeader`, `hub/pkg/server/action_authorize.go`; `scripts/hub-request.sh` |
| Remote shell limits | `hub/pkg/server/terminal_limits.go` |
| Expected rules | `hub/pkg/storage/expected_rules.go`; routes in `hub/pkg/server/expected_rules.go` |
| Tuning, replay, closing findings | `hub/pkg/server/detection_tuning.go`, `tuning_replay.go` |
| Detection floor and floor drill | `hub/pkg/detector/floor.go`, `drill.go` |
| Detection tiers | `hub/pkg/storage/anomaly_tier.go`, `hub/pkg/detector/tier.go` |
| Agent egress | `hub/pkg/detector/agent_egress.go` |
| Health findings, which machines should be up | `hub/pkg/server/health_findings.go` |
| Topology | `hub/pkg/server/topology_workspace.go` |

## Remote admin

Terminal, screen, scripts, maintenance packages and playbooks stay on every platform and
are one separate part of the code: `hub/pkg/{terminal,screen,scripts}`, the `terminal_`,
`screen_`, `script_`, `maintenance_`, `playbooks`, `software_catalog` and `data_inventory`
files in `hub/pkg/server`, `screen/`, and the `terminal_`, `screen_`, `script_`, `forensics_`,
`software_inventory_` and `data_inventory_` headers in `agent/include`. Detection never imports
them (`TestDetectionDoesNotDependOnRemoteAdmin`), and the agent's collectors don't include them.

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
  shows). Per-item findings fold into one row per family (`ominull.run`, `ominull.decisions`, `ominull.compliance`) with the worst state.
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

`scripts/deploy-hub.sh` builds the committed hub, copies the binaries into the hub container over the Proxmox root SSH alias, keeps the previous binaries as `.prev`, restarts and checks the hub reports the new build; `--rollback` puts the previous ones back.

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

A Windows agent update is authorized on the first request (no rule, no tap). The
hub signs it; agents verify the package signature themselves before installing.
The audit row is `ACTION_AUTHORIZED`. Linux agents update with
`scripts/update-linux-agents.sh`, which `release.sh` runs before the Windows
rollout; rerun it to pick up machines that were powered off.

Official protocol and provider references:

- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
- [Cloudflare Access JWT validation](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [Debian maintainer scripts](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
- [Windows service installation](https://learn.microsoft.com/en-us/windows/win32/services/service-programs)

See [`docs/RELEASE.md`](../docs/RELEASE.md) for the release runbook and
[`docs/TRUST_FABRIC.md`](../docs/TRUST_FABRIC.md) for the trust fabric.

Maintenance packages (Windows updates, cleanup, privacy, debloat, performance
and a standards check, run as authorized script jobs with a Maintenance card on
the asset view) are described in
[`docs/MAINTENANCE_PACKAGES.md`](../docs/MAINTENANCE_PACKAGES.md).

## License

See [`LICENSE`](../LICENSE).
