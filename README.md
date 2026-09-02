# Ominull

Ominull is a Linux and Windows endpoint telemetry, detection, and containment
hub. The hub embeds the operator console and SQLite store. Agents use signed
native packages, authenticated REST heartbeats, unique per-device credentials,
and optional matching client certificates.

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
sudo dpkg -i ./ominull-hub_1.8.2_amd64.deb
sudo ominullctl setup-token
```

The package creates `/opt/ominull/bin/ominull-hub`, `/usr/bin/ominullctl`,
`/etc/ominull/hub.env`, the package-owned `ominull-hub.service`, and the
root-only local setup-token file. It owns one service only. The database,
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
3. LAN/direct-WAN/optional-Cloudflare network mode and separate console/agent URLs.
4. DNS and operator-prepared self-issued, ACME, or custom server certificates.
5. Client-certificate proof mode: optional during migration, or required after
   every retained agent is proven.
6. Optional native OIDC and optional Cloudflare Access console authentication.
7. Separate WAN agent access with a JSON-only, non-redirecting agent route.
8. Native Linux/Windows installation, enrollment, heartbeat, and provenance proof.

After saving a changed listener or certificate configuration, restart the one
package service. The permanent `/status` page runs the same bounded checks and
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

## Network, TLS, and identity

Ominull works fully on a LAN or over direct WAN HTTPS. Cloudflare is an
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
issuer/audience checks, and stable issuer-plus-subject identity binding. ACME
certificates are prepared and installed by the operator; Ominull does not alter
router or DNS state. See [`docs/OIDC_ACME.md`](docs/OIDC_ACME.md).

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
signed Linux/Windows endpoint artifacts, and one systemd service. The Linux
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

For fleet operations, `scripts/ominull-cli` reads `OMINULL_HUB_URL` and
`OMINULL_API_KEY`. Never commit those values.

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
| `/oidc/start` | GET | begin native OIDC authorization-code sign-in |
| `/oidc/callback` | GET | validate OIDC state, PKCE, nonce, issuer, and operator identity |

Unknown and removed routes return not found. The old `/api/v1/pki/enroll`
route is retained only for authenticated legacy recovery; new enrollment uses
the profile API and returns device identity in the protected response.

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
- [ACME RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)
- [Debian maintainer scripts](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
- [Windows service installation](https://learn.microsoft.com/en-us/windows/win32/services/service-programs)

See [`docs/AGENT_TLS.md`](docs/AGENT_TLS.md),
[`docs/AGENT_SELFUPDATE.md`](docs/AGENT_SELFUPDATE.md),
[`docs/TRUST_FABRIC.md`](docs/TRUST_FABRIC.md),
[`docs/SETUP.md`](docs/SETUP.md), and
[`docs/CLOUDFLARE.md`](docs/CLOUDFLARE.md).

Proposed future forensics and remote-response work is tracked in
[`docs/NEXTGEN_FORENSICS_AND_RESPONSE_PLAN.md`](docs/NEXTGEN_FORENSICS_AND_RESPONSE_PLAN.md).
It does not describe current release behavior.

## License

See [`LICENSE`](LICENSE).
