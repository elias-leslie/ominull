# Ominull

Ominull is a fleet management and network telemetry hub with Linux and Windows
endpoint agents. It stores authenticated inventory and flow data, detects
evidence-backed behavioral anomalies, and returns explicit containment state to
the agents that reported it.

The supported release set is:

- Linux agent `.deb`
- Windows agent `.msi`
- Linux hub `.deb`

The hub embeds its operator console and SQLite store. Endpoint traffic uses the
hub's authenticated REST API and mutual TLS when client certificates are
enabled. Signed package updates are verified by the endpoint before install.

## Architecture

```text
Linux agent ─┐
             ├─ authenticated telemetry batch ─> hub ─> SQLite + console
Windows agent┘                                  │
                                                ├─ detector and threat intel
                                                ├─ asset graph and subnet scanner
                                                └─ heartbeat control response
                                                     ├─ Linux iptables/ip6tables
                                                     └─ Windows user-mode WFP
```

Linux collection reads socket tables and one socket-diagnostic snapshot per
interval, with bounded process attribution. Windows collection uses bounded
socket-table and ESTATS state. Neither agent claims privileged packet capture
or in-flight payload inspection. Host isolation is managed with iptables or
user-mode Windows Filtering Platform rules; mesh quarantine is reconciled in
the same heartbeat control response.

Retained hub capabilities include authenticated endpoint inventory, asset and
scanner provenance, threat-intelligence matching, behavioral detection with
stored tuning, explicit detector exclusions, baseline isolation policies with a
readiness gate, mesh quarantine, mTLS identity, operator roles, audit records,
signed updates, and platform recovery tools.

## Directory structure

```text
ominull/
├── agent/
│   ├── include/                  shared C headers and release key
│   ├── linux/                    Linux socket collector and agent
│   ├── src/                      Windows service, transport, updater
│   ├── windows/                  user-mode WFP recovery and enforcement
│   └── tests/                    parser and collector feedback tests
├── hub/
│   ├── cmd/main.go               hub entrypoint
│   └── pkg/
│       ├── auth/                 operator and tenant authentication
│       ├── bootstrap/             native-package enrolment scripts
│       ├── detector/              behavioral detection
│       ├── pki/                   hub CA and endpoint certificates
│       ├── scanner/               subnet discovery and asset provenance
│       ├── server/                REST API and embedded console
│       ├── storage/               SQLite persistence and analytics
│       └── threatintel/           IOC feed management
├── packaging/                    native package metadata and scripts
├── scripts/                      build, release, lifecycle, and CLI tools
├── docs/                         operational and protocol notes
└── tests/                        retained C tests
```

## Hub install

Build and sign the hub package with the release workflow, then install it with
the system package manager:

```bash
sudo dpkg -i ominull-hub_1.7.16_amd64.deb
sudo install -m 0600 /dev/null /etc/ominull/admin.key
sudoedit /etc/ominull/hub.env
sudo systemctl enable --now ominull-hub.service
```

`hub.env` is a package-owned environment file. A minimal deployment names the
database, admin-key file, public hub URL, agent TLS URL, binary directory, and
listeners:

```text
OMINULL_DB=/var/lib/ominull/ominull.db
OMINULL_ADMIN_KEY_FILE=/etc/ominull/admin.key
OMINULL_HUB_URL=https://hub.example.invalid
OMINULL_AGENT_HUB_URL=https://hub.example.invalid:9443
OMINULL_BINARY_DIR=/opt/ominull/bin
OMINULL_LISTEN=:9999
OMINULL_TLS_LISTEN=:9443
OMINULL_CLIENT_CERTS=optional
```

The package owns `/opt/ominull/bin/ominull-hub` and the single
`ominull-hub.service`. Database and PKI paths survive package upgrades and hub
purges. Use the canonical `scripts/release.sh` workflow for production.

## Endpoint enrolment

The console renders a short-lived Linux or Windows bootstrap command. The
bootstrap fetches a signed native package, verifies its digest and detached
ECDSA signature, invokes `dpkg` or Windows Installer, then asks the
package-installed agent to write enrollment material. It never copies a
privileged daemon or creates a service definition.

Linux package install:

```bash
curl -fsSL https://hub.example.invalid/download/ominull-agent_1.7.16_amd64.deb -o /tmp/ominull-agent.deb
curl -fsSL https://hub.example.invalid/download/ominull-agent_1.7.16_amd64.deb.sig -o /tmp/ominull-agent.deb.sig
sudo dpkg -i /tmp/ominull-agent.deb
```

Windows package install uses the signed file through Windows Installer:

```powershell
Start-Process msiexec.exe -ArgumentList @('/i', '.\ominull-agent-windows-1.7.16.msi', '/qn', '/norestart') -Wait
```

The final installer identities are `ominull-agent` and `ominull-hub` for
Debian, and `OminullAgent` in Windows Installer metadata. Upgrades preserve
endpoint identity. Purging the Linux agent removes endpoint configuration and
identity but leaves shared hub data alone. Hub purge preserves the database and
PKI. The Windows MSI removal action clears Ominull WFP state before removing
package files.

Self-service enrolment windows can authorize a bounded network and use budget;
each visitor still receives its own one-use ticket. The portal exposes only
retained Linux and Windows commands.

## CLI

`scripts/ominull-cli` reads `OMINULL_HUB_URL` and `OMINULL_API_KEY` and supports:

```text
status
scan [subnet] [profile]
assets
train <ip> <name> <vendor> <category>
alerts
quarantine-mesh <ip> [mac] [reason]
unquarantine-mesh <ip>
agent-versions
agent-update <endpoint-id|all> [version]
```

Run `scripts/ominull-cli help` for usage. Credentials are supplied through the
environment, never committed to the repository.

## REST surface

All protected routes use `X-API-Key`. The admin key controls fleet-wide
operations; tenant keys are scoped to their own endpoints.

| Route | Method | Purpose |
|---|---:|---|
| `/api/v1/hierarchy` | GET | tenants, locations, and endpoint summary |
| `/api/v1/endpoints` | GET | authenticated endpoint inventory |
| `/api/v1/events` | POST | authenticated telemetry batch ingestion |
| `/api/v1/analytics/summary` | GET | cached traffic analytics |
| `/api/v1/assets` | GET | merged agent and scanner asset graph |
| `/api/v1/scanner/scan` | POST | start an on-demand subnet scan |
| `/api/v1/threatintel/sync` | POST | refresh IOC feeds |
| `/api/v1/endpoints/isolate` | POST | host isolation with readiness checks |
| `/api/v1/mesh/quarantine` | POST | mesh quarantine for unmanaged assets |
| `/api/v1/agents/update` | POST | queue a signed package update |
| `/api/v1/agents/update-status` | GET | version and install provenance |
| `/api/v1/enrolment/script` | POST | render a retained-platform bootstrap |
| `/api/v1/enrolment/windows` | GET/POST/DELETE | manage bounded self-service enrolment |
| `/enrol` | GET/POST | self-service ticket portal |

The bootstrap, download, and CA routes are deliberately narrow and do not
serve raw executables. Removed or unknown paths return not found.

## Performance and correctness

The performance plan records equal-workload baselines and budgets. Use these
local loops before a release:

```bash
scripts/version.sh check
scripts/build-packages.sh
OMINULL_RELEASE_VERSION="$(scripts/version.sh show)" scripts/test-package-lifecycle.sh
(cd hub && go test -race ./... && go vet ./...)
```

`scripts/release.sh` runs the retained gates, builds and signs packages, installs
the hub first through the deployment hook, and verifies agent convergence and
native provenance. It accepts `--bridge` only for the transitional Windows
release; final releases use native packages only.

See [`docs/AGENT_SELFUPDATE.md`](docs/AGENT_SELFUPDATE.md),
[`docs/AGENT_TLS.md`](docs/AGENT_TLS.md), and the two refactor plans for the
full release, rollback, retention, and evidence contracts.

## License

See [`LICENSE`](LICENSE).
