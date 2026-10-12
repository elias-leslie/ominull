# Ominull

Ominull is an endpoint telemetry, detection, and containment hub for operators managing Linux and Windows devices. It combines a fleet console, observed communication evidence, device identity, and bounded response controls in a self-hosted Linux hub.

![Ominull console in demo mode, showing a synthetic fleet](docs/images/ominull-console-demo.png)

*Console demo mode (`?demo=true`) with a synthetic fleet; no real hosts or addresses.*

## What it does

- **Endpoint collection on both platforms.** The Linux agent loads an embedded
  eBPF CO-RE program ([`agent/linux/bpf/udp.bpf.c`](agent/linux/bpf/udp.bpf.c))
  through libbpf to observe UDP sends and receives with process identity, and
  samples TCP socket counters. The Windows agent consumes kernel network ETW
  events for UDP and reads TCP counters. [Collection semantics](docs/UDP_OBSERVATION.md)
  documents byte units, timing and coverage limits. Flow telemetry is not packet
  capture.
- **Host isolation on Linux and Windows.** Linux applies iptables/ip6tables
  rules. Windows manages Windows Filtering Platform rules from user mode
  ([`agent/windows/wfp_user.c`](agent/windows/wfp_user.c)), with a standalone
  recovery tool that clears Ominull filters without the agent. Isolation state
  persists on the hub and each agent reconciles it, keeping a path back to the
  hub so the host can be released.
- **Per-device identity.** Enrollment issues each endpoint a unique credential
  and a client certificate from the hub's own CA; a presented certificate must
  name the same endpoint as the credential. See [trust fabric](docs/TRUST_FABRIC.md)
  and [agent TLS](docs/AGENT_TLS.md).
- **Signature-verified bootstrap and self-update.** Native `.deb` and `.msi`
  packages carry a SHA-256 digest and a detached ECDSA P-256 signature, checked
  against a public key compiled into the agent before the platform package
  manager runs. See [self-update](docs/AGENT_SELFUPDATE.md).
- **Detection.** Per-process transfer sizes are scored with a modified z-score
  (median and median absolute deviation, which tolerate heavy-tailed traffic
  better than mean and standard deviation), alongside threat-intelligence
  matching, first-seen destinations, stored tuning and explicit exclusions.
- **Router telemetry.** An optional [router collector](scripts/router/README.md)
  sends dnsmasq leases, conntrack flows and DNS observations from an OpenWrt-style
  gateway, so devices without an agent still appear in the asset view and
  communication topology. The hub stays out of the network path.
- **Bounded response.** Forensic collection and other response jobs run only
  under signed, time-limited grants and are recorded in the audit log.

## Measured performance work

- First-seen destination lookups on a synthetic 100,000-profile store went from
  about 21 ms to about 11 µs after adding a covering index and a two-match limit.
  Reproduce with `BenchmarkFirstSeenDestination` in
  [`hub/pkg/storage/destination_history_test.go`](hub/pkg/storage/destination_history_test.go):
  `cd hub && go test ./pkg/storage -run '^$' -bench BenchmarkFirstSeenDestination`.
- Baseline policy resolution with 1,000 unrelated policies dropped from 9.0 ms
  to 27 µs per request. Method and the full table are in
  [docs/evidence/HUB-PREPARATION-REFACTOR.md](docs/evidence/HUB-PREPARATION-REFACTOR.md).

## Current scope

Supported products are the Debian-family Linux hub `.deb`, Linux agent `.deb`, and Windows agent `.msi`. The hub is written in Go and embeds its operator console and SQLite store; the agents are written in C. macOS and other retired paths are outside the supported release; the [design history](docs/DESIGN_HISTORY.md) explains what was cut and why.

The release scripts (`scripts/release.sh`, `scripts/sign-release.sh`) build and sign these packages, but signed packages are not published as GitHub releases. To run your own fleet, build from source, replace the public key in `agent/include/release_key.h`, and sign with the matching private key through `OMINULL_SIGNING_KEY`.

Observation records are bounded evidence, not packet capture or proof of complete network visibility. Learning proposals require explicit application. Package updates and privileged response actions follow their own trust and authorization boundaries.

## Getting started

Use a Debian-family Linux hub host and the verified signed package matching the intended release. Follow [hub setup](docs/SETUP.md) for the package installation command, then obtain the local first-run token:

```bash
sudo ominullctl setup-token
```

Open the hub's `/setup` route on the configured console origin and complete the wizard. The default HTTP listener is port 9999; production console TLS/origin requirements are documented in setup. Use `/install` for the supported enrollment path after configuring an enrollment window/profile.

## Runtime, data, and integrations

The Go hub embeds web assets and SQLite; native Linux/Windows agents report through authenticated REST. Package-managed systemd services, configuration, device PKI, database, and release artifacts have distinct persistence boundaries. Hub purge does not delete retained database/PKI/backup data.

LAN operation is the supported network mode, with an optional Cloudflare Tunnel for remote console access. Native OIDC and Cloudflare console access are optional identity paths; agent transport needs its separate non-interactive route. Router telemetry is an optional passive input and does not put the hub in the network path. See the [project guide](docs/project-guide.md) for setup, identity, package lifecycle, and API detail.

## Development and verification

```bash
scripts/version.sh check
(cd hub && go test -race ./... && go vet ./...)
```

Package lifecycle, signing, canary convergence, and runtime acceptance require their respective release checks. Some historical records under `docs/` mention `st`, the author's private workspace tool; the commands above are the public equivalents. The [project guide](docs/project-guide.md#build-test-and-release) preserves build/test/release commands. Production deployment requires its own authorization and credentials.

## Documentation

- [Project guide](docs/project-guide.md): installation, identity, enrollment, package lifecycle, CLI/API, and release workflow.
- [Hub setup](docs/SETUP.md), [collection semantics](docs/UDP_OBSERVATION.md), and [topology workspace](docs/TOPOLOGY_WORKSPACE.md).
- [Agent TLS](docs/AGENT_TLS.md), [self-update](docs/AGENT_SELFUPDATE.md), and [trust fabric](docs/TRUST_FABRIC.md).
- [Router collection](scripts/router/README.md), [OIDC](docs/OIDC.md), [Cloudflare](docs/CLOUDFLARE.md), and [license](LICENSE).
- [Design history](docs/DESIGN_HISTORY.md) and dated verification records in [docs/evidence](docs/evidence), where real host names and addresses are replaced with placeholders.
- [Security policy](SECURITY.md), including how to report a vulnerability.
