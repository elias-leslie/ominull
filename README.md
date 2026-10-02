# Ominull

Ominull is an endpoint telemetry, detection, and containment hub for operators managing Linux and Windows devices. It combines a fleet console, observed communication evidence, device identity, and bounded response controls in a self-hosted Linux hub.

## What it does

- Collects endpoint TCP counter and passive UDP socket observations with explicit attribution and coverage limits.
- Groups fleet, detection, router, and communication-topology evidence for operator review.
- Enrolls devices with unique credentials and matching client certificates.
- Distributes signed native Linux/Windows packages and verifies update provenance.
- Retains detection tuning, learning-window proposals, and bounded response records.

## Current scope

Supported products are the Debian-family Linux hub `.deb`, Linux agent `.deb`, and Windows agent `.msi`. The hub embeds its operator console and SQLite store. macOS and retired deployment/product paths are outside the supported release.

Observation records are bounded evidence, not packet capture or proof of complete network visibility. Learning proposals require explicit application. Package updates and privileged response actions follow their own trust and authorization boundaries.

## Getting started

Use a Debian-family Linux hub host and the verified signed package matching the intended release. Follow [hub setup](docs/SETUP.md) for the package installation command, then obtain the local first-run token:

```bash
sudo ominullctl setup-token
```

Open the hub's `/setup` route on the configured console origin and complete the wizard. The default HTTP listener is port 9999; production console TLS/origin requirements are documented in setup. Use `/install` for the supported enrollment path after configuring an enrollment window/profile.

## Runtime, data, and integrations

The Go hub embeds web assets and SQLite; native Linux/Windows agents report through authenticated REST. Package-managed systemd services, configuration, device PKI, database, and release artifacts have distinct persistence boundaries. Hub purge does not delete retained database/PKI/backup data.

LAN and direct-WAN operation are supported. Native OIDC and Cloudflare console access are optional identity paths; agent transport needs its separate non-interactive route. Router telemetry is an optional passive input and does not put the hub in the network path. See the [project guide](docs/project-guide.md) for setup, identity, package lifecycle, and API detail.

## Development and verification

```bash
scripts/version.sh check
(cd hub && go test -race ./... && go vet ./...)
```

Package lifecycle, signing, canary convergence, and runtime acceptance require their respective release checks. The [project guide](docs/project-guide.md#build-test-and-release) preserves build/test/release commands. Production deployment requires its own authorization and credentials.

## Documentation

- [Project guide](docs/project-guide.md): installation, identity, enrollment, package lifecycle, CLI/API, and release workflow.
- [Hub setup](docs/SETUP.md), [collection semantics](docs/UDP_OBSERVATION.md), and [topology workspace](docs/TOPOLOGY_WORKSPACE.md).
- [Agent TLS](docs/AGENT_TLS.md), [self-update](docs/AGENT_SELFUPDATE.md), and [trust fabric](docs/TRUST_FABRIC.md).
- [Router collection](scripts/router/README.md), [OIDC/ACME](docs/OIDC_ACME.md), [Cloudflare](docs/CLOUDFLARE.md), and [license](LICENSE).
