# Hub setup and recovery

This is the shipped first-run path for a new Ominull hub. It assumes a
Debian-family amd64 host with `systemd`, `openssl`, and the signed
`ominull-hub_<version>_amd64.deb` package.

## Install

```bash
sudo dpkg -i ./ominull-hub_<version>_amd64.deb
sudo ominullctl setup-token
```

Package post-install creates the one `ominull-hub.service`, its root-only
admin-key file, its root-only setup-token file, the persistent data directories,
and the bundled retained-platform packages. It does not create a Cloudflare
Tunnel, change DNS, open a router, or start a second service.

`ominullctl setup-token` prints the current one-use token only to the local
terminal. `sudo ominullctl setup-token --rotate` invalidates it and creates a
replacement. The token file is owned by root and mode `0600`; symlinked token
paths are rejected.

Open `/setup` over the local hub route. The browser submits the token in the
POST body. The hub consumes it under a file lock, sets a short-lived HTTP-only
setup cookie, and gives the browser a CSRF token. The token is never accepted
from a query string and never enters a URL, service command line, package
metadata, or log.

## Wizard order

The wizard is resumable until completion and runs bounded diagnostics at the
start, after each save, and on demand:

1. Host preflight: package registration, one service, listeners, data path,
   device PKI, bundled signed packages, and basic dependency checks.
2. Local admin and recovery: save the initial operator identity; retain the
   local admin-key and token commands as break-glass access.
3. Network mode: LAN-only, direct WAN, or optional Cloudflare Tunnel + Access.
   Console and agent URLs are separate fields.
4. DNS and server TLS: native self-issued certificate, operator-prepared ACME,
   or operator-supplied certificate and key. The device CA remains separate.
5. Client-certificate proof: keep it optional during migration, then require it
   after every retained agent presents its matching hub-issued certificate.
6. Human authentication: optional native OIDC and optional Cloudflare Access.
7. WAN agent access: prove the agent route returns bounded JSON and no browser
   login redirect.
8. Agent proof: install retained Linux/Windows packages, redeem a profile,
   receive a unique device credential and matching certificate, report a
   heartbeat, and show native package provenance.

Apply validates the complete configuration before writing it. OIDC client
secret is stored in a sibling root-only file; diagnostics return only redacted
configuration. `OMINULL_CLIENT_CERTS=optional` verifies a presented native
certificate while allowing migration; `required` makes the mTLS proof mandatory
after fleet convergence. Listener and certificate changes require a restart of the one
package service. No service-file editing is part of setup.

`/status` remains available after setup. It runs the same checks and has a
rerun action. Completion writes `setup.complete=true`; later package upgrades
preserve it and do not reopen the wizard. A fresh setup token intentionally
opens a recovery session and records an audit event, but does not clear data or
configuration.

When native OIDC is configured, the local console gate exposes **Sign in with
OIDC**. Direct local admin-key recovery remains available if the provider or
the external network is down.

## Network choices

LAN mode needs no public provider. Direct WAN needs operator-controlled DNS,
public TLS, and upstream forwarding to the configured HTTPS listener. The
Cloudflare path is documented in [`CLOUDFLARE.md`](CLOUDFLARE.md); the hub only
validates and records the choice. It never mutates an external security
boundary.

The agent route must not redirect to a human login page. Agents authenticate
with their unique Ominull device credential. A direct native client certificate
is an additional matching proof when present; its subject must match the
credential's endpoint.

In Cloudflare or public-ACME mode, native installers use the host operating
system's public certificate trust for the edge/server certificate. In direct
self-issued LAN mode, they pin the hub's Ominull CA. Both modes use the
hub-issued device credential, and direct connections may add the matching
client certificate.

## Recovery checks

Use the local commands when OIDC or Cloudflare is unavailable:

```bash
sudo ominullctl setup-status
sudo ominullctl setup-token --rotate
```

The status command reports token availability, not the token value. Keep the
admin key and setup-token commands restricted to the hub operator. Never paste
credentials into shell history, URLs, service properties, ticket fields, or
support logs.
