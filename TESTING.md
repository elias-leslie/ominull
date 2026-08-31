# Testing

Ominull gates use equal workloads and real runtime paths. A compile-only result
is not package, service, route, containment, or rollout evidence.

## Local gates

```bash
scripts/version.sh check
(cd hub && go test -race ./... && go vet ./...)
node --check hub/pkg/server/web/app.js
bash -n scripts/*.sh
scripts/build-packages.sh
OMINULL_RELEASE_VERSION="$(scripts/version.sh show)" scripts/test-package-lifecycle.sh
```

The C feedback loops compile with warnings enabled and cover baseline parsing,
Linux process attribution, socket collection, and release-signature parsing.
Windows sources are cross-compiled for both bridge and final native modes with
warnings treated as errors in CI.

## Retained capability checks

Exercise authenticated Linux and Windows telemetry, endpoint heartbeat status,
scanner and asset provenance, threat-intelligence matching, behavioral alerts,
baseline readiness, IPv4 and IPv6 isolation, mesh quarantine, dead-man release,
standalone Windows recovery, mTLS identity, signed update rollback, and native
package uninstall. Check that accepted telemetry and control responses are
durable and that errors fail closed.

## Package checks

The lifecycle script runs in an isolated root. It verifies Debian ownership,
registration, upgrade, downgrade refusal, identity preservation, purge, and
hub-data/PKI preservation. It extracts the MSI and checks its service metadata,
uninstall action, recovery tool, and absence of a kernel payload.

## Runtime checks

Run the real hub route through its middleware. Removed paths must return 404;
tenant keys must fail on admin routes; operator routes must reject malformed
input. Use a managed headless browser or direct HTTP client for console checks.
Record status, package provenance, process count, CPU, RSS, database latency,
and errors during the production observation window.

## Production release

Use `scripts/release.sh`. It installs the signed hub package first, then rolls a
retained canary and the remaining retained endpoints. Never hand-copy an agent
binary or bypass a failed signature, lifecycle, rollback, or convergence gate.
