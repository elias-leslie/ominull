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
Windows sources are cross-compiled for the retained native MSI with warnings
treated as errors in CI.

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

## Phase 0 Baseline Measurements & Performance Characterization

Baseline performance captured on 2026-09-03 using `scripts/measure-baseline.sh`
under a representative 100-endpoint telemetry workload:

### Environment & Toolchain
- **OS:** Linux 6.8.0-138-generic x86_64 (Ubuntu 24.04.4 LTS)
- **CPU:** AMD Ryzen 7 7800X3D 8-Core Processor (16 threads)
- **Memory:** 30,685 MB RAM
- **Toolchains:** Go 1.22.2, GCC 13.3.0, MinGW-w64 GCC 13-win32

### Binary Footprints
| Component | Binary | Size | SHA-256 Digest |
|---|---|---|---|
| Linux Agent | `build/ominulld` | 70,760 bytes | `42e92e5b50fbc0e17c00ee64dc825bad1932a722b0adc56d5e51bf75445689f0` |
| Linux Hub | `build/ominull-hub` | 24,258,990 bytes | `07dd1e59bbe66545ea66edb5744b12d055575719c04da55ec70fae371535b71f` |
| Windows Agent | `build/ominulld.exe` | 404,980 bytes | `d1b3d4baf73c6bd82caa63d68c636586cc35bc584b916ecc86cd186d29d574d8` |
| Windows Recovery | `build/ominull_wfp_user.exe` | 270,930 bytes | `cb229d9fd19dcfbcc2740cf9141743337d3fb6af9f58382de312365d541e1d68` |

### Package Lifecycle Verification
- **Sandbox Test:** `scripts/test-package-lifecycle.sh`
- **Elapsed Duration:** 5,069 ms
- **Scope:** Rootless Bubblewrap namespace verifying Debian agent/hub install, upgrade, downgrade refusal, identity preservation, purge, and Windows MSI table inspection.

### Representative Hub & SQLite Latency
| Workload / Benchmark | Operations / Sample | Latency (ns/op) | Latency (ms) | Memory Allocations |
|---|---|---|---|---|
| `BenchmarkHeartbeatIngestion` | 804 iterations | 1,490,184 ns/op | 1.49 ms | 199,777 B/op (2,458 allocs/op) |
| `BenchmarkSQLiteEventBatchInsert` (50 events/batch) | 157 iterations | 7,692,578 ns/op | 7.69 ms | 68,642 B/op (1,462 allocs/op) |
| `BenchmarkResponseGateFailClosed` (404 reject) | 4,165 iterations | 287,708 ns/op | 0.28 ms | 132,807 B/op (1,724 allocs/op) |

### Automation Command
To replicate baseline measurement capture:
```bash
./scripts/measure-baseline.sh
```
