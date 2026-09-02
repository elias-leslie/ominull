# DNS and DHCP incident remediation plan

## Primer for the next agent

This plan exists because a previously stable legacy thermostat and several voice-assistant
devices lost cloud connectivity within hours of two new Ominull network features being put
into production. The network router had been configured to use the Ominull Hub as its primary
DNS upstream. Ominull also began binding UDP port 67 to observe DHCP broadcasts. No other
known network change occurred during the incident window.

The thermostat kept its expected address and hardware identity but both vendor applications
reported it offline. Restarting the thermostat, restarting the router, restoring automatic
router DNS, and stopping the Ominull Hub did not repair the cloud registration. Recovery
required resetting account data on the thermostat, removing it from the vendor application,
and adding it again. This means the Hub-off test ruled out an ongoing block, but it did not
rule out Ominull DNS as the event that broke the device's durable cloud session.

The strongest code-level cause is a DNS cache-format defect in the Hub version active during
the outage. The cache key allowed queries with different client capabilities to share one
entry, and cached replies retained client-specific EDNS formatting. A response cached for a
modern client could be replayed to a strict non-EDNS IoT client. Commit `da3cdba` partially
fixed this after the outage. Remaining size-limit and cache-key defects mean production DNS
must stay disabled until the tests and fixes below are complete.

The DHCP observer is not a DHCP server. Its code has no send path and the real router
continued issuing acknowledgments. It still binds the DHCP server port by default, which is
too risky and too easy to mistake for an authoritative service. This work makes both DNS and
DHCP observation explicit opt-ins.

Production state at the latest checkpoint:

- The affected client is online after account reset and re-enrollment; the operator
  reconfirmed it through the vendor application after Hub 1.8.3 returned to service.
- The router uses automatic DNS.
- The Ominull Hub runs version 1.8.3 with its normal HTTP/TLS listeners active.
- DNS reports `disabled`, and the Hub has no TCP/UDP 53 or UDP 67 listener.
- No automatic Hub restart timer remains.
- No endpoint isolation or mesh quarantine targeted the affected client.
- Thirty forced, cache-cleared ARP probes each received exactly one response from the same
  device identity. No active address conflict was present.
- macOS agent support was intentionally removed. It is out of scope for this release and
  may return as a future agent; missing macOS files are not a gate failure.

## Status

Remediated and deployed, 2026-09-02. Production Hub 1.8.3 is active with DNS and passive
DHCP observation disabled. The network router remains on automatic DNS. The affected legacy
IoT client recovered only after its cloud account data was reset and the device was removed
and re-added in its vendor application; the operator confirmed it still online after the
corrected Hub deployment.

Do not copy private fleet addresses, hostnames, account data, or hardware identifiers into
this file. Use the repository's documented `10.0.0.x` stand-ins in any added test fixture.

## Incident evidence

- Ominull DNS forwarding was the only new dependency in the affected clients' network path.
- Several legacy IoT clients lost cloud connectivity after the router began using Ominull
  as its primary upstream resolver.
- The DNS build active during the incident cached client-specific upstream replies. An EDNS
  response seeded by one query could therefore be replayed to a non-EDNS client. Commit
  `da3cdba` partially corrected this after the incident by caching the upstream response
  before delivery formatting and removing cached OPT records for non-EDNS clients.
- The current implementation still treats 1232 bytes as the default UDP limit for a client
  without EDNS. RFC 1035 clients advertise no size extension and require the 512-byte limit.
- The current miss path sets the TC bit after removing authority and extra records but can
  still transmit an oversized answer section. It does not call `dns.Msg.Truncate`.
- The cache-hit path and cache-miss path use separate response-formatting logic. Their
  behavior can drift again.
- The cache key omits DNSSEC DO state and query class. Replies with different semantics can
  share a cache entry.
- DNS currently defaults to `:53`, so installing or restarting a Hub silently turns it into
  a network resolver.
- The scanner's passive DHCP collector binds UDP port 67 by default. It only reads packets
  and contains no response path, so it was not a DHCP server. Holding a DHCP service port by
  default is still unsafe and makes the feature look authoritative.
- Repeated fresh ARP probes during isolation produced one reply per request from one stable
  device identity. No active address conflict was observed.
- No Ominull endpoint isolation or mesh quarantine targeted the affected client.

## Safety constraints

- Keep production Ominull stopped until a build with opt-in DNS and DHCP listeners is ready.
- Do not change router DNS away from automatic during remediation or verification.
- Preserve unrelated work already present in the shared checkout. At incident start, tracked
  and untracked response-authority work was in progress, including changes under
  `hub/pkg/server`, `hub/pkg/storage`, `agent/linux`, and packaging scripts.
- Do not build a production release from a checkout containing unrelated uncommitted changes.
  Use the assigned checkout only after that work reaches a safe checkpoint, or use a clean
  release directory from the exact remediation commit if isolation is required.
- Follow the private operations brief for release order, credentials, live paths, and repo
  hygiene. Never place those values in this public repository.

## Shared-checkout ownership and overlap

`st pulse` at the first code checkpoint reported zero writers, readers, specialists, sessions,
or task claims. It also reported an ownerless dirty checkout. No live agent owns the existing
changes, but they remain user work and must be preserved.

Existing unrelated changes at that checkpoint:

- Modified: `agent/linux/main.c`
- Modified: `hub/cmd/ominullctl/main.go`
- Modified: `hub/pkg/server/server.go`
- Modified: `hub/pkg/server/telemetry_ingestion.go`
- Modified: `hub/pkg/storage/storage.go`
- Modified: `scripts/build-packages.sh`
- Untracked response-authority, evidence, script, terminal, vulnerability, and test packages
  under `hub/` and `tests/`

The required private-identifier scan later found a real LAN subnet literal inside the
pre-existing `hub/cmd/ominullctl/main.go` work. That one literal was replaced with the
documented `10.0.0.0/24` public stand-in. This is a deliberate hygiene-only overlap; all
other changes in that file still belong to the pre-existing response-authority work and
must not be staged with this incident remediation.

Incident work should use these clean files where possible:

- `hub/pkg/dns/dns.go`
- `hub/pkg/dns/dns_test.go`, or a new focused DNS test file
- `hub/pkg/scanner/scanner.go`
- `hub/pkg/scanner/modern_discovery_test.go`, or a new focused scanner test file
- `hub/cmd/main.go`
- a new file in `hub/pkg/server` if an exported scanner control is required
- this plan and public operator documentation

Avoid editing dirty `hub/pkg/server/server.go`. A new file in the same package can expose an
explicit DHCP-snoop start method without changing that file. A patch-version bump may update
the already-dirty `agent/linux/main.c` because Ominull compiles one version into every agent.
That overlap is mechanical and required by the single-version invariant, but it must happen
only after the pre-existing diff is captured and compared so no response-authority work is
lost. Do not stage or commit those unrelated hunks as incident work.

Production packaging cannot safely use the dirty working directory because uncommitted
response-authority code would enter the binaries. Before release, either wait for that work
to reach its own commit or build from a clean directory at the exact remediation commit. If
a clean release directory is used, bring in only deployment helpers required by the private
operations brief and keep all credentials outside Git.

## Progress checkpoints

- [x] Read the private operations brief and applicable Ominull/debugging instructions.
- [x] Capture service listeners, package timeline, DNS event history, isolation state, and
  affected-client network evidence.
- [x] Run Hub-off isolation with router on automatic DNS.
- [x] Rule out active address conflict with repeated forced ARP resolution.
- [x] Recover affected client through account reset and application re-enrollment.
- [x] Create this handoff plan.
- [x] Inspect shared-checkout ownership and preserve the existing dirty work inventory.
- [x] Attempt a workspace safety snapshot. `st snap` could not run because this host does
  not have the configured Btrfs workspace root mounted. Continue with narrow clean-file
  edits, explicit diff inspection, and no staging of unrelated work.
- [x] Add focused DNS tests and observe the intended failures. The red run produced 9,319
  byte non-EDNS replies instead of the 512-byte maximum, EDNS replies over 10 KB instead of
  the negotiated 700/1,232-byte limits, and one cache entry shared by DO and non-DO queries.
- [x] Complete the listener-default red test. The initial privileged-port test skipped, so
  `DHCPSnooper` gained an injectable listen address for tests while retaining UDP 67 in the
  production constructor. The unprivileged test then failed because background startup
  opened its listener without opt-in.
- [x] Implement one DNS delivery formatter and complete cache-key isolation. Cache entries
  now remain full upstream copies; delivery rebuilds client OPT state and applies
  `dns.Msg.Truncate` at 512 bytes or the capped EDNS limit. Cache keys include class, type,
  CD, DO, and RD state.
- [x] Make DNS and DHCP snooping opt-in. Default DNS is `disabled`; normal scanner startup
  no longer starts DHCP snooping; `--dhcp-snoop` is the explicit start path.
- [x] Pass focused tests: `go test ./pkg/dns ./pkg/scanner ./cmd`.
- [x] Complete cache-safety review. Queries carrying EDNS options now bypass the shared
  cache, and cache-hit delivery echoes the current request ID and question rather than
  retaining either field from the client that populated the entry.
- [x] Re-run focused tests after cache-safety changes: all DNS, scanner, and Hub command
  packages pass.
- [x] Pass focused race tests: `go test -race ./pkg/dns ./pkg/scanner ./cmd`.
- [x] Pass the full Hub race suite: `cd hub && go test -race ./...` (including the
  unrelated dirty response-authority packages already present in the checkout).
- [x] Pass Hub static analysis: `cd hub && go vet ./...`.
- [x] Pass `scripts/version.sh check` and `st check --check` at version 1.8.2.
- [x] Reconcile stale native gate instructions. macOS is intentionally unsupported, and
  the current Linux and Windows commands come from `scripts/build-packages.sh` rather than
  retired source paths in the older operations gate block.
- [x] Pass current native gates: warning-clean Linux and Windows agent builds, Windows WFP
  recovery build, Linux baseline parser test, Linux collector regression test, DER-signature
  parser test, and JavaScript syntax check.
- [x] Update the private operations brief so future agents do not restore retired macOS code
  or run stale native compiler commands.
- [x] Run repository hygiene scans. Task-owned files contain no private identifiers.
  `gitleaks` reports only the one documented historical placeholder. The required tracked
  scan exposed one real subnet in unrelated dirty `ominullctl` work; it was substituted as
  documented in the shared-checkout section above and will be re-scanned before commit.
- [x] Commit the isolated remediation as `e7beaf9` with no unrelated response-authority
  files or hunks.
- [x] Create a clean release clone from `e7beaf9` and bump all retained version sites to
  1.8.3. Production packages must come only from this clean release tree.
- [x] Document safe listener defaults in `README.md` and mark the older v1.8.1 production
  port assumptions as superseded by this incident plan.
- [x] Pass full repository gates and private-identifier scans. The clean 1.8.3 release tree
  passed the full Hub race/vet suite, JavaScript and shell syntax, retained native tests,
  warning-clean package builds, signing verification, and isolated MSI/Debian lifecycle.
- [x] Produce clean signed 1.8.3 packages without unrelated working-tree code.
- [x] Deploy Hub first, then converge every reachable retained agent. One intentionally
  powered-off laptop correctly retains a pending update until it returns.
- [x] Verify live Hub health: package 1.8.3 and service active, normal HTTP/TLS listeners
  open, DNS status `disabled`, and no TCP/UDP 53 or UDP 67 listener.
- [x] Confirm the recovered client remains online in the vendor application after deployment.
- [x] Verify deployed Hub and endpoint package hashes match the clean release artifacts and
  record the exact checksums in the private operations brief.

The first release attempt completed all local stages and produced signed 1.8.3
packages from the clean tree. The deploy helper then stopped before installation because it
cannot push files into the intentionally stopped Hub container. No production service was
started and no package was installed during that attempt. Once the signed build was ready,
the container was started and the canonical release resumed immediately.

Deployment resumed after the corrected signed build was ready. Hub 1.8.3 installed first,
then all reachable retained agents converged on 1.8.3 with native provenance. One Windows
laptop remains at its older version with a pending update because it is intentionally powered
off; this is expected deferred convergence, not a release failure.

## Required changes

### 1. Lock down DNS response behavior with failing tests

Add package-level integration tests using a local fake upstream. Cover all of these before
changing production code:

- EDNS query populates cache, equivalent non-EDNS query receives no OPT record.
- Non-EDNS UDP response never exceeds 512 bytes and has TC set when records are omitted.
- EDNS UDP response respects the client's advertised size, capped at Ominull's safe UDP size.
- TCP response is not UDP-truncated.
- Cache hit and miss apply identical client formatting.
- DO and non-DO requests cannot reuse one cache entry.
- Query class participates in the cache key.
- Requests with anything other than one question return FORMERR and never enter cache.

The focused red/green command is `cd hub && go test ./pkg/dns`.

### 2. Use one DNS delivery formatter

Create one helper used by cache hits, cache misses, and policy responses where applicable.
It must operate on a copy and leave the cached upstream message unchanged.

- Non-EDNS UDP: remove OPT, then call `Msg.Truncate(dns.MinMsgSize)`.
- EDNS UDP: preserve the request's DO state, use at least 512 bytes, cap at 1232 bytes, and
  call `Msg.Truncate`.
- TCP: preserve a valid request OPT response but do not apply the UDP size cap.
- Reset the response ID to the current request ID after copying.

### 3. Make network listeners opt-in

- Change `--dns-listen` default from `:53` to disabled. Port 53 must open only when an
  operator supplies a non-disabled address explicitly.
- Add `--dhcp-snoop`, default false. Do not bind UDP 67 unless explicitly enabled.
- Keep scan scheduling independent from DHCP snooping.
- Report disabled listener state through existing status APIs and startup logs.
- Document both flags and their safe defaults.

### 4. Verify before release

Run the focused tests first, then the canonical project gates from the private operations
brief. At minimum:

- `cd hub && go test -race ./...`
- `cd hub && go vet ./...`
- `scripts/version.sh check`
- `st check --check`
- the documented native-agent compiler and script checks
- the repository secret and private-identifier scans

Inspect the staged diff and release contents. Confirm no unrelated working-tree files, real
identifiers, credentials, or private addresses enter the commit or packages.

### 5. Release and runtime proof

- Bump the patch version once the fix and tests pass.
- Use the canonical release script. Deploy Hub first, then converge agents as required by the
  single-version invariant.
- On the live Hub, verify HTTP and agent TLS listeners are active.
- Verify no process listens on TCP or UDP 53.
- Verify no process listens on UDP 67.
- Verify the DNS status API reports disabled. Prove DHCP snooping is disabled through the
  startup journal and the absence of a UDP 67 listener; no DHCP status route exists yet.
- Run direct runtime DNS tests against a temporary high-port listener, not production port
  53. Cover UDP without EDNS, UDP with EDNS, TCP, truncation, cache hit, and mixed-client order.
- Verify the router remains on automatic DNS and the recovered IoT client remains online.
- Record deployed package checksums and runtime evidence in the private operations brief.

## Acceptance criteria

- A default Hub start cannot become a DNS resolver or bind a DHCP service port.
- Mixed EDNS, non-EDNS, DNSSEC, and query-class traffic cannot cross-contaminate cache entries.
- Every UDP response fits the negotiated client limit and carries correct truncation state.
- Focused regression tests fail against the incident behavior and pass against the fix.
- Full project gates pass without bypasses.
- Production Hub runs normally with ports 53 and 67 closed.
- Router stays on automatic DNS and affected client connectivity remains stable.

## Rollback

If the corrected Hub fails its runtime checks, stop the Hub. Do not restore the router's
Ominull DNS setting. Preserve the failed package, journal excerpt, listener inventory, and
focused test output. Revert only the release commit through the normal versioned release
path after identifying the failed check.
