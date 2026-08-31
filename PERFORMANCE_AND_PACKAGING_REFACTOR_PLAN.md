# Ominull performance and native packaging execution plan

## Goal

Cut steady-state CPU, memory, process churn, database work, and telemetry volume without weakening detection, enforcement, identity, update verification, or rollback. Replace every manual agent and hub install path with a native, package-manager-owned install.

This plan ends only when code is committed and pushed, signed releases have reached the production hub and agents in the required order, every production install reports native package provenance, and live resource measurements meet the budgets below.

## Non-negotiable rules

- Read the private operations brief in full before code, fleet, package, or deployment work. It owns topology, credential paths, release order, live verification, and repository hygiene.
- Use `README.md` section 3 for repository layout. Do not infer live topology from tracked files.
- Preserve unrelated working-tree changes. Inspect status and diffs before editing. Never restore, overwrite, commit, or reformat another task's work.
- Use the canonical `st` capabilities for tasks, snapshots, checks, services, VMs, and headless UI checks. Use `scripts/release.sh` for Ominull releases. Do not hand-deploy the hub and agents.
- Keep real usernames, hostnames, domains, LAN addresses, credential paths, credentials, and production captures out of tracked files. Run the authoritative repository hygiene check from the operations brief before each commit and push.
- Never put credentials in process arguments, logs, fixtures, package properties, installer logs, URLs, or tracked files.
- Keep the existing ECDSA release signature and digest verification. Native package registration does not replace release verification.
- Do not bypass failed tests, hooks, package validation, signing checks, or release convergence gates.
- Do not expose profiling endpoints on a production listener. Use benchmarks, loopback-only diagnostics, or temporary local sockets.
- Do not reinstall the workstation that was deliberately uninstalled before this plan was written.
- Do not delete the production hub database during install, upgrade, rollback, remove, or purge.
- Do not mix performance changes with unrelated trust-fabric, copilot-provider, history-rewrite, or native code-signing work.

## Starting evidence and ranked hypotheses

A Linux workstation running the current agent showed a three-second CPU burst pattern. A five-second `pidstat` sample measured 15.6 percent of one logical CPU on average, with one-second spikes of 33 to 45 percent. About 88 percent of sampled CPU time was kernel time. Resident memory was small, so CPU and syscall churn are the first agent problem.

Treat these as hypotheses until a red-capable benchmark or profiler proves them:

1. Linux process attribution is quadratic in practice. `CollectActiveFlows` calls `FindProcessForInode` once per socket, and each call walks every process and file descriptor under `/proc`.
2. Agents repeatedly create external processes for collection, TLS, and transport. Linux forks `curl` for every heartbeat. macOS runs `nettop`, `lsof`, `curl`, and certificate tooling in a three-second loop.
3. Agents report repeated full socket snapshots, causing avoidable endpoint work, network traffic, hub enrichment, detector work, and SQLite writes.
4. Hub ingestion performs repeated per-event work. The request handler and detector both resolve GeoIP, while detector evaluation performs several separately locked storage calls and a communication-profile write per event before the event batch transaction.
5. Analytics and topology queries still scan large retained tables. Existing caches hide repeated polls but do not make cold work cheap.
6. Broad `Store` locking serializes unrelated SQLite work and can magnify ingestion and dashboard latency.

## Completion budgets

Measure CPU as a percentage of one logical CPU. Use ten-minute idle runs and repeat each workload three times after warm-up.

### Agent budgets

| Measure | Linux | Windows | macOS |
|---|---:|---:|---:|
| Idle mean CPU | <= 1% | <= 2% | <= 2% |
| Idle p95 one-second CPU | <= 5% | <= 10% | <= 10% |
| Mean CPU with 64 stable flows | <= 5% | <= 5% | <= 5% |
| Resident memory | <= 32 MiB | <= 64 MiB | <= 64 MiB |
| Enforcement state delivery | <= 5 seconds | <= 5 seconds | <= 5 seconds |
| Lost accepted telemetry | 0 | 0 | 0 |

Also require at least an 80 percent reduction from each platform's measured baseline in steady-loop child-process launches or syscalls, whichever profiler proves dominant. Do not get under budget by increasing the current three-second control latency unless tests prove the new schedule still meets the five-second enforcement limit.

### Hub budgets

Use a production-shaped database with at least 400,000 synthetic event rows and a workload of four agents, each sending up to 64 observations every three seconds while the console polls its normal routes.

- Mean CPU under the steady workload: <= 20 percent of one logical CPU.
- Resident memory under the steady workload: <= 256 MiB with no unbounded growth over 30 minutes.
- Telemetry POST p95: <= 100 ms. p99: <= 250 ms.
- Cached analytics and topology p95: <= 100 ms.
- Cold analytics and topology p95: <= 1 second.
- SQLite busy errors, silently ignored statement errors, dropped committed events, and detector input drops: zero.
- Event, alert, communication-profile, endpoint, isolation, and update results must match the pre-refactor correctness fixture.

If hardware makes an absolute budget impossible, the final report must show the normalized before and after values and at least a 75 percent reduction in the proven hot path. Do not weaken correctness or security to hit a number.

## Phase 0: protect current work and establish one source of truth

1. Read the operations brief, this file, `README.md` section 3, `docs/AGENT_SELFUPDATE.md`, and relevant tests.
2. Run `st ready`, `st pulse`, `st vcs doctor`, and inspect `git status`, staged changes, unstaged changes, and untracked files.
3. Record unrelated dirty paths. Work around them. If a required file overlaps active work, use task coordination rather than overwriting it.
4. Take a workspace snapshot before broad changes.
5. Record the current commit, release version, hub version, agent versions, package provenance, service ownership, package receipts, process counts, and install paths. Store production-specific output outside the repository.
6. Inventory every supported release artifact and every code path that installs, updates, repairs, or removes it. At minimum inspect:
   - `scripts/build-packages.sh`
   - `scripts/release.sh`
   - `scripts/version.sh`
   - `hub/pkg/bootstrap/bootstrap.go`
   - `hub/pkg/deployer/`
   - agent updaters and service installers
   - hub package mapping and download allow-list
   - README and self-update documentation
7. Remove stale-artifact fallback behavior from the intended design. A build must fail when a compiler or packaging tool is absent. It must never package an old binary that happens to exist.

Deliverable: an untracked baseline bundle containing commands, profiler outputs, package inventory, query plans, and redacted production measurements.

## Phase 1: build red-capable performance loops

Do not optimize before these loops run and show the current failure.

### Linux agent loop

Create a committed test or benchmark that models many processes, file descriptors, and sockets. Refactor only enough to let the collector read a fixture proc root. Assert an upper bound on descriptor walks per collection, not only elapsed time. The current one-full-proc-walk-per-socket implementation must fail.

Add a VM-level script that records:

- `pidstat` CPU, faults, context switches, and RSS once per second
- process births by executable
- `strace -f -c` or equivalent syscall totals
- a CPU profile when available
- telemetry batch count, event count, payload bytes, and accepted response count

Run idle, 64 stable sockets, and socket-churn cases.

### Windows agent loop

Use isolated command-line ETW or another background profiler. Measure the service, child processes, socket-table calls, process-path resolution, WinHTTP activity, updater checks, and WFP reconciliation. Do not open desktop tools.

### macOS agent loop

Use isolated command-line sampling. Count and time `nettop`, `lsof`, `curl`, certificate verification, `pfctl`, and shell process launches. Run idle, stable-flow, and churn cases.

### Hub loop

Add benchmarks using temporary SQLite databases and synthetic public-safe fixtures:

- telemetry ingestion for 0, 1, and 64 events
- concurrent ingestion from four and 100 simulated agents
- communication-profile updates
- analytics summary, cold and cached
- topology graph, cold and cached
- retention pruning with concurrent reads and writes

Seed at least 400,000 events. Capture CPU, allocation, mutex, block, and SQLite query-plan evidence. Add a load test that asserts persisted counts and detector input counts, so a faster path cannot pass by dropping work.

Deliverable: one command per platform and hub that is deterministic, agent-runnable, red-capable for the measured resource defect, and saved in project documentation.

## Phase 2: deepen the agent runtime modules

Keep one small runtime interface per platform: collect a snapshot, send one authenticated batch, apply returned control state, and process a verified update. Hide scheduling, caching, process attribution, transport reuse, and enforcement reconciliation inside the implementation.

Do not add an abstract port for a dependency with only one adapter. Test through the runtime or collector interface. Use internal seams only for proc/sysctl/socket fixtures and transport fakes.

### Linux

1. Replace per-socket `/proc` walks with one inode-to-process index per collection pass. Cache process executable paths by PID plus process start identity so PID reuse cannot return a stale path.
2. Implement the operations brief's selected `SOCK_DIAG` byte-count path. Guard every netlink attribute read by payload length. Join socket diagnostics to the one-pass inode index.
3. Cover IPv4 and IPv6 with the same collector contract. Preserve honest unknown values.
4. Replace per-heartbeat `fork` and `exec` transport with an in-process TLS client that reuses connections and still enforces the pinned CA, mutual TLS, redirect restrictions, timeouts, and secret handling. Verify the dependency and package it explicitly.
5. Cache host identity and infrastructure observations until their backing files or routes change. Do not shell out every heartbeat.
6. Allocate reusable bounded buffers rather than rebuilding large heap buffers every cycle where measurements justify it.
7. Never claim an eBPF program or map is attached unless runtime evidence confirms it.

### Windows

1. Reuse WinHTTP session and connection handles while creating a request handle per operation as required. Apply the client certificate on every request, including downloads.
2. Cache process paths by PID plus process creation time. Keep the existing bounded flow-counter table and prove eviction under churn.
3. Reconcile WFP state only when desired state changes. A no-change heartbeat must not enumerate or rewrite filters.
4. Preserve service restart recovery, signed update rollback, mutual TLS, IPv4 and IPv6 enforcement, and dead-man release behavior.

### macOS

1. Profile before choosing implementation. Consolidate socket ownership and byte collection so the three-second loop does not independently launch full `nettop` and `lsof` scans when one measured source can supply both.
2. Cache successful certificate-chain validation for the lifetime of unchanged CA, client certificate, hub address, and leaf certificate. Expiry or file changes must invalidate it.
3. Reuse one transport path and cut shell process creation. A small native collector is preferred if shell tooling cannot meet the CPU and process-churn budgets.
4. Reconcile `pf` only on desired-state changes. Preserve the attached anchor, rule order, bash 3.2 compatibility where scripts remain, and dead-man release.

### Telemetry semantics

Separate flow collection from control heartbeat scheduling, but keep control delivery within five seconds. If deduplication or delta reporting changes event semantics, version the wire field and update detector tests in the same release. Never silently reinterpret cumulative counters as interval bytes or absence as zero.

Deliverable: agent benchmarks green on all three platforms, with enforcement and signed-update tests still green.

## Phase 3: deepen hub ingestion and queries

Create one deep ingestion module with an interface equivalent to:

```text
Ingest(authenticated endpoint, telemetry batch) -> control state or explicit error
```

The HTTP handler should authenticate, decode, call this module once, and encode the result. The module should own validation, endpoint projection, enrichment, threat checks, detection, communication-profile updates, event persistence, and construction of the control response.

Use temporary real SQLite in tests. It is a local-substitutable dependency, so do not place a database port on the external interface merely to mock it.

Implement only changes supported by profiles and query plans, with these known candidates tested first:

1. Resolve GeoIP and threat-intelligence lookups once per unique address in a batch. Remove the current duplicate GeoIP resolution between handler and detector.
2. Snapshot endpoint, policy, exclusion, quarantine, baseline, and update state once per batch where semantics allow. Do not query them once per event.
3. Persist event rows, communication-profile upserts, and produced alerts in a deliberate transaction strategy. Batch communication-profile upserts. Propagate every SQL error.
4. Stop ignoring statement errors in batch insertion. Return a bounded explicit failure and do not acknowledge uncommitted telemetry as stored.
5. Send detector and inference work only after durable acceptance. Replace silent full-channel drops with measured backpressure or a durable bounded handoff. Expose queue depth and drop counters.
6. Replace the broad store mutex only after race, lock, and load tests prove the new locking model. Keep separate locks for in-memory caches. Let SQLite and explicit transactions serialize database writes.
7. Run `EXPLAIN QUERY PLAN` on topology, analytics, recent events, endpoint status, update status, and retention. Add or change indexes only when the plan and benchmark prove the gain.
8. If cold scans remain over budget, add incremental hourly rollups with additive migrations and correctness reconciliation. Do not add rollups speculatively.
9. Bound and prune communication profiles under the same documented retention model as their source events, or rebuild them from retained data. Remove cumulative-since-install ambiguity.
10. Add loopback-only runtime metrics for request latency, batch sizes, SQLite time, queue depth, dropped work, cache hits, and last successful retention. Keep them unavailable on public listeners by default.

Regression fixtures must compare endpoint projection, alerts, anomaly decisions, communication profiles, event rows, isolation control state, baseline rules, and update descriptors before and after the refactor.

Deliverable: hub benchmark and load-test budgets green, no race failures, no silent persistence errors, and no new public debug route.

## Phase 4: replace manual installs with native packages

Create source-controlled packaging definitions under a dedicated `packaging/` tree. Keep `scripts/build-packages.sh` as a thin orchestrator. Generated units, installer scripts, and manifests must come from those files instead of large divergent heredocs.

Use one package identity and one canonical service identity per product and platform. Every package must support fresh install, unattended install, in-place upgrade, rollback, repair, remove, and security purge. Every executable and privileged startup file must be owned by the privileged account and writable only by it.

### Linux agent

- Keep the native `.deb` as the only supported install and self-update artifact.
- Make bootstrap write enrollment material through a secure, package-defined configuration command, verify the signed `.deb`, and install it immediately with `dpkg`. Bootstrap must not copy the daemon or write the systemd unit.
- Add maintainer scripts that distinguish upgrade, remove, and purge correctly.
- Before remove or purge, clear only Ominull-owned IPv4 and IPv6 enforcement state and detach any verified Ominull BPF or TC state.
- Remove stops and disables the service and removes package-owned files. Purge also removes enrollment keys, client identity, agent CA copy, update staging, logs owned by the package, and trust-store links.
- A reinstall or upgrade preserves valid enrollment identity unless purge was requested.
- `dpkg-query` must report the installed version, and `dpkg -S` must own the daemon and unit.

### Windows agent

- Replace the tar bundle and executable self-registration as the final state with an x64 MSI built from a checked-in installer definition.
- Use stable upgrade identity, per-version product identity as required by the chosen MSI upgrade model, machine-wide installation, ServiceInstall and ServiceControl tables, rollback, repair, ARP registration, quiet install, and a real uninstall command.
- Keep keys out of MSI properties and `msiexec` arguments. Provision enrollment material through a protected file or pipe before service start. ACL private files to SYSTEM and Administrators only.
- Install and remove the WFP service, user-mode fallback, recovery tool, failure actions, and firewall state through one package-owned path. Uninstall must clear Ominull WFP filters and sublayer before deleting binaries.
- Update through a verified MSI using quiet `msiexec`, then confirm the registered product version and running service version.
- Do not query `Win32_Product` during inventory because it can trigger repair. Validate the uninstall registry key, MSI product registration, service image path, file ACLs, and one running service process.

### macOS agent

- Replace the tar bundle as the final state with a native `.pkg` built on the macOS build target from a checked-in package root and scripts.
- Use one stable package identifier and receipt. Install the daemon, `pf` helper, LaunchDaemon, CA, client identity, update state, logs, and an explicit uninstall tool at canonical paths.
- Preinstall and postinstall scripts must handle upgrades without duplicating LaunchDaemons or losing identity.
- The uninstall tool must boot out the LaunchDaemon, clear the Ominull `pf` anchor and main-ruleset attachment, remove package files and private enrollment material, and forget the package receipt.
- `pkgutil --pkg-info` must report the installed version. LaunchDaemon label, plist path, executable path, and package identifier must agree everywhere.

### Hub

- Package the Linux hub as a native `.deb` with its binary and systemd unit owned by the package.
- Keep deployment-only config and credentials in root-readable files outside the package payload. Preserve them on upgrade.
- Keep the database and PKI state under persistent state paths. Remove and purge must preserve the database unless a separate, explicit, destructive data-removal command is approved.
- Update the deployment step behind `scripts/release.sh` to install the hub package atomically, validate health, then publish agent packages.

### Bootstrap, provenance, and fleet gate

1. Bootstrap scripts may enroll and invoke a native package manager. They may not write privileged services or binaries directly.
2. Add heartbeat fields for install type, package identifier, registered package version, and provenance status. Determine them once at startup and cache them. Report `unknown` honestly.
3. Store and display provenance in hub endpoint and update status data.
4. Release convergence must fail if a production endpoint is current by binary version but reports manual, unknown, mismatched, or duplicate installation state.
5. After all supported bootstraps use native packages, remove raw bootstrap payloads from the anonymous download allow-list unless a current, signed repair flow still requires a specific payload.
6. Delete or retire legacy unit names, LaunchDaemon labels, service registrations, duplicate binaries, stale update staging, and manual installer code only after the bridge release can migrate them.

Native vendor signing and notarization require external certificates. Keep that work separate if approved credentials are unavailable. Do not fake it and do not weaken the portable release-signature checks. Package-manager registration, ownership, upgrade, rollback, and uninstall must still be completed and deployed.

Deliverable: clean-VM package evidence for every platform and hub, including package-manager registration and uninstall residue checks.

## Phase 5: migration and release compatibility

Windows and macOS need a two-hop migration because old agents understand legacy archives and cannot consume the final native packages directly.

### Bridge release

1. Keep legacy artifact names only for this release.
2. Ship optimized agent code plus an updater that understands the final native package format and reports a new unambiguous capability and install provenance.
3. Make the bridge clean up duplicate legacy registrations without deleting enrollment identity.
4. Release hub first, then all old agents through the old verified update path.
5. Wait until every target reports the bridge version and new update capability.
6. Prove the update from the previous production release. Installing bridge binaries directly does not count.

### Final native-package release

1. Publish `.deb`, `.msi`, `.pkg`, and hub `.deb` artifacts with signatures and digests.
2. Switch hub package mapping and allow-list to the new capabilities while retaining only the compatibility needed for recovery.
3. Release hub first, then one canary per operating system, then the rest of the fleet.
4. Wait until every production endpoint reports the final binary version and registered native package version.
5. Remove bridge-only legacy code after convergence, run the full gates again, and make the final cleanup commit if needed.

Use two distinct semantic versions. Never publish different bytes under one version.

## Phase 6: verification matrix

### Performance and correctness

- Run each red-capable loop before and after.
- Run Go benchmarks with memory results and compare them with a standard benchmark comparison tool.
- Run hub CPU, mutex, and block profiles under the production-shaped load.
- Run each agent for 30 minutes idle and 30 minutes under stable and churn workloads.
- Verify no CPU or memory growth after update, hub loss, certificate failure, and network recovery.
- Confirm detection, baseline readiness, isolation, mesh quarantine, dead-man release, signed update, and rollback behavior on all platforms.

### Package lifecycle

For every agent package and hub package:

1. Fresh unattended install on a clean snapshot.
2. Native package-manager registration and version query.
3. Exactly one service, one startup definition, and one process.
4. Restart and reboot survival.
5. Upgrade from the previous release while preserving enrollment identity and config.
6. Repair or reinstall idempotence.
7. Downgrade refusal.
8. Interrupted update rollback.
9. Uninstall while not isolated.
10. Uninstall while isolated, proving Ominull firewall, WFP, `pf`, BPF, and TC residue is zero.
11. Reinstall after purge.
12. No secrets in process lists, service definitions, installer logs, package metadata, or repository history.

### Project gates

Run every gate listed in the operations brief, including Go race tests, Go vet, Linux and Windows warning-free builds, DPI and baseline tests, macOS script and `pf` tests, JavaScript syntax, version consistency, unified project checks, package ownership and mode audits, secret scanning, and repository hygiene.

Add package-specific validation:

- Debian package metadata, contents, maintainer scripts, ownership, modes, install, upgrade, and purge.
- MSI database validation, quiet install, upgrade, repair, rollback, ARP entry, service control, and quiet uninstall.
- macOS package expansion, scripts, ownership, modes, receipt, LaunchDaemon, upgrade, and uninstall.
- Hub package install and upgrade against a copy of production-shaped persistent data.

Do not accept compile and unit tests as runtime proof. Exercise real services, routes, package managers, and isolated headless UI.

## Phase 7: commit, push, deploy, and observe

1. Inspect the final diff for unrelated work, credentials, private topology, unsafe deletion, stale generated artifacts, and version drift.
2. Commit coherent checkpoints. At minimum use one bridge-release commit and one final native-package release commit. Include the measured hot-path cause and before/after result in commit messages.
3. Push without bypassing hooks.
4. Load release credentials only from approved sources named by the operations brief.
5. Run `scripts/release.sh` in its enforced hub-first order for the bridge version. Wait for full version and capability convergence.
6. Run it again for the final native-package version. Canary each operating system before fleet-wide rollout when the release tooling permits it.
7. Exercise the live health endpoint, telemetry route, analytics, topology, update status, installer generation, package download, and console in an isolated headless browser.
8. Verify all live agents report current binary version, registered package version, native provenance, mutual TLS identity, readiness, and one process.
9. Verify hub and agent resource budgets over at least 30 minutes after final convergence. Check logs and console errors.
10. Confirm the deliberately removed workstation remains uninstalled.
11. Record exact commits, pushed branch, release versions, package hashes, convergence output, before and after measurements, runtime route evidence, UI console evidence, package provenance, rollback readiness, and any external credential blocker.

## Final handoff contract

The final response must state:

- proven agent and hub hot paths
- before and after CPU, memory, process, payload, database, and latency measurements
- package format and identifier for hub and every agent platform
- clean-install, update, rollback, uninstall, and residue results
- commit hashes and pushed branch
- bridge and final release versions
- production hub and fleet convergence evidence
- native package provenance for every production endpoint
- exact remaining blocker, if one depends on an unavailable vendor-signing credential

Do not declare completion with an outdated endpoint, manual or unknown install provenance, a failed gate, an unpushed commit, an undeployed hub, an unverified runtime, or a resource budget miss hidden by lower sampling frequency.
