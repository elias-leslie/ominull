# Ominull next-generation forensics and response execution plan

Status: proposed; owner decisions recorded; implementation not started

Last reviewed: 2026-09-02

Supported endpoints: Linux and Windows

## Objective

Extend the retained Ominull hub, agents, web console, and installed native CLI
with durable remote response, forensic collection, interactive shells, process
context, and vulnerability correlation. Preserve the current outbound endpoint
control model, tenant isolation, packaging, signed updates, and recovery paths.

This is an execution plan, not a promise that every proposed capability already
exists. Each phase must leave the product releasable and must pass its stated
acceptance gates before dependent work starts.

## Fixed product decisions

- Support Linux and Windows only. Do not add macOS support.
- `ominullctl` is the sole command interface for users, automation, and agents.
  It ships with Ominull and exposes stable JSON output. Do not create a second
  wrapper or mirror the commands in another project.
- Move the existing fleet operations from `scripts/ominull-cli` into
  `ominullctl`. Delete the script after native parity and documentation migration.
  Do not maintain a compatibility implementation beside the native CLI.
- Provide a real interactive shell behind one global setting, disabled by
  default. An administrator changes the setting. Administrators and analysts
  may open and close sessions; auditors remain read-only. Opening a session has
  no secondary authorization workflow.
- A shell runs as the installed agent service identity: `root` on Linux and
  `LocalSystem` on Windows. State this in the console, CLI help, and audit record.
- Exclude packet capture, TLS or HTTP fingerprinting, deep packet inspection,
  Linux eBPF, Windows kernel drivers, and generic WebSockets. A narrowly scoped
  WebSocket transport is allowed only for interactive terminal byte streams.
- Keep SQLite as the hub database until measurements show it is insufficient.
- Make hub-local evidence storage the first supported backend. S3-compatible and
  SFTP export are later adapters. Consumer cloud-drive integrations require a
  separate product decision and threat model.
- Keep the repository's current Business Source License 1.1 unchanged while
  executing this plan. A return to Apache License 2.0 is a separate owner and
  release decision. Versions published before the date specified in `LICENSE`
  retain their existing license.

## Source of truth and execution rules

Before changing code, read `README.md`, `TESTING.md`, `PLAN.md`, `LICENSE`, and
the private Ominull operations brief. Inspect current routes, schemas, packages,
and agent protocol definitions rather than relying on this document alone.

For every task:

1. Confirm the current working tree and preserve unrelated changes.
2. Write or update the protocol/schema contract and tests before its producers
   and consumers diverge.
3. Use repository migrations. Never mutate an existing released migration.
4. Bound request bodies, output, concurrency, retention, and timeouts at ingress.
5. Exercise the real authenticated route or packaged runtime, not only unit tests.
6. Update operator documentation and the installed CLI in the same change as an
   operator-facing API.
7. Record measured results. Do not replace evidence with claims such as zero
   overhead, zero false positives, guaranteed safety, or fixed latency.

Do not run parallel agents against the same shared files. In particular,
`hub/pkg/server/server.go`, storage migrations, embedded console assets, agent
protocol structs, and packaging scripts need one owner at a time. Parallel work
is safe only after a contract is merged and file ownership does not overlap.

## Current architecture to preserve

- The hub is Go, SQLite, and an embedded web console.
- Endpoint agents are C. Linux uses socket diagnostics, `/proc`, and iptables.
  Windows uses native socket APIs and user-mode WFP management.
- Endpoint control is returned through authenticated heartbeat responses. Agents
  initiate connections; the hub does not dial endpoints directly.
- Each endpoint has a unique credential and can use its matching client
  certificate. Tenant and endpoint identity checks remain mandatory.
- Existing roles are administrator, analyst, and auditor. Auditor access is
  read-only.
- Linux and Windows packages, signed release metadata, rollback, containment,
  dead-man release, and standalone Windows recovery are retained capabilities.
- `ominullctl` currently handles local setup-token recovery. Fleet operations
  currently live in a repository script and must be consolidated into the
  packaged binary.

## Security and correctness invariants

- Authenticate every API and stream before allocating expensive resources.
- Bind endpoint operations to tenant, endpoint ID, job ID, and an expiring nonce.
- Reject replayed, expired, cross-tenant, and wrong-endpoint messages.
- Persist state transitions before exposing them to callers. Retried requests
  must be idempotent.
- Never place credentials, secret parameter values, or terminal contents in URLs,
  process arguments, normal application logs, or telemetry events.
- Treat all endpoint data, archive paths, filenames, terminal bytes, and script
  output as hostile input. Never trust client paths or extract an endpoint-made
  archive directly into hub storage.
- Use explicit size, item-count, duration, and concurrency limits. Return a clear
  truncated or partial status when a collector reaches a limit.
- Encrypt all evidence and terminal recordings at rest. Require additional
  capacity and access review before enabling memory capture.
- Hash-chain and signed-receipt storage is tamper-evident, not immutable or WORM.
  Use those terms accurately.
- Keep endpoint transport identity and evidence-signing keys separate.
- Record actor, tenant, endpoint, action, timestamps, outcome, and reason where a
  reason field exists. Do not claim semantic command logs for an interactive
  terminal; record exact input/output frames and session metadata.

## Target module boundaries

Create deep modules with narrow interfaces rather than adding feature branches
throughout the HTTP server:

- `hub/pkg/response`: durable jobs, leases, cancellation, result transitions,
  authorization inputs, and endpoint offer/ack/result protocol.
- `hub/pkg/evidence`: collection manifests, item/chunk validation, local object
  storage, receipts, retention, holds, export, and verification.
- `hub/pkg/terminal`: session state, expiring connection grants, bounded relay,
  recording, and closure. It does not implement shell policy or generic jobs.
- Linux and Windows response workers: bounded dispatchers that translate a typed
  offer into a platform operation and return a typed result.
- `hub/cmd/ominullctl`: local recovery plus a native API client and stable output.
  The CLI owns argument parsing and presentation; server packages own behavior.

Keep transport DTOs separate from stored domain records. Centralize transition
validation and authorization. HTTP handlers should parse, authorize, call a
module, and render a response.

## Shared durable job contract

Forensics and scripts use one durable job model. Do not build separate queues.

Minimum job fields:

```text
id, tenant_id, endpoint_id, kind, requested_by, requested_at,
state, lease_id, lease_expires_at, started_at, completed_at,
cancel_requested_at, attempt, request_json, result_json, error_code
```

States:

```text
queued -> offered -> acknowledged -> running -> succeeded
                                            -> failed
queued|offered|acknowledged|running -> cancel_requested -> cancelled
offered|acknowledged -> queued when a lease expires and retry is safe
```

Requirements:

- Generate job IDs at the hub. Use an idempotency key on creation.
- Offers include job ID, kind, bounded typed payload, lease, and expiring nonce.
- Endpoint acknowledgements and results include job ID and lease ID.
- Ignore duplicate terminal results after the first valid terminal transition.
- Cancellation is cooperative. Report `cancel_requested` until the endpoint
  confirms termination or the job reaches a documented timeout state.
- Requeue only operations explicitly marked retry-safe. Never automatically
  rerun a script or volatile collection after an ambiguous disconnect.
- Retain audit metadata independently of bulky stdout or evidence objects.

## Native CLI contract

The final installed interface is:

```text
ominullctl setup-token [--rotate]
ominullctl setup-status
ominullctl status
ominullctl endpoints list|show
ominullctl scanner scan|status|assets|train
ominullctl alerts list
ominullctl mesh quarantine|release
ominullctl agents versions|update
ominullctl install reports list|show
ominullctl response jobs list|show|cancel
ominullctl forensics gather|list|show|export|verify|hold|release
ominullctl scripts list|show|create|update|retire|run
ominullctl shell status|enable|disable
ominullctl shell open <endpoint-id> [--program powershell|cmd|sh|bash]
ominullctl shell sessions|close
ominullctl software list
ominullctl vulnerabilities list|show|sync
```

Contract requirements:

- Preserve current local setup-token commands and their secure file handling.
- On the hub host, root-run API commands default to the configured local listener
  and `/etc/ominull/admin.key`, so a fresh install works without extra setup.
  Remote use accepts `--url` and `--api-key-file`, or `OMINULL_HUB_URL` and
  `OMINULL_API_KEY_FILE`. Do not accept an API key directly on the command line
  or from a plaintext environment variable.
- `--json` emits one documented versioned JSON shape to stdout. Human-readable
  output is bounded; errors go to stderr.
- List commands require server-side pagination and honor `--limit`; set a safe
  default and hard maximum. Never dump an unbounded fleet or evidence index.
- Exit `0` for success, `1` for runtime/API failure, and `2` for usage errors.
  Define a distinct documented exit for a completed remote job that failed.
- `shell open` enters raw terminal mode only after the session connects and must
  restore the terminal on normal exit, signal, disconnect, and server error.
- Ship `ominullctl` in fresh hub installations. Users and automation must not
  need a repository checkout or a separate orchestration product.

## Web console contract

The embedded console is a human UI over the same authenticated hub APIs. It is
not a second command implementation. Add views as their backend phase lands:

- response-job list/detail, progress, result, and cancel;
- evidence collection launch, bundle/item detail, partial status, export,
  verification result, retention, and hold state;
- interactive terminal session and active-session list;
- immutable script versions, run form, and execution result;
- software inventory and explainable vulnerability match detail.

Keep fleet lists paginated and filters server-side. Show destructive or
high-impact effects plainly, including shell service identity and collection
size estimates. Enforce authorization in the server; hiding a control in the
browser is not authorization. Vendor all new assets in the embedded package,
pin versions and licenses, and avoid remote runtime dependencies.

## Phase 0: reconcile contracts and capture a baseline

Deliverables:

1. Inventory current API routes, auth middleware, heartbeat request/response,
   migrations, audit records, endpoint workers, packaging, and console state.
2. Write versioned DTOs for response offers, acknowledgements, progress, results,
   cancellation, evidence items/chunks, and terminal grants.
3. Add cross-language JSON fixtures consumed by Go and both C agents. Cover
   missing optional fields, unknown fields, maximum sizes, and old-agent behavior.
4. Capture baseline CPU, RSS, heartbeat size/latency, SQLite latency, package
   lifecycle time, and hub behavior under a documented representative workload.
5. Record OS/toolchain minimums, especially Windows ConPTY availability and the
   Linux HTTP/WebSocket library capabilities in supported distributions.

Acceptance:

- Existing tests and package lifecycle pass unchanged.
- Old agents ignore unsupported offers safely and continue normal heartbeats.
- New fields are additive and bounded.
- Baseline commands, fixture data, hardware, sample size, and results are checked
  into test documentation.

## Phase 1: durable response jobs and CLI consolidation

### 1A. Hub job engine

- Add response-job migrations, indexes, transition validation, repository, and
  service layer.
- Add tenant-scoped create/list/show/cancel routes with existing role middleware.
- Attach at most a bounded number of offers to each heartbeat response.
- Add acknowledgement, progress, and result ingestion with replay protection.
- Audit creation, cancellation, lease expiry, retry, and terminal outcome.

### 1B. Endpoint dispatcher

- Implement a small bounded worker pool on Linux and Windows.
- Persist enough local job state to prevent duplicate execution after restart.
- Apply per-kind payload limits before spawning work.
- Linux child processes use process groups, closed inherited descriptors, fixed
  environment, explicit working directory, resource limits, and kill-on-cancel.
- Windows child processes use a Job Object, restricted inherited handles, fixed
  environment, explicit working directory, and kill-on-cancel.

### 1C. Native CLI parity

- Refactor `ominullctl` into subcommands without weakening setup-token behavior.
- Port every retained command from `scripts/ominull-cli` to the Go API client.
- Add endpoint and response-job commands plus stable JSON fixtures.
- Update README, packaging checks, and operator examples.
- Delete `scripts/ominull-cli` only after parity tests pass and no documentation,
  package, or test refers to it.

Acceptance:

- A packaged old agent and new agent both heartbeat against the new hub.
- Duplicate offers do not duplicate execution.
- Cross-tenant results, stale leases, malformed payloads, and replayed results fail.
- Cancellation terminates real Linux and Windows child process trees.
- A fresh package install provides all retained fleet commands through
  `ominullctl --json` with no repository files present.

## Phase 2: local evidence store, upload, and receipt

### 2A. Data model and storage

- Store metadata in SQLite and bytes beneath `/var/lib/ominull/evidence` by object
  digest. Do not store large evidence blobs in SQLite.
- Encrypt bytes before writing them to their final or temporary object files.
  Use authenticated encryption with a random per-item data key, bind tenant,
  bundle, item, and chunk metadata as associated data, and wrap each data key
  with a dedicated hub evidence key. Store that hub key in a root-only file
  outside the database and preserve it through package upgrade and backup.
  Rotation rewraps data keys instead of rewriting every evidence object.
- Resolve all final paths from validated IDs and hashes. Use temporary files in
  the same filesystem, `O_NOFOLLOW` or platform equivalent, restrictive modes,
  fsync, atomic rename, and quota checks.
- Model a bundle as a manifest plus individually uploaded items. Do not require
  endpoints to construct an archive or let endpoint filenames choose hub paths.
- Track expected size, received ranges, SHA-256, content type, collector status,
  and completion. Support resumable fixed-size chunks and reject overlaps or
  mismatched retries.
- Add retention and legal-hold fields. A hold blocks normal retention deletion;
  it is not filesystem immutability.

### 2B. Integrity records

- Generate a dedicated endpoint evidence-signing key during enrollment or agent
  upgrade. Store it with platform protections and register only its public key.
- Sign a canonical manifest containing endpoint identity, job ID, monotonic item
  order, collection times, collector versions/statuses, sizes, and hashes.
- Verify endpoint signatures, item hashes, and declared sizes at the hub.
- Create a hub-signed receipt covering the verified manifest hash, storage object
  hashes, ingestion time, actor/trigger, and previous receipt hash.
- Provide offline `ominullctl forensics verify` for manifest, item, and receipt
  validation without requiring trust in a live database query.

### 2C. Export

- Build exports at the hub from verified objects using a deterministic safe
  layout. Produce the archive and checksum as streamed output with size limits.
- Never include hub credentials or unrestricted local paths in an export.
- Defer remote backends until the local backend, resume path, and verification
  path survive interruption and restart tests.

Acceptance:

- Interrupted uploads resume after agent and hub restart without data corruption.
- Traversal, symlink, sparse-file, overlap, digest, quota, and cross-tenant tests
  fail closed.
- Export then offline verification succeeds from a packaged installation.
- Tampering with a manifest, item, receipt, or receipt-chain link is detected.
- Ciphertext or associated-data tampering fails authentication; key rotation and
  documented backup restore preserve access to existing evidence.

## Phase 3: interactive shell

Start with a transport spike. Do not merge console work until the supported Linux
and Windows agents can establish and cleanly tear down an authenticated loopback
session through the hub.

### 3A. Session and transport

Flow:

1. An operator creates a tenant-scoped shell session through the REST API.
2. A heartbeat offers the endpoint an expiring session ID and one-time grant.
3. The endpoint opens an outbound WSS connection to the configured agent address.
4. The console or `ominullctl` opens an authenticated WSS connection to the
   configured console address.
5. The hub validates both sides, pairs them, relays bounded binary frames, records
   the stream, and closes both sides on any terminal state.

- Use maintained platform/library WebSocket implementations. Do not hand-roll
  framing, masking, fragmentation, TLS, or proxy behavior.
- Bind grants to tenant, endpoint, session, side, and expiry; make them one use.
- Keep REST and heartbeat as the control plane. The terminal endpoint is the only
  new WebSocket route.
- States are `waiting`, `connecting`, `active`, `closing`, `closed`, `failed`,
  and `expired`. Persist every transition and final reason.
- First-release defaults: one active shell per endpoint, four per hub, 30-second
  connect timeout, 15-minute idle timeout, 60-minute maximum duration, and 1 MiB
  maximum queued relay data per direction. Make lower caps configurable; changes
  require measured tests.
- The global setting is `response.shell_enabled=false`. Disabling it rejects new
  sessions and closes active and waiting sessions with an audited reason.

### 3B. Endpoint terminals

- Linux: use `forkpty` with fixed choices `/bin/sh` and `/bin/bash`; validate the
  selected executable, set a minimal environment, and propagate terminal resize.
- Windows: use ConPTY with fixed choices Windows PowerShell, `cmd.exe`, and `pwsh`
  only when installed; contain the tree in a Job Object and propagate resize.
- Do not accept arbitrary executable paths, startup commands, environment maps,
  working directories, or shell profile injection in the first release.
- Close the pseudoterminal and full child tree on toggle-off, timeout, disconnect,
  agent shutdown, hub shutdown, or explicit close.

### 3C. Console and CLI

- Vendor and pin the browser terminal emulator in embedded assets. Do not load it
  from a CDN. Keep the bundle reproducible and include its license notice.
- Display endpoint identity, tenant, service identity, start time, remaining
  duration, connection state, and recording state around the terminal.
- Treat terminal output as untrusted text. The emulator must not enable browser
  escape sequences that can navigate, fetch remote content, or access clipboard
  without an explicit user action.
- The CLI relays raw bytes, sends resize events, handles signals, and always
  restores local terminal settings.

### 3D. Recording and access

- Store timestamped input, output, and resize frames with session metadata under
  the evidence storage controls. Bound per-session bytes and retention.
- Record exact frames, not inferred commands. Interactive editing, full-screen
  programs, aliases, and encrypted subprocesses make command reconstruction
  unreliable.
- Administrators can change the global setting. Administrators and analysts can
  open, list, and close sessions. Auditors can list and inspect metadata and any
  recordings their existing read scope permits.

Acceptance:

- Toggle-off blocks creation and terminates active sessions.
- Real Linux and Windows sessions support input, output, resize, Ctrl-C, process
  exit, disconnect, idle timeout, maximum duration, and hub restart behavior.
- Wrong-tenant, wrong-endpoint, expired, replayed, and reused grants fail.
- Slow-reader and oversized-frame tests stay within memory caps.
- Browser and CLI sessions leave no orphan shell or altered local terminal state.
- Packaged fresh installs provide console and native CLI access to the feature.

## Phase 4: forensic collection profiles

Build collectors on the durable job and evidence protocols. Each collector
returns one of `collected`, `empty`, `unsupported`, `permission_denied`,
`truncated`, `timed_out`, or `failed`, plus bounded diagnostics.

Profiles:

- `diagnostic`: OS/version, interfaces, routes, DNS configuration, resource
  summary, selected service state, bounded system/application logs, and agent
  diagnostics.
- `live_volatile`: process snapshot, socket-to-process snapshot, logged-in
  sessions, network neighbors, firewall state, and bounded loaded-module data.
- `ir_standard`: the preceding profiles plus allowlisted persistence, scheduler,
  event-log, shell-history, and platform-specific artifacts that exist and are
  authorized on the endpoint.

Rules:

- Define every collector's source allowlist, redaction behavior, item/byte cap,
  timeout, privilege expectation, and supported OS versions.
- Snapshot files safely and report inconsistency when a live source changes.
- Do not promise process injection detection from an artifact snapshot.
- Automatic collection is a separate global policy, disabled by default. It maps
  explicit alert types/severities to one profile and enforces fleet concurrency,
  endpoint cooldown, daily byte quota, and deduplication.
- Full memory capture remains disabled until evidence encryption at rest, capacity
  estimation, retention, access review, and platform tooling are complete.
- External tools are never downloaded or executed by name. A later signed tool
  registry must pin source, version, license, platform, digest, fixed arguments,
  timeout, output limits, and redistribution status. Do not bundle tools without
  confirmed redistribution rights.

Acceptance:

- Each supported collector has success, missing-source, permission, timeout,
  truncation, and hostile-filename tests on its real OS.
- A partial collection produces a verifiable bundle with honest item statuses.
- Auto-collection cannot create a trigger loop or exceed quotas after restart.
- The package lifecycle and retained endpoint capabilities still pass.

## Phase 5: versioned script library and execution

- Store immutable script versions. Metadata changes create a new version; used
  versions can be retired but not silently overwritten.
- First-release interpreters are fixed to `/bin/sh` and `/bin/bash` on Linux and
  Windows PowerShell or `cmd.exe` on Windows. Add `pwsh` only when detected.
- Validate a typed parameter schema at creation and execution. Write values into
  a private parameter file or platform-equivalent protected input channel. Do not
  perform textual template substitution into source.
- Do not support secret-valued parameters in the first release.
- Enforce source size, parameter size, output size, duration, concurrency, and
  interpreter allowlists. Use the same process containment as response jobs.
- Return bounded stdout/stderr as job output; store larger explicitly retained
  output through the evidence module.
- UI and CLI use the same API and expose version, digest, actor, target, duration,
  exit status, truncation, and cancellation state.

Acceptance:

- Immutable-version, parameter-injection, output-cap, timeout, cancellation,
  process-tree, replay, tenant, and role tests pass on both platforms.
- Script retirement never changes historical job meaning or audit records.
- Fresh installs can manage and run scripts using only the console or
  `ominullctl`.

## Phase 6: process lineage and executable hashes

Add optional enrichment fields without delaying baseline telemetry:

```text
process_instance_id, pid, parent_process_instance_id, ppid,
process_name, executable_path, command_line, user_identity,
executable_sha256, attribution_status, observed_at
```

- A process instance must include boot identity and process start time so PID
  reuse cannot attach a flow to the wrong executable.
- Linux initially uses bounded `/proc` sampling and current socket attribution.
  Document races and return `unknown` when attribution is not defensible.
- Windows uses a documented real-time ETW process provider plus current socket/WFP
  observations. Security audit Event 4688 is an optional separate artifact, not
  an ETW provider, and command-line content depends on host audit policy.
- Hash in user space from a safely opened executable. Cache by stable file
  identity, size, modification metadata, and algorithm; cap bytes, workers, queue,
  and cache. Report inaccessible or changed files rather than blocking telemetry.
- Preserve raw observation time and attribution confidence. Never invent lineage
  after a race or missing event.

Acceptance:

- PID reuse, rapid exit, renamed/deleted executable, permission denial, hash race,
  boot transition, cache eviction, and event-loss tests pass.
- CPU, RSS, disk reads, heartbeat size, and event loss are measured against the
  Phase 0 workload. Regressions require an explicit reviewed budget.
- Old hubs ignore additive fields and new hubs accept old-agent records.

## Phase 7: software inventory and vulnerability correlation

### 7A. Inventory first

- Collect authoritative installed-package records from supported OS package
  systems and Windows uninstall/package sources. Keep scanner banners separate.
- Store source, vendor, product, version, architecture, install scope, observed
  time, endpoint, and confidence. Preserve raw values beside normalized values.
- Deduplicate by source-aware identity; do not merge unrelated products because
  their display names look similar.

### 7B. Feed ingestion

- Add a separate vulnerability schema and versioned feed snapshots.
- Ingest NVD 2.0 data and the CISA Known Exploited Vulnerabilities catalog from
  their official machine-readable sources. Follow published pagination, rate
  limits, conditional requests, and update metadata.
- Keep the last complete known-good snapshot. Build a new snapshot off to the
  side, validate counts and references, then atomically activate it.
- Treat EPSS as a separate optional feed with its own provenance and date.

### 7C. Matching

- Parse CPE data and version ranges with their defined comparison semantics.
- Produce match candidates with exact evidence, feed snapshot, confidence, and
  reason. Never use a banner regex as the final vulnerability verdict.
- Distinguish `matched`, `possible`, `not_affected`, and `insufficient_data`.
- Prioritization may combine severity, KEV membership, exposure, confidence, and
  asset context, but must preserve each source value independently.

Acceptance:

- Official conformance examples and curated affected/not-affected boundary cases
  pass, including prerelease and vendor-specific versions.
- Corrupt, partial, rate-limited, and interrupted syncs leave the active database
  usable and report staleness.
- Queries are tenant-scoped, paginated, explainable, and reproducible from a feed
  snapshot ID.

## Later work requiring separate plans

Do not pull these into the critical path:

- S3-compatible and SFTP evidence export adapters, after a credentials and retry
  model is approved and the local store is proven.
- Consumer cloud-drive storage, after deciding whether it belongs in the product.
- Host-local decoy listeners, only if the product still needs them. Avoid decoy
  IP ownership, protocol emulation claims, and claims that every connection is
  malicious without a separate network and false-positive design.
- Identity-threat detection. Accurate Kerberos, NTLM relay, and directory
  replication detections require domain-controller event sources and an explicit
  identity data model; endpoint socket telemetry alone is insufficient.
- Full memory acquisition and third-party collection frameworks, after evidence
  encryption, licensing, signing, capacity, and support boundaries are complete.

## Performance and capacity method

Do not set marketing numbers before measurement. For each phase:

1. Re-run the Phase 0 representative workload on the same hardware and dataset.
2. Report median, p95, and maximum for CPU, RSS, I/O, database latency, endpoint
   heartbeat latency/size, job latency, errors, and dropped/truncated work.
3. Add stress cases at configured limits and verify memory remains bounded.
4. Set release budgets from observed baseline deltas and product requirements.
5. Store commands, configurations, raw results, and environment metadata so the
   result can be reproduced.

Interactive shell latency depends on network path and cannot have a universal
fixed guarantee. Vulnerability query performance depends on data volume and
indexes. SQLite remains the default unless these measurements prove a need for a
different store.

## Verification gates

### Every change

Run the smallest relevant tests during development, then the documented project
gates before a release checkpoint:

```bash
scripts/version.sh check
(cd hub && go test -race ./... && go vet ./...)
node --check hub/pkg/server/web/app.js
bash -n scripts/*.sh
scripts/build-packages.sh
OMINULL_RELEASE_VERSION="$(scripts/version.sh show)" scripts/test-package-lifecycle.sh
```

Also run C builds with repository warning settings and Windows cross-compilation.
Never bypass a failed hook, signature, package, rollback, or convergence gate.

### Protocol and security

- Cross-version fixture tests for hub, Linux agent, and Windows agent.
- Tenant, role, endpoint binding, replay, expiry, malformed input, and size limits.
- Restart tests at every persisted state and network interruption point.
- Fuzz parsers and transition handlers that consume endpoint or operator input.
- Verify no credential, private endpoint data, terminal content, or evidence bytes
  enter ordinary logs, URLs, telemetry, packages, or tracked fixtures.

### Runtime and packaging

- Exercise authenticated routes through real middleware.
- Exercise console paths in an isolated browser target.
- Install built Debian and Windows packages in clean test systems and run the
  actual CLI, agents, service lifecycle, update, rollback, recovery, and removal.
- Verify existing telemetry, containment, mesh quarantine, dead-man release,
  scanner provenance, alerts, mTLS identity, and signed updates remain functional.

## Release sequence

Release one independently reversible phase at a time:

1. Hub additive schema/API support with features disabled.
2. Packaged native CLI support.
3. Linux and Windows agent support, initially disabled.
4. Console support.
5. Enable on a retained canary endpoint and observe the documented window.
6. Expand to the retained fleet only after package, runtime, security, rollback,
   resource, and evidence-integrity gates pass.

Use the repository release process: install the signed hub package first, then a
retained agent canary, then remaining retained endpoints. Never hand-copy agent
binaries.

## Agent dispatch contract

Give an implementation agent one numbered slice at a time. The task must name:

- phase and subphase;
- exact desired behavior and non-goals;
- owned files or module boundary;
- prerequisite contract and migration version;
- required unit, integration, package, and runtime evidence;
- compatibility expectation for old hub/agent versions;
- artifacts to update, including CLI help and operator documentation.

The agent must return:

- changed files and schema/protocol changes;
- commands run and exact pass/fail result;
- real route, package, or endpoint evidence where applicable;
- measured resource deltas for agent or hot-path changes;
- unresolved risks and the next dependency, without silently expanding scope.

Do not assign hub schema, both endpoint implementations, console, and CLI as one
task. Merge the contract and hub foundation first. Then Linux, Windows, CLI, and
console work may proceed in parallel only when their files do not overlap.

## Completion definition

This program is complete only when a fresh supported Ominull installation:

- exposes every retained script command and every command added by this plan
  through the packaged `ominullctl` binary;
- has no second maintained fleet-command implementation;
- creates, audits, cancels, and recovers durable response jobs;
- collects and verifies bounded forensic evidence with honest partial results;
- opens and records globally toggleable Linux and Windows interactive shells;
- runs immutable versioned scripts with bounded execution;
- enriches flows with defensible optional process context and executable hashes;
- inventories software and explains reproducible vulnerability matches;
- passes package, runtime, security, compatibility, rollback, and resource gates;
- leaves all new high-impact features disabled by default until configured.
