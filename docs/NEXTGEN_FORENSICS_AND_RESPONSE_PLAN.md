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
- `ominullctl` is the sole CLI for users, automation, and agents. It ships with
  Ominull and exposes stable JSON output. Do not create a second wrapper or
  mirror the commands in another project. The embedded console remains the only
  place that can activate endpoint shell and script execution.
- Move the existing fleet operations from `scripts/ominull-cli` into
  `ominullctl`. Delete the script after native parity and documentation migration.
  Do not maintain a compatibility implementation beside the native CLI.
- Do not add a global or persistent per-endpoint shell setting. A shell exists
  only after an administrator or analyst with an active tenant response session
  clicks the endpoint's shell action in the console. One click creates one
  short-lived endpoint grant and one terminal session. Closing or expiring the
  session returns the endpoint to its dormant state.
- Script execution follows the same rule. Operators may manage immutable script
  definitions through the console or native CLI, but only the console can run or
  schedule them. A schedule is an explicit durable authorization for a fixed
  script digest and fixed endpoint set.
- A response session is separate from normal console login and covers one tenant.
  The default absolute lifetime is eight hours with a 30-minute response idle
  lock. Switching tenants or reaching the absolute limit requires a new strong
  authentication event. Ordinary shells and one-off scripts within that session
  do not repeatedly prompt the operator.
- Cross-device WebAuthn using a platform passkey and QR scan is the preferred
  built-in method. Built-in TOTP is the no-cost compatibility fallback. Hardware
  FIDO keys, number-matched push, external identity providers, separate signer
  hosts, Vault, KMS, and HSM integrations are optional. Core response capability
  must never require paid services or new hardware.
- Give every tenant an independent response signing key. The normal hub process,
  platform administrator credentials, static API keys, and other tenants must
  not be able to authorize endpoint execution. A separate response authority
  validates the operator proof and signs typed endpoint grants.
- A shell runs as the installed agent service identity: `root` on Linux and
  `LocalSystem` on Windows. State this in the console and audit record.
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
6. Update operator documentation and, when the route is CLI-accessible, the
   installed CLI in the same change. Test console-only response routes against
   static API keys and CLI credentials instead of mirroring them in the CLI.
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
- The current packaged hub runs as `root` and owns one service. Same-host response
  key isolation is not credible until the normal hub runs under a dedicated
  unprivileged identity and the response authority runs under another identity.
  This plan intentionally changes the package to own those two services while
  preserving one-command installation, upgrade, recovery, and removal.
- Linux and Windows packages, signed release metadata, rollback, containment,
  dead-man release, and standalone Windows recovery are retained capabilities.
- `ominullctl` currently handles local setup-token recovery. Fleet operations
  currently live in a repository script and must be consolidated into the
  packaged binary.

## Security and correctness invariants

- Authenticate every API and stream before allocating expensive resources.
- Reject static API keys, CLI credentials, and ordinary console sessions on
  shell creation and script run/schedule routes. Those routes require a valid
  tenant response session and a proof from its browser-bound key.
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
- Keep tenant response keys separate from transport, evidence, setup, and release
  keys. There is no fleet-wide response key and no platform-admin override.
- The response authority accepts typed actions only. It must never expose an
  interface that signs caller-supplied bytes.
- Keep the release-signing private key offline and outside both hub processes.
  Otherwise the update path bypasses every response control in this plan.
- Record actor, tenant, endpoint, action, timestamps, outcome, and reason where a
  reason field exists. Do not claim semantic command logs for an interactive
  terminal; record exact input/output frames and session metadata.

## Target module seams

Create deep modules with narrow interfaces rather than adding feature branches
throughout the HTTP server:

- `hub/pkg/response`: durable jobs, leases, cancellation, result transitions,
  authorization-grant references, and endpoint offer/ack/result protocol.
- `hub/pkg/responseauth`: response-session policy, WebAuthn and TOTP verification,
  browser-key binding, typed action validation, per-tenant grant signing, signer
  partitioning, authentication-method policy, and recovery transitions.
- `hub/cmd/ominull-response-authority`: a separately packaged internal process
  exposing the narrow typed interface from `hub/pkg/responseauth`. It has a
  signer-owned minimal store for tenant keys, response memberships,
  authenticators, method policy, sessions, and audit. It has no hub database,
  telemetry, package-update, evidence, or shell access.
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

## Response authorization contract

### Normal login and response sessions

Normal console authentication grants no shell or script execution capability.
An administrator or analyst also needs matching response membership for the
currently selected tenant. Hub role and authority membership are both required;
neither one grants response alone. The response authority then issues a session
bound to:

```text
operator_id, tenant_id, browser_session_id, browser_public_key,
allowed_action_kinds, issued_at, idle_expires_at, absolute_expires_at
```

- Default absolute lifetime is eight hours. Default response idle lock is 30
  minutes. Activity may move the idle deadline but never the absolute deadline.
- Generate a non-exportable ephemeral signing key inside the response-authority
  browser context during unlock. The hub receives only its public key. A stolen
  normal session cookie is not enough to create response actions from another
  browser.
- Keep the ephemeral key in that context's memory. Closing the browser loses it
  and locks response. Do not expose it to the hub page or persist it in local
  storage, IndexedDB, or a downloadable file.
- Browser binding prevents reuse of a stolen cookie from another browser. It does
  not defeat malicious code already running in the unlocked console origin. The
  tenant scope, idle lock, absolute limit, target caps, and signer partition bound
  that accepted risk. A tenant may optionally require a new WebAuthn event for
  every action when it needs stronger protection.
- Scope one response session to one tenant. Switching tenants locks response and
  requires another strong authentication event.
- Display the active tenant, operator, remaining time, idle state, active shells,
  running scripts, and a persistent `Lock response` control in the console.
- Locking or absolute expiration rejects new actions and expires unstarted grants.
  Give active shells a short reauthentication grace period, then close them.
  Already running scripts obey their signed execution limit; an explicit lock-all
  action may request cooperative cancellation.

### Built-in authentication methods

The base package must work without an external identity provider, paid push
provider, managed key service, or purchased authenticator.

- Preferred no-cost method: WebAuthn with user verification using a platform
  passkey on the current device or a nearby phone. Allow the browser's standard
  cross-device hybrid transport and QR flow when the browser and authenticator
  support it. Require a trusted HTTPS relying-party origin.
- Compatibility fallback: built-in TOTP using any standards-compatible
  authenticator application. Rate-limit attempts, lock after repeated failures,
  and never represent TOTP as phishing-resistant.
- Optional methods: device-bound FIDO keys and external WebAuthn providers.
- Optional push adapter: require number matching and show deployment, tenant,
  operator, request time, and response-session expiration. Never send a blind
  approve/deny notification. Allow only one outstanding prompt and rate-limit
  new prompts. Repeated denied or expired prompts lock response temporarily.
- Authentication-method policy is tenant-owned. A tenant may require WebAuthn or
  a stronger configured method. The ordinary hub interface cannot downgrade that
  minimum. Change it through an existing qualifying response session or local
  recovery.

For browser-managed cross-device WebAuthn, the browser and authenticator own the
QR payload, proximity checks, and hybrid transport. Ominull supplies the relying-
party ID, trusted origin, one-use challenge, timeout, and user-verification
requirement; it must not generate, parse, or reimplement the QR protocol. Before
starting the ceremony, the authority page displays the deployment, tenant, and
requested eight-hour scope. If the supported browser cannot offer hybrid
transport, use a current-device passkey, security key, or built-in TOTP instead.

### Browser-bound action proof

Every shell, one-off script, forensic collection, or durable schedule request
contains a canonical action digest and a signature from the active browser key.
The response authority verifies that proof, the response session, operator role,
tenant, action type, target count, limits, and freshness. It then signs one compact
endpoint grant per target. The normal hub queues and relays the grants but cannot
create them.

Minimum endpoint grant fields:

```text
version, grant_id, tenant_id, endpoint_id, action_kind, action_digest,
operator_id, response_session_id, issued_at, expires_at, nonce, signer_key_id
```

- Shell grants name one endpoint, one terminal session, and one fixed program.
- One-off script grants name one immutable script digest, parameter digest,
  endpoint, execution limit, and attempt count.
- Schedule grants also name a fixed endpoint snapshot, start/end window,
  recurrence, and maximum runs. They never cover current and future group members.
- Agents pin their tenant response public key. They reject wrong-tenant,
  wrong-endpoint, expired, replayed, altered, unknown-version, or revoked grants.
- A response grant is not an agent configuration setting. It cannot permanently
  enable a shell, generic command execution, or arbitrary executable path.

Require another strong authentication event before changing tenant, creating a
recurring schedule, authorizing work beyond the current response-session limit,
exceeding the tenant's script batch threshold, changing response trust, enrolling
a new authenticator through remote recovery, or distributing a new agent release.

### Response authority isolation

Ship one protocol with deployment adapters of increasing isolation:

- Portable default: one package installs the unprivileged hub and response
  authority as separate OS identities. They communicate through a restricted
  local socket. Store software response keys in signer-only files and use an
  existing TPM or OS-backed key store automatically when available.
- Hardened portable option: place the response authority and its key in a small
  separate VM connected through a narrow private channel. A container alone is
  not a root-compromise boundary because it shares the host kernel.
- MSP/MSSP cloud option: run the authority in a separate account, project, or
  subscription with private ingress. Use one asymmetric key per tenant in a
  software vault, KMS, or HSM. Divide tenants among signer processes and workload
  identities so one always-running identity cannot sign for every customer.
- High-isolation option: let a customer own its response authority or signing key.

Hardware and managed services strengthen isolation but never unlock extra product
features. The portable software-key path remains supported and honest about its
limit: it protects against compromise of the unprivileged hub process, not full
root or kernel compromise of the same machine.

### Recovery and trust rotation

- Provide a local root-only `ominullctl response-auth recovery-token` command that
  emits a short-lived one-use authenticator-enrollment token. It cannot authorize
  a shell, script, collection, or trust-policy downgrade.
- Enroll at least two authenticators when practical. Record enrollment, removal,
  recovery, method-policy changes, session unlock/lock, grant creation, and denial
  in both hub and response-authority audit records.
- Trust-root replacement requires the current tenant response authority or local
  endpoint recovery. A hub administrator cannot silently replace the public key
  pinned by existing agents.
- Rotation supports an overlap window signed by the outgoing tenant key. Agents
  retain no retired key after convergence and the documented recovery window.

## Shared durable job contract

Forensics and scripts use one durable job model. Do not build separate queues.

Minimum job fields:

```text
id, tenant_id, endpoint_id, kind, requested_by, requested_at,
state, lease_id, lease_expires_at, started_at, completed_at,
cancel_requested_at, attempt, authorization_grant_id,
request_json, result_json, error_code
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
- Any job that runs code or collects sensitive endpoint data includes a valid
  endpoint response grant. The queue cannot manufacture or broaden that grant.
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
ominullctl response-auth status|recovery-token
ominullctl forensics list|show|export|verify|hold|release
ominullctl scripts list|show|create|update|retire
ominullctl shell sessions|show|close
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
- The CLI cannot unlock response, open or attach to a shell, run or schedule a
  script, or launch a forensic collection. Those actions require the embedded
  console and its browser-bound response proof. CLI credentials cannot call the
  console-only mutation routes.
- `response-auth recovery-token` is a local root-only recovery command. It cannot
  create a response session or endpoint action.
- Ship `ominullctl` in fresh hub installations. Users and automation must not
  need a repository checkout or a separate orchestration product.

## Web console contract

The embedded console is a human UI over the same authenticated hub APIs. It is
not a second command implementation. Add views as their backend phase lands:

- response unlock/lock, authenticator enrollment, QR challenge, method policy,
  remaining lifetime, tenant scope, and recent response activity;
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

The response authority owns its confirmation origin and page. The main hub may
redirect there but cannot render or rewrite the tenant and scope confirmation.
The response-authority browser context keeps the ephemeral key in memory and
returns only origin-checked signatures over canonical action digests. It never
exposes the key to the hub page or persistent browser storage.

## Phase 0: reconcile contracts and capture a baseline

Deliverables:

1. Inventory current API routes, auth middleware, heartbeat request/response,
   migrations, audit records, endpoint workers, packaging, console state, hub
   process privileges, and every route capable of changing endpoint behavior.
2. Write versioned DTOs for response offers, acknowledgements, progress, results,
   cancellation, evidence items/chunks, response sessions, browser proofs,
   endpoint grants, trust rotation, and terminal grants.
3. Add cross-language JSON fixtures consumed by Go and both C agents. Cover
   missing optional fields, unknown fields, maximum sizes, and old-agent behavior.
4. Capture baseline CPU, RSS, heartbeat size/latency, SQLite latency, package
   lifecycle time, and hub behavior under a documented representative workload.
5. Record OS/toolchain minimums, especially Windows ConPTY availability and the
   Linux HTTP/WebSocket library capabilities in supported distributions.
6. Write the response threat model for stolen cookies, static keys, hub process
   compromise, root compromise, signer compromise, malicious operators, tenant
   crossover, agent compromise, authenticator recovery, and signed updates.
7. Prove the supported WebAuthn relying-party origins for public cloud, local
   portable, and disconnected deployments. Define when platform passkeys,
   cross-device QR, or TOTP is available instead of guessing at browser behavior.

Acceptance:

- Existing tests and package lifecycle pass unchanged.
- Old agents ignore unsupported offers safely and continue normal heartbeats.
- New fields are additive and bounded.
- The threat model names which deployment modes resist hub-process compromise and
  which do not resist root or hypervisor compromise.
- Baseline commands, fixture data, hardware, sample size, and results are checked
  into test documentation.

## Phase 1: response authorization, durable jobs, and CLI consolidation

### 1A. Hub privilege split and packaging

- Move the normal hub process from `root` to a dedicated unprivileged account.
  Inventory every file, socket, listener, package, certificate, database, backup,
  and setup operation first. Move only the privileges the runtime needs.
- Keep root-only setup and recovery work in local `ominullctl` commands and package
  maintainer scripts. Never make the web process a general privileged helper.
- Package the response authority under a different unprivileged identity. Its
  signing keys and state are unreadable by the hub identity.
- Proposed installed layout is `/opt/ominull/bin/ominull-response-authority`,
  `/etc/ominull/response-authority.env`, signer-owned state beneath
  `/var/lib/ominull-response-authority`, and a restricted control socket beneath
  `/run/ominull-response-authority`. Confirm these paths against Debian policy and
  package lifecycle tests before freezing them.
- Give the hub only a restricted local client socket to the typed authority
  interface. The authority has no access to the hub database or agent packages.
- Make install, upgrade, rollback, backup, removal, purge, status, and recovery
  cover both services as one Ominull product. Update the current one-service
  package contract and tests explicitly rather than leaving hidden service drift.

### 1B. Response authority foundation

- Implement tenant response-key creation, software-key storage, rotation,
  revocation, and public-key distribution. Use existing TPM or OS-backed storage
  when available without requiring it.
- Implement WebAuthn registration and authentication with user verification,
  one-use challenges, origin and relying-party checks, replay protection, and
  browser-supported cross-device hybrid transport.
- Implement built-in TOTP enrollment, verification, encrypted secret storage,
  attempt limits, temporary lock, recovery, and honest security labeling.
- Define the optional number-matched push adapter at a real seam. Ship no push
  implementation until a provider or maintained delivery mechanism is selected.
- Implement browser-key certification, response-session state, tenant method
  policy, typed action validation, per-target grant signing, and signer audit.
- Keep response membership in the authority's minimal store. Hub roles may
  nominate an operator, but the hub cannot assert or rewrite response membership
  on each request. Tenant response administrators grant and revoke it through the
  authority workflow; local recovery bootstraps the first membership.
- Keep first-run setup simple: the package wizard provisions the first tenant
  response key, first response administrator, and either a platform passkey or
  TOTP enrollment in the same guided flow. It prints no private key or reusable
  enrollment secret and leaves local recovery available if enrollment is deferred.
- Deny generic byte signing, cross-tenant signing, platform-admin inheritance,
  static API-key authorization, method-policy downgrade, and unbounded target sets.
- Add a production local-socket adapter and an in-memory adapter for tests. Add a
  private-network adapter only when the separate-VM or cloud deployment exists.

### 1C. Hub job engine

- Add response-job migrations, indexes, transition validation, repository, and
  module interface.
- Add tenant-scoped create/list/show/cancel routes with existing role middleware.
  Shell and script creation routes also require response-session middleware and a
  valid browser-bound action proof.
- Attach at most a bounded number of offers to each heartbeat response.
- Add acknowledgement, progress, and result ingestion with replay protection.
- Audit creation, cancellation, lease expiry, retry, grant ID, and final outcome.

### 1D. Endpoint dispatcher and trust

- Enroll or migrate a tenant response public key onto each Linux and Windows
  endpoint without weakening existing transport identity.
- Verify the complete signed endpoint grant before parsing the larger action
  payload or starting work. Cache used grant IDs and nonces across restart for the
  grant lifetime.
- Implement a small bounded worker pool on Linux and Windows.
- Persist enough local job state to prevent duplicate execution after restart.
- Apply per-kind payload limits before spawning work.
- Linux child processes use process groups, closed inherited descriptors, fixed
  environment, explicit working directory, resource limits, and kill-on-cancel.
- Windows child processes use a Job Object, restricted inherited handles, fixed
  environment, explicit working directory, and kill-on-cancel.

### 1E. Native CLI parity

- Refactor `ominullctl` into subcommands without weakening setup-token behavior.
- Port every retained command from `scripts/ominull-cli` to the Go client.
- Add endpoint, response-job, response-auth status, and local recovery commands
  plus stable JSON fixtures.
- Do not add shell-open, shell-attach, script-run, script-schedule, or collection-
  launch commands. Keep console-only response mutations out of API-key automation.
- Update README, packaging checks, and operator examples.
- Delete `scripts/ominull-cli` only after parity tests pass and no documentation,
  package, or test refers to it.

Acceptance:

- A fresh package installs and operates the unprivileged hub and isolated local
  response authority without external services or purchased hardware.
- Compromise of the hub identity cannot read response private keys or call a
  generic signing interface.
- Platform passkey, phone QR, TOTP fallback, local recovery, method-policy lock,
  rotation, signer outage, and package rollback paths work in clean test systems.
- A stolen normal session cookie, static API key, browser proof from another
  tenant, expired QR, replayed assertion, missing browser key, or downgraded method
  cannot create a response grant.
- A packaged old agent and new agent both heartbeat against the new hub.
- Duplicate offers do not duplicate execution.
- Cross-tenant results, stale leases, malformed payloads, grants signed by another
  tenant, and replayed results fail.
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
  with a dedicated hub evidence key. Store that key outside the database in a
  file readable only by the unprivileged hub identity and local recovery tooling,
  then preserve it through package upgrade and backup.
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

1. An administrator or analyst unlocks response for the selected tenant in the
   console using a configured strong authentication method.
2. The operator clicks the shell action on one endpoint. The browser signs the
   canonical action digest with its response-session key.
3. The response authority validates the proof and signs a one-use grant for that
   tenant, endpoint, terminal session, fixed program, and expiration.
4. The hub stores the session and returns its grant through the endpoint's next
   authenticated heartbeat.
5. Only after validating the grant, the endpoint creates a pseudoterminal and
   opens an outbound WSS connection to the configured agent address.
6. The console opens the operator side through its active response session. The
   hub validates both sides, pairs them, relays bounded binary frames, records the
   stream, and closes both sides on any final state.

- Use maintained platform/library WebSocket implementations. Do not hand-roll
  framing, masking, fragmentation, TLS, or proxy behavior.
- Bind grants to tenant, endpoint, session, side, and expiry; make them one use.
- Keep REST and heartbeat as the control plane. The terminal endpoint is the only
  new WebSocket route.
- There is no global switch and no persistent endpoint-enabled state. Before the
  grant is accepted, the agent has no listener, WSS connection, pseudoterminal,
  shell process, generic execution token, or reusable shell state. The terminal
  route is inert when no exact active session exists.
- States are `closed`, `waiting`, `connecting`, `active`, `closing`, `failed`, and
  `expired`. `closed` is the initial and final endpoint state. Persist every hub
  transition and final reason.
- First-release defaults: one active shell per endpoint, four per tenant, 30-second
  connect timeout, 15-minute terminal idle timeout, 60-minute terminal maximum,
  and 1 MiB maximum queued relay data per direction. Make lower caps configurable;
  changes require measured tests.
- Response-session idle or absolute expiration rejects new terminals. Give active
  terminals a two-minute reauthentication grace period, then close both sides and
  the child tree if the operator does not unlock response again.

### 3B. Endpoint terminals

- Linux: use `forkpty` with fixed choices `/bin/sh` and `/bin/bash`; validate the
  selected executable, set a minimal environment, and propagate terminal resize.
- Windows: use ConPTY with fixed choices Windows PowerShell, `cmd.exe`, and `pwsh`
  only when installed; contain the tree in a Job Object and propagate resize.
- Do not accept arbitrary executable paths, startup commands, environment maps,
  working directories, or shell profile injection in the first release.
- Close the pseudoterminal and full child tree on response lock, timeout,
  disconnect, agent shutdown, hub shutdown, grant revocation, or explicit close.

### 3C. Console

- Vendor and pin the browser terminal emulator in embedded assets. Do not load it
  from a CDN. Keep the bundle reproducible and include its license notice.
- Display endpoint identity, tenant, service identity, terminal limit, response-
  session limit, connection state, and recording state around the terminal.
- Treat terminal output as untrusted text. The emulator must not enable browser
  escape sequences that can navigate, fetch remote content, or access clipboard
  without an explicit user action.
- The first release is console-only. Static API keys and `ominullctl` cannot create
  or attach to a terminal. The CLI may list and close existing sessions.

### 3D. Recording and access

- Store timestamped input, output, and resize frames with session metadata under
  the evidence storage controls. Bound per-session bytes and retention.
- Record exact frames, not inferred commands. Interactive editing, full-screen
  programs, aliases, and encrypted subprocesses make command reconstruction
  unreliable.
- Administrators and analysts assigned to the active tenant can open, list, and
  close sessions while response is unlocked. Auditors can list and inspect
  metadata and any recordings their existing read scope permits. Platform
  administrators receive no implicit tenant response permission.

Acceptance:

- An endpoint has no shell process, listener, or WSS connection before a valid
  one-use grant and returns to that state after every final outcome.
- Normal login, static API key, CLI credentials, another tenant's response session,
  or a platform-admin role without tenant assignment cannot create a shell.
- One phone/passkey/TOTP unlock permits subsequent terminals within the same
  tenant response session without repeated prompts. Tenant switch, idle lock, and
  eight-hour absolute expiration require another qualifying authentication event.
- Real Linux and Windows sessions support input, output, resize, Ctrl-C, process
  exit, disconnect, idle timeout, maximum duration, and hub restart behavior.
- Wrong-tenant, wrong-endpoint, expired, replayed, and reused grants fail.
- Slow-reader and oversized-frame tests stay within memory caps.
- Browser sessions leave no orphan shell or persisted ephemeral browser key.
- Packaged fresh installs provide the full console workflow using platform
  passkeys or built-in TOTP without an external service or purchased hardware.

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

- Manual collection starts only from the console under an active tenant response
  session. The signed grant fixes endpoint, profile, collector policy, limits, and
  expiration. Static API keys and the native CLI may inspect or export evidence
  but cannot launch collection.
- Define every collector's source allowlist, redaction behavior, item/byte cap,
  timeout, privilege expectation, and supported OS versions.
- Snapshot files safely and report inconsistency when a live source changes.
- Do not promise process injection detection from an artifact snapshot.
- Automatic collection is a tenant policy created in the console and disabled by
  default. Its durable signed authorization fixes alert types, severities,
  profile, endpoint scope, expiration, fleet concurrency, endpoint cooldown,
  daily byte quota, and deduplication. It cannot authorize shell or script work.
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
- CLI credentials and ordinary console sessions cannot launch a collection or
  broaden an automatic collection policy.
- The package lifecycle and retained endpoint capabilities still pass.

## Phase 5: versioned script library and execution

- Store immutable script versions. Metadata changes create a new version; used
  versions can be retired but not silently overwritten.
- Allow the console and native CLI to manage script definitions. Only the console
  can create a run or schedule, and it must present a browser-bound proof from an
  active tenant response session. Static API keys cannot execute scripts.
- A one-off run within an unlocked response session does not prompt again. The
  response authority signs a separate endpoint grant for the exact script digest,
  parameter digest, execution limit, endpoint, and attempt.
- Freeze every schedule to an immutable script digest and explicit endpoint
  snapshot. Include start, end, recurrence, maximum runs, and execution limit.
  Never target all current and future endpoints or dynamically expand a group.
- Require a new qualifying authentication event for a recurring schedule, work
  extending beyond the current response session, or a batch above the tenant's
  configured threshold. Signing a schedule never enables arbitrary later scripts.
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
- Console and CLI use the same read and library-management routes and expose
  version, digest, actor, target, duration, exit status, truncation, and
  cancellation state. Run and schedule routes remain console-only.

Acceptance:

- Immutable-version, parameter-injection, output-cap, timeout, cancellation,
  process-tree, replay, tenant, and role tests pass on both platforms.
- Normal login, static API key, CLI credential, altered script, changed parameter
  digest, expanded endpoint set, expired response session, and another tenant's
  grant cannot start a script.
- One response unlock permits subsequent one-off scripts for that tenant without
  repeated prompts. Tenant switch, durable schedule, threshold batch, and
  eight-hour expiration behave as specified by the authorization contract.
- Script retirement never changes historical job meaning or audit records.
- Fresh installs can manage definitions through the console or `ominullctl`, and
  can run scripts through the console using platform passkeys or built-in TOTP
  without an external service or purchased hardware.

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

## Authentication and transport references

Implementation agents must verify the current revision and test actual supported
browsers and operating systems. Start with these primary references:

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [NIST SP 800-63B-4 authentication guidance](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [FIDO passkeys and cross-device authentication](https://fidoalliance.org/passkeys-2/)
- [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [CISA number-matching guidance](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf)
- [RFC 6455 WebSocket protocol](https://www.rfc-editor.org/rfc/rfc6455)

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
- WebAuthn origin, relying-party ID, challenge, user-verification, expiry, replay,
  and wrong-browser tests. TOTP includes attempt-limit, clock-window, reuse,
  recovery, and method-downgrade tests. Push adapters include number-match,
  duplicate-prompt, denial, flood, and expiry tests.
- Prove a stolen normal cookie or static API key cannot create response actions.
  Prove one signer partition cannot use another partition's tenant keys.
- Verify that hub-process credentials cannot read signer keys, replace endpoint
  response trust, invoke generic signing, or publish an unsigned agent update.
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

1. Hub privilege split and two-service package lifecycle.
2. Response authority, built-in authentication, and additive hub schema support.
3. Packaged native CLI support without response activation commands.
4. Linux and Windows response-key trust and grant validation, still dormant.
5. Console response-session and action workflow.
6. Activate on one retained canary endpoint and observe the documented window.
7. Expand to the retained fleet only after package, runtime, security, rollback,
   resource, and evidence-integrity gates pass.

Use the repository release process: install the signed hub package first, then a
retained agent canary, then remaining retained endpoints. Never hand-copy agent
binaries.

## Agent dispatch contract

Give an implementation agent one numbered slice at a time. The task must name:

- phase and subphase;
- exact desired behavior and non-goals;
- owned files or module seam;
- prerequisite contract and migration version;
- required unit, integration, package, and runtime evidence;
- compatibility expectation for old hub/agent versions;
- artifacts to update, including CLI help and operator documentation;
- response-authorization requirement, tenant scope, and whether the route is
  console-only or CLI-readable.

The agent must return:

- changed files and schema/protocol changes;
- commands run and exact pass/fail result;
- real route, package, or endpoint evidence where applicable;
- measured resource deltas for agent or hot-path changes;
- unresolved risks and the next dependency, without silently expanding scope.

Do not assign hub schema, both endpoint implementations, console, and CLI as one
task. Merge the contract and hub foundation first. Then Linux, Windows, CLI, and
console work may proceed in parallel only when their files do not overlap.
Give the hub privilege split, authority package, signer store, WebAuthn/TOTP,
browser session, endpoint grant verifier, and cloud signer adapter separate slices.
No slice may weaken the no-cost portable path or add a shared cross-tenant key.

## Completion definition

This program is complete only when a fresh supported Ominull installation:

- exposes every retained command from `scripts/ominull-cli` and every CLI command
  added by this plan through the packaged `ominullctl` binary;
- has no second maintained fleet-command implementation;
- installs an unprivileged hub and isolated response authority with a complete
  no-cost platform-passkey or TOTP path;
- uses independent tenant response keys and has no hub or platform-admin path that
  can authorize execution across customers;
- creates, audits, cancels, and recovers durable response jobs;
- collects and verifies bounded forensic evidence with honest partial results;
- opens and records one-session, per-endpoint Linux and Windows shells only after
  UI action under an active tenant response session;
- runs or schedules immutable versioned scripts only after the equivalent UI and
  signed-grant workflow;
- enriches flows with defensible optional process context and executable hashes;
- inventories software and explains reproducible vulnerability matches;
- passes package, runtime, security, compatibility, rollback, and resource gates;
- leaves every endpoint dormant until it receives a valid one-use or explicitly
  scheduled tenant grant.
