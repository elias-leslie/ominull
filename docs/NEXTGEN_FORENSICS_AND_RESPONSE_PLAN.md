# Ominull next-generation forensics and response execution plan

Status: **AUDITED WORKING TREE; NOT RELEASE-READY; RESPONSE EXECUTION AND
INTERACTIVE SHELL ARE NOT SAFE TO USE**

Last reviewed: 2026-09-02

Supported endpoints: Linux and Windows

## Implementation audit as of 2026-09-02

Code presence is not completion. None of the new response phases has passed its
acceptance gate. Treat the current files as an unsafe prototype to salvage or
replace, not as released behavior.

| Phase | Audited state | Evidence and blocking gaps |
|---|---|---|
| Phase 0 | Not accepted | Go DTOs and copied JSON examples exist. Both C agents do not consume the fixtures. Bounds, old-version behavior, canonical signed-byte fixtures, baseline measurements, and the response threat model are absent. |
| Phase 1A | Unsafe prototype deployed | A second service and Unix socket exist, including on the observed production installation. Both the hub and authority run as `root`; signer state is root-owned; `NoNewPrivileges` is disabled. This provides no hub-process key isolation and conflicts with the documented one-service v1.8.3 package contract. |
| Phase 1B | Unsafe prototype | Per-tenant Ed25519 key files, basic TOTP calculation, and Unix-socket RPC exist. There is no SQLite signer store: `Authority` keeps `authenticators`, `sessions`, and `recoveryTokens` in Go maps (`hub/pkg/responseauth/authority.go:40-47`), so every session, enrollment, and recovery token is lost on restart and no signer audit record is written anywhere. Memberships, method policy, TOTP attempt/reuse controls, and WebAuthn are absent. General hub authentication can reach enrollment, and handlers trust caller-supplied operator identifiers. |
| Phase 1C | Incomplete prototype | `response_jobs`, basic leases, REST handlers, and heartbeat offers exist. The full transition model, progress, tenant and endpoint binding on ACK/result/cancel, replay protection, retry-safety policy, durable cancellation, and complete audit do not. Handlers do not recompute the action digest from the typed payload. |
| Phase 1D | Reject, unsafe to execute | Linux and Windows use substring searches rather than a bounded protocol parser (`agent/src/service.c` `ProcessResponseOffersWindows`, `agent/linux/main.c`). They do not verify the grant signature, action digest, tenant, endpoint, expiry, signer key, nonce, or replay state; the word `grant` does not appear in the agent tree at all. They acknowledge before validation and then post a hard-coded `"state":"succeeded"` result for work that was never performed. The Windows parser also reads `lease_id` from the whole response body rather than from the matched offer. There is no worker isolation or durable duplicate prevention. |
| Phase 1E | Failing | `ominullctl` does not compile at this checkpoint (`hub/cmd/ominullctl/main.go:750`, `declared and not used: raw`). It retains a plaintext API-key environment fallback (`main.go:174`, `OMINULL_API_KEY`), contains forbidden `shell open`/`shell exec` paths (`main.go:695-725`), prints the terminal connection token to stdout (`main.go:718`), and reports any parseable forensic manifest as `"verified": true` without cryptographic checks (`main.go:592`). Parity and pagination are incomplete. |
| Phase 2 | Unsafe storage prototype | AES-GCM helpers and basic SQLite rows exist and the item encryption path works. Every gap in the original row is confirmed. Detailed findings are listed under "Phase 2 re-verification" below. |
| Phase 3 | No usable shell; unsafe surface exposed | There is no WebSocket route, PTY, ConPTY, pairing, or byte relay. Detailed findings are listed under "Phase 3 re-verification" below. |
| Phase 4 | Unsafe demo collector | Linux uploads one `uname` JSON object, hard-codes `"tenant_id":"default"` in the manifest, sends an empty `"sha256":""` for the single item, performs no grant verification, and runs inline with the heartbeat (`agent/linux/main.c`). Windows collection profiles and all bounded profile contracts are absent. |
| Phase 5 | Storage prototype only, cross-tenant execution path | Immutable rows and source hashes exist. Every gap in the original row is confirmed, and the run route additionally reads a script version with no tenant check. Detailed findings are listed under "Phase 5 re-verification" below. |
| Phase 6 | DTO fields only | Optional fields were added to the Go `Event` struct, but no durable schema path, agent production, boot identity, process lineage, ETW provider, executable hashing, or measurement evidence exists. |
| Phase 7 | Schema demo only | Tables and caller-supplied ingestion exist. There is no endpoint inventory collector, NVD/KEV fetcher, feed snapshot lifecycle, CPE/version-range implementation, or scheduler. The current matcher is `strings.Contains(strings.ToLower(product), strings.ToLower(pattern))` (`hub/pkg/vuln/store.go:231`) and ignores version ranges while labeling results as authoritative. |

Audit evidence captured on 2026-09-02:

- Production observation showed both services active as `root`, with root-owned
  authority runtime and state paths. Service presence proves deployment only.
- `go build ./...` in `hub/` fails on `cmd/ominullctl/main.go:750`. `go test` for
  the touched Go packages therefore cannot pass as a set. The server package
  passed on its own, but that does not clear the failed gate.
- `README.md` still defines v1.8.3 as one hub service and labels this document as
  proposed future work. Reconcile package, documentation, commit, version, and
  signed artifact identity before another deployment. Never publish different
  bytes under an already released version.

### Phase 3 re-verification (interactive shell)

Every item below was confirmed in the working tree on 2026-09-02 and must be
fixed or removed before any shell work is called usable. This list is the Phase 3
starting defect set, not a summary.

Authorization path:

1. `POST /api/v1/terminal/sessions` is registered behind `s.authMiddleware`
   (`hub/pkg/server/server.go:3156`), so a static admin API key or an ordinary
   console session reaches the shell-creation route. The plan requires that route
   to reject static keys, CLI credentials, and ordinary sessions.
2. The handler reads the operator from the caller-supplied `X-Operator-ID` header
   and falls back to the literal `"admin"` (`hub/pkg/server/terminal_handlers.go:73-76`).
   `authMiddleware` strips `X-Role`, `X-Tenant-ID`, `X-Username`, `X-User-ID`,
   `X-Client-CN`, and `X-Device-Endpoint-ID` (`server.go:811`) but not
   `X-Operator-ID`. Operator identity is therefore forgeable and is never derived
   from authenticated server context.
3. The handler forwards the caller's `action_digest` to the authority unchanged
   and never recomputes it from `endpoint_id` and `program`
   (`terminal_handlers.go:88-99`). A proof signed for one action authorizes a
   different endpoint or program with the same digest string.
4. `Authority.SignGrant` compares only `Proof.ActionDigest` to the requested
   digest (`hub/pkg/responseauth/authority.go:252-255`). It never checks
   `Proof.TenantID`, `Proof.ActionKind`, or `Proof.TargetEndpoints` against the
   request, so a proof issued for one tenant, kind, or endpoint set is accepted
   for another.
5. `ActionProof.Nonce` is signed but never stored or consumed
   (`hub/pkg/responseauth/dto.go:79-98`). Within the +/-300s window one captured
   proof mints unlimited grants. Grant nonces are generated but no hub or agent
   replay cache exists.
6. Both `EndpointGrant.CanonicalString` (`hub/pkg/response/dto.go:60-74`) and
   `ActionProof.CanonicalString` (`responseauth/dto.go:65-76`) are colon-joined
   `fmt.Sprintf` strings over unescaped free-text fields. The plan requires
   deterministic length-prefixed bytes and explicitly forbids delimiter-joined
   signing input. Any field containing `:` shifts the field boundaries.
7. `Authority` sessions are in-memory, so restarting the authority silently
   invalidates every unlocked response session and every grant it could issue.

Session, token, and state handling:

8. `TerminalSession.Summary()` marshals the whole struct, so the REST response,
   the session list, and `ominullctl shell show` all return `connect_token` and
   the full signed `Grant` (`hub/pkg/terminal/session.go:55,64,195-204`). The plan
   requires that neither ever appear in a normal API DTO.
9. The connect token is also written in cleartext into the response job's
   `request_json` (`terminal_handlers.go:109-113`) and therefore into the hub
   database, and printed to stdout by the CLI (`ominullctl/main.go:718`). It is
   never hashed and never marked one-use.
10. `GetSession`, `CloseSession`, and `RecordFrame` take a session ID with no
    tenant argument (`terminal/session.go:129,155,175`), and the handlers do not
    re-check tenant. Any authenticated caller who knows a session ID reads,
    writes frames to, or closes another tenant's session.
11. `ExpiresAt` and `IdleExpiresAt` are set but never enforced. No sweeper exists;
    sessions stay in the map forever and `CloseSession` does not remove them.
    Only the per-endpoint check in `CreateSession` reads `ExpiresAt`. The
    four-per-tenant cap is not implemented anywhere.
12. `Frames` is an unbounded `[]TerminalFrame` in process memory
    (`terminal/session.go:65`), never persisted, never encrypted, and lost on
    restart.
13. `POST /api/v1/terminal/frames` is registered behind
    `s.deviceOrLegacyMiddleware` (`server.go:3158`), so any endpoint device
    credential can append forged "audit" frames to any session ID, while the
    console calls the same route from a browser context it was not scoped for.
14. The console posts `{kind, payload, timestamp}` but `terminal.TerminalFrame`
    decodes `{type, data, rows, cols}` (`app.js:5173-5180` against
    `terminal/session.go:36-43`). Every recorded frame is currently empty with an
    unknown type, and the mismatch is silently accepted.

Console:

15. `openTerminalSession` posts only `{endpoint_id, program}` with no response
    session, no browser key, and no action proof (`app.js:5133-5135`). There is
    no unlock flow, no response-authority controller window, and no browser key
    generation in the console at all, so the intended secure path is not merely
    incomplete, it is absent.
16. The modal renders `SESSION ACTIVE`, `Connected to <endpoint> ... via Ominull
    Relay`, `Interactive pseudoterminal ready`, and `Frames encrypted & audited`
    (`app.js:5150-5194`) when no relay, pseudoterminal, encryption, or recording
    exists. A queued frame is reported to the operator as
    `[Command queued on endpoint heartbeat relay]`.
17. No terminal emulator is vendored. The control is a single-line text input
    that cannot carry control characters, resize, or full-screen output.

Endpoint:

18. Neither agent implements a pseudoterminal, ConPTY, WSS client, or grant
    verification, and neither recognizes the `terminal_session` action kind. Any
    offer reaching an agent is acknowledged and reported `succeeded` by the
    generic handler described in the Phase 1D row.

### Phase 2 re-verification (evidence store)

Confirmed in the working tree on 2026-09-02. Object encryption itself is sound:
a random per-item data key, AES-GCM, a wrapped key, and a content-digest object
name. Everything around it is not.

1. Uploads are unbounded and buffered whole: `io.ReadAll(r.Body)`
   (`hub/pkg/server/evidence_handlers.go:109`) into `StoreItem(..., plaintext
   []byte)`. There is no `MaxBytesReader`, no chunking, no resume, no range
   tracking, and no quota. One endpoint can exhaust hub memory and disk.
2. Object writes use `os.WriteFile(objectPath, ciphertext, 0600)`
   (`hub/pkg/evidence/store.go:176`): no temporary file, no atomic rename, no
   `O_NOFOLLOW`, no fsync, no free-space or quota check, and no transaction
   spanning the object write and the row insert. A crash between them leaves an
   orphan object or a row pointing at nothing.
3. No store method takes a caller tenant. `StoreItem`, `FinalizeBundle`,
   `GetBundle`, `SetLegalHold`, and `ExportBundleToTarGz` all read the tenant
   *out of* the bundle row and never compare it to the requester. The handlers do
   not compare it either: the hold handler acts on `req.BundleID` alone
   (`evidence_handlers.go:180`) and the export handler on `?id=` alone
   (`evidence_handlers.go:198-215`). Any authenticated caller who knows a bundle
   ID reads, exports, or holds another tenant's evidence.
4. `FinalizeBundle` accepts the caller's manifest, marshals it, and hashes the
   result (`store.go:217-240`). It never checks the manifest against the stored
   items, their hashes, their count, or their sizes, and there is no endpoint
   signature to verify because no endpoint evidence-signing key exists.
5. The receipt is a hash chain with no signature (`store.go:262-280`). Anything
   that can write the database can rewrite the whole chain, so the current
   construction is not tamper-evident against the threat it is meant to cover.
   Chain order comes from `ORDER BY ingested_at DESC LIMIT 1`, which is ambiguous
   under equal timestamps and clock movement.
6. The upload response serializes the item DTO including
   `"encrypted_key"` (`hub/pkg/evidence/dto.go:48`,
   `evidence_handlers.go:118`). The plan forbids returning a wrapped evidence key
   in a normal API DTO.
7. Export writes `tar.Header{Name: it.Name}` from the endpoint-supplied item name
   (`store.go:378-383`). A name containing `../` or an absolute path escapes on
   extraction. The export also decrypts each item fully into memory with no size
   limit.
8. `handleEvidenceExport` swallows a mid-stream error after headers are sent
   (`evidence_handlers.go:214-219`), so a truncated archive is indistinguishable
   from a complete one, and the `EVIDENCE_EXPORTED` audit row is written even
   when the export failed. The download filename is built from the
   endpoint-controlled `bundle.EndpointID` without sanitizing, and `bundleID[:8]`
   assumes a length the code never checks.
9. Retention is stored and never enforced. `retention_expires_at` is written on
   create and read back on get; nothing anywhere deletes or reviews it, so legal
   hold currently blocks a process that does not exist. `SetLegalHold` also does
   not record who set it or why.
10. Encryption associated data is `fmt.Sprintf("%s:%s:%s", tenantID, bundleID,
    name)` (`store.go:166`). The item name is attacker-controlled and unescaped,
    so the same delimiter ambiguity described for the grant and proof
    canonicalization applies to the AEAD binding.
11. Offline verification does not exist. `ominullctl forensics verify` reports
    `"verified": true` for any parseable manifest file
    (`hub/cmd/ominullctl/main.go:592`).

### Phase 5 re-verification (script library and execution)

Confirmed in the working tree on 2026-09-02.

1. `POST /api/v1/scripts/run` is registered behind `s.authMiddleware`
   (`hub/pkg/server/server.go:3162`), so a static admin API key reaches the run
   route. It also takes the operator from `X-Operator-ID` with an `"admin"`
   fallback (`hub/pkg/server/script_handlers.go:155-158`) and forwards the
   caller's `action_digest` to the authority unchanged
   (`script_handlers.go:172`). The three defects described for the terminal route
   apply here identically.
2. `GetScriptVersion(req.ScriptID, req.Version)` takes no tenant
   (`hub/pkg/scripts/store.go:189`, called at `script_handlers.go:149`). An
   operator in one tenant can name another tenant's script ID and the handler
   copies that tenant's full source into the job payload and dispatches it. The
   same missing tenant check applies to `GetScript`, `UpdateScript`, and
   `RetireScript`.
3. The grant does not bind what the plan requires. It carries only the generic
   caller-supplied digest: no script digest, no parameter digest, no execution
   limit, and no attempt count, so nothing ties the signed authorization to the
   source that actually runs.
4. There is no interpreter allowlist. `CreateScript` accepts any interpreter
   string and defaults to `/bin/bash` (`scripts/store.go:70-71`). There is no
   source size bound, no parameter size bound, and no validation of
   `parameter_schema_json`, which is stored as an opaque string and never parsed.
5. Parameters are passed as a `map[string]string` straight into the job payload
   JSON (`script_handlers.go:139,186`) and stored in the job's `request_json`.
   There is no private parameter file, no typed validation against the declared
   schema, and no redaction anywhere on that path.
6. `TimeoutSeconds: 60` and `MaxOutputBytes: 1048576` are hard-coded in the
   payload (`script_handlers.go:190-191`) and enforced by nothing, because no
   endpoint worker exists. Concurrency limits, cancellation, retirement
   semantics, and schedules are entirely absent.

Until Phase 3 is accepted, production must not expose a shell action or terminal
mutation/stream route. Agents must reject terminal offers. Do not use the current
response-auth, job, script-run, collection-launch, terminal, or evidence mutation
prototypes against real endpoints or evidence.

## Slice R0: contain the deployed prototype (do this first)

This slice precedes Phase 0. The unsafe surface described above is present in a
running production installation, so containment is not optional cleanup and is
not to be merged into a later feature slice.

Required behavior:

1. Make every unreleased response mutation route fail closed behind one
   build/config gate that is off by default: terminal session create/close/frames,
   response job create/cancel, script run, evidence mutation and export, response
   auth enroll/unlock/lock, and vulnerability sync. Fail closed means the route
   is absent or returns a 404/503 with no side effect. Returning 2xx, creating a
   session object, or signing a grant is a release blocker.
2. Remove `shell open`, `shell exec`, and any connection-token printing from
   `hub/cmd/ominullctl`. Fix the build error at `main.go:750` and remove the
   `OMINULL_API_KEY` plaintext environment fallback in the same change.
3. Remove the console shell modal and its entry points, or replace their text
   with an explicit "not implemented" state. No control may claim connected,
   active, encrypted, relayed, or audited while item 16 of the Phase 3
   re-verification list stands.
4. Remove the agent-side offer handlers that acknowledge and report `succeeded`
   without doing work (`agent/src/service.c`, `agent/linux/main.c`). An agent
   that cannot verify a grant must ignore the offer and continue normal
   heartbeats; it must not ACK.
5. Reconcile the production host: stop and disable the unaccepted
   `response-authority` service, remove or restrict its root-owned state, and
   record what was found and removed. Any tenant key material generated by the
   prototype is compromised by definition and must be destroyed, not reused.
6. Reconcile version identity. The deployed bytes must not remain published under
   an already released version number. State the version this containment ships
   as and rebuild the signed artifacts for it.

Acceptance:

- `(cd hub && go build ./... && go vet ./... && go test -race ./...)` passes.
- An authenticated request with the admin API key to each gated route returns a
  fail-closed status with no database row, session object, grant, or audit entry
  claiming work was done. Record the exact requests and responses.
- A packaged agent receiving a synthetic terminal or job offer neither ACKs nor
  posts a result. Show the hub-side log for the offer and the agent log.
- `scripts/build-packages.sh` and the package lifecycle test pass, and the
  installed tree on the production host matches the committed tree, package
  contents, reported version, and signed digests.
- The console contains no control that claims a capability listed as absent in
  the audit table.

Until R0 is accepted, no Phase 0-7 slice may be dispatched.

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
8. Derive actor, tenant, role, and credential class from authenticated server
   context. Never trust identity or scope headers supplied by the caller. Strip
   every inbound identity header in one place before any handler runs, and add
   each new identity header to that list in the same change that introduces it.
   `X-Operator-ID` is currently missing from that list.
9. Recompute every action digest from a validated typed request. Never accept a
   caller-supplied digest as proof that a different payload was authorized.
10. Keep unreleased response routes absent or fail-closed. A placeholder that
    acknowledges work, returns success, or renders an active-looking control is
    a release blocker.
11. Use a new version for every changed release artifact. Do not rebuild or
    deploy different bytes under an existing version.

Each numbered slice maintains an evidence record in the task or checked-in test
documentation with these fields:

```text
slice, prerequisite commit, owned files, protocol/schema version,
claims, test commands, exact results, package artifact digests,
runtime target, observed behavior, resource measurements,
known gaps, rollback result, final commit, release version
```

Use only these status values:

- `planned`: no implementation claim;
- `implemented`: code exists, but one or more acceptance gates remain;
- `verified`: every slice gate passed with recorded evidence;
- `accepted`: dependent phases may use it because package, runtime, security,
  compatibility, and rollback gates all passed.

The audit table at the top of this document is the single status ledger. Each
slice updates its row in the same commit as the code, with file:line evidence for
every remaining gap and the exact commands that produced the claim. A slice that
changes behavior without updating that row is incomplete.

An implementation agent may not mark a phase `verified` or `accepted` from unit
tests, code inspection, a process being active, a route returning 2xx, or a UI
screenshot alone. An agent may not mark its own slice `accepted`; `accepted`
requires the recorded package, runtime, security, compatibility, and rollback
evidence to be present in the repository where a later agent can re-run it. One failed required command keeps the phase below `verified`.
Record failures as evidence; do not delete them from the handoff. Before release,
compare the clean committed tree, package contents, installed files, service
definitions, reported version, and signed artifact digests. They must identify
the same build.

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
- The published v1.8.3 documentation defines one root-run hub service. The
  observed installation now also has a root-run response-authority service.
  Treat this as unaccepted release drift, not the target architecture. Same-host
  response key isolation begins only when the hub and authority use different
  unprivileged identities and package/runtime evidence proves the split.
- Linux and Windows packages, signed release metadata, rollback, containment,
  dead-man release, and standalone Windows recovery are retained capabilities.
- `ominullctl` currently handles local setup-token recovery. Fleet operations
  currently live in a repository script and must be consolidated into the
  packaged binary.

## Security and correctness invariants

- Authenticate every API and stream before allocating expensive resources.
- Require trusted HTTPS for response unlock and terminal UI. Require `wss://`
  end to end from each peer to the hub. Never permit `ws://` for terminal data,
  even on a LAN, and never follow a redirect during a terminal handshake.
- Reject static API keys, CLI credentials, and ordinary console sessions on
  shell creation and script run/schedule routes. Those routes require a valid
  tenant response session and a proof from its browser-bound key.
- Apply exact-origin and CSRF checks to cookie-authenticated mutations. The
  server must distinguish console-cookie, OIDC/Access, static-key, CLI, tenant,
  and device authentication classes rather than treating all successful login
  methods as interchangeable.
- Bind endpoint operations to tenant, endpoint ID, job or terminal ID, complete
  typed action payload, signer key ID, issued/expiry times, and an expiring
  nonce. Sign deterministic length-prefixed bytes. Do not sign delimiter-joined
  strings or language-default JSON encodings.
- Reject replayed, expired, cross-tenant, and wrong-endpoint messages.
- Persist state transitions before exposing them to callers. Retried requests
  must be idempotent.
- Never place credentials, secret parameter values, or terminal contents in URLs,
  process arguments, normal application logs, or telemetry events.
- Never return a response grant, raw relay token, browser private key, wrapped
  evidence key, TOTP secret after enrollment, or authority private state in a
  normal API DTO. Store one-use relay tokens as hashes and redact headers at
  every proxy and log layer.
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
- A terminal agent connection requires its unique device credential, its one-use
  relay proof, and the endpoint identity proof required by the deployment. A
  browser connection requires its signed console session, exact allowed Origin,
  active response session, and one-use HttpOnly attach cookie. Session IDs are
  identifiers, not credentials.
- Revoking an operator, response membership, authenticator, endpoint credential,
  response key, grant, or session closes affected live terminals and prevents
  reconnect. Closing a browser terminal socket closes the endpoint child tree.
- Never emit a success result for an unknown action kind, unverified grant,
  unsupported worker, dropped frame, incomplete collection, or failed recording.
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
credential_id, authentication_method, authenticated_at,
allowed_action_kinds, issued_at, last_activity_at,
idle_expires_at, absolute_expires_at
```

- Default absolute lifetime is eight hours. Default response idle lock is 30
  minutes. Activity may move the idle deadline but never the absolute deadline.
- Generate a non-exportable ephemeral signing key in a dedicated
  response-authority controller window during unlock. The authority certifies
  the public key into the response session. The hub receives only the public key
  and signed action proofs. A stolen normal session cookie is not enough to
  create response actions from another browser.
- Keep the controller window and key in memory. Communicate with the console only
  through schema-checked `postMessage` calls with exact `targetOrigin`, source
  window, tenant, session, request nonce, and action digest checks. Closing the
  controller locks response. Never put the key in the hub page, a URL,
  `localStorage`, `sessionStorage`, IndexedDB, a service worker cache, or a file.
- Browser binding prevents reuse of a stolen cookie from another browser. It does
  not defeat malicious code already running in the unlocked console origin. The
  tenant scope, idle lock, absolute limit, target caps, and signer partition bound
  that accepted risk. A tenant may optionally require a new WebAuthn event for
  every action when it needs stronger protection.
- Scope one response session to one tenant. Switching tenants locks response and
  requires another strong authentication event.
- Bind `operator_id` and `browser_session_id` to server-authenticated context.
  Reject caller-supplied identity headers. Re-read hub role and authority
  membership for every grant and close sessions after either is revoked.
- Display the active tenant, operator, remaining time, idle state, active shells,
  running scripts, and a persistent `Lock response` control in the console.
- Explicit `Lock response` closes active shells immediately, rejects new actions,
  and expires unstarted grants. Idle or absolute expiry rejects new actions and
  gives active shells the Phase 3 reauthentication grace period before closing.
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
  accept a time-step value only once, encrypt secrets with an authority-owned key,
  and never represent TOTP as phishing-resistant. Rate limits bind tenant,
  operator, authenticator, source, and a global ceiling so identifier rotation
  cannot bypass them.
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
WebAuthn registration and authentication set user verification to `required`,
verify the exact configured origin and RP ID, consume each challenge once, and
store credential ID, public key, transports, backup state, signature counter, and
last use. Counter behavior is risk evidence, not a universal clone verdict for
syncable passkeys.

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
- `shell sessions|show|close` is read-and-close only, and its output omits the
  grant, the connection token, and terminal contents. The CLI cannot unlock
  response, open or attach to a shell, run or schedule a
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

Every state the console displays comes from the server or a live connection.
Do not hard-code a status badge, a connection line, or a claim about encryption,
recording, or relaying. A view for an unimplemented capability shows that it is
unimplemented. Keep fleet lists paginated and filters server-side. Show destructive or
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
- Put the signer store on durable storage before anything depends on it. Tenant
  keys, memberships, authenticators, method policy, sessions, recovery tokens,
  replay state, and audit records survive an authority restart. In-memory maps
  are acceptable only in the test adapter. An authority restart must not silently
  invalidate unlocked sessions or lose an enrollment, and whatever restart
  behavior it does have must be documented and tested.
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
- Parse offers with a bounded protocol parser over a fixed schema. Substring
  scanning of the heartbeat body is not acceptable: it matches fields from
  unrelated parts of the document, has no length or type discipline, and cannot
  reject a malformed offer.
- Verify the complete signed endpoint grant before parsing the larger action
  payload, before acknowledging, and before starting work. Cache used grant IDs
  and nonces across restart for the grant lifetime.
- Acknowledge only after verification succeeds. An agent that cannot verify a
  grant, does not recognize the action kind, or has no worker for it ignores the
  offer and continues normal heartbeats. It never ACKs and never posts a result.
- Never synthesize a terminal result. `succeeded` is written only by a worker
  that ran the work and observed its outcome.
- Do not print job identifiers, payloads, tokens, or terminal bytes to agent
  stdout or the service log.
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

### 3.0 Prerequisites and contracts (blocking, resolve before 3A)

These were undefined in earlier revisions and are the practical reason a
correctly implemented shell can still be unusable or insecure in this
deployment. Each one is a named deliverable with its own evidence.

**Trusted browser origin.** The response path depends on two browser APIs that
only exist in a secure context: WebCrypto for the non-exportable ephemeral
browser key, and WebAuthn for the preferred unlock method. A hub reached as
`http://<address>` or over an untrusted certificate cannot generate the browser
key, cannot run WebAuthn, and therefore cannot open a shell at all. TOTP does not
rescue that case, because the browser proof itself needs WebCrypto.

Deliverables: document the supported console origins for a LAN or disconnected
installation; specify a stable DNS name plus a certificate the operator's browser
trusts, obtained from an internal CA or ACME; define the WebAuthn relying-party ID
for that name; state that changing the name or RP ID invalidates enrolled
passkeys; and confirm the hub serves HSTS and rejects mixed content on that
origin. Provide the operator-facing setup procedure in the same slice. Record a
real browser check on the actual deployment, not a localhost check, since
`localhost` is a secure context and will hide this failure.

**Canonical signing bytes.** Replace both colon-joined `fmt.Sprintf`
canonicalizations with one shared deterministic length-prefixed encoding:
a fixed domain-separation label, then for each field in a fixed order a 4-byte
big-endian length followed by the raw field bytes, with integers encoded as
fixed-width big-endian. Ambiguity between adjacent fields must be impossible.
Ship it as one function used by the hub, the authority, and both agents, with
byte-exact cross-language fixtures. Old prototype signatures are not accepted;
bump the grant and proof versions.

**Action digest definition.** Define, per action kind, the exact typed payload
that is digested. For `terminal_session` it is at minimum: protocol version,
tenant ID, endpoint ID, terminal session ID, program identifier from the fixed
allowlist, requested TTL, and the response session ID. The hub recomputes the
digest from its own validated typed request and passes only that value to the
authority. A caller-supplied digest is never used; the authority rejects a
request whose recomputed digest is absent. The authority additionally verifies
that the proof's tenant, action kind, and target endpoint set match the request.

**Proof and grant replay state.** Proof nonces are recorded and single-use for
the proof freshness window. Grant IDs and nonces are recorded at the hub and, per
1D, cached durably at the endpoint for the grant lifetime. Define the store,
retention, and eviction for both.

**Relay token handling.** The one-use connection token is delivered only inside
the signed grant payload carried by the authenticated heartbeat and, for the
operator side, as a one-use HttpOnly attach cookie set on the response-session
origin. It is stored at the hub only as a hash. It must never appear in a REST
DTO, a session summary, the response job `request_json`, CLI output, logs,
telemetry, or a URL. Add a test that greps the API responses, database rows, and
log output for the issued token value and fails if it is found.

**Agent connection target and proxy path.** Specify how the agent learns the WSS
address, which is not necessarily the hub API address; whether the agent presents
its existing client certificate on that connection; and the required behavior
behind a reverse proxy. State the proxy requirements explicitly: `Upgrade` and
`Connection` headers preserved, no redirect during handshake, per-connection
idle timeout at least the terminal idle timeout, and no response buffering.
Document the observable failure for each unmet requirement rather than letting
the session hang in `connecting`. Provide a working reference proxy
configuration for the deployment's actual front end.

**Restart and revocation semantics.** Define what happens to a `waiting`,
`connecting`, and `active` session when the hub restarts, the response authority
restarts, the agent restarts, or the network drops. The authority's session and
authenticator state must be durable before Phase 3 begins; an authority restart
that silently invalidates every unlocked session is a Phase 1B defect, not a
Phase 3 one. Persist every terminal state transition with a final reason, and
close the endpoint child tree on every path.

**Enforcement of the stated limits.** The caps in 3A are contract, not
documentation. Implement and test: one active shell per endpoint, four per
tenant, connect timeout, idle timeout, absolute maximum, queued-bytes cap per
direction, and a sweeper that expires and removes sessions. Every read, write,
frame, and close path takes a tenant and verifies it against the session.

**Frame schema ownership.** `hub/pkg/terminal` owns the frame wire schema. The
console and both agents consume the same fixtures. A frame that does not match
the schema is rejected, counted, and surfaced, never silently recorded as empty.

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
- The response-session, terminal-session, and frame routes reject a static API
  key, a CLI credential, and an ordinary console session with no side effect.
  Record the request and response for each.
- Operator identity, tenant, and role on every response route come from
  authenticated server context. A request that sets `X-Operator-ID` or any other
  identity header is unaffected by it. Add the header to the sanitized set in
  `authMiddleware` and test that the forged value never reaches a grant, a
  session record, or an audit row.
- The issued connection token does not appear in any API response, database row,
  log line, CLI output, or exported artifact.
- Every claim rendered next to the terminal is true at the moment it is shown.
  Connection state comes from the live socket, recording state from the recorder,
  and encryption state from the evidence module. No static "encrypted & audited"
  text.

**Operator walkthrough (required end-to-end evidence).** Run this on the real
deployment, from the operator's own browser, and record each step with its
observed result. A passing unit suite does not substitute for it.

1. Load the console over its trusted HTTPS name. Confirm the secure context and
   that the response controller can generate a browser key.
2. Unlock response for one tenant with a platform passkey, then repeat the whole
   walkthrough with TOTP as the only enrolled method.
3. Confirm the endpoint has no pseudoterminal, shell process, listener, or
   outbound WSS connection before the click. Capture the process and socket state
   on the endpoint.
4. Open a shell on one endpoint. Type an interactive command, a long-running
   command interrupted with Ctrl-C, a full-screen program, and a resize.
5. Confirm the recording contains the exact frames, is encrypted at rest, and is
   readable only through the intended path.
6. Close the session from the console. Confirm the child tree is gone on the
   endpoint and the session's final state and reason are persisted.
7. Repeat and instead let the idle timeout, then the absolute timeout, then an
   explicit `Lock response` close the session. Confirm each path closes the
   endpoint side.
8. Restart the hub, then the authority, then the agent, each with a session open.
   Confirm the documented behavior occurs and no orphan shell survives.
9. Attempt the same shell from a second browser using a copied session cookie,
   from a static API key, and from `ominullctl`. All must fail with no endpoint
   side effect.

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
(cd hub && go build ./... && go test -race ./... && go vet ./...)
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

Slice R0 precedes step 1. Phase 3 recording depends on the Phase 2 evidence
store being accepted, so the console shell workflow in step 5 cannot ship before
it; a shell that cannot record is not releasable. Phase 3 also depends on the
durable signer store from Phase 1B and the trusted-origin work from Phase 3.0.

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
- unresolved risks and the next dependency, without silently expanding scope;
- the updated audit-table row and an evidence record checked in under
  `docs/evidence/<phase>-<slice>.md` using the field list above.

An agent's report is rejected, and the slice stays below `verified`, when any of
these is true:

- a command is described rather than quoted with its exact output;
- a gate was skipped and the report does not say which and why;
- a capability is called working on the strength of a unit test, a 2xx response,
  a running process, or a screenshot;
- the working tree does not build, vet, and test clean at the final commit;
- the console, CLI, or API presents a state the implementation cannot deliver;
- a route that this plan marks console-only is reachable with a static API key;
- a claim in the audit table is now stale.

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
