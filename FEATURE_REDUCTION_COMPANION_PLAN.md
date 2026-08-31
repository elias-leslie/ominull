# Feature reduction companion plan

## Execution prompt

Execute this file before continuing the optimization work in
`PERFORMANCE_AND_PACKAGING_REFACTOR_PLAN.md`.

The owner approved the product cuts in this document. Implement them. Do not stop at an
inventory or proposal. Preserve useful work already present in the checkout, remove the
approved features, update tests and documentation, finish native packaging for the retained
platforms, measure the smaller system, commit and push the result, then update production
through the canonical release path.

Read the private Ominull operations brief before code, package, or fleet work. It owns live
topology, credentials, release order, install layout, quality gates, and recovery procedures.
Do not copy private values into this public repository. Read README section 3 for repository
layout.

This file changes the earlier plan in three ways:

1. Remove approved features before spending time optimizing them.
2. Support Linux and Windows agents only. Retire macOS rather than building a macOS package.
3. Keep the SSH push-deployer only until native enrolment and package installation replace it.

Where this file conflicts with `PERFORMANCE_AND_PACKAGING_REFACTOR_PLAN.md`, this file wins.
All performance, package-lifecycle, verification, commit, push, and production-observation
requirements from that plan still apply to retained code.

## Product that remains

Ominull is a hub plus Linux and Windows endpoint agents. Retain:

- authenticated endpoint inventory and flow telemetry
- the asset graph and on-demand subnet scanner
- behavioral detection with stored tuning
- threat-intelligence matching
- host isolation and mesh quarantine
- the baseline isolation policy and readiness gate
- explicit detection exclusions
- mutual TLS endpoint identity, operator roles, and audit records
- signed updates and native package lifecycle
- platform recovery tools that remove stranded enforcement state

Do not replace removed features with new abstractions, compatibility facades, feature flags,
or renamed copies. Apply the deletion test. If deleting a module makes its complexity vanish
without losing a retained capability, delete it.

## Approved removals

### Embedded Copilot

Remove the embedded Copilot completely:

- `hub/pkg/copilot`
- Copilot fields and initialization in the server
- chat, investigation, and provider-configuration handlers and routes
- provider connectors, outbound model calls, persisted configuration access, and dependencies
- console drawer, buttons, command-palette entries, demo responses, state, styles, and copy
- CLI chat and investigation commands
- Copilot-specific tests and documentation

Do not retain the rule-based fallback. It makes generic claims that are not derived from the
request's fleet evidence. Keep deterministic alert evidence in the detector and stored alert
records.

Preserve an old `copilot.config` database row as inert legacy data during this release. Do not
drop production tables or settings merely to make the schema look clean.

### Dead WebSocket command path

Control state travels in telemetry responses. Remove the unused WebSocket path:

- WebSocket handler, upgrader, client type, client registry, locks, send channels, and writers
- `SendCommand`, tenant broadcast helpers, and ignored calls to them
- WebSocket-derived online status
- the Gorilla WebSocket dependency if nothing retained imports it
- lock and tenant tests that exist only for this dead path

Keep internal event processing that is independent of endpoint command delivery. Endpoint
online status must use authenticated heartbeat recency.

### Generic rules

Remove the generic `Rule` feature:

- model and storage methods
- HTTP handlers and route
- console and CLI controls, fixtures, and documentation
- broadcasts that claimed to distribute rule changes
- tests that only cover the removed feature

No detector or endpoint enforcement path consumes these rows. Leave the old database table
in place and inert for this release. New databases need not create it unless an additive
migration contract requires the table for downgrade safety. Document the choice in a schema
test.

### Dynamic policy groups

Remove the current `PolicyGroup` feature. Its `BLOCK` action labels received telemetry as
blocked after the flow reached the hub. It does not install an endpoint firewall rule and
must not be presented as enforcement.

Remove:

- policy-group model, evaluation, storage methods, snapshots, routes, UI, fixtures, and tests
- `BLOCK`, `PERMIT`, `ISOLATE`, `ALERT`, and `THROTTLE` claims attached to this feature
- policy-group broadcasts through the dead command path

Keep these distinct retained modules:

- baseline isolation policies and their all-or-nothing replacement interface
- the isolation readiness gate
- detection tuning
- detection exclusions, described as detector allowlists rather than firewall pinholes

Preserve old policy-group rows as inert legacy data during this release. Do not translate a
policy into an endpoint rule without a designed delivery, acknowledgement, reconciliation,
and verification protocol.

### Scheduled flow-role inference

Remove scheduled flow-role inference:

- `hub/pkg/inference`
- startup goroutine and periodic full-window work
- status and manual-run routes
- inference controls, panels, demo data, copy, and styles in the console
- inference-specific tests and documentation

Keep agent and scan provenance in the asset graph. Existing inferred claims may remain as
historical database rows, but they must not win current identity or appear as fresh evidence.
Do not delete durable claim rows during deployment.

After removal, reassess `comm_profiles`. Keep only fields and queries required by retained
traffic analytics. Bound the table under documented retention or replace it with bounded
rollups. Do not preserve lifetime accumulation for a deleted inference feature.

### Dormant Windows kernel driver and DPI

Keep user-mode WFP enforcement in the Windows agent. Remove the unused kernel path:

- the Windows kernel driver sources, headers, project files, build steps, and package payloads
- driver IOCTL client code and kernel-device fallback logic
- driver installation, registration, signing, probing, and cleanup scripts
- driver-only DPI sources and tests
- the obsolete control executable if no retained recovery operation needs it
- driver-specific update capability and documentation

Keep the standalone user-mode WFP recovery tool. It must clear Ominull filters and the
sublayer without the main service.

Remove claims of kernel, ring-0, microsecond, or in-flight DPI enforcement. Describe the
implemented Windows mechanism as user-mode management of Windows Filtering Platform rules.

### False Linux eBPF and DPI claims

The retained Linux agent uses socket inspection for telemetry and iptables or ip6tables for
enforcement. Remove:

- stale eBPF build commands and nonexistent source references
- BPF or TC package payloads that no running agent loads
- unconditional attachment messages
- the `eBPF_TC` telemetry label
- BPF, TC, ring-0, and DPI product claims without runtime proof
- portable DPI headers or tests unused by the retained Linux and Windows agents

Use a truthful, versioned collection-layer value. Update fixtures, storage tests, UI copy,
and documentation in the same commit. Do not rewrite historical production rows.

### macOS agent support

Remove macOS from the supported agent matrix:

- shell telemetry daemon and PF helper from normal builds and releases
- unused Objective-C NetworkExtension prototype
- macOS package and archive generation
- macOS update capability, download mapping, bootstrap path, UI choices, CLI choices, tests,
  docs, demo data, and version checks
- product claims that name macOS as supported

Create one bounded retirement procedure for an already-installed macOS agent. It must:

1. stop and boot out every known Ominull LaunchDaemon label
2. clear the Ominull PF anchor and remove only Ominull's main-ruleset attachment
3. verify the active PF ruleset contains no Ominull rule or anchor
4. remove Ominull binaries, helpers, update staging, logs, configuration, keys, certificates,
   and obsolete package receipts
5. verify no Ominull process, startup definition, PF state, or private material remains
6. preserve unrelated PF configuration and system trust
7. leave the hub's historical endpoint and audit records intact

This procedure is migration tooling, not a supported installer. Keep it explicit, idempotent,
and narrow. Do not build a new macOS agent or `.pkg`.

### Agent on the hub host

The hub host should not run an endpoint agent by default. Remove the production co-installed
agent while preserving the hub:

1. identify package-managed and manually installed agent registrations
2. record the current agent enforcement state
3. stop and disable only endpoint-agent services
4. clear only Ominull agent firewall state
5. remove agent binaries, config, identity, update state, and stale service definitions
6. verify the hub process, database, PKI, console, and listeners remain healthy
7. verify no endpoint-agent process or firewall residue remains

Update installers and docs so hub installation never implies endpoint-agent installation.
Allow co-installation only as an explicit operator choice after a platform capability check.

### SSH push-deployer

Do not optimize the embedded SSH deployer. Keep it only while building and proving the native
replacement. After Linux and Windows native installation passes clean-machine and production
canary gates, remove:

- `hub/pkg/deployer`
- SSH and host-key dependencies used only by it
- push, status, and job handlers and routes
- credential fields and remote-execution audit actions
- console forms, buttons, polling code, demo jobs, CLI commands, tests, and documentation

Keep enrolment-ticket generation. A ticket may produce a short-lived installer command that
enrolls the endpoint and invokes its native package manager. The hub must not accept or store
remote account passwords or private SSH keys.

## Execution order

### 1. Protect current work and record a baseline

1. Inspect `git status`, diffs, and recent commits. The checkout may contain active work from
   the performance and packaging plan. Do not reset, restore, format, or overwrite it.
2. Map each approved feature to imports, routes, CLI commands, UI state, storage calls, schema,
   tests, docs, build scripts, package payloads, and dependencies.
3. Run the current relevant gates and record failures that predate deletion.
4. Capture production resource and feature-use evidence without copying private values into
   tracked files.
5. Make a production rollback backup through the canonical operations procedure before any
   fleet change. A backup does not authorize dropping durable data.

### 2. Cut false and unused code first

Remove, in this order:

1. generic rules
2. dynamic policy groups
3. dead WebSocket command delivery
4. embedded Copilot
5. scheduled inference
6. Windows kernel driver and unused DPI
7. false Linux eBPF and unused DPI
8. macOS build and product support

After each cut:

- compile and test the affected package
- remove its callers rather than leaving a compatibility wrapper
- remove dependencies that have no retained caller
- search for stale route names, symbols, labels, package names, UI copy, and product claims
- inspect the diff before moving on

Prefer coherent deletion commits. Do not mix performance rewrites into a deletion commit
unless the deletion exposes the retained module seam and the change is required to compile.

### 3. Reconcile the retained design

After deletion, draw the actual runtime path and make code match it:

```text
Linux or Windows agent
  -> authenticated telemetry batch
  -> one hub ingestion module
  -> durable event and asset state
  -> detector and threat-intelligence decisions
  -> heartbeat response with desired containment and update state
  -> agent reconciliation through iptables or user-mode WFP
```

Keep one deep hub ingestion module and one deep runtime module per retained agent platform.
Do not add interfaces around deleted features. Do not maintain parallel command delivery.

### 4. Finish native lifecycle for retained products

The final supported package set is:

- Linux agent `.deb`
- Windows agent MSI
- Linux hub `.deb`

Each package must own one canonical service and support unattended install, upgrade, repair,
rollback, uninstall, and security purge. Preserve enrollment identity on upgrade. Purge removes
private endpoint identity. Hub uninstall preserves the database and PKI unless a separate,
explicit destructive command is approved.

Bootstrap may create a short-lived enrollment ticket and invoke a native package manager. It
must not copy a daemon, write a service definition, or create a second install identity.

Implement the bridge and final native-package releases required by the earlier plan. Windows
still needs a bridge from its legacy updater to MSI. Linux must migrate any manual install to
package ownership without duplicate processes or lost identity.

### 5. Retire production roles that were cut

Before rolling the final retained fleet:

1. run the macOS retirement procedure and verify zero residue
2. remove the endpoint agent from the hub host and verify the hub remains healthy
3. mark those endpoints retired or unsupported in operator-facing status without deleting
   their audit or telemetry history
4. verify release convergence no longer waits for retired endpoints

Do not isolate an endpoint as part of uninstall. If either endpoint is already isolated,
release or clear only Ominull-owned enforcement state before removing its control path.

### 6. Remove SSH deployment

Prove native fresh install, enrollment, upgrade, repair, and uninstall on clean Linux and
Windows machines. Prove one production canary per retained platform. Then remove the SSH
deployer and its dependency tree. Re-run route, role, audit, UI, and repository searches.

### 7. Optimize only retained code

Resume the measurement loops in `PERFORMANCE_AND_PACKAGING_REFACTOR_PLAN.md` against the
smaller product. Recreate baselines because deletion changes process count, query mix, binary
size, and idle CPU.

Priority hot paths remain:

- Linux socket collection and process attribution
- Linux in-process, connection-reusing mutual TLS transport
- Windows WinHTTP reuse and bounded flow state
- telemetry batch validation and persistence
- communication-profile retention or bounded rollups
- SQLite lock time, transaction count, and query plans
- analytics and topology cache behavior
- hub background-job cadence

Never claim a gain from slower sampling alone. Control delivery must stay within the documented
limit. Compare equal workloads and prove no events, alerts, bytes, or containment updates were
dropped.

### 8. Documentation and naming pass

Rewrite README, architecture diagrams, CLI help, route tables, package docs, update docs, demo
mode, and console copy to describe only retained behavior.

Repository-wide negative searches must find no live claim or implementation reference to:

- Copilot, ChatOps, or autonomous AI
- WebSocket endpoint commands
- generic rules or dynamic policy groups
- scheduled role inference
- Windows kernel driver, ring-0, or in-flight DPI
- Linux eBPF or TC attachment
- macOS endpoint support
- SSH push deployment

Historical changelogs and migration comments may name removed behavior when clearly marked as
historical. Do not falsify git history or rewrite old production evidence.

## Verification gates

### Removed-feature gates

- Removed routes return 404 through the real server handler.
- Removed controls and copy do not appear in the real console or demo mode.
- Removed CLI commands fail with concise usage output.
- No retained package imports removed modules.
- Go module and other dependency manifests contain no dependency used only by removed code.
- Fresh databases and upgraded production-shaped database copies both start successfully.
- Old rules, policy groups, Copilot settings, and inferred claims remain inert and do not alter
  current runtime behavior.
- Binary and package contents contain no deleted driver, macOS agent, or SSH deployer payload.

### Retained-capability gates

- authenticated Linux and Windows telemetry persists expected rows
- online status follows heartbeat recency
- scanner and asset provenance still work
- threat-intelligence and behavioral detection still produce evidence-backed alerts
- baseline readiness rejects unsafe isolation
- host isolation and release work on IPv4 and IPv6
- mesh quarantine reconciles additions and removals
- dead-man release and standalone WFP recovery leave zero residue
- mutual TLS identity and operator role checks still fail closed
- signed update rollback still works

### Package and production gates

- Linux agent is registered and owned by `dpkg`
- Windows agent is registered in MSI and uninstall metadata
- hub is registered and owned by `dpkg`
- each retained product has exactly one service and one running process
- no production endpoint reports manual, unknown, duplicate, or mismatched provenance
- retired macOS endpoint has no process, startup entry, PF residue, file, receipt, key, or cert
- hub host has no endpoint-agent process, service, identity, or firewall residue
- hub database and PKI survive hub package upgrade
- final hub and retained agents report the same release version
- idle and loaded resource budgets from the earlier plan pass for at least 30 minutes

Run the current canonical project gates from the operations brief, adjusted only to remove
gates for deleted source. Add tests for every changed guarantee. Compile and unit tests do not
replace real package, service, route, UI, containment, update, and uninstall evidence.

## Commit, release, and completion rules

1. Keep deletion, native-package bridge, final package, and production cleanup as reviewable
   commits where practical.
2. Inspect every staged diff for private values, credentials, unrelated work, generated binary
   churn, and accidental durable-data deletion.
3. Run the repository hygiene search required by the operations brief before each push.
4. Push without bypassing hooks or failed gates.
5. Release hub first. Use the bridge path where an old agent cannot consume its final native
   package.
6. Canary retained platforms, verify containment recovery and package provenance, then converge
   the remaining retained fleet.
7. Retire macOS and the hub-host agent through the approved narrow cleanup procedures.
8. Remove the SSH deployer only after its replacement has live proof.
9. Observe production for at least 30 minutes. Record resource use, process count, route health,
   telemetry acceptance, database latency, update status, package provenance, and errors.

Completion requires:

- every approved feature removed from code, UI, CLI, packages, docs, and live runtime
- no false enforcement or unsupported platform claim
- Linux agent, Windows agent, and hub installed through native package managers
- macOS agent and hub-host endpoint agent fully removed with zero enforcement residue
- SSH deployer removed after native replacement proof
- retained performance and correctness budgets green
- all commits pushed
- production hub and retained agents on the final release
- exact verification evidence and rollback state in the final handoff

Do not declare completion because code compiles, because a package was built, or because an
update was queued. Completion means the smaller product is running in production and every
remaining installation has native ownership and measured resource use.
