# Security, browser memory and isolated IPv6 follow-up

The September 9 follow-up resumes existing task `task-7863efdbf6894cc0`.
The user requested the remaining CodeQL triage and native-browser-memory
investigation, and IPv6 tests on the test machines without disturbing the LAN.
Manual assistive technology/zoom/Google/battery work and offline-agent follow-up
are explicitly deferred by the user. Previously completed v1.8.38 work remains
complete.

## Security review

The fresh canonical scan reported 22 open alerts. Six findings describe intended
or safe behavior; the other source locations have been changed, with actual
behavioral failures recorded before fixes where a defect was confirmed.
Scanning results after publication are recorded below, separately from CI success.

- **#20, credential file:** `ReadKeyFile` now opens once with no-follow and
  validates the descriptor, owner, regular-file type and owner-only permissions.
  The fixture previously accepted both a readable-by-everyone file and a symlink;
  it now rejects both and accepts the private regular file. No credential values
  are printed. Existing package-created root-owned key files remain supported.
- **#27, response key paths:** path components in tenant identifiers are rejected;
  legacy key writes use `os.Root` confinement. The previous helper accepted
  `../escaped`, nested paths and backslash paths. The authoritative durable key
  store and Ed25519 response proof remain intact.
- **#12–14, package descriptors:** release versions must be numeric triplets;
  descriptor filenames pass the existing package allowlist before filesystem
  access. Invalid versions are rejected before updating desired fleet state.
  Traversal-shaped version fixtures failed before the fix.
- **#28–30, evidence staging:** the existing same-tenant DB lookup and generated
  item identifiers already constrained the remote path. A separate local
  symlink weakness was reproduced: a staging symlink modified a file outside
  the evidence directory. Descriptor-relative `os.Root` operations now reject
  that escape; normal chunk assembly, encryption and resume remain covered.
- **#35–37, feed requests:** default clients accept only the built-in feed URLs
  and refuse redirects. Custom URL selection from the HTTP API is rejected
  before creating a snapshot. Trusted programmatic clients can still supply
  isolated fixtures or configured mirrors. The fail-before local server received
  three custom-target requests; after the fix it receives zero. No public or LAN
  target was used to reproduce SSRF.
- **Related authorization defect:** POST to the general vulnerabilities endpoint
  previously accepted an analyst while its `/sync` alias required admin.
  A real handler/cookie regression reproduced HTTP200 on the alias bypass;
  both paths now reject the analyst with403. Bad online source URLs return400.
- **#31, session identifier:** browser response session IDs now use128 random
  bits from Web Crypto instead of `Math.random`. The regression rejects insecure
  randomness. Ephemeral Ed25519 signing and server response authorization remain.
- **#15, legacy password helper:** repository-wide call inspection found only
  tests calling `CheckPassword`, with no runtime callers. Its unused fast SHA256
  compatibility branch was nevertheless removed to prevent future reuse as an
  authentication path. A legacy verifier fails now; bcrypt positive/negative
  tests pass. No stored credential, login session or operator identity changed.
- **#32–34, redundant pathname checks:** shell-history collection opens directly
  and handles the real missing-file result, instead of checking existence first.
  The process-lineage permission fixture uses `fchmod` on its existing descriptor.
  Fixture tests pass; these changes do not broaden forensic collection scope.

The following alerts were reviewed rather than patched to change correct behavior:

- **#6–8:** `h()` appends existing DOM nodes or creates a text node for string
  children. `appendChild` does not interpret text as HTML. The real browser
  regression supplies a markup-shaped exception message and DOM text, confirms
  literal output, no created image element and no executed handler.
- **#22:** setup state is emitted as an unquoted JSON expression from
  `encoding/json.Marshal`, whose default HTML escaping prevents a closing script
  tag. The regression round-trips quotes, a closing-script payload and a Unicode
  line separator through the actual document, and verifies no raw closing script
  in that expression. This is not JSON inserted inside another quoted string.
- **#23–24:** the scanner deliberately inspects self-signed TLS certificates and
  public root-page fingerprints without credentials. These results are untrusted
  discovery metadata, not authenticated identity. Existing
  `TestLiveTLSCertAndHTTPProbe` verifies this against an isolated TLS server.
  Certificate verification for hub/agent transport remains unchanged.

## Memory experiment

The earlier30-minute installed1007-asset soak showed bounded JS heap, DOM and
listeners but embedder-heap five-minute medians9.42→11.32MB. That observation did
not establish an application leak.

Checkpoint593cee7 runs three matched isolated installed-Chromium jobs: repeated
sort/detail rebuilds, idle polling, and the same rebuild workload without the
long-task observer. Each lasts30minutes at1280×720,4xCPU,150ms latency and
187500B/s download. All preserve1007fixture assets and at most100mounted rows.
Start/end heap snapshots and delayed repeated-GC checkpoints distinguish retained
objects from delayed native collection. Snapshot instrumentation differs from the
original soak and can itself affect collection; compare the new controls with
one another before attributing any trend. Results pending at this checkpoint.

## IPv6 test-machine evidence

The dedicated Linux test VM passed actual AF_PACKET router-advertisement capture
and kernel NDP discovery inside a temporary network namespace containing only
loopback and a veth pair. No interface connects this namespace to a host bridge
or LAN. Parser/trust/bounded-aggregation tests also passed on that VM, covering
RA evidence, DHCPv6 DNS, malformed packets, invalid source MACs and refusal to
approve infrastructure merely because it was observed.

The dedicated Windows test VM passed native counter-family/scope/process baseline
fixtures and IPv6 URL/scoped-address JSON fixtures. These use deterministic
IP Helper rows, not a newly enabled LAN IPv6 segment. No WFP policy was changed.
Linux packet capture is real isolated-kernel evidence; Windows network rows are
synthetic native-process evidence. Neither establishes live dual-stack LAN coverage.

No router/DNS configuration, host LAN interface, installed-agent policy, production
capture configuration or service capabilities changed. Production monitoring stays
off on the IPv4 reference LAN. Temporary test files are removed after verification.

## Verification checkpoint

Fail-before logs, managed browser output, race/build results and memory artifacts
are preserved in the private audit output directory. Local browser15behavior/
row-budget checks pass, including literal-text rendering. A harness failure was
also reproduced: synchronous ST browser commands blocked the fixture HTTP server
in the same Node process. Asynchronous commands repair the self-contained local
run without changing application behavior.

Full Go vet/race, native build, Node regressions, version and managed gates pass
at the recorded checkpoint. Gitleaks reports only the known665795f placeholder;
real-infrastructure hygiene is clean. The managed service adapter still has no
remote Go hub deployment hook; rebuild jobe252e5fcd42744ba8182c5f5d8836fc4 failed.
Canonical Ominull release, final scanning and memory results are pending here.
