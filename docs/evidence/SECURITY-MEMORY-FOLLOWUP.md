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
  A real handler/cookie regression reproduced HTTP 200 on the alias bypass;
  both paths now reject the analyst with 403. Bad online source URLs return 400.
- **#31, session identifier:** browser response session IDs now use 128 random
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

The earlier 30-minute installed 1007-asset soak showed bounded JS heap, DOM and
listeners but embedder-heap five-minute medians 9.42→11.32 MB. That observation did
not establish an application leak.

Checkpoint 593cee7 runs three matched isolated installed-Chromium jobs: repeated
sort/detail rebuilds, idle polling, and the same rebuild workload without the
long-task observer. Each lasts 30 minutes at 1280×720, 4x CPU, 150 ms latency and
187,500 B/s download. All preserve 1,007 fixture assets and at most 100 mounted rows.
Start/end heap snapshots and delayed repeated-GC checkpoints distinguish retained
objects from delayed native collection. Snapshot instrumentation differs from the
original soak and can itself affect collection; compare the new controls with
one another before attributing any trend. All three jobs passed in workflow 34419900099. Compact measurements are in
[1.8.39-memory-controls.json](1.8.39-memory-controls.json).

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
are preserved in the private audit output directory. Local browser 15 behavior/
row-budget checks pass, including literal-text rendering. A harness failure was
also reproduced: synchronous ST browser commands blocked the fixture HTTP server
in the same Node process. Asynchronous commands repair the self-contained local
run without changing application behavior.

Full Go vet/race, native build, Node regressions, version and managed gates pass
at the recorded checkpoint. Gitleaks reports only the known 665795f placeholder;
real-infrastructure hygiene is clean. The managed service adapter still has no
remote Go hub deployment hook; rebuild job e252e5fcd42744ba8182c5f5d8836fc4 failed.
Subsequent canonical release, scanning and memory results follow below.


## Published scanning result

At `d91f7c1`, CodeQL workflow 34421098942 completed successfully and canonical
`st check codeql` returned **zero open alerts**. Of the original 22, **16 are
fixed**, #6–8/#22 were dismissed as false positives with evidence comments, and
#23–24 were closed as intentional scanner behavior (`won't fix`). This is triage
plus remediation, not a claim that all 22 were exploitable defects. No query,
workflow or security gate was disabled. The raw request URL no longer reaches
feed options: the handler builds destinations from approved constants.

The alert disposition API was checked against [GitHub's documented update
endpoint](https://docs.github.com/en/rest/code-scanning/code-scanning#update-a-code-scanning-alert).
The browser metric is [Chromium's `embedderHeapUsedSize`](https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-getHeapUsage),
which measures the embedder's garbage-collected heap; it is not process RSS or
physical battery use.


## Terminal regression gate correction

Security checkpoint 71b3615 passed every CI job in 34420882021. The constant-feed
checkpoint d91f7c1 failed CI 34421099372 only in the existing terminal idle test:
its five-second deadline raced the manager's five-second sweep and reported
failure with the session already closed. The release was stopped during package
building before deployment; its failure evidence is preserved.

The test now observes real socket-frame receipt, asserts agent output leaves the
operator idle deadline unchanged, then calls the same production sweep after that
deadline. It passes 20 race-enabled repetitions in 4.29 seconds; all terminal race
tests pass in 2.062 seconds. Temporarily restoring the old stdout-renews-deadline
bug made the revised test fail in 0.016 seconds. Production terminal code was
restored unchanged. The full canonical release was restarted with no skipped gate.


## Intermediate security release

The full canonical release completed **v1.8.39** hub first, then explicit Linux
and Windows canaries and all six frozen online endpoints, with zero provenance
issues. Two initially offline endpoints remain queued; their manual follow-up is
deferred by the user. No release gate was skipped. The earlier stopped package
build is retained as failure evidence. Terminal-test correction `df8ce38` changes
no production terminal behavior.


Live verification confirmed served JS/CSS hashes, signed-cookie console/status
HTTP 200 with no key in the cookie GET document, unauthorized topology validator
HTTP 401, two distinct 100-entry audit pages, and disabled/inactive IPv6 capture.
The current topology snapshot contained 1,207 nodes / 1,315 edges / 11,337 conversations:
5,711,975 identity bytes versus 411,852 gzip bytes, followed by 304/zero bytes in
0.59ms. Its first observed read took 13.18 seconds. The dataset changed since the
prior release; this is a bounded live observation, not a comparable query-speed
benchmark or an improvement claim. No topology query changed in this pass.


## Native-memory attribution and verified workaround

The three 30-minute controls produced 343 samples without browser errors.
Warm DOM/listener counts stayed at 5,621/464 with one document. First-to-last
five-minute JS heap medians were 4.77→4.40 MB (stress), 4.64→4.19 MB (idle),
and 4.74→4.38 MB (stress without the long-task observer). Native medians rose
9.51→11.42 MB, 8.68→10.23 MB and 9.41→13.70 MB respectively; the last value
includes collection spikes and drops to 10.87 MB after the snapshot. These are
bounded instrumented observations, not process RSS or production percentiles.

Heap retainers identify two different sources:

- Inspector network history retained 5,770/4,602/5,724 additional native
  `NetworkResourcesData::ResourceData` objects (1.66/1.33/1.65 MB self size).
  A fresh controlled page receiving 500 fixture requests retained 1,000 objects
  under two recording sessions; disabling one session released exactly 500.
  This is browser measurement overhead. Clearing application data would not
  address it. Causal workflow 34422522252 passed.
- Chromium's style engine retained functional media-query results during table
  rebuilds. The controlled pre-fix run 34422763533 counted 16→116 native
  `MediaQuerySet` objects after 100 renders, then 316 after 100 detail cycles.
  Plain controls did not reproduce this growth. The browser's default table
  header/footer print rule uses `if(media(overflow-block: paged): avoid;)`.

The application now supplies the equivalent explicit screen/paged rule for
`thead` and `tfoot`. On the same Chromium 153.0.8010.12 and fixture workload,
workflow 34423042642 stayed at **15→15→15** native media-query objects
([compact comparison](1.8.40-native-memory.json)): zero
additional retained queries versus 300 before. This is a matched short causal
experiment; the post-fix workload was not another 30-minute soak. Native heap
as a whole can still vary with inspector history and garbage collection.

The new behavioral regression failed against the pre-fix browser snapshots
(`16 -> 116`) and passes on the fix. All jobs in CI 34423009353 passed, including screen
`break-inside: auto`, print `break-inside: avoid`, all three browser engines,
responsive accessibility checks and installed PWA lifecycle on Linux/Windows.
The explicit rule preserves print behavior without discarding application state.
Chromium's [default table rules](https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/core/html/resources/html.css)
provide source context; measured browser version and actual retainers establish
this result, not an assumption about future browser versions.


## Final release and remaining limits

The full canonical **v1.8.40** release passed every local gate, deployed the hub
first, verified Linux/Windows canaries, and converged all six frozen online
endpoints with zero native provenance issues. Version sites and generated package
digests are included in this checkpoint. The managed remote-service adapter gap
remains; actual deployment used the project's canonical release script.

Live verification passed served JS/CSS hash matching, credential-free signed-cookie
console and diagnostics, unauthorized conditional reads returning 401, two
distinct 100-entry audit pages, registry freshness, and disabled/inactive IPv6
monitoring. A cached topology snapshot had 1,223 nodes, 1,331 edges and 11,970
conversations: 5,990,262 identity bytes versus 427,917 gzip bytes; a conditional
read returned 304/zero bytes in 0.74 ms. The observed initial read was 4.82 ms
and was already cached. It cannot be compared with the prior cold read as a
query-speed improvement. The native-memory change does not alter topology queries.

Task-owned test files were removed from both VMs, fixture servers stopped, and
the managed headless browser returned to a blank page. Original audit fixes and
completed topology/attribution/IPv6 implementation remain intact. As explicitly
requested, manual screen-reader/200% zoom review, interactive public Google
sign-in, physical battery measurement and follow-up on the two offline agents
are deferred, not claimed as passed. No shared-LAN IPv6 capability was enabled.
