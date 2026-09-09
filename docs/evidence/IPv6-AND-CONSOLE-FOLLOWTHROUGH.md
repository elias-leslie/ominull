# IPv6 infrastructure and console follow-through

Released as v1.8.38 on September 9, 2026; final release evidence follows below.
No production IPv6 packet coverage is claimed: the reference deployment has
IPv6 disabled. Tests below use documentation addresses and isolated namespaces.

## IPv6 discovery and infrastructure

- Wide IPv6 prefixes use directly connected all-nodes solicitation and kernel
  neighbors rather than enumeration. Small IPv6 ranges retain first/last addresses;
  literals preserve zones; malformed input cannot silently become an IPv4 sweep.
- NDP imports validated unicast MACs and preserves interface zones on link-local
  addresses. Reverse naming supports `ip6.arpa`. Linux hub packaging declares
  `iproute2` and `iputils-ping` for the discovery commands.
- Optional administrator-configured Linux capture binds an explicit Ethernet
  interface. It never changes routing, DNS, addresses or containment. It reports
  missing raw-socket capability and persistence failures, instead of claiming
  healthy coverage. It starts disabled, with no automatically trusted peers.
  The native hub unit deliberately retains only `CAP_NET_BIND_SERVICE`; packet
  capture additionally requires an operator-approved `CAP_NET_RAW` grant in the
  hub service bounding and ambient sets. This release does not broaden the
  default service privileges or enable capture on an IPv6-disabled deployment.
- Complete IPv6 RA/RS/ND, direct DHCPv6 and UDP WPAD queries are validated and
  aggregated. Prefix/address observations support investigating SLAAC; they do
  not prove how an endpoint configured an address. Fragments, encrypted packets,
  routing extension headers, DHCP relays and TCP DNS are not decoded.
- Trusted router/DHCP IP/MAC pairs, prefixes and DNS addresses are explicit.
  Mismatches create findings through the existing learning-hold path. They never
  trigger automatic isolation and are not described as proof of compromise.
- Capture retains at most 1,024 distinct observations per five-second batch and
  reports overflow. Storage retains 2,048 recent distinct records per tenant;
  the inspector displays the latest 100 with packet counts. Identical findings
  are suppressed for an hour only after the alert was successfully recorded.

## Console and history

- Source identity is recorded when a finding can be attributed to an asset in
  the same tenant. An unmanaged host view queries that source identity; a
  destination reference is never treated as an alert raised by that host.
  Older unattributed findings are explicitly excluded from this scope.
- Audit history uses indexed numeric event time with stable keyset pagination
  and an insertion high-water mark. Actor/action and UTC date filters are applied
  before pagination. A page export contains only the authorized displayed page,
  with its filters and export timestamp. New writes do not shift older pages.
- Saved comfortable/compact density, grouped labeled desktop navigation and a
  compact section selector improve navigation. Policy separates baseline/detection
  from hub health/updates. Response separates active jobs and recent completed
  history, still disclosing the underlying latest-50 limit.
- Cached JSON snapshots negotiate gzip, cache the compressed representation, and
  retain authorization, private validators and actual snapshot time. Conditional
  requests remain body-free. No API or personalized document is added to PWA
  shell storage.

## Verification evidence

Fail-before regressions reproduced wrong IPv6 boundary/literal targeting,
missing IPv6 reverse names, ignored source-asset alert scope, absent negotiated
compression and acceptance of a non-unicast infrastructure sender. Focused fixes
passed their behavioral tests. Additional tests cover source scope including
legacy invalid evidence JSON, concurrent/backdated audit inserts, role checks,
learning holds, observation aggregation and alert cooldown.

`test-ipv6-monitor.sh` passed actual raw-frame receive and kernel NDP ingestion
inside a temporary network namespace. Kernel neighbor identities are deliberately
seeded fixtures; this does not prove real endpoints answer multicast discovery.
The parser also has a fuzz entry point and bounded recursive DHCP option parsing.

Full Go vet/race, native build, managed quick checks, Node regressions, version,
syntax and whitespace checks passed before checkpoint publication. The sole
history secret-scan finding is the previously removed placeholder in `665795f`.
Browser application update, responsive/a11y checks and the 30-minute throttled
soak are exercised by isolated CI; results must be recorded after completion.

## Performance observations

A synthetic 100,000-event workspace with 1,090 nodes, 83,581 directed edges and
20,000 retained conversations took 975–1,015 ms per uncached query across four
samples on the development host, producing about 38.5 MB JSON. This deliberately
large graph is not comparable to the original 1,007-asset render fixture or the
live 3.42 MB topology read. Profiling identifies both SQLite grouping and graph
materialization; no speculative index or second topology model was introduced.

The compression regression fixture transferred 450,021 identity bytes versus
2,865 gzip bytes, with byte-identical decoded JSON and zero-body conditional
repeats. This highly repetitive fixture is not a production compression estimate.
Release verification must record actual cold/warm route measurements separately.

## Verification limits

Headless Chromium/Firefox/WebKit worker and application tests are separate from
OS-installed application integration and real assistive technology. The soak
records heap, DOM/listener counts and long tasks under CPU/network throttling;
it cannot measure physical battery use. The local managed browser initially failed to open, then recovered before release.
The managed service runtime currently addresses local user units only; it has
no remote Go hub adapter. Ominull's canonical hub-first release remains the actual
remote deployment path. Do not report a local service restart as fleet evidence.

## Final query and lifecycle follow-through

The workspace now obtains graph aggregates and conversation evidence in one SQL
pass through the existing graph builder. It still builds every edge while retaining
only the latest 20,000 eligible conversations and the truncation sentinel. A parity
fixture checks direction, asset identity, byte/flow/measured totals and verdicts
against independent graph aggregation. That test exposed an order-dependent port
verdict: anomalous permitted traffic could overwrite a blocked port. Blocked
observations now retain priority regardless of group order.

Under the same opt-in fixture, Go profiler settings and development host, with
other task tests/builds stopped, four uncached query samples changed from
1,014.84 / 975.17 / 980.86 / 1,003.47 ms to
869.49 / 863.36 / 856.36 / 873.79 ms. Median 992.17 → 866.43 ms, about 12.7% lower.
The 100,000 events, 1,090 nodes, 83,581 directed edges and 20,000 conversation bound
were unchanged. These are synthetic samples, not production percentiles.

At 3856473, CI 34410572126 passed every job: Chromium, Firefox and WebKit behavior,
accessibility/row budgets, Go/race/vulnerabilities, native Linux/Windows and package
checks. The isolated Linux Chromium PWA test installed the app, selected standalone
mode, launched two app windows, exercised dirty draft/update protection and upgrade,
and restarted the installed app offline with anonymous content. It does not certify
Windows installation or provide a manual screen-reader review.

Firefox first-install tracing revealed an unsolicited controller-change reload.
Fail-before regressions confirmed both first control and a previously blocked update
could reload without current approval. Reload now requires an explicit guarded update;
a blocked request clears that authorization. Host alert and flow reads also have
independent loading/error state; a failing flow read cannot conceal healthy alerts.

The first soak run used the small demo fleet after ordinary refresh replaced the
initial large population. It is not accepted as a 1,007-asset result. The corrected
soak runs an installed standalone app, serves the large sanitized fleet over real
throttled loopback HTTP, and asserts 1,007 assets on every sample. Final soak and
release results remain to be appended.


## Code scanning review

A successful scan workflow means analysis completed; it does not mean no alerts
remain. The September 9 state check found eight new prototype-assignment alerts
(#47–54) sharing a host-cache lookup. A fail-before regression using `__proto__`
confirmed mutation of `Object.prototype.loading`. The cache now has no prototype;
`__proto__`, `constructor` and `toString` are ordinary own entries. Host-resource
failure independence remains covered.

The other 22 open alerts predate this audit remediation (August 30–September 6).
They remain open, with no dismissals, suppressions or security-gate changes:

- #6–8: DOM/exception flows through the shared DOM builder. Inspection shows
  text-node construction at the reported lines; full source-to-sink triage remains.
- #31: noncryptographic randomness for a browser response-session identifier.
- #12–15, #27–30: package/evidence/signer paths and legacy password verification.
  Evidence item writes require an existing tenant-owned generated item, and the
  password path retains legacy verification alongside bcrypt; these observations
  do not close the alerts or certify all callers.
- #22–24: setup JSON quoting and scanner certificate-verification bypasses.
- #20, #32–34: Linux credential/history file races and lineage test-fixture races.
- #35–37: configurable vulnerability-feed request destinations.

These are explicit existing security backlog, separate from the audit findings;
this release must not be described as having zero open CodeQL alerts.


## Final browser and soak evidence

Standard CI `34413316385` at `9426c13` passed every job, including Go/race,
reachable-vulnerability checks, actual isolated packet capture, Linux and Windows
native tests, package inspection, Chromium/Firefox/WebKit and installed Linux PWA.
All 80 viewport/theme axe and overflow checks passed: five sections, four themes,
390/768/1024/1440px. Compact state labels remain on one line after visual review.
This is automated accessibility evidence, not a manual screen-reader certification.

The corrected installed standalone Chromium 153 soak (`34411619767`, source
`3525f64`) ran 1,800,334ms with 4x CPU slowdown, 150ms network latency and
187,500 bytes/s download. All 114 samples retained exactly 1,007 assets and 100
mounted rows; no page errors occurred. After warm-up, all five-minute median
DOM/listener readings remained 5,621/464. JavaScript heap median changed from
4.77MB in the first five minutes to 4.41MB in the last five minutes. Browser
embedder-heap median rose from 9.42MB to 11.32MB; attribution of that native-memory
trend requires further profiling. Do not claim complete memory or battery stability.

Throttled synchronous sort/render median was 202.15ms (178.30–247.10ms). The
1,559 observed long tasks include the deliberate repeated route rebuild stress;
maximum duration was 360ms. This is not a production percentile or the unthrottled
reference-machine budget. The final non-throttled Chromium CI fixture rendered
1,007 assets in 25.4–29.9ms with 100 rows mounted and 3,308 nodes. The comparable
older before/after evidence remains in `1.8.37-console-audit.md`; do not compare
unmatched CI runners or confuse the original 315–475ms audit samples with it.

Changes after the soak source are the prototype-safe host dictionary and compact
CSS, plus viewport tests. The soak uses ordinary host keys at 1280px; these changes
do not alter that exercised path. `1.8.38-soak.json` retains the measured summary.

Remaining verification limits: real screen-reader use and a complete 200% browser
zoom/operator walkthrough; real public identity-provider walkthrough;
physical battery measurement;
and the embedder-memory trend above. Direct cookie sign-in/diagnostics and signed
session server tests are separate evidence. Production IPv6 packet reception cannot
be verified on the reference IPv6-disabled LAN. None of these limits is represented
as a passing check.


## v1.8.38 release and live evidence

The canonical full release completed hub first, then explicit Linux/Windows
canaries and the frozen online cohort. All six captured online endpoints reported
v1.8.38 with valid native provenance. Two initially offline endpoints remain queued;
they did not shrink the captured cohort. Version sites and generated package digests
are included in the release checkpoint. No monitoring was enabled or service
capability broadened on the reference deployment.

The first release attempt stopped before deployment when ST's managed browser
could not open. Its failure log was retained. A direct managed headless recheck and
the complete canonical browser gate subsequently passed. The full release workflow
was restarted without skip flags; retained Go/race/vet, browser/model, native
collector/isolation, signed packaging and isolated package-lifecycle gates passed.
The separate managed-service adapter still lacks a remote Go hub deployment hook;
the canonical Ominull release script performed the actual deployment.

Live read-only verification found:

- Deployed `app.js` and `app.css` hashes match the tested checkout. Registry
  diagnostics report 58,451 assignments fetched September 9; the read-only database
  migration marker matches the embedded registry SHA-256.
- A topology workspace with 1,174 nodes, 1,275 edges and 9,623 conversations
  returned 362,851 gzip bytes for 4,972,870 decoded bytes, a 92.7% transfer reduction
  for that exact representation. Identity and decoded bytes matched exactly.
  The first observed read took 7,723.62ms; cached identity took 43.52ms and a
  conditional repeat returned 304/zero bytes in 0.63ms. An unauthenticated
  conditional request still returned 401. These are bounded route samples;
  the earlier 4.32MB/8,637.19ms read had different live data.
- Normal POST sign-in, cookie console and credential-free diagnostics return 200.
  Cookie GET HTML contains no admin credential. Two audit-history pages each
  contain 100 entries with no repeated IDs. The IPv6 monitor accurately reports
  disabled/no observations.

An additional disposable real-Go-hub test passed in ST's managed headless browser:
normal POST sign-in followed by cookie GET; a genuinely expired signed JWT; actual
API 401 and visible Sign in required; diagnostics authentication recovery;
reauthentication; switching to an auditor; visible read-only role and actual 403
mutation refusal. The installed worker's caches contained neither personalized
routes nor sentinel credentials/identity after the account switch. The test clears
its own cookie/cache/worker and closes the disposable hub; no real credentials,
fleet actions or production sign-in state are involved.

Reproduce that optional browser integration from `hub/` with
`OMINULL_MANAGED_BROWSER_TEST=1 go test ./pkg/server -run '^TestExpiredConsoleSessionAndBrowserRecovery$' -count=1 -v`.
The expired-session HTTP assertion runs in ordinary Go CI; this optional browser
portion requires ST's managed profile. Public identity-provider integration remains
separate from these local signed-cookie checks.


## Installed Windows PWA follow-up

Test-only checkpoint `ba30bd3` extends the same installed Chromium lifecycle to
an isolated Windows CI desktop. Both Windows and Linux jobs passed in run
`34415868983`. Windows recorded real installed standalone launch, two app windows
protecting dirty work during upgrade, anonymous offline reload, and an installed
standalone restart while the fixture origin was offline. This closes the earlier
Windows-installed-app verification deferral; it does not certify every Windows
version, public identity-provider configuration or assistive technology.
The fixture never uses the operator desktop or production credentials.
