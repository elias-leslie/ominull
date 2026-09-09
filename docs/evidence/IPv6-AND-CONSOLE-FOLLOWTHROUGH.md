# IPv6 infrastructure and console follow-through

Implementation checkpoint; release evidence will be appended after deployment.
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
it cannot measure physical battery use. The local managed browser failed to open.
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
