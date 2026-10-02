# Hub policy and network preparation

This behavior-preserving refactor reduces repeated preparation in heartbeat
control responses, topology graphs, and router talker summaries.

Baseline resolution selects enabled policies for the endpoint's global, tenant,
location, and endpoint scopes, and reads only their rules. The same scope predicate
serves both reads. Four prepared statements belong to the store and read current
rows; policy results are never cached. Administrative listing still returns all
policies and rules. Explicit insertion order preserves the winning rule's author
and note when policies or rules tie. The single-policy rule read uses an indexed
seek; multiple policies use a fixed-parameter subquery without a variable-count
limit.

Topology and router summaries parse configured prefixes once per request. The
validated longest-prefix order, zone handling, mapped IPv4, estate membership,
network labels and kinds remain unchanged. No shared configuration cache was added.
The installation documentation now names both package-owned hub services.

## Matched measurements

Five samples per case, Go 1.26.7, linux/amd64, Ryzen 7 7800X3D, GOMAXPROCS 16,
500 ms benchmark intervals. Original implementation is commit `80ee3fa`.
Fixtures and inputs are identical; the final classification benchmark includes
preparing the request snapshot before classifying the same 1,000 addresses.
All fixtures use temporary databases and sanitized addresses.

| Workload | Original median | Refactored median | Original bytes/op | Refactored bytes/op |
| --- | ---: | ---: | ---: | ---: |
| Baseline: one policy, four rules | 39.296 µs | 25.406 µs | 6,933 | 7,285 |
| Same baseline plus 1,000 unrelated policies/four rules each | 9.032 ms | 26.587 µs | 3,183,244 | 7,286 |
| 1,000 addresses, one configured prefix | 124.692 µs | 100.816 µs | 31,936 | 32,016 |
| 1,000 addresses, eight configured prefixes | 286.922 µs | 125.784 µs | 31,936 | 32,640 |
| 1,000 addresses, 64 configured prefixes | 1.354 ms | 270.082 µs | 21,248 | 26,624 |

Small baseline allocations rise from 167 to 180 per operation; large-fixture
allocations fall from about 69,202 to 180. Prefix preparation adds one allocation
per request. Initial unprepared filtering slowed the small-policy case; prepared
statements resolved that latency regression before release.

The measurements compare sequential synthetic runs, not controlled production
throughput or battery consumption. The live estate had no online agents during
inspection, one baseline policy and no custom network prefixes. Production CPU
savings are therefore not established by this experiment. Multiple-policy
performance and broader topology query latency are outside these measurements.

## Verification

The existing full Go suite passed before implementation. Added characterization
also passes against the original implementation: all four scopes contribute,
disabled and unrelated policies stay out, nonzero enabled values remain enabled,
duplicate provenance survives, administrative listing retains every rule, and
policy enable/disable/re-enable/delete is immediately visible. Closed-store and
missing-endpoint errors remain errors. Address cases cover overlapping prefixes,
IPv4-mapped IPv6, IPv6 zones, known/unmanaged/public/private/shared addresses and
invalid input. Existing graph and router integration coverage is retained.

Final storage checks and benchmarks ran through:

```sh
st check cleanroom -- bash -c 'cd hub && go test ./pkg/storage -count=1 && go test ./pkg/storage -run "^$" -bench "Benchmark(BaselineResolution|TopologyClassification)" -benchmem -count=5 -benchtime=500ms'
```

Independent read-only review found no correctness or statement-lifecycle blocker.
Native builds, managed acceptance, canonical release gates and source-bound live
verification are retained separately in the private operations record. That record
also preserves failed experiments and the remote managed-service adapter gap.

Router counter transition rewrites and name-selection query changes were deferred:
overflow and equal-timestamp selection need their own contracts and measurements.
Agent collector changes would require native cross-platform and fleet rollout
verification. This release changes hub implementation only.

Final CodeQL review also found a pre-existing inline-script encoding defect
(alert 55). The console now uses Go's JSON string encoder, which escapes HTML
delimiters, control characters and JavaScript line separators while preserving
the decoded identity. Harmless character and rendered-configuration regression
tests fail on the old serializer and pass on the replacement. Identity-provider
verification constrains input control; practical exploitability was not tested.
The alert remains subject to the fresh CodeQL result, with no dismissal.
