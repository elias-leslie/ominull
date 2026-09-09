# Attribution follow-through

Phase 4 adds the IEEE IAB registry to the existing longest-prefix lookup. The
September 9, 2026 snapshot contains 58,451 assignments, including 4,575 IAB rows.
The diagnostics checks expose the embedded fetch date, count and SHA-256 revision;
registries older than 180 days are marked for refresh.

A versioned transactional startup migration revises only scan/router vendor
claims. Operator and agent claims keep precedence. Original observation times
are retained: refreshing a registry does not mean a device was seen again.
Legacy source=scan claims alone no longer assert that an active probe occurred.

Offline IPv6 attribution seeds were checked against primary sources:

- [IEEE IAB registry](https://standards-oui.ieee.org/iab/iab.csv)
- [Apple enterprise network requirements](https://support.apple.com/en-us/101555)
- [Cloudflare IPv6 ranges](https://www.cloudflare.com/ips-v6)
- [Google ranges](https://www.gstatic.com/ipranges/goog.json)
- [AWS ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)

These are coarse owner seeds; existing live-feed precedence and tenancy labels
remain intact. They do not locate a device or prove who operates a workload.

IAB, offline IPv6 and legacy-probe regressions failed against preceding behavior
and passed after correction. Migration tests cover precedence, timestamp
preservation and idempotence. Full Go vet/race passed (server 218.237 seconds),
native builds, 30 Node regressions, managed quick checks, version/syntax and
real-value hygiene passed. Gitleaks reported only the known historical placeholder.
Browser CI and production release evidence are recorded in the private operations
brief when completed. The reference LAN is IPv4-only; IPv6 evidence is synthetic.
