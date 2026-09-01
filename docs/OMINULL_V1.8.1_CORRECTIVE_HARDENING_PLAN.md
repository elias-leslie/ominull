# Ominull v1.8.1 corrective hardening and UX plan

## Objective

Keep Ominull DNS forwarding and sinkholing. Replace ineffective DNS internals without changing the current DNS address, port, or clients. Correct the resource, security, data-integrity, installer, Traffic, and broader UI defects found during the v1.8.0 audit. Preserve Ominull's industrial operations-console identity.

Before changing code or production, read the private Ominull operations brief supplied by the runtime. Treat it as the source of truth for deployment topology, credentials, release order, and current fleet state. Do not copy private values into this public repository.

The existing operator-workstation agent was intentionally reinstalled after earlier performance work. Keep it installed. Use it as a canary and verify that resource use, firewall updates, and log volume remain bounded.

## Product and resource work

- Keep all intentionally installed Linux and Windows agents. Do not retire or purge the operator-workstation agent.
- Verify the previous resource fix under the live agent. Threat-indicator configuration must have deterministic order and content, and agents must rebuild firewall state only when its semantic hash changes.
- Remove automatic generic IOC firewall enforcement only if the audited implementation is still Linux-only or cannot meet the stability, reporting, and cross-platform acceptance criteria in this plan. Hub detection and DNS enforcement must remain available either way.
- Remove low-value passive ARP inventory, fake `/etc/hosts` DNS attribution, and duplicate agent-side lateral-sweep detection if they remain in the current branch. Keep hub scanning and real flow telemetry.
- Remove unauthenticated install-error reporting and its database and temporary-file storage. Installers must print useful local failures without sending arbitrary logs to the hub.
- Remove consensus-based automatic policy adoption and its misleading UI if it remains. Keep explicit manual baseline policies.

## DNS forwarding and sinkholing

- Rebuild DNS handling with the maintained `miekg/dns` Go library.
- Preserve UDP and TCP port 53, the current service identity, and existing client configuration.
- Keep IOC types separate. IP indicators remain flow-detection inputs. Only normalized domain indicators may drive DNS blocking.
- Match exact domains and their subdomains. An explicit allowlist must override a block rule.
- Provide local allowlist and blocklist management plus optional HTTPS domain feeds. ThreatFox may be supported with a user-supplied community key, but Ominull must not require a paid service.
- Use explicitly configured upstream resolvers or safely detected system resolvers. Detect and reject forwarding loops.
- Honor DNS TTLs, UDP truncation and TCP fallback, EDNS, response codes, transaction IDs, and DNSSEC-related flags.
- Bound cache size, query concurrency, TCP connections, packet sizes, upstream timeouts, and telemetry queues.
- Record the real transport, client, response code, cache status, latency, upstream, and block reason. Do not fabricate a process, port, destination, resolver, or response time.
- Expose `disabled`, `starting`, `forwarding`, `protecting`, `degraded`, and `failed` states. `protecting` requires at least one loaded domain rule.
- Validate the replacement on a temporary listener before moving production port 53. Existing DNS clients must not require changes.

## Security and data correctness

- Fix mutual TLS enrollment. The TLS listener may request and validate a presented client certificate, but bootstrap and enrollment-token redemption must work before certificate issuance. Protected agent routes must require a verified certificate whose identity matches the endpoint.
- Tenant-scope assets, discovery, topology, analytics, endpoint joins, and identity uniqueness.
- Correct bandwidth and topology rollups so selected windows equal the underlying retained events. Apply retention to aggregate tables too.
- Move private PKI material to a dedicated root-only persistent directory, separate from downloadable packages. Migrate atomically and keep a rollback copy until the new hub passes its runtime checks.
- Replace duplicate public-install probes with one canonical bootstrap, download, and enrollment check.
- Make status diagnostics read effective runtime configuration so Cloudflare, OIDC, TLS, URL, and DNS status match the running service.
- Remove hardcoded deployment values and fix whitespace and repository-hygiene failures.

## Traffic investigation experience

### Visualization rules

Use each chart for the relationship it explains best.

- Make trendlines the primary view. Draw two synchronized time lanes. The first shows measured inbound and outbound bytes as distinct lines with restrained area fills. The second shows flow count with block and anomaly markers.
- Use donut charts for composition only. Show protocol, permit/block/anomalous, and inbound/outbound distributions. Limit each chart to five slices plus `Other`. Put the total in the center and show an accessible legend with counts and percentages.
- Use ranked bars and sortable tables for endpoints, processes, destinations, domains, countries, and ports. Do not use pie charts for high-cardinality rankings.
- Add per-row sparklines to the top-talker and destination tables.
- For ranges of 24 hours or longer, show an hour-by-day heatmap to reveal recurring peaks and quiet periods.
- Do not use dual axes that imply a correlation between unrelated units.
- Display measured-flow coverage beside every byte-based chart. Never imply that unmeasured flows carried zero bytes.

### Filtering and drill-down

- Add range presets for 15 minutes, 1 hour, 6 hours, 24 hours, 7 days, and retained history. Default to 1 hour.
- Show the last refresh time. Live mode may refresh only while the page is visible.
- Let the operator click a trend point, brush a time span, select a donut segment, or select a table row. Each interaction adds a visible filter chip and refreshes every Traffic panel.
- Support progressive investigation from endpoint to process, destination or domain, and then individual flow.
- Keep filters individually removable and encode non-secret investigation state in the URL for bookmarks and browser history.
- Use a persistent right-side investigation drawer on desktop. Routine analysis must not open a modal that hides surrounding evidence.
- The drawer must show the selected identity and time window, totals and sparkline, top peers and services, related DNS activity, security findings, and paginated underlying flows.
- On narrow screens, turn the inspector into a full-height bottom sheet with the same URL state and keyboard behavior.
- Reserve modal dialogs for confirmation of consequential actions.
- Replace the fixed recent-200-events table with a server-paginated and sortable flow table. Selecting a row opens complete evidence in the inspector.
- Provide explicit loading, empty, stale, partial-measurement, and query-error states.

### Traffic APIs

Add these tenant-scoped routes:

- `GET /api/v1/traffic/overview`
- `GET /api/v1/traffic/flows`
- `GET /api/v1/traffic/flows/{id}`

The overview and flow queries must accept validated time, endpoint, source, destination, process, domain, country, protocol, port, direction, action, and measured-state filters. Responses must include `as_of`, selected window, bucket size, measured-flow coverage, totals, trends, distributions, rankings, and active filter metadata. Raw flows must use opaque cursor pagination.

Use corrected aggregates for overview charts and retained raw events for drill-down. Normalize terminology so `blocked` means observed enforcement, not an IOC match that was merely detected.

## Remaining API and UI work

Add authenticated DNS routes:

- `GET /api/v1/dns/status`
- `GET /api/v1/dns/events`
- `GET /api/v1/dns/policy`
- `PUT /api/v1/dns/policy`
- `POST /api/v1/dns/policy/test`

Keep the old agent-indicator response compatible during migration. If that feature is removed, return a stable empty set long enough for older agents to clear obsolete rules.

Fix the installer experience:

- Windows shows MSI and PowerShell only. Linux shows DEB and shell only.
- Replace `Render installer` with `Download installer` and `Copy install command`.
- Put endpoint-ID override under an Advanced section.
- Warn before discarding an active enrollment code.
- Trap focus, restore it on close, support Escape, and make the background inert.

Fix the LAN installation flow:

- Display one verified portal URL with copy and open actions.
- Require confirmation of advertised LAN addresses and CIDRs.
- Label temporary controls `Start access` and `End access`.
- Never place enrollment credentials in URLs.

Complete the rest of the console work:

- Offer agent installation only for devices confidently identified as supported Linux or Windows systems.
- Add inline red and green verification beside domain, certificate, console URL, agent URL, DNS listener, upstream, Cloudflare, and OIDC fields.
- Keep Cloudflare optional and compatible with its free tier.
- Drive the DNS dashboard from the new DNS APIs only.
- Replace the oversized topology canvas with a fit-to-content layout, readable labels, zoom, pan, reset, persistent positions, and an accessible companion table.
- Fix fleet-version sourcing, duplicate update actions, rollout confirmation, mobile navigation, viewport overflow, overlay focus management, and unsupported marketing claims.
- Preserve the existing dark industrial typography, compact density, restrained color, and purposeful motion.

## Tests and acceptance criteria

### DNS

- Test UDP and TCP queries, common record types, exact and subdomain rules, allowlist precedence, TTLs, EDNS, DNSSEC flags, truncation fallback, upstream failure, malformed packets, and load bounds.
- Prove that safe queries resolve equivalently through the old and replacement listeners.
- Test blocking with controlled local domains. Do not contact malicious infrastructure.
- Prove that the live service continues to answer throughout the production transition.

### Security, storage, and agents

- Test tenant isolation, pre-certificate enrollment, certificate-bound endpoint identity, PKI migration and rollback, retention, and raw-to-rollup equality.
- Verify the operator-workstation agent remains installed, checks in normally, and does not churn firewall rules or logs when threat configuration has not changed.
- Measure hub and agent CPU, RSS, log rate, and open handles before and after the fix.

### Browser and UX

- Use the managed headless browser against the real runtime, not static HTML alone.
- Cover trend selection, time brushing, donut filtering, `Other`, filter composition and removal, direct bookmarked views, drawer navigation, mobile bottom sheet, cursor pagination, and browser back/forward behavior.
- Cover Windows and Linux installer separation, LAN portal access, setup/status verification, keyboard navigation, focus restoration, and viewport overflow.
- Test empty, small, and production-scale Traffic datasets. Traffic queries must remain bounded and cancellable.
- Check browser console errors and take comparison screenshots at desktop, tablet, and phone widths.

### Project gates

- Replace stale documented commands with one canonical check script used by CI, release tooling, and operations documentation.
- Run Go race tests and vet, Linux and Windows builds, package lifecycle tests, JavaScript checks, secret scanning, `git diff --check`, and the repository's exact private-value hygiene check.
- Do not bypass failed hooks or checks.

## Release and production rollout

- Reconcile the current branch first. Preserve completed work from other agents and remove duplicated or superseded implementations.
- Bump the patch release only after behavior and package contents agree with the version source of truth.
- Update README and operator documentation for DNS, Traffic investigation, installers, supported platforms, access modes, recovery, updates, and uninstall behavior.
- Back up production database, configuration, and PKI before deployment.
- Deploy the hub first. Validate replacement DNS on a shadow listener, then move port 53 without client changes.
- Canary the already installed operator-workstation agent and one representative agent for each supported operating system before fleet rollout.
- Verify DNS resolution and blocking, installer portal access from an unmanaged LAN workstation, secure enrollment, agent check-ins, resource use, raw-to-rollup equality, Traffic drill-down, and browser console state.
- Observe production for at least 30 minutes. Watch DNS failures and latency, hub and agent resources, log rate, check-ins, update convergence, Traffic query latency, and UI errors.
- Commit and push only after all gates and runtime checks pass.

## Fixed assumptions

- DNS forwarding and sinkholing remain Ominull features.
- Current DNS clients and port 53 must not be disrupted.
- The production hub remains in its current Proxmox-hosted environment.
- The intentionally reinstalled operator-workstation agent remains installed.
- Linux and Windows remain supported. Do not reintroduce macOS in this release.
- Cloudflare remains optional. Core operation must not require Cloudflare or any paid service.
- Historical install-error data does not need preservation.
