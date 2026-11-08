# Ominull
Ominull is an endpoint telemetry, detection and containment hub for operators managing Linux and Windows devices. It pairs a fleet console, observed network evidence, device identity and bounded response controls with agents on each machine, all served from a self-hosted Linux hub.

## Now
## Next
- M5: Aico owns machine inventory, intent and liveness (plan: docs/audit-2026-11-06.md)
- M8 rest: confirm the abuse.ch ThreatFox and URLhaus feeds load once the owner puts an abuse.ch Auth-Key in /etc/ominull/abusech.key on the hub (asked in Aico); decoys, decoy names and planted credentials are live (plan: docs/audit-2026-11-06.md)
- M9: Monthly live drill that proves a page reaches the phone (plan: docs/audit-2026-11-06.md)
- M4, M7: Agent release with one key, Linux updates through Aico fleet; drop the page budget note, legacy settings keys (copilot.config, legacy_agent_auth, byte/hunt repair flags), docs/history and extra keys. M7's Nightshift part is done: dead routes gone, alerts/verdict and agent-builds now under /api/v1/aico/ (plan: docs/audit-2026-11-06.md)
- M6: Fold the response authority into the hub (owner approved 2026-11-06); with it remove host-script signing (dead nightshift:tap/auto operators) and the unused steward key route (plan: docs/audit-2026-11-06.md)
- M10-M12: Remote-admin kept everywhere (tidy only), console trim, Go Linux agent only with remote-admin parity (plan: docs/audit-2026-11-06.md)
- Console: overhaul the Traffic page once Topology is verified
- Rust static library for hub-input parsing and signature verification (C ABI, both platforms) after the grant fix
- Trust fabric: IP and CIDR rules enforced end to end, including older agents that refuse ranges (plan: docs/TRUST_FABRIC.md)
- Trust fabric: FQDN rules with hub-side resolution, and close the blanket DNS egress
- Platform-native code signing on top of the portable release signature
- Port posture data from SHA: 17 controls as data, IR-readiness pack, Nightshift pack scoring, archive SHA
## Later
- Evaluate BloodHound CE and OpenGraph, then build the AI weak-point finder
- Household: back up the router and repair the approved parental, DNS and Ominull config; then IoT segmentation and DNS filtering (vault proposal direction-2026-10)
- Phase 2: AI-agent egress policy with agent-session attribution, and data inventory contract v4 (vault proposal direction-2026-10)
- Phase 3: measured agent move from C to Go, portable Go collector (Windows first), labeled Neri-lab drill harness, time-boxed Velociraptor benchmark
- Phase 4: business line with paid certs, licensing, multi-tenant and macOS
- Umbrella direction: a lean sensor-and-response fleet (vault proposal direction-2026-10)
