# Ominull
Ominull is an endpoint telemetry, detection and containment hub for operators managing Linux and Windows devices. It pairs a fleet console, observed network evidence, device identity and bounded response controls with agents on each machine, all served from a self-hosted Linux hub.

## Now
- Agent: close the terminal-session grant signature gap, then fuzz and sanitizer-harden hub-input parsing (security, first)
- Console: browser-check and accessibility-check the Topology rewrite (700fe82; shipped, never checked past a render)
- Windows agent: confirm ESTATS byte counts stay clean after 1.8.99 (32-bit wraps unconfirmed), fix any left in agent/src/service.c
## Next
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
