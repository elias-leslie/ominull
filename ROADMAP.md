# Ominull
Ominull is an endpoint telemetry, detection and containment hub for operators managing Linux and Windows devices. It pairs a fleet console, observed network evidence, device identity and bounded response controls with agents on each machine, all served from a self-hosted Linux hub.

## Now
## Next
- M8 rest: confirm the abuse.ch ThreatFox and URLhaus feeds load once the owner puts an abuse.ch Auth-Key in /etc/ominull/abusech.key on the hub (asked in Aico); decoys, decoy names and planted credentials are live (plan: docs/audit-2026-11-06.md)
- M12: Go Linux agent only with remote-admin parity, if the owner still wants the rewrite (asked in Aico) (plan: docs/audit-2026-11-06.md)
- Trust fabric leftovers: never run yet: the live IPv6 rig `test_wfp_ipv6_live.exe` on real Windows, and waiting out a real dead-man timer on either platform (plan: docs/TRUST_FABRIC.md)
## Later
- Evaluate BloodHound CE and OpenGraph, then build the AI weak-point finder
- Household: back up the router and repair the approved parental, DNS and Ominull config; then IoT segmentation and DNS filtering (vault proposal direction-2026-10)
- Phase 2: AI-agent egress policy with agent-session attribution, and data inventory contract v4 (vault proposal direction-2026-10)
- Phase 3: measured agent move from C to Go, portable Go collector (Windows first), labeled Neri-lab drill harness, time-boxed Velociraptor benchmark
- Phase 4: business line with paid certs, licensing, multi-tenant and macOS
- Umbrella direction: a lean sensor-and-response fleet (vault proposal direction-2026-10)
- Audit leftovers (Nov 8): rerun `scripts/update-linux-agents.sh` when linux-agent-work, linux-blackbox-vault and linux-neri-hunters start; a fresh Windows MSI install leaves the service stopped
