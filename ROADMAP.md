# Ominull
Ominull is an endpoint telemetry, detection and containment hub for operators managing Linux and Windows devices. It pairs a fleet console, observed network evidence, device identity and bounded response controls with agents on each machine, all served from a self-hosted Linux hub.

## Now
## Next
- M8 rest: confirm the abuse.ch ThreatFox and URLhaus feeds load once the owner puts an abuse.ch Auth-Key in /etc/ominull/abusech.key on the hub (asked in Aico); decoys, decoy names and planted credentials are live (plan: docs/audit-2026-11-06.md)
- M12: Go Linux agent only with remote-admin parity, if the owner still wants the rewrite (asked in Aico) (plan: docs/audit-2026-11-06.md)
- Trust fabric: IP and CIDR rules enforced end to end, including older agents that refuse ranges (plan: docs/TRUST_FABRIC.md)
- Trust fabric: FQDN rules with hub-side resolution, and close the blanket DNS egress
## Later
- Console: what the M11 trim left. These routes have no caller, but each is the only way to do its job, so decide keep or give them a screen: creating a tenant, setting topology networks, retiring an endpoint, allow-isolation and host capabilities. `/api/v1/assets/correct` has lost its only console caller. `legacyAssetGraph` still runs when the assets list is empty and the browser fixture depends on it, so check a just-enrolled hub first. Hub request logs would settle the routes outside tools might call, which were not touched
- Evaluate BloodHound CE and OpenGraph, then build the AI weak-point finder
- Household: back up the router and repair the approved parental, DNS and Ominull config; then IoT segmentation and DNS filtering (vault proposal direction-2026-10)
- Phase 2: AI-agent egress policy with agent-session attribution, and data inventory contract v4 (vault proposal direction-2026-10)
- Phase 3: measured agent move from C to Go, portable Go collector (Windows first), labeled Neri-lab drill harness, time-boxed Velociraptor benchmark
- Phase 4: business line with paid certs, licensing, multi-tenant and macOS
- Umbrella direction: a lean sensor-and-response fleet (vault proposal direction-2026-10)
- Agent reading cost: docs/project-guide.md "CLI and API" (25 KB, read 43 times in 4 sessions) holds route and policy detail agents page through; put each rule next to its code or in ominullctl --help and keep the guide to pointers (usage-burn lane 7 report, Nov 8)
- Audit leftovers (Nov 8): rerun `scripts/update-linux-agents.sh` when linux-agent-work, linux-blackbox-vault and linux-neri-hunters start; Linux agent forensics list still names the old service (`agent/include/forensics_linux.h`); no health finding for failing domain feeds or for endpoints matching no Aico machine; served-flow rule is port-inferred; host authority pinned on two hosts with no way to deliver it; decide on the kept routes `/api/v1/maintenance/escalate` and `/api/v1/scripts/digest` and on the grants auto-isolate brake (the plan said delete it); a fresh Windows MSI install leaves the service stopped; `curl --cacert` on Windows fails with exit 60 with the hub CA
