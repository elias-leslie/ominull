# Ominull
Ominull is an endpoint telemetry, detection and containment hub for operators managing Linux and Windows devices. It pairs a fleet console, observed network evidence, device identity and bounded response controls with agents on each machine, all served from a self-hosted Linux hub.

## Now
## Next
- Trust fabric leftover: a full 12-hour owner dead-man timer has never been waited out; it held 39 minutes on Linux and 6 on Windows, and the 5-minute timer released on both. Moved-hub following on real Windows was proven with a hosts-file answer, not through a resolver in the baseline (plan: docs/TRUST_FABRIC.md)
## Later
- AI weak-point finder, on a small graph in the hub's own database, not BloodHound (evaluation: docs/BLOODHOUND_EVALUATION.md)
- Household: back up the router and repair the approved parental, DNS and Ominull config; then IoT segmentation and DNS filtering (vault proposal direction-2026-10)
- Phase 3: measured agent move from C to Go (owner Nov 8: skipped for now, reopen if C starts costing us; the Linux agent needs remote-admin parity before any switch), portable Go collector (Windows first), labeled Neri-lab drill harness, time-boxed Velociraptor benchmark
- Phase 4: business line with paid certs, licensing, multi-tenant and macOS
- Umbrella direction: a lean sensor-and-response fleet (vault proposal direction-2026-10)
- Audit leftovers (Nov 8): rerun `scripts/update-linux-agents.sh` when linux-agent-work, linux-blackbox-vault and linux-neri-hunters start; when windows-laptop-85t7ci9j and windows-laptop-tjk0q7df next connect, check they report the engagement profile the hub has signed for them
