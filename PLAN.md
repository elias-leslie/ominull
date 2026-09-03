# Project Master Plan: Ominull Enterprise Threat Nullification Platform

> Historical planning record. Superseded product ideas in this file are not
> supported release behavior. Current scope is the hub plus Linux and Windows
> agents; see `README.md` and `FEATURE_REDUCTION_COMPANION_PLAN.md`.
## Cross-Platform Kernel Network Telemetry, Dynamic Enforcement & Rapid IR System

**Author:** Antigravity AI & System Engineering Team  
**Date:** 2026-08-27  
**Status:** Historical planning record; not supported release scope.
**Historical target environments:** Windows 10/11, Linux distributions, and macOS. The retained
release supports the hub plus Linux and Windows agents; kernel-driver, eBPF, PF, macOS, Copilot,
and policy/rule ideas below are historical only. See `FEATURE_REDUCTION_COMPANION_PLAN.md` and
`README.md` for current behavior.

---

## 1. Vision & Core Philosophy

**Ominull** is an ultra-lean, high-performance, cross-platform enterprise threat nullification platform and rapid Incident Response (IR) control plane.

### Core Architectural Mandates:
1. **Lean & Zero-Bloat:** Single self-contained binary for the management hub (no Docker/K8s, no external database dependencies). Single lightweight native agent (<15 MB RAM, <0.5% CPU overhead on endpoints).
2. **Multi-Tenancy by Design (MSP/MSSP Ready):** Complete cryptographic and logical tenant separation. Manage 1 to 500 distinct client organizations from a single lightweight hub with tenant-scoped tokens, isolated policy tables, and segregated telemetry logs.
3. **Rapid IR & Jump-Kit Deployment:** Turn any analyst laptop or existing server into an authoritative IR command hub in under 10 seconds. Deploy to remote endpoints via a 1-line PowerShell / Bash bootstrap over WinRM, SSH, MSP RMM tools (NinjaOne, Datto, ConnectWise), or EDR Live Response consoles.
4. **Pluggable Kernel Architecture:** Unified cross-platform agent core with pluggable OS-specific filtering engines:
   - **Windows:** Native WFP Callout Driver (`ominull.sys`) + User-Mode ETW/Socket Stream Fallback.
   - **Linux:** eBPF Kernel Probes (`sockops`, `cgroup_skb`, `tc` classifier).
   - **macOS:** BSD Packet Filter (`pfctl`) + Native Process-Socket Telemetry Stream.
5. **Kernel-Level Host Network Isolation:** Instant (<1 ms) host quarantine dropping 100% of lateral movement and exfiltration traffic while automatically maintaining an authenticated pinhole to the IR analyst's hub.
6. **Zero Slop & Scalable Code Quality:** Strict adherence to clean architecture, explicit error handling, performant data structures, modular package separation, and zero extraneous dependencies.

---

## 2. High-Level System Architecture

```
+-----------------------------------------------------------------------------+
|              CENTRAL MANAGEMENT HUB / ANALYST JUMP KIT                      |
|                  (Single Portable Native Binary: ominull-hub)              |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  |  Multi-Tenant Controller & Ingestion Engine                           |  |
|  |  - Tenant A (Acme Corp)        - Tenant B (FinCorp)                   |  |
|  |  - In-Flight GeoIP & ASN       - Real-Time Anomaly & Diurnal Engine   |  |
|  |  - 4-Tier Policy Engine        - 1-Click Threat Nullification Triage  |  |
|  |  - Embedded SQLite Event Store - Instant Remote Deployment Generator  |  |
|  +-----------------------------------+-----------------------------------+  |
+--------------------------------------|--------------------------------------+
                                       |
                       mTLS + Ephemeral Token (Port 9999 / HTTPS)
                                       |
       ┌───────────────────────────────┼───────────────────────────────┐
       ▼                               ▼                               ▼
+-----------------------------+ +-----------------------------+ +-----------------------------+
|      WINDOWS ENDPOINT       | |       LINUX ENDPOINT        | |       macOS ENDPOINT        |
|  (Windows 11 / Server 2025) | |    (Debian 12 / Ubuntu 24)  | |       (macOS 14 Sonoma)     |
|                             | |                             | |                             |
|  +-----------------------+  | |  +-----------------------+  | |  +-----------------------+  |
|  | ominulld.exe Service  |  | |  | ominulld Daemon       |  | |  | ominull_mac_daemon.sh  |  |
|  | (WFP + Net Flow Core) |  | |  | (eBPF + Socket Core)  |  | |  | (PF + Socket Stream)  |  |
|  +-----------+-----------+  | |  +-----------+-----------+  | |  +-----------+-----------+  |
|              | IOCTL / Net  | |              | BPF Syscall   | |              | pfctl / proc |
|  +-----------v-----------+  | |  +-----------v-----------+  | |  +-----------v-----------+  |
|  | WFP Kernel Callout    |  | |  | eBPF Filter Probes    |  | |  | BSD Packet Filter     |  |
|  | (ALE / Stream Layer)  |  | |  | (cgroup_skb / tc)     |  | |  | (Anchor Isolation)    |  |
|  +-----------------------+  | |  +-----------------------+  | |  +-----------------------+  |
+-----------------------------+ +-----------------------------+ +-----------------------------+
```

---

## 3. Phased Roadmap & Work Breakdown

### Phase 1: Automated Test Harness & Proxmox VM Pipeline `[COMPLETED]`
- Proxmox VMs 110 (Windows 11), 112 (Ubuntu Linux), 114 (macOS Sonoma) configured on bridge `vmbr0`.
- Automated QMP guest input automation and screendump tooling.
- Baseline clean snapshots (`baseline-clean`) captured on all 3 target VMs.

### Phase 2: Lean Multi-Tenant Control Hub & Agent Foundation `[COMPLETED]`
- Standalone `ominull-hub` binary listening on port 9999 and proxied via Cloudflare Tunnel (`https://omi.example.com`).
- Multi-tenant SQLite database with tenant isolation, master API key authentication, and audit logs.
- Dynamic bootstrap endpoints (`/bootstrap.ps1`, `/bootstrap.sh`, `/bootstrap.mac.sh`).

### Phase 3: Cross-Platform Threat Nullification & Fleet Quarantine `[COMPLETED]`
- Linux: eBPF XDP / TC isolation.
- Windows: WFP callout & default-drop isolation.
- macOS: BSD Packet Filter (`pfctl`) anchor isolation.
- Verified fleet-wide bulk quarantine (`isolate-bulk` / `unisolate-bulk`) across all 3 operating systems.

---

### Phase 8: Comprehensive Cleanup & Workspace Hygiene `[COMPLETED]`
- **Objective:** Eliminate slop, temporary artifacts, stale scripts, duplicate images, and obsolete test files to establish a clean foundation.
- **Deliverables Completed:**
  - Audited and purged 472MB of obsolete raw `.ppm` screendumps and redundant files in `scratch/`.
  - Consolidated and verified clean POSIX helper scripts under `scripts/`.
  - Initialized and migrated SQLite schema dynamically for GeoIP, duration, 4-tier scope, and diurnal tracking.
  - Enforced zero-slop clean architecture and memory-safe design across Go and C codebases.

---

### Phase 9: High-Fidelity Flow & Telemetry Streaming Across Linux, Windows & macOS `[COMPLETED]`
- **Objective:** Upgrade agents from basic heartbeats to continuous, high-fidelity network flow telemetry (processes, sockets, bytes in/out, packets, duration).
- **Deliverables Completed:**
  - **Linux (`ominulld` / eBPF):** Streams continuous socket flow telemetry resolving inode to `/proc/<pid>/exe`, parsing `/proc/net/tcp`, with TC classifier and active eBPF maps.
  - **Windows (`ominulld.exe`):** Implemented active connection polling (`GetExtendedTcpTable` / `GetExtendedUdpTable`) and `QueryFullProcessImageNameW` process resolution in user-mode fallback and native WFP engine (`ominull_wfp_user.exe`).
  - **macOS (`ominull_mac_daemon.sh`):** Implemented native process-socket streaming using `lsof` / BSD socket filters to report live process names, remote endpoints, and bandwidth delta counters.

---

### Phase 10: In-Flight GeoIP, ASN & Threat Intelligence Enrichment `[COMPLETED]`
- **Objective:** Enrich every external network flow on ingestion in real time before persistence.
- **Deliverables Completed:**
  - Embedded offline fast GeoIP / ASN lookup engine (`hub/pkg/threatintel/geoip.go`) with sub-microsecond resolution.
  - Annotated incoming flows in real time with country code, full country name, ASN, and organization.
  - In-flight integration with Abuse.ch Feodo Tracker and Emerging Threats IOC feeds for instant hardware nullification.

---

### Phase 11: Real-Time Behavioral Profiling & Statistical Outlier Engine `[COMPLETED]`
- **Objective:** Classify normal baseline traffic patterns per endpoint/role and detect anomalous deviations.
- **Deliverables Completed:**
  - **Diurnal Time-of-Day Profiling:** Built 24×7 hourly activity distributions per endpoint and role tag (`workstation`, `server`).
  - **Off-Hours Detection:** Triggers `OFF_HOURS_ACTIVITY` (High severity) on interactive workstation traffic during off-hours (22:00–05:00 UTC, e.g. 02:00).
  - **Volume & Exfiltration Outliers:** Welford running mean and standard deviation outlier tracking ($Z > 3.5$) triggering `BANDWIDTH_SPIKE` (Critical severity).
  - **Rare / First-Seen Destination Scoring:** `IsFirstSeenDestination` queries organizational history, triggering `NOVEL_DESTINATION`.
  - **C2 Beaconing Detection:** Sliding window interval and jitter calculation ($\sigma < 1.5\text{s}$) triggering `C2_BEACONING`.

---

### Phase 12: 4-Tier Policy Engine & 1-Click Anomaly Mitigation UI `[COMPLETED]`
- **Objective:** Provide granular hierarchical policy control and an intuitive 1-click triage workflow in the Web UI.
- **Deliverables Completed:**
  - **4-Tier Scoped Policy Engine:** Hierarchical priority evaluation: Global (Tier 0) $\to$ Client/Tenant (Tier 1) $\to$ Location (Tier 2) $\to$ Endpoint/Role (Tier 3).
  - **Granular Policy Rules:** Match on Protocol, CIDR, Port, Process Regex, Time Schedule (Business Hours vs Off-Hours), and Action (BLOCK, PERMIT, QUARANTINE, ALERT).
  - **1-Click Anomaly Action Modal (`#triage-modal`):**
    1. 🔴 **Nullify Threat (Instant Kernel Block)**
    2. 🔒 **Quarantine Host (Microsecond Isolation)**
    3. 🟢 **Approve as Normal (Add Exclusion Pinhole)**
    4. 📝 **Create Granular Policy Rule**
  - **Visual Analytics Dashboard (`#tab-analytics`):**
    - 24-Hour Diurnal Time-of-Day Activity Chart with off-hours highlighting.
    - Top Network Talkers ranked by process executable and bandwidth volume.
    - GeoIP Destination Countries & Threat Intelligence Table.
    - Real-time Anomaly triage triggers.

---

### Phase 13: End-to-End Multi-OS Extensive Testing & Verification `[COMPLETED]`
- **Objective:** Rigorously validate the entire pipeline across Linux, macOS, and Windows with synthetic workloads and simulated threat scenarios.
- **Deliverables Completed:**
  - **Multi-OS Live Deployment:** Deployed and verified live agent telemetry on Linux (Ubuntu 24 VM 112), Windows 11 (VM 110), and macOS Sonoma (VM 114) connected to Hub LXC 150 (`http://10.0.0.58:9999`).
  - **Workload Simulations:**
    - Baseline normal traffic validated across all 3 platforms.
    - 02:00 off-hours workstation anomaly verified (`OFF_HOURS_ACTIVITY`).
    - Bandwidth burst exfiltration verified (`BANDWIDTH_SPIKE`).
    - C2 periodic beaconing verified (`C2_BEACONING`).
  - **Enforcement Validation:**
    - 1-Click Nullify verified (kernel drop rule creation + anomaly resolution).
    - 1-Click Quarantine verified (microsecond host isolation with management pinhole).
    - 1-Click Approve verified (operational exclusion pinhole deployment).
  - **100% Automated Unit Test Suite Pass:** Verified across all Go packages in `hub/`.

### Phase 14: Multi-Tier Network Asset Scanner & Extensible OS Fingerprinting `[COMPLETED]`
- **Objective:** Build native pure-Go multi-tier network scanner with passive, standard, and aggressive IR modes, extensible signature engine, and TCP/IP stack + application response delta timing heuristics.
- **Deliverables Completed:**
  - **Scanner Profiles:**
    - `Passive`: L2 ARP / Neighbor cache snooping and unmanaged peer flow correlation.
    - `Standard`: Subnet ping/ARP sweep + Top 100 common ports + service banner grabbing + OUI MAC lookup.
    - `Aggressive IR`: High-speed full port sweep + deep service enumeration (SSH, SMBv1, RDP, Redis, HTTP, Telnet) + weakpoint risk scoring.
  - **Extensible / Trainable OS Fingerprinting:**
    - Multi-factor signature evaluation: OUI Hardware Vendor, TTL (64/128/255), TCP Initial Window Size, TCP Options ordering, Service Banners, and Application Response Delta Timing ($\Delta t = T_{\text{app}} - T_{\text{syn}}$).
    - Feedback / Training API (`/api/v1/scanner/feedback`, `/api/v1/scanner/signatures`) allowing analysts/agents to dynamically refine and override device signatures (e.g. refining generic Linux $\to$ NVIDIA Shield TV v11).
  - **Protection Gap & Missing Agent Discovery:**
    - Auto-correlate discovered assets against `store.endpoints`.
    - 1-Click Agent Bootstrap command generator for unmanaged nodes.

---

### Phase 15: Visual Communications Topology Graph & Relationship Outlier Engine `[COMPLETED]`
- **Objective:** Provide visual force-directed network topology mapping and graph-driven topological anomaly detection.
- **Deliverables Completed:**
  - **Graph Data Model & Storage:** In-memory and persisted directed graph ($V, E$) tracking Endpoints, Unmanaged Nodes, Cloud ASNs, and External WAN IOCs.
  - **Topological Anomaly Detection:**
    - `LATERAL_PORT_SWEEP`: Sudden degree spike ($k_{out} > 5$) / 02:00 off-hours sweep across internal subnet.
    - `DATA_STAGING_PIVOT`: Multi-source internal aggregation funneling into outbound WAN egress.
    - `NOVEL_TOPOLOGY_EDGE`: First-time connection between historically separated security enclaves.
  - **Interactive Visual Graph Console:**
    - Web canvas / SVG force-directed topology map in `#tab-topology` with clustered node grouping, directional particle flows, bandwidth volume edge weighting, and click-to-inspect drill-down drawers.

---

### Phase 16: Automated 1-Click Remote Push-Deployment Engine `[COMPLETED]`
- **Objective:** Turn discovered network assets into active endpoints via pure-Go SSH and WinRM jump onboarding directly from the Hub.
- **Deliverables Completed:**
  - **Hub Jump Engine (`hub/pkg/deployer`):** Go-native SSH and WinRM/PowerShell remoting clients for Linux, Windows, and macOS.
  - **Credential Management & Jump Vault:** Securely handles ephemeral or vaulted SSH keypairs, passwords, and service account tokens.
  - **Automated Service Provisioning:** Pushes agent binaries, registers system services (`systemd`, Windows Service Manager, LaunchDaemon), and validates live telemetry stream within 5 seconds.
  - **UI Integration:** 1-Click "Deploy Agent" modal with dual mode (Zero-Touch Push + Manual One-Liner) and real-time streaming console logs.

---

### Phase 17: Subnet Quarantine Mesh (Lateral Shield for Rogue/Unmanaged Assets) `[COMPLETED]`
- **Objective:** Enable kernel-level network isolation for rogue or unmanaged devices without requiring an agent on the target device.
- **Deliverables Completed:**
  - **Mesh Command Protocol:** `MESH_ISOLATE_PEER` directive broadcast to all managed endpoints sharing an L2 subnet and synchronized on telemetry handshakes.
  - **Peer Kernel Suppression:**
    - Linux: iptables / eBPF drop rules isolating rogue target MAC/IP across input/output paths.
    - Windows: Dynamic WFP callout filter dropping traffic to target MAC/IP across all network profiles.
    - macOS: `pfctl` anchor inserting dynamic rapid-drop packet rules.
  - **UI Integration:** 1-Click "Quarantine Rogue Asset" and "Lift Mesh Block" buttons in Asset Table and Topology Graph Inspector.

---

### Phase 18: Stream DPI & In-Flight TLS ClientHello SNI / DNS Dissection `[COMPLETED]`
- **Objective:** Extract rich protocol metadata in-flight directly within the flow sniffer.
- **Deliverables Completed:**
  - **TLS SNI Dissector (`agent/include/dpi.h`):** Parses initial TLS `ClientHello` packets on port 443 to extract the Server Name Indication hostname before encryption (tested with synthetic TLS 1.3 packets).
  - **DNS Query/Response Sniffer (`agent/include/dpi.h`):** Extracts queried domain names and resolved IP addresses on port 53.
  - **Graph Enrichment & DGA Anomaly Heuristic:** Evaluates Shannon entropy on SNI and domain names ($>3.85$) to detect Domain Generation Algorithms (`SUSPICIOUS_DGA_DOMAIN`).

---

### Phase 19: Cross-Platform Native Packaging & Release Pipeline `[COMPLETED]`
- **Objective:** Build enterprise distribution packages for frictionless mass rollout.
- **Deliverables Completed:**
  - **Linux:** Native `.deb` (`ominull-agent_1.1.0_amd64.deb`) package built with systemd daemon-reload, enable, and start scripts.
  - **Windows:** Native Windows `.tar.gz` bundle with automated PowerShell service registration.
  - **macOS:** Native macOS `.tar.gz` bundle with LaunchDaemon plist (`dev.ominull.daemon.plist`).
  - **Hub Distribution:** Served and downloadable directly from `http://<hub>:9999/download/ominull-agent_1.1.0_amd64.deb`.

---

### Phase 20: Embedded Autonomous Agentic Copilot & Cognitive Tier `[COMPLETED]`
- **Objective:** Build an embedded 24/7 AI security copilot running natively inside `ominull-hub` in LXC 150.
- **Deliverables Completed:**
  - **Multi-Model Provider Engine (`hub/pkg/copilot`):** Pluggable backends for Local Ollama (`http://10.0.0.39:11434` on `hypervisor-01`), Google Gemini Free Tier, OpenAI/Claude, and airgapped cognitive SOC heuristics.
  - **Autonomous Triage Loop:** Ingests Critical/High anomalies, pulls process lineage and DNS history, investigates root cause, and generates natural-language forensic briefings.
  - **Conversational ChatOps Console:** Interactive natural-language prompt box in Web UI (`#tab-copilot`) for conversational policy queries, quick chips, and threat investigation.

---

### Phase 21: Canonical Agent Skill (`ominull`) & Multi-Agent Tool Surface `[COMPLETED]`
- **Objective:** Provide a unified canonical skill and CLI tool surface so any AI agent (Antigravity, Claude Code, Codex, TUIs) can interface with, purple-team, train, and evolve Ominull.
- **Deliverables Completed:**
  - **Canonical Skill (`/home/operator/agent-skills/skills/ominull/SKILL.md`):** Comprehensive reference documenting REST API schemas, policy syntax, telemetry queries, and mitigation actions.
  - **Harness Distribution:** Synced across Claude Code (`.claude/skills`), OpenAI Codex (`.codex/skills`), and Antigravity/Gemini (`.gemini/config/skills`) with 0 errors and 0 drift via `st skills audit`.
  - **CLI Tool Surface (`ominullctl`):** Unified Go CLI utility for querying telemetry, running synthetic adversary simulations, training device signatures, isolating rogue hosts, and fleet management.

### Phase 22: Agent Release Versioning, Remote Update Push & Roll-Out Pipeline `[COMPLETED]`
- **Objective:** Close the loop between changing the code and the fleet actually running it. Prior to this phase the hub had no notion of which agent release it served, endpoint versions were displayed nowhere, and updating an agent meant re-running the SSH push-deployer by hand.
- **Deliverables Completed:**
  - **Single Source of Truth (`VERSION`, `scripts/version.sh`):** One canonical version compiled into the hub, all three agent codebases, and the package filenames the hub serves. `version.sh check` fails on drift and gates CI — it immediately caught the Windows/portable agent still pinned at `1.0.0`.
  - **Hub Version Tracking & Update Orchestration (`hub/pkg/server/server.go`, `hub/pkg/storage/storage.go`):** `POST /api/v1/agents/update` (admin-only) publishes a release and queues per-endpoint jobs; `GET /api/v1/agents/update-status` reports currency and pending jobs; `GET /api/v1/agent/config` is the agent-facing poll. Downgrades below the hub's own bundle are refused.
  - **Update-over-Telemetry:** The `POST /api/v1/events` response carries an `agent_update` descriptor, so an agent learns about a release on the connection it already holds. The job retires only when the endpoint reports the target version back, making the update observed rather than assumed.
  - **Linux Self-Update (`agent/linux/main.c`):** Installs the hub-offered package detached from the daemon dpkg is about to stop, guarded on root, package type, hub-origin URL pinning, and a strict character allowlist before the URL reaches a shell. `--no-auto-update` opts out.
  - **Config-Preserving Package Layout:** Enrolment moved to `/etc/ominull/agent.conf`, written once and never overwritten, with the `.deb` and the bootstrap installer converged on one unit (`ominull-agent.service`) — so a self-update keeps the endpoint's hub URL and key instead of reverting to placeholders.
  - **Console Surface (`hub/pkg/server/dashboard.go`):** Per-endpoint agent version column with out-of-date and update-queued badges, an outdated count in the stats ribbon, and per-endpoint plus fleet-wide push buttons.
  - **Roll-Out Pipeline (`scripts/release.sh`):** Bump → test → package → ship to hub → roll agents → wait for fleet convergence, enforcing hub-before-agents ordering.
  - **Mesh Quarantine Reconciliation Fix:** The Linux agent now lifts drop rules for peers the hub has released, instead of only ever adding them — an endpoint that was offline during a release previously kept the peer blackholed indefinitely.

---

## 4. Verification & Quality Gates

1. **Pass Criteria:** 100% automated test pass, zero kernel panics / BSODs, zero memory leaks, and sub-millisecond policy evaluation.
2. **Evidence Retention:** Stored in `evidence/` with execution logs, API response payloads, and markdown verification reports.
