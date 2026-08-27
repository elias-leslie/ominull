# Ominull: Autonomous CyberOps & Ring-0 Threat Nullification Platform

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](file:///srv/workspaces/projects/ominull/hub)
[![C Standard](https://img.shields.io/badge/C-C11-00599C?style=flat&logo=c)](file:///srv/workspaces/projects/ominull/agent)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows%20%7C%20macOS-informational)](#system-architecture)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](file:///srv/workspaces/projects/ominull/LICENSE)

**Ominull** is an enterprise-grade, ultra-lean kernel network security and autonomous Incident Response (IR) platform. It unifies microsecond ring-0 enforcement, in-flight Deep Packet Inspection (DPI), statistical behavioral anomaly detection, subnet quarantine mesh isolation, automated 1-click push-deployment, and an embedded 24/7 AI CyberOps Copilot into a single self-contained architecture.

![Ominull Dashboard — Demo Mode](docs/screenshots/dashboard-demo.png)

> **🎭 Demo Mode:** The web console ships with a built-in demo mode (toggle button in the header, or append `?demo=true` to the URL) that renders the entire dashboard against seeded synthetic fleet data — no live endpoints, keys, or infrastructure required. Ideal for screenshots, evaluations, and public documentation.

---

## 1. System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CENTRAL MANAGEMENT HUB (LXC 150 / VM / BAREMETAL)               │
│                                  [ominull-hub Native Binary]                           │
│                                                                                        │
│  • Zero External Dependencies (Embedded SQLite + In-Memory Threat Intel IOC Cache)     │
│  • Multi-Tenant Hierarchy (MSPs / Enterprise Units / Locations / Dynamic Roles)       │
│  • Real-Time Web Console (Zero-CDN, Zero-NPM, Embedded Single-Binary Dashboard)        │
│  • In-Flight Stream DPI & DGA Shannon Entropy Heuristic Engine                         │
│  • Statistical Behavioral Anomaly Engine (Diurnal Baselines, Z-Scores, Fan-Out sweeps) │
│  • Automated 1-Click Push-Deployer (Pure-Go SSH Remote Provisioning Engine)            │
│  • Autonomous AI Security Copilot (Local Ollama llama3.2, Gemini Free Tier, OpenAI)   │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
           ┌────────────────────────────────┼────────────────────────────────┐
           │ mTLS / REST / WS               │ Telemetry Stream               │ MESH_ISOLATE_PEER
           ▼ (Port 9999 / 443)              ▼                                ▼
┌───────────────────────┐        ┌───────────────────────┐        ┌───────────────────────┐
│   WINDOWS ENDPOINT    │        │    LINUX ENDPOINT     │        │    macOS ENDPOINT     │
│  (Win 11 / Server 25) │        │ (Debian / Ubuntu / PVE│        │   (macOS 14+ Sonoma)  │
│                       │        │                       │        │                       │
│ • WFP Callout Driver  │        │ • eBPF / TC Classifier│        │ • pfctl Packet Anchor │
│   (ominull.sys)       │        │ • Socket Inode Finder │        │ • Process Associator  │
│ • User-Mode Daemon    │        │ • In-Flight TLS DPI   │        │ • Dynamic PF Drop Set │
│ • Forensic Pinholing  │        │ • Mesh Lateral Drop   │        │ • Subnet Mesh Shield  │
└───────────────────────┘        └───────────────────────┘        └───────────────────────┘
```

---

## 2. Core Capabilities

### 🛡️ Dual-Tier Network Threat Containment
1. **Ring-0 Endpoint Quarantine (Agent-Managed Hosts):**
   - Drops 100% of ingress and egress network traffic instantly at the kernel layer (WFP sublayer at `0xFFFF` priority on Windows, eBPF TC classifier on Linux, `pfctl` anchor on macOS).
   - Preserves an encrypted, unidirectional **Forensic Pinhole** allowing the endpoint to communicate exclusively with the Ominull Hub for live forensic triage and remediation.
2. **Subnet Quarantine Mesh (Rogue & Unmanaged Hosts):**
   - When an unmanaged or rogue asset is detected (e.g. vulnerable IoT, compromised printer, unauthorized shadow server), the Hub broadcasts `MESH_ISOLATE_PEER` directives to all agent-managed peers on the same L2 broadcast domain.
   - All managed endpoints drop traffic to/from the target MAC/IP, achieving total network isolation without requiring an agent on the target device.

### 🔍 Multi-Tier Asset Discovery & Extensible OS Fingerprinting
- **Non-Intrusive & Aggressive Sweeps:** Scans CIDR subnets using combined ARP discovery, TCP SYN probes against top service ports, and reverse DNS PTR lookups.
- **Multi-Vector Fingerprinting Heuristics:**
  - Initial IP Time-To-Live (TTL) inspection (Linux `64`, Windows `128`, Cisco/Network `255`).
  - TCP Window Size analysis & Service Banner extraction (SSH, HTTP/HTTPS, SMB, ADB, RTSP).
  - Round-Trip Response Timing Delta ($\Delta t$ app-layer latency profiling).
  - IEEE OUI MAC vendor database lookup.
- **Dynamic Feedback Loop & Training:** Machine learning and operator feedback can refine fingerprints on the fly (`POST /api/v1/scanner/feedback`) without restarting the hub or agents.

### 🔬 Stream DPI & DGA Domain Detection
- **TLS ClientHello SNI Dissection:** Zero-copy C packet parser extracts cleartext Server Name Indication (SNI) hostnames from TCP port 443 initial handshakes before encryption.
- **DNS Wire Sniffer:** Dissects UDP/TCP port 53 length-prefixed query domains and response mappings.
- **Shannon Entropy Heuristic:** Measures character distribution entropy on queried hostnames. Domains exceeding $3.85$ bits/byte (or $3.5$ with suspicious TLDs like `.xyz`, `.top`, `.cc`) trigger immediate `SUSPICIOUS_DGA_DOMAIN` anomaly alerts.

### 📊 Behavioral Anomaly & Threat Profiling
- **Diurnal Time-of-Day Profiling:** Flags anomalous off-hours outbound connections from workstations (e.g. interactive shell egress or cloud connections at 02:00 UTC).
- **Exfiltration Spike Detection:** Calculates real-time rolling mean and variance using Welford's algorithm to trigger alerts when traffic spikes exceed baseline ($Z > 3.5$).
- **C2 Periodic Beaconing:** Calculates timestamp delta standard deviations ($\Delta t < 0.2\text{s}$) to uncover low-and-slow periodic command-and-control heartbeats.
- **Internal Fan-Out / Lateral Port Sweeps:** Detects workstations probing $\ge 5$ internal subnet hosts within a 60-second window.

### 🚀 1-Click Remote Push-Deployment
- **Pure-Go SSH Provisioning:** Uses `golang.org/x/crypto/ssh` to jump to internal LAN endpoints, probe target architecture (`uname -s`), upload bootstrap installers, register systemd / Windows services, and verify live check-in.
- **Web UI & CLI Integration:** Deploy directly from the Discovered Assets table in the console or via CLI.

### 🤖 Embedded Autonomous AI CyberOps Copilot
- **Pluggable Multi-Model Providers:** Local Ollama (`llama3.2` / `mistral` on LAN), Google Gemini Free Tier, OpenAI (`gpt-4o-mini`), and airgapped cognitive SOC heuristics.
- **ChatOps & Automated Triage:** Conversational query interface (`#tab-copilot`), automated MITRE ATT&CK technique mapping, root-cause analysis, and recommended containment steps.

---

## 3. Directory Structure

```
ominull/
├── agent/                         # Multi-platform endpoint agent source
│   ├── include/                   # Shared headers & DPI protocol dissectors
│   │   ├── agent.h                # Event schemas & config structs
│   │   ├── dpi.h                  # In-flight TLS ClientHello SNI & DNS wire parser
│   │   └── ominull_ioctl.h        # Windows IOCTL command definitions
│   ├── linux/                     # Native Linux eBPF / TC agent (main.c)
│   ├── macos/                     # Native macOS pfctl daemon (ominull_mac_daemon.sh)
│   ├── src/                       # Windows WFP driver client & WinHTTP telemetry
│   └── tests/                     # Agent & DPI unit test suite (test_dpi.c)
├── dist/                          # Packaged release artifacts (.deb, .tar.gz)
├── driver/                        # Windows Kernel Callout Driver (ominull.sys)
│   ├── include/                   # Kernel-mode WFP definitions
│   └── src/                       # ALE Callouts & Sublayer driver (driver.c)
├── evidence/                      # Verification artifacts, logs & test evidence
├── hub/                           # Central Management Hub & API server (Go)
│   ├── cmd/main.go                # Hub daemon entrypoint
│   └── pkg/
│       ├── auth/                  # RBAC, password hashing & JWT tokens
│       ├── bootstrap/             # Dynamic bash / PowerShell / sh agent scripts
│       ├── copilot/               # Multi-model AI Copilot & ChatOps engine
│       ├── deployer/              # Pure-Go SSH remote push-deployer
│       ├── detector/              # Behavioral anomaly engine & DGA heuristics
│       ├── pki/                   # Autonomous mTLS certificate authority
│       ├── scanner/               # Multi-tier subnet scanner & OS fingerprinting
│       ├── server/                # REST / WebSocket server & Web Dashboard UI
│       ├── storage/               # SQLite persistence & Topology Graph builder
│       └── threatintel/           # Live C2 / IOC feed ingestion (Feodo, Abuse.ch)
├── scripts/                       # Build, deployment & CLI helper scripts
│   ├── build-packages.sh          # Cross-platform .deb / .tar.gz release builder
│   ├── ominull-cli                # Standalone operator / AI agent CLI interface
│   ├── sign.sh                    # Authenticode kernel driver signing script
│   └── deploy_remote.sh.example   # Proxmox LXC hub deployment template
├── PLAN.md                        # Master Architecture & Milestone Plan (Phases 1-21)
├── README.md                      # Comprehensive Project Documentation
└── TESTING.md                     # Verification Playbooks & Purple Team Tests
```

---

## 4. Quick Start & Installation

### Option A: Running the Hub

```bash
# 1. Build the Hub binary
cd /srv/workspaces/projects/ominull/hub
CGO_ENABLED=1 go build -o bin/ominull-hub cmd/main.go

# 2. Start the Hub
./bin/ominull-hub \
  -addr "0.0.0.0:9999" \
  -key "<your-admin-key>" \
  -url "http://10.0.0.58:9999" \
  -db "/opt/ominull/data/ominull.db"
```

Open the embedded Web Console at `http://<hub-ip>:9999` and authenticate with your API key.

---

### Option B: Deploying Agents to Endpoints

#### 1. Linux (Debian / Ubuntu / Proxmox)
```bash
# Download and install native .deb package from Hub
curl -s http://10.0.0.58:9999/download/ominull-agent_1.1.0_amd64.deb -o /tmp/ominull.deb
sudo dpkg -i /tmp/ominull.deb

# Or 1-line instant curl bootstrap:
curl -s http://10.0.0.58:9999/bootstrap.sh?key=<your-admin-key> | sudo bash
```

#### 2. Windows 11 / Server 2025
```powershell
# In an Administrative PowerShell:
Set-ExecutionPolicy Bypass -Scope Process -Force
irm "http://10.0.0.58:9999/bootstrap.ps1?key=<your-admin-key>" | iex
```

#### 3. macOS (Sonoma 14+)
```bash
curl -s http://10.0.0.58:9999/bootstrap_mac.sh?key=<your-admin-key> | sudo bash
```

---

## 5. CLI Usage Cheatsheet (`ominull-cli`)

The [`scripts/ominull-cli`](file:///srv/workspaces/projects/ominull/scripts/ominull-cli) utility provides a fast, scriptable interface for human operators and AI agents:

```bash
# 1. Check Fleet Status & Online Agents
ominull-cli status

# 2. Run Subnet Asset Sweep
ominull-cli scan 10.0.0.0/24 standard
ominull-cli scan 10.0.0.0/24 aggressive

# 3. View Discovered Assets, OS Guesses & Weakpoints
ominull-cli assets

# 4. Train / Refine OS Fingerprint
ominull-cli train 10.0.0.25 "NVIDIA Shield TV Pro" "NVIDIA Corporation" "Smart TV / Media Streamer"

# 5. Review Behavioral Anomaly Alerts
ominull-cli alerts

# 6. Autonomous AI Forensic Investigation
ominull-cli investigate alert-f8a129

# 7. Subnet Quarantine Mesh Containment
ominull-cli quarantine-mesh 10.0.0.57
ominull-cli unquarantine-mesh 10.0.0.57

# 8. Interactive Natural-Language ChatOps
ominull-cli chat "Are there any unauthorized devices communicating on sensitive ports?"

# 9. 1-Click Remote SSH Push Deployment
ominull-cli deploy 10.0.0.50 operator "YourPassword"
```

---

## 6. REST API Reference

All administrative API endpoints require the master or tenant authentication header:
`X-API-Key: <OMINULL_API_KEY>`

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/hierarchy` | `GET` | Retrieve multi-tenant org hierarchy and location metrics |
| `/api/v1/endpoints` | `GET` | List all registered endpoints, OS info, and online status |
| `/api/v1/events` | `GET/POST` | Query telemetry event stream or ingest agent batch |
| `/api/v1/isolate` | `POST` | Enforce ring-0 host quarantine on managed endpoint |
| `/api/v1/unisolate` | `POST` | Restore network connectivity on quarantined endpoint |
| `/api/v1/scanner/scan` | `POST` | Launch standard or aggressive subnet discovery sweep |
| `/api/v1/scanner/results` | `GET` | List discovered subnet assets, open ports, and weakpoints |
| `/api/v1/scanner/feedback`| `POST` | Submit ground-truth device fingerprint training |
| `/api/v1/mesh/quarantine` | `POST` | Enforce subnet-wide lateral mesh drop for rogue host |
| `/api/v1/mesh/unquarantine` | `POST` | Lift subnet-wide lateral mesh quarantine |
| `/api/v1/mesh/quarantined` | `GET` | List all active mesh-quarantined peer IPs |
| `/api/v1/topology/graph` | `GET` | Retrieve visual communications topology graph nodes & edges |
| `/api/v1/deployer/push` | `POST` | Dispatch 1-click SSH push-deployment job |
| `/api/v1/copilot/chat` | `POST` | Natural-language query interface with Threat Copilot |
| `/api/v1/copilot/investigate` | `POST` | Autonomous AI forensic investigation of an alert |
| `/api/v1/copilot/config` | `GET/POST` | Retrieve or configure active LLM provider backend |

---

## 7. Canonical Agent Skill & Multi-Agent Interface

Ominull includes a canonical agent skill authored for Claude Code, OpenAI Codex, and Antigravity:
- **Skill Definition:** [`~/agent-skills/skills/ominull/SKILL.md`](file:///home/operator/agent-skills/skills/ominull/SKILL.md)
- **Harness Distribution:** Verified with `st skills audit` with 0 drift across `.claude/skills`, `.codex/skills`, and `.gemini/config/skills`.

---

## 8. Verification & Quality Gates

Run the automated test suites:

```bash
# 1. Run full Go Hub & sub-engine tests
cd /srv/workspaces/projects/ominull/hub
go test -v ./...

# 2. Run C Stream DPI tests
gcc -O2 -Wall -Wextra -o /tmp/test_dpi /srv/workspaces/projects/ominull/agent/tests/test_dpi.c
/tmp/test_dpi
```

---

## 9. License

Licensed under the [Apache License, Version 2.0](LICENSE).
