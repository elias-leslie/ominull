# Project Master Plan: Ominull / Ominull
## Cross-Platform Kernel Network Telemetry, Dynamic Enforcement & Rapid IR System

**Author:** Antigravity AI & System Engineering Team  
**Date:** 2026-08-26  
**Status:** Approved / Active Plan  
**Target Environments:** 
- **Windows:** Windows 10/11, Windows Server 2019/2022/2025 (x86_64, Windows Filtering Platform)
- **Linux:** Debian 11/12, Ubuntu 20.04/22.04/24.04, RHEL/Rocky 8/9 (eBPF / cgroup / tc)
- **macOS:** macOS 12+ (Apple Silicon & Intel, NetworkExtension Framework)

---

## 1. Vision & Core Philosophy

**Ominull** (Enterprise Threat Nullification Platform) is an ultra-lean, high-performance, cross-platform kernel network security agent and rapid Incident Response (IR) control plane.

### Core Architectural Mandates:
1. **Lean & Zero-Bloat:** Single self-contained binary for the management hub (no Docker/K8s, no PostgreSQL/Redis requirements). Single lightweight native agent (<15 MB RAM, <0.5% CPU overhead on endpoints).
2. **Multi-Tenancy by Design (MSP/MSSP Ready):** Complete cryptographic and logical tenant separation. Manage 1 to 500 distinct client organizations from a single lightweight hub with tenant-scoped tokens, isolated policy tables, and segregated telemetry logs.
3. **Rapid IR & Jump-Kit Deployment:** Turn any analyst laptop or existing server into an authoritative IR command hub in under 10 seconds. Deploy to remote endpoints via a 1-line PowerShell / Bash bootstrap over WinRM, SSH, MSP RMM tools (NinjaOne, Datto, ConnectWise), or EDR Live Response consoles.
4. **Pluggable Kernel Architecture:** Unified cross-platform user-mode agent core (`ominulld`) with pluggable OS-specific ring 0 filtering engines:
   - **Windows:** Native WFP Callout Driver (`ominull.sys` / `ominull.sys`).
   - **Linux:** eBPF Kernel Probes (`sockops`, `cgroup_skb`, `tc` classifier).
   - **macOS:** System NetworkExtension (`NEFilterDataProvider`, `NEFilterPacketProvider`).
5. **Kernel-Level Host Network Isolation:** Instant (<1 millisecond) host quarantine dropping 100% of lateral movement and exfiltration traffic while automatically maintaining an authenticated pinhole to the IR analyst's hub.

---

## 2. High-Level System Architecture

```
+-----------------------------------------------------------------------------+
|              CENTRAL MANAGEMENT HUB / ANALYST JUMP KIT                      |
|                  (Single Portable Native Binary: ominull-hub)              |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  |  Multi-Tenant Controller & Ingest Engine                              |  |
|  |  - Tenant A (Acme Corp)        - Tenant B (FinCorp)                   |  |
|  |  - Ephemeral Enrollment CA     - Embedded DuckDB / SQLite Event Store |  |
|  |  - Lightweight TUI / Web SOC   - Instant Remote Deployment Generator  |  |
|  +-----------------------------------+-----------------------------------+  |
+--------------------------------------|--------------------------------------+
                                       |
                       mTLS + Ephemeral Token (Port 8443)
                                       |
       ┌───────────────────────────────┼───────────────────────────────┐
       ▼                               ▼                               ▼
+-----------------------------+ +-----------------------------+ +-----------------------------+
|      WINDOWS ENDPOINT       | |       LINUX ENDPOINT        | |       macOS ENDPOINT        |
|  (Windows 11 / Server 2025) | |    (Debian 12 / Ubuntu 24)  | |       (macOS 14 Sonoma)     |
|                             | |                             | |                             |
|  +-----------------------+  | |  +-----------------------+  | |  +-----------------------+  |
|  | ominulld.exe Service |  | |  | ominulld Daemon      |  | |  | ominulld Daemon      |  |
|  | (Cross-Platform Core) |  | |  | (Cross-Platform Core) |  | |  | (Cross-Platform Core) |  |
|  +-----------+-----------+  | |  +-----------+-----------+  | |  +-----------+-----------+  |
|              | IOCTL         | |              | BPF Syscall   | |              | SystemExtension |
|  +-----------v-----------+  | |  +-----------v-----------+  | |  +-----------v-----------+  |
|  | ominull.sys      |  | |  | eBPF Filter Probes    |  | |  | NEFilterProvider     |  |
|  | (WFP 6-Layer Callout) |  | |  | (cgroup_skb / tc)     |  | |  | (NetworkExtension)    |  |
|  +-----------------------+  | |  +-----------------------+  | |  +-----------------------+  |
+-----------------------------+ +-----------------------------+ +-----------------------------+
```

---

## 3. Phased Roadmap & Work Breakdown

### Phase 1: Automated Test Harness & Proxmox VM Pipeline `[FOUNDATIONAL]`
- **Objective:** Eliminate all manual VM testing steps to accelerate subsequent phases to 25-second automated verification loops.
- **Deliverables:**
  - Automated Proxmox VM 110 lifecycle script (`scripts/vm_test_pipeline.py`):
    1. Automated snapshot rollback: `qm rollback 110 baseline-clean`.
    2. Automated payload delivery & unattended execution via guest automation / HTTP.
    3. Automated service installation, execution of test suite, and retrieval of evidence logs.
    4. XML state diff assertions (ensuring 0 WFP object leaks).
  - Single-command verification runner: `./scripts/test_vm.sh`.

---

### Phase 2: Lean Multi-Tenant Control Hub & Endpoint Agent (`ominulld`)
- **Objective:** Build the single-binary management server and native Windows endpoint service with simple, robust authentication and multi-tenancy.
- **Deliverables:**
  - **`ominull-hub` (Central Management Server & Jump Kit):**
    - Single standalone executable with zero external database dependencies (embedded SQLite/DuckDB).
    - Multi-tenant tenant segregation (`TenantID`, tenant-scoped API keys, separate event logs).
    - Automated self-signed mTLS CA & ephemeral enrollment token generation.
    - Embedded Interactive Terminal UI (TUI) connection dashboard and lightweight REST/WebSocket API.
    - One-line remote bootstrap script generator (`/bootstrap.ps1`, `/bootstrap.sh`) for rapid deployment via WinRM, SSH, RMM, or EDR Live Response.
  - **`ominulld.exe` (Windows Endpoint Service):**
    - Background Windows Service managing `ominull.sys` lifecycle.
    - Inverted-call streaming consumer (`IOCTL_OMINULL_STREAM_EVENT`) with local ring-buffer offline buffering.
    - Outbound mTLS / token connection to `ominull-hub`.

---

### Phase 3: Kernel Host Isolation & Active IR Controls
- **Objective:** Implement microsecond kernel-level network quarantine with analyst hole-punching.
- **Deliverables:**
  - **Kernel Isolation Subsystem:**
    - Driver IOCTL `IOCTL_OMINULL_SET_ISOLATION_MODE` enabling default-drop in `OminullSubLayer` (priority `0xFFFF`).
    - Automatic whitelisting of Management Server IP:Port and essential DHCP lease maintenance.
    - Reversible via `IOCTL_OMINULL_CLEAR_ISOLATION_MODE`.
  - **Remote IR Orchestration:**
    - Hub CLI / API command: `ominull-hub isolate <endpoint_id|tenant_id>`.
    - Instant broadcast C2 block: `ominull-hub broadcast-block <cidr|domain|port> --tenant <tenant_id>`.
    - Live VM verification of isolation (proving lateral SMB/RDP and external HTTP are blocked while management stream remains active).

---

### Phase 4: Kernel Hardening, HVCI & Driver Verifier Matrix
- **Objective:** Ensure production stability, memory safety, and full Windows security compliance.
- **Deliverables:**
  - **HVCI (Hypervisor-Protected Code Integrity) Compliance:**
    - Audit all memory allocations to strictly use `NonPagedPoolNx` / `NonPagedPoolNxCacheAligned`.
    - Validate with `PAGE_EXECUTE_READWRITE` prohibition audits.
  - **Driver Verifier Matrix:**
    - Automated test run on VM 110 with Driver Verifier active (Deadlock Detection, Special Pool, Force Pending I/O, I/O Verification).
  - **Concurrency Stress Test:**
    - Multi-threaded test harness generating 10,000+ simultaneous TCP/UDP connections to verify spinlock scalability under load.

---

### Phase 5: Transport & Stream Layer DPI (TCP/UDP Payload Inspection)
- **Objective:** Extend kernel callouts beyond ALE connection authorization into live payload parsing.
- **Deliverables:**
  - **`FWPM_LAYER_STREAM_V4` / `FWPM_LAYER_STREAM_V6`:**
    - TCP stream buffer inspection (`FWPS_STREAM_CALLOUT_IO_PACKET0`).
    - In-kernel TLS Server Name Indication (SNI) extractor for encrypted HTTPS domain visibility.
    - In-kernel HTTP Host header and URI parser for unencrypted traffic.
  - **`FWPM_LAYER_DATAGRAM_DATA_V4` / `FWPM_LAYER_DATAGRAM_DATA_V6`:**
    - In-kernel DNS query (A / AAAA / TXT) packet parser on UDP port 53.
    - Domain reputation / dynamic blocklist matching before DNS response reaches user space.

---

### Phase 6: Cross-Platform Linux Engine (Debian eBPF Backend)
- **Objective:** Implement the `KernelFilterEngine` abstraction for Debian/Ubuntu Linux endpoints using modern eBPF.
- **Deliverables:**
  - Portable eBPF C program (`ominull_ebpf.c`) loaded via `libbpf`:
    - `BPF_PROG_TYPE_CGROUP_SKB` for socket connect & bind tracking.
    - `BPF_PROG_TYPE_SCHED_CLS` (tc) for high-performance packet drop & host isolation.
    - BPF ring buffer for real-time event streaming to Linux `ominulld`.
  - Unified parity verification on Debian 12 / Ubuntu 24.

---

### Phase 7: Cross-Platform macOS Engine (NetworkExtension Backend)
- **Objective:** Implement the `KernelFilterEngine` abstraction for macOS endpoints.
- **Deliverables:**
  - Native Swift / C `NEFilterDataProvider` & `NEFilterPacketProvider` extension.
  - Socket flow tracking and block enforcement without legacy kernel extensions (kexts).
  - Parity verification on macOS 14/15.

---

## 4. Verification & Quality Gates

Each phase requires automated evidence collection:
1. **Pass Criteria:** 100% automated test pass, zero kernel panics / bugchecks (BSOD), zero resource leaks (WFP / eBPF object diff == 0).
2. **Evidence Retention:** Stored in `evidence/phaseX-<name>/` with execution logs, state diff XMLs/JSONs, and markdown verification reports.
