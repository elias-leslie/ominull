# Ominull

**Ominull** is an ultra-lean, high-performance, cross-platform kernel network security agent, dynamic enforcement engine, and rapid Incident Response (IR) control plane.

It provides ring-0 connection and stream telemetry, dynamic policy evaluation, kernel-level host network isolation with forensic pinholing, and inverted-call event streaming across Windows (WFP), Linux (eBPF), and macOS (NetworkExtension).

---

## Architecture Overview

```
+-----------------------------------------------------------------------------+
|              CENTRAL MANAGEMENT HUB / ANALYST JUMP KIT                      |
|                  (Single Portable Native Binary: ominull-hub)               |
|                                                                             |
|  - Zero dependencies (no PostgreSQL, no Redis, no Docker required)          |
|  - Multi-Tenant Segregation for MSPs & MSSPs (Tenant A | Tenant B)          |
|  - Ephemeral CA & Token Generation (mTLS + Ed25519)                         |
|  - Embedded DuckDB / SQLite Event Store + TUI & Web SOC console             |
+-----------------------------------------------------------------------------+
                                       ▲
                       mTLS + Ephemeral Token (Port 8443)
                                       │
       ┌───────────────────────────────┼───────────────────────────────┐
       ▼                               ▼                               ▼
+-----------------------------+ +-----------------------------+ +-----------------------------+
|      WINDOWS ENDPOINT       | |       LINUX ENDPOINT        | |       macOS ENDPOINT        |
|  (Windows 11 / Server 2025) | |    (Debian 12 / Ubuntu 24)  | |       (macOS 14 Sonoma)     |
|                             | |                             | |                             |
|  [ominulld.exe + WFP]       | |  [ominulld + eBPF]          | |  [ominulld + NEFilter]      |
+-----------------------------+ +-----------------------------+ +-----------------------------+
```

### Core Components
1. **Windows Kernel Callout Driver (`driver/src/driver.c` $\rightarrow$ `ominull.sys`)**:
   - Creates a dedicated high-priority WFP sublayer at `0xFFFF` priority (`FWPM_SUBLAYER_WEIGHT_MAX`).
   - Registers callouts & filters across all 6 core dual-stack ALE layers:
     - `FWPM_LAYER_ALE_AUTH_CONNECT_V4` & `_V6` (Outbound connection authorization)
     - `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` & `_V6` (Inbound connection & listening socket monitoring)
     - `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` & `_V6` (Flow context tracking & lifetime cleanup)
   - Dynamic policy engine supporting CIDR subnets, port ranges, protocols, PID, and executable path filtering.
   - Host isolation mode (`IOCTL_OMINULL_SET_ISOLATION_MODE`) dropping all traffic except management hub pinholes.
   - Inverted-call streaming (`IOCTL_OMINULL_STREAM_EVENT`) with zero polling overhead.
   - Guaranteed zero WFP object leaks on service teardown.

2. **Endpoint Control CLI (`cli/ominullctl.c` $\rightarrow$ `ominullctl.exe`)**:
   - `ominullctl block <ip> <port> [tcp|udp] [pid]`: Inserts dynamic kernel block rule.
   - `ominullctl isolate`: Activates kernel-level network quarantine.
   - `ominullctl unblock / clear`: Flushes active dynamic rules.
   - `ominullctl monitor`: Streams ring-0 connection events in real-time.
   - `ominullctl stats`: Queries live connection, flow, and policy counters.

---

## Directory Structure

```
ominull/
├── build/                 # Compiled driver, CLI, and test-signed artifacts
├── certs/                 # Authenticode test-signing certificates & keys
├── cli/                   # User-mode control utility source (ominullctl.c)
├── driver/                # Kernel-mode driver source & headers
│   ├── include/
│   │   ├── ominull_driver.h
│   │   ├── ominull_ioctl.h
│   │   └── wfp_kernel.h
│   └── src/
│       ├── driver.c
│       └── fwpkclnt.def
├── evidence/              # Captured verification evidence & WFP state XML dumps
├── scripts/               # Automation, build, signing, and test runners
│   ├── build.sh
│   ├── sign.sh
│   └── vm_test_pipeline.py
├── LICENSE                # Apache 2.0
├── NOTICE
├── PLAN.md                # Project Master Plan & Multi-Tenant Roadmap
├── README.md
└── TESTING.md
```

---

## Build & Signing Instructions

Cross-compile the driver and CLI from Linux using `mingw-w64` and test-sign with `osslsigncode`:

```bash
# 1. Compile driver and control CLI
./scripts/build.sh

# 2. Test-sign the kernel driver
./scripts/sign.sh
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
