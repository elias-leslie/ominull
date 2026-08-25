# WfpSentinel

**WfpSentinel** is a lightweight, high-performance Windows Filtering Platform (WFP) kernel-mode callout driver (`wfpsentinel.sys`) and user-mode control suite (`wfpsentinel_ctl.exe`) built for Windows 11 Enterprise (x86_64).

It demonstrates kernel-level network telemetry inspection, dynamic policy enforcement via IOCTL, spinlock-synchronized policy evaluation, and clean zero-leak engine deregistration at the Application Layer Enforcement (ALE) connect layer (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`).

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                              USER MODE                                  |
|                                                                         |
|   +-----------------------+              +--------------------------+   |
|   |   curl.exe / browser  |              |   wfpsentinel_ctl.exe    |   |
|   |  (Outbound Traffic)   |              | (Dynamic Policy & Stats) |   |
|   +-----------+-----------+              +------------+-------------+   |
+---------------|---------------------------------------|-----------------+
                | Connect()                             | DeviceIoControl()
                |                                       | (\DosDevices\WfpSentinel)
+---------------v---------------------------------------v-----------------+
|                              KERNEL MODE                                |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |                WfpSentinel Driver (wfpsentinel.sys)             |   |
|   |                                                                 |   |
|   |   - Device Control Dispatch: Add / Clear / GetStats IOCTLs       |   |
|   |   - Policy Engine: Spinlock-guarded Dynamic Block Rules Table   |   |
|   |   - Statistics Engine: Total Classified, Permitted, Blocked     |   |
|   |   - Custom Sublayer: Priority 0xFFFF (Evaluates First)          |   |
|   |   - Callout Callback: WfpSentinelClassify                       |   |
|   +--------------------------------+--------------------------------+   |
|                                    |                                    |
|   +--------------------------------v--------------------------------+   |
|   |             Windows Filtering Platform (fwpkclnt.sys)           |   |
|   |               [FWPM_LAYER_ALE_AUTH_CONNECT_V4]                  |   |
|   |                                                                 |   |
|   |     Match Block Rule?                                           |   |
|   |       YES -> FWP_ACTION_BLOCK (Drops Connection)                |   |
|   |       NO  -> FWP_ACTION_CONTINUE (Permits Normal Flow)          |   |
|   +-----------------------------------------------------------------+   |
+-------------------------------------------------------------------------+
```

### Core Components
1. **Kernel Callout Driver (`driver/src/driver.c`)**:
   - Registers device object `\Device\WfpSentinel` and symbolic link `\DosDevices\WfpSentinel`.
   - Creates a dedicated WFP sublayer at `0xFFFF` priority (`FWPM_SUBLAYER_WEIGHT_MAX`).
   - Registers kernel callout and inspection filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
   - Extracts 4-tuple (Local/Remote IP & Port), IP protocol, Process ID (PID), and executable image path.
   - Evaluates connections against dynamic block rules and returns `FWP_ACTION_BLOCK` or `FWP_ACTION_CONTINUE`.
   - Guarantees zero WFP object leaks on driver unload (`DriverUnload`).

2. **User-Mode Control CLI (`cli/wfpsentinel_ctl.c`)**:
   - `wfpsentinel_ctl block <ip> <port> [tcp|udp] [pid]`: Inserts kernel block rule dynamically via IOCTL.
   - `wfpsentinel_ctl clear`: Clears all active kernel block rules.
   - `wfpsentinel_ctl stats`: Queries live connection and policy counters from ring 0.

---

## Directory Structure

```
wfpsentinel/
├── build/                 # Compiled driver, CLI, and test-signed artifacts
├── certs/                 # Authenticode test-signing certificates & keys
├── cli/                   # User-mode control utility source
│   └── wfpsentinel_ctl.c
├── driver/                # Kernel-mode driver source & headers
│   ├── include/
│   │   ├── driver.h
│   │   ├── wfp_kernel.h
│   │   └── wfpsentinel_ioctl.h
│   └── src/
│       ├── driver.c
│       └── fwpkclnt.def
├── evidence/              # Captured verification evidence & WFP state XML dumps
│   ├── m0-toolchain/      # Cross-compilation and Authenticode signing report
│   ├── m1-callout/        # Callout registration, ALE inspection, and zero-leak unload
│   └── m2-enforcement/    # Dynamic IOCTL block enforcement, ping selectivity, and stats
├── scripts/               # Automation, build, signing, and test runners
│   ├── build.sh
│   ├── sign.sh
│   ├── m2_runner.bat
│   └── receiver.py
├── LICENSE                # Apache 2.0
├── NOTICE
├── README.md
├── SECURITY.md
└── TESTING.md
```

---

## Build & Signing Instructions

The driver and CLI are cross-compiled from Linux using `mingw-w64` and Authenticode test-signed using `osslsigncode`:

```bash
# 1. Compile driver and control CLI
./scripts/build.sh

# 2. Test-sign the kernel driver
./scripts/sign.sh
```

---

## Verification & Testing

All milestones are verified on an isolated Windows 11 Enterprise test VM with Driver Verifier active:

- **Milestone 0 (Toolchain)**: Zero-dependency cross-compilation of native NT subsystem driver and PE Authenticode signing.
- **Milestone 1 (Callout & Inspection)**: Driver load, ALE connection inspection, telemetry logging, and `netsh wfp show state` zero-leak verification across pre-load, loaded, and post-unload states.
- **Milestone 2 (Dynamic Enforcement)**: Dynamic IOCTL rule insertion, kernel-level traffic blocking against targeted ports, selective non-targeted traffic pass-through, live stats accounting, and clean rule flushing.

For complete test protocols, see [TESTING.md](TESTING.md).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
