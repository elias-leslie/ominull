# Milestone 1: Minimal WFP Callout Driver Verification Evidence

## Overview
- **Component:** `ominull.sys`
- **Target OS:** Windows 11 Enterprise LTSC 24H2 (Build 26100.1742)
- **Target Architecture:** x86_64 (UEFI OVMF, TPM 2.0, VirtIO / Intel e1000e)
- **Layer:** `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (`{c38d57d1-05a7-4c33-904f-7fbceee60e82}`)
- **Verification Date:** 2026-08-25
- **Result:** **PROVEN PASS (100% Zero-Leak Teardown)**

## Evidence Artifacts
- [`m1_log.txt`](file:///srv/workspaces/projects/ominull/evidence/m1-callout/m1_log.txt): Full live execution console trace captured from the Windows 11 kernel session.
- [`wfp_baseline.xml`](file:///srv/workspaces/projects/ominull/evidence/m1-callout/wfp_baseline.xml): WFP engine state captured prior to driver service startup.
- [`wfp_loaded.xml`](file:///srv/workspaces/projects/ominull/evidence/m1-callout/wfp_loaded.xml): WFP engine state captured while `ominull.sys` is running, demonstrating registered sublayer (`OminullSubLayer`), callout (`OminullAleConnectCallout`), and filter (`OminullAleConnectFilter`).
- [`wfp_post_unload.xml`](file:///srv/workspaces/projects/ominull/evidence/m1-callout/wfp_post_unload.xml): WFP engine state captured after driver stop and unload, demonstrating zero leaked WFP objects.

## Key Verification Results

### 1. Driver Lifecycle
```
SERVICE_NAME: ominull 
        TYPE               : 1  KERNEL_DRIVER  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
```

### 2. Kernel Presence
```
ominull  ominull            ominull            Kernel        Manual     Running    OK         TRUE        FALSE        0                 4,096       4,096      8/25/2026 1:08:52 PM   \??\C:\drv\ominull.sys                       0          
```

### 3. WFP Engine Objects
- **Sublayer:** `OminullSubLayer` (Weight: 0x8000) -> Registered & Active
- **Callout:** `OminullAleConnectCallout` at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` -> Registered & Active
- **Filter:** `OminullAleConnectFilter` with `FWP_ACTION_CALLOUT_INSPECTION` -> Bound to Callout

### 4. Telemetry & Outbound Traffic Inspection
- Outbound HTTP GET connections to test server (`/traffic-1`, `/traffic-2`) successfully inspected and permitted.
- ICMP Echo network requests successfully permitted.

### 5. Clean Teardown & Zero Leaks
- `sc stop ominull` returned `STATE: 1 STOPPED` with exit code `0x0`.
- Comparison between `wfp_loaded.xml` and `wfp_post_unload.xml` confirms complete unregistration of the filter, callout, and sublayer with zero engine leaks.
