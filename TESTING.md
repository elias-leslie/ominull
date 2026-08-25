# Testing Methodology and Verification Protocol

This document outlines the testing standards, safety requirements, and verification protocols for `wfpsentinel.sys`.

## 1. Isolation & Safety Standard
Kernel drivers execute with ring-0 privileges. A failure in kernel space triggers a system bugcheck (BSOD).
- **Target Isolation**: All driver binaries are loaded exclusively on disposable, snapshot-restorable test VMs.
- **Baseline Snapshots**: A clean VM snapshot is captured prior to testing. VMs are restored rather than repaired.

## 2. Verification Protocol

### A. Driver Verifier Certification
The target VM executes with Driver Verifier active against `wfpsentinel.sys`:
```cmd
verifier.exe /standard /driver wfpsentinel.sys
```
Validation criteria:
1. Special Pool allocations enabled.
2. Force IRQL Checking enabled (validating no pageable memory access at DISPATCH_LEVEL).
3. Pool Tracking enabled.
4. Zero bugchecks during continuous load, connection inspection, and unload cycles.

### B. WFP Engine Lifetime & Leak Checks
Driver unload must leave zero residual state in the BFE/WFP subsystem:
1. Capture pre-load state: `netsh wfp show state file=wfp_before.xml`
2. Load driver, register callouts, process traffic, unload driver.
3. Capture post-unload state: `netsh wfp show state file=wfp_after.xml`
4. Diff `wfp_before.xml` and `wfp_after.xml` to verify 100% clean object destruction (no orphaned filters, callouts, or sublayers).

### C. Kernel Debugging & WinDbg Drills
- Kernel debugging enabled via KDNET.
- Explicit breakpoint validation on `DriverEntry` and `DriverUnload`.
- Controlled bugcheck inspection drill (`!analyze -v`) for diagnostic verification.

## 3. Evidence Collection
All test runs, WinDbg transcripts, and Verifier logs are recorded in the `evidence/` directory.
