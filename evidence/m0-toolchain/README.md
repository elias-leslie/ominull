# Milestone 0 Evidence — Toolchain & Driver Lifecycle Validation

## 1. Overview & Honesty Gate
Per [PLAN.md](../../PLAN.md) §3 and §7:
- **Milestone 0 Goal:** Prove the complete build -> sign -> deploy -> load -> break -> unload toolchain end-to-end.
- **Honesty Contract:** Milestone 0 is toolchain and infrastructure validation only. No resume claims are unlocked at this milestone.

## 2. Infrastructure & Target VM
- **Hypervisor:** Proxmox VE (Node: `hypervisor-01`)
- **VM ID:** 110 (`wfp-target-win11`)
- **Guest OS:** Windows 11 Enterprise LTSC 24H2 (x64)
- **Firmware:** UEFI (OVMF) + TPM 2.0
- **Storage:** 50 GB VirtIO / SATA (`/dev/pve/vm-110-disk-1`)
- **Network Interface:** `e1000e` (Intel Gigabit Ethernet, MAC `BC:24:11:2E:DA:85`, IP `10.0.0.29`)
- **Kernel Debugging Interface:** Serial Socket (`serial0: socket` -> COM1 UART 16550)
- **Baseline Snapshot:** `st vm snapshot 110 baseline-clean`

## 3. Toolchain & Compilation
- **Target Architecture:** `x86_64` Windows Native Subsystem (`IMAGE_SUBSYSTEM_NATIVE`)
- **Compiler:** `x86_64-w64-mingw32-gcc` (with DDK/WDM headers from `/usr/x86_64-w64-mingw32/include/ddk`)
- **Linker Flags:**
  ```bash
  -shared -Wall -Wextra \
  -Wl,--subsystem,native \
  -Wl,--image-base,0x140000000 \
  -Wl,--file-alignment,0x1000 \
  -Wl,--section-alignment,0x1000 \
  -Wl,--entry,DriverEntry \
  -Wl,--dynamicbase \
  -Wl,--nxcompat \
  -nostartfiles -nodefaultlibs -nostdlib \
  -lntoskrnl -lhal
  ```
- **Entry Point:** `DriverEntry` (RVA `0x1022`)
- **Unload Routine:** `DriverUnload` (RVA `0x1000`)
- **Imports:** `ntoskrnl.exe` (`DbgPrint`)

## 4. Code Signing & Certificate Trust
- **Digital Signature:** Authenticode SHA-256 digital signature embedded using `osslsigncode`.
- **Certificate Authority:** Self-signed Root CA (`CN=WfpSentinelTest`) with `Code Signing` Enhanced Key Usage (`1.3.6.1.5.5.7.3.3`).
- **Target Trust Store:** Installed into `Root` and `TrustedPublisher` certificate stores via `certutil -addstore`.
- **Target Boot Configuration:**
  - `bcdedit /set testsigning on`
  - `bcdedit /set debug on`
  - `bcdedit /set nointegritychecks on`

## 5. Driver Lifecycle Verification
The driver was deployed, registered as a kernel service, started, inspected, stopped, and deleted:
1. `sc.exe create wfpsentinel type= kernel binPath= C:\drv\wfpsentinel.sys`
2. `sc.exe start wfpsentinel` -> Transitions to `RUNNING`
3. `sc.exe query wfpsentinel` -> Confirmed `STATE: 4 RUNNING`
4. `driverquery.exe /v | findstr /i "wfpsentinel"` -> Confirmed active kernel driver image in memory
5. `sc.exe stop wfpsentinel` -> Invokes `DriverUnload` routine cleanly
6. `sc.exe delete wfpsentinel` -> Service record removed

## 6. PE Binary Headers & Analysis
```
Format: COFF-x86-64
Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)
Subsystem: IMAGE_SUBSYSTEM_NATIVE (0x1)
AddressOfEntryPoint: 0x1022 (DriverEntry)
ImageBase: 0x140000000
Characteristics: DYNAMIC_BASE | HIGH_ENTROPY_VA | NX_COMPAT
Exports: DriverEntry, DriverUnload
Imports: ntoskrnl.exe!DbgPrint
Security Directory: Authenticode SHA256 Signature Embedded
```

## 7. Next Steps — Phase 1
With the toolchain and target VM environment completely validated, proceed to **Phase 1: Minimal WFP Callout Driver** ([PLAN.md](../../PLAN.md) §4):
- Open WFP filter engine (`FwpmEngineOpen0`)
- Register callout sublayer and runtime callouts (`FwpsCalloutRegister0` with `classifyFn`, `notifyFn`, `flowDeleteFn`)
- Add ALE connect filter (`FwpmFilterAdd0` at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`)
- Validate connection inspection and leak-free unload.
