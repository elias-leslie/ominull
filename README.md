# wfpsentinel

**wfpsentinel** is a lightweight, high-performance Windows Filtering Platform (WFP) kernel-mode callout driver (`wfpsentinel.sys`) and telemetry engine for Windows 11 / Windows Server.

## Architecture

wfpsentinel operates as a non-PnP software driver that integrates directly with the Windows Filtering Platform at the Application Layer Enforcement (ALE) connect and accept layers:
- **Kernel-Mode Callout (`wfpsentinel.sys`)**: Registers callouts at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (and `_V6`) to inspect network 5-tuples (source IP/port, remote IP/port, protocol), process IDs, and application paths in real time.
- **Policy Enforcement**: Kernel-level inline allow/block verdicts with atomic rule table updates.
- **Telemetry Stream**: Emits structured connection events to user-mode listeners over an inverted-call / filter communication port.

## Verification & Testing

Every build and change is strictly verified according to the protocols in [TESTING.md](TESTING.md):
- **Driver Verifier**: Validated clean under standard DDI compliance, IRQL checking, special pool, and pool tracking.
- **Zero Leak Invariant**: Tested for zero residual WFP engine objects (`netsh wfp show state`) and pool allocations on driver unload.
- **Fault Injection & Concurrency**: Stress-tested against high-frequency parallel connection bursts and transaction rollback drills.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
