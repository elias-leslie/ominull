# Design history

A short record of how Ominull reached its current shape. Git history holds the
full detail.

## Kernel driver prototype (August 2026)

The project started on 2026-08-25 as a Windows kernel-mode Windows Filtering
Platform (WFP) callout driver. Four milestones were run against a Windows 11
test virtual machine: build, test-sign, load and unload the driver; register an
ALE connect callout and filter; enforce block and allow rules; and extend the
callout to IPv4 and IPv6 with inbound monitoring. The callout milestones
compared WFP engine state before load, while loaded, and after unload to
confirm the driver left no WFP objects behind.

## Feature reduction (2026-08-31)

A hub with Linux, Windows and macOS agents grew quickly around that prototype.
Before optimizing anything, the product was cut back to what it could support
and prove. Removed:

- the embedded AI copilot
- an unused WebSocket command path
- generic rules, dynamic policy groups, and scheduled flow-role inference
- the dormant Windows kernel driver and its deep packet inspection code
- Linux eBPF and packet-inspection claims that no running agent backed
- the macOS agent, with a bounded retirement script for existing installs
- the agent on the hub host and the SSH push-deployer

Windows kept user-mode management of WFP rules, with a standalone recovery tool
that clears Ominull filters without the main service. Linux kept socket
inspection for TCP telemetry and iptables/ip6tables for host isolation. Agents
moved to signed native packages (`.deb` and `.msi`) with enrollment-issued
per-device credentials in place of SSH deployment.

## Second trim (2026-10-12)

Sized for one hub and a handful of agents. Removed:

- automated ACME DNS-01 certificate issuance (`hub/pkg/acme`) and the
  direct-WAN network mode. A public certificate is now operator-supplied; saved
  configurations load as LAN mode with the custom certificate source.

Kept on purpose: the console terminal (now also fail-closed on its WebSocket
routes when the response subsystem is off), native OIDC, and the Cloudflare
Tunnel + Access console path. Retention-expired evidence, including terminal
recordings (30 days), is now pruned hourly instead of only on an explicit API
call.

## Measured additions

- **Linux UDP observation (2026-09-07).** eBPF returned as a real collector: an
  embedded libbpf CO-RE program (`agent/linux/bpf/udp.bpf.c`) that records UDP
  send and receive observations with process identity. Windows gained an ETW
  consumer for the same data. See [UDP observation](UDP_OBSERVATION.md).
- **Destination-history lookup (2026-09-15).** A covering index and a
  two-match limit took first-seen destination checks on a synthetic
  100,000-profile store from about 21 ms to about 11 µs per lookup. The benchmark
  is `BenchmarkFirstSeenDestination` in
  `hub/pkg/storage/destination_history_test.go`.
- **Policy and prefix preparation (2026-10-02).** Baseline resolution reads only
  the policies in scope, and topology classification parses prefixes once per
  request. Measurements are in
  [HUB-PREPARATION-REFACTOR.md](evidence/HUB-PREPARATION-REFACTOR.md).
