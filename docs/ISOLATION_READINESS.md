# Isolation readiness

Isolation is a safety-sensitive state transition. The hub must know what the
endpoint needs to keep working and the endpoint must be able to apply the
resulting rules before normal isolation is accepted.

## Readiness flow

1. The endpoint reports observed services and its local enforcement status.
2. The hub resolves the endpoint's applicable baseline policy.
3. The hub compares observed services with the resolved allowed destinations.
4. If anything needed is uncovered, the normal request is rejected with the
   missing services. An administrator may use an explicit emergency override;
   that decision is audited.
5. The desired state is persisted. The next authenticated heartbeat applies it
   and reports the result.

The baseline is an all-or-nothing replacement set. The hub expands named
services into concrete destination, protocol, and port entries before sending
them. Empty and oversized policies are handled explicitly; no hidden fallback
turns a rejected policy into a broad permit.

## Mechanisms

Linux applies Ominull-owned iptables and ip6tables rules. Windows applies
user-mode Windows Filtering Platform rules. The hub does not claim packet
content inspection or privileged event capture.

The standalone Windows recovery tool removes only Ominull's WFP filters and
sublayer. A dead-man timer releases host isolation when the hub is unavailable,
and the agent reports that release in its next accepted heartbeat.

## Mesh quarantine

Mesh quarantine is separate from host isolation. It stores a target IP/MAC and
reason in the hub. Retained agents reconcile the target on heartbeat and report
the applied peer set. Removing a target removes the corresponding Ominull-owned
state; unrelated firewall rules remain untouched.

## Verification

Tests cover readiness refusal, emergency override, IPv4/IPv6 rule rendering,
mesh add/remove reconciliation, dead-man release, and recovery cleanup. Live
verification must inspect the actual firewall state before and after each
operation and confirm telemetry, audit, and endpoint status.
