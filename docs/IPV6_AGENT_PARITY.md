# IPv6 agent collection and isolation

Windows enumerates both TCP address families and uses each family's ESTATS API.
Counter and pending-flow identities include the full tuple, address family,
interface scope and process creation time. Counter samples remain interval deltas;
first readings establish a baseline. Deferred scans retain that baseline for up to
five minutes. PID reuse during enrichment clears the untrusted process details.
IPv6 TCP addresses serialize directly, with an interface index for link-local
addresses. Ambiguous link-local rows cannot produce a batch with invented scope.
UDP ETW still omits link-local records because its event schema lacks that index.

The shared hub parser supports bracketed IPv6 URLs and rejects malformed ports,
credentials in URLs and unsupported scoped hub addresses. Isolation resolves the
complete A/AAAA set, deduplicates it and refuses an incomplete set over 16 entries.
Every hub permit names its IP, TCP protocol and configured port. Peer quarantine
and dead-man release retain hub recovery permits. The heartbeat's representative
`hub_literal` remains one address; it is not the complete pinhole inventory.

Windows accepts IPv4 and IPv6 quarantine/allow entries. Unsupported scoped or
link-local policy destinations reject the update; they cannot become an
unqualified block on every interface. Its WFP replacement runs in one transaction.
An invalid rule or failed filter operation leaves the previous state intact.
Policy rejection is reported in `isolation_readiness.last_applied`.

Both agents preserve IPv6 neighbor and router discovery during isolation. Linux
requires hop limit 255 for types 133–136 and permits related ICMPv6 error feedback.
Windows ALE permits those four types with code zero; its IPv6 stack validates NDP.
ALE authorization applies to non-error ICMP, so these permits do not authorize
arbitrary echo requests. This is link control, analogous to IPv4 ARP, and does not
replace the later trusted-router observation sensor. Console baseline previews
list this intrinsic traffic alongside hub recovery and loopback.

Linux forensic socket evidence now retains the IPv6 addresses parsed from `/proc`
instead of replacing both endpoints with `::`.

## Limits and checks

Linux still flushes and rebuilds existing iptables/ip6tables chains sequentially.
That non-atomic reload remains a known risk; this work does not migrate to nftables.
Native checks prove the final installed rules and recovery behavior, not atomic
Linux replacement. Router-advertisement renewal and path-MTU feedback are specified
by the rules, but were not separately exercised by the native echo fixtures.

`scripts/test-native-ipv6.sh` runs Linux parser, forensic and command-boundary
fixtures, and builds native Windows fixtures. The live Linux isolation executable
refuses the initial network namespace. The live Windows WFP probe uses its own
dynamic sublayer and must run through an out-of-band guest control channel.
Neither live probe uploads synthetic telemetry or modifies the installed agent's
policy. Failed checks close the dynamic WFP session or tear down the test namespace
chains. Runtime evidence is recorded per release.

References: [Microsoft IPv6 ESTATS](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcp6connectionestats),
[Microsoft ALE authorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers),
[SDK ICMP condition identifiers](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/fwpmu.h),
and [RFC 4890 IPv6 filtering recommendations](https://www.rfc-editor.org/rfc/rfc4890).
