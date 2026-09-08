# Router collection

`ominull-router-poll.sh` sends dnsmasq leases, conntrack flows, and optional
DNS observations to `/api/v1/router/telemetry`. Keep its configuration at
`/etc/ominull-router.conf` with mode 0600. Transfer scripts by piping over SSH
on gateways without an SFTP server. The hub never forwards DNS or binds UDP 67.

## DHCPv4 fingerprints on OpenWrt

Install `ominull-dhcp-hook.sh` at `/usr/lib/ominull-dhcp-hook.sh`, mode 0755.
Check `uci -q get dhcp.@dnsmasq[0].dhcpscript` first. If another user hook exists,
compose the two hooks explicitly; do not overwrite it. Preserve OpenWrt's stock
`/usr/lib/dnsmasq/dhcp-script.sh` and existing DHCP hotplug handlers.

Set `dhcp.@dnsmasq[0].dhcpscript=/usr/lib/ominull-dhcp-hook.sh`, commit the DHCP
configuration, then restart dnsmasq during an appropriate maintenance window.
Verify DNS resolution before and after the restart. To roll back, restore the
previous UCI hook setting and restart dnsmasq. Ominull does not change upstream
DNS servers, lease ranges, or client configuration.

The hook records dnsmasq's `DNSMASQ_REQUESTED_OPTIONS` (option 55, in client
order) and `DNSMASQ_VENDOR_CLASS` (option 60). These structured fields avoid
correlating interleaved DHCP log lines. `log-dhcp` is unnecessary for this path.
See the [dnsmasq lease-script documentation](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).

The hook writes a private cache under `/tmp/ominull-dhcp`. Confirm the dnsmasq
process and poller share that directory. On jailed deployments, it must be
explicitly writable and shared; do not disable the jail. The cache holds at most
2,000 MAC records, removes a record on lease deletion, and disappears on reboot.
Startup lease replays without options preserve existing fingerprints. Fresh
fingerprints arrive as clients naturally obtain or renew leases. No forced
client renewal is needed. Existing lease renewals whose metadata is unchanged
do not need a new fingerprint observation.

The poller attaches a cached fingerprint only to a current lease with the same
MAC. The hub bounds vendor class to 255 bytes and validates up to 255 ordered
option codes. Invalid optional metadata does not discard a valid lease.
Observation timestamps remain the DHCP event time, not the latest poll time;
older replays and future-dated evidence cannot overwrite a current fingerprint.

Asset identity claims show **DHCP vendor class** and **DHCP requested options**,
with router provenance and observation time on hover. These are client-reported
fingerprints, not verified operating systems. Ominull does not guess an OS from
an undocumented option-list signature or attribute a manufacturer to a randomised MAC.
This collector handles DHCPv4 only; it does not label DHCPv6 DUIDs as MACs.

## Removed hub collection

The former `--dns-listen`, `--dhcp-snoop`, `OMINULL_DNS_LISTEN`, and
`OMINULL_DHCP_SNOOP` settings are retired. Remove old command-line flags before
upgrading. `/api/v1/dns/*` management routes are gone. Router DNS events and
`dns_resolutions` remain available for traffic attribution.

The unused legacy `alerts` table is retired only when empty. Unexpected rows
from upgrades skipping its grace release remain intact. Current findings live
in `anomaly_alerts` and are unaffected.
