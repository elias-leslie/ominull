# Router collection

`ominull-router-poll.sh` sends dnsmasq leases, conntrack flows, optional DNS
observations and per-client counters to `/api/v1/router/telemetry`. Keep its configuration at
`/etc/ominull-router.conf` with mode 0600. Transfer scripts by piping over SSH
on gateways without an SFTP server. The hub never forwards DNS or binds UDP 67.

## Transport and router identity

Post to the agent TLS listener (`https://<hub>:9443`) with a router client
certificate instead of the tenant key. An administrator issues one:

```sh
curl -fsS -K <admin-key-header-file> -H 'Content-Type: application/json' \
  -d '{"router_id":"gl-axt1800"}' https://<hub>:9443/api/v1/router/identity
```

The reply holds `cert_pem`, `key_pem` and `ca_pem`; write them to
`/etc/ominull-router/` (directory 0700, key 0600) and set `TLS_CA`, `TLS_CERT`
and `TLS_KEY` in the configuration. The certificate is accepted only for
`/api/v1/router/telemetry` and only for its own `router_id`. Issuing a new one
for the same router revokes the old one. `HUB_KEY` remains a fallback for
gateways without a certificate.

## DNS from a tmpfs log file

With query logging on, dnsmasq's default destination is the shared system log
ring, which it floods: on a busy LAN the ring holds under an hour, evicting
authentication and kernel lines. Send dnsmasq's log to tmpfs instead:

```sh
uci set dhcp.@dnsmasq[0].logfacility='/tmp/dnsmasq.log'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

and set `DNS_LOG_FILE="/tmp/dnsmasq.log"`. The poller reads the file by byte
offset and advances only after the hub answers 200, so a hub outage delays DNS
rather than losing it. A half-written line waits for the next poll. Once every
line is delivered and the file passes `DNS_TRUNCATE_AT` (1 MiB) it is emptied;
a backlog past `DNS_FILE_CAP` (16 MiB) is dropped and logged. Roll back with
`uci delete dhcp.@dnsmasq[0].logfacility`, commit, restart dnsmasq, and clear
`DNS_LOG_FILE`. Re-check after a firmware upgrade, which may reset both.

The hub keeps raw DNS events 14 days and per-client daily domain counts 90 days.

## Per-client traffic

On GL.iNet firmware the poller forwards `ubus call gl-clients list`. The hub
turns its cumulative per-client counters into daily received/sent bytes per
MAC (90 days), readable at `/api/v1/router/clients?days=N`.

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
