# Trust fabric

Ominull has four deliberate trust layers: operator authorization, endpoint
identity, transport proof, and signed release identity.

## Operator roles

The local admin key, a signed console session, native OIDC, or a verified
Cloudflare Access assertion may establish an operator. Tenant credentials remain
tenant-scoped and cannot perform fleet-wide operations. Cloudflare identity is
not accepted from a plaintext email header; the signed assertion's issuer,
audience, time claims, key, and explicit Ominull operator mapping are checked.

## Endpoint identity

Enrollment creates a unique per-endpoint `omd_...` credential and device CA
certificate. The credential binds agent routes to one endpoint and tenant. A
direct native mTLS certificate, when offered, must name that same endpoint. A
retained shared tenant-key request is accepted only during explicit migration;
the updated agents automatically switch to unique credentials.

Retired endpoints keep telemetry, certificates, and audit history. Late
heartbeats are rejected and cannot revive them. Credential listing never returns
secret material; rotation revokes the old credential, and revocation stops the
endpoint.

## Release identity

Each Debian package and MSI has a detached ECDSA signature and SHA-256 digest.
The agent verifies both against the public key compiled into its release. Hub
artifact serving requires the sidecars. Package registration is reported apart
from compiled version so a copied binary cannot look native.

## Containment and preservation

The hub stores desired isolation, baseline, mesh, and recovery state. Agents
apply only authenticated heartbeat state and report readiness and applied state.
Linux uses iptables/ip6tables; Windows uses user-mode Windows Filtering
Platform. Recovery tools clear only Ominull-owned state.

Removing a product role retires endpoint records instead of deleting durable
telemetry or audit data. Old feature tables and settings may remain as inert
legacy rows during schema upgrades. New installations do not recreate removed
product paths. Retention bounds raw events, profiles, alerts, anomalies, and
audit data by configured policy.

## Trusted destinations during isolation

Rules name what an isolated endpoint may still reach. A rule has a scope
(`provider`, `client` = tenant, `site` = location, `group` = role tag,
`endpoint`), an `ip`, `cidr` or `fqdn` value, `allow` or `deny`, and optionally
a port and protocol, a direction, `locked`, `expires_at` and a justification.
Precedence (`hub/pkg/trustfabric`): the hub and loopback are always reachable,
and so is what the signed baseline names (DHCP, the resolvers, NTP); a locked
rule cannot be overridden from below (the least specific locked scope wins);
otherwise the most specific rule wins (scope, then prefix length, then
port/protocol), deny on a tie; no match means not trusted. Rules decide the
allow list and nothing else: a deny does not take an address out of the baseline.

- `GET|POST /api/v1/trust/rules`, `DELETE /api/v1/trust/rules?id=` (admin).
- `GET /api/v1/trust/effective?endpoint_id=ID[&addr=A&port=P&proto=tcp]`:
  the compiled allow list, which part agents enforce, and one decision.
- `POST /api/v1/endpoints/isolate` takes `mode`: `full` reaches the hub and the
  signed baseline and refuses `allow_ips`; `selective` adds the endpoint's
  effective policy to `allow_ips` in the same request before the hub signs, so
  the signed grant carries exactly the list the agent enforces. Without `mode`
  only the request's own `allow_ips` apply. Detector isolation is always full.

### What an agent receives

An allow list holds at most 32 entries, because an agent refuses a grant with
more and would then not isolate at all. Single addresses go first and ranges
follow widest first, then what only a name answered, each name's newest answer
first; what does not fit is listed as not enforced in the audit
summary and in `trust/effective`, and stays closed.

Agents from 1.8.65 report `allow_prefixes` and enforce ranges (Linux iptables
`-s/-d addr/len`, Windows WFP address-mask filters), no wider than `/8` (IPv4)
or `/32` (IPv6); the hub and the agent both refuse wider ones. A request may
name a range only for one endpoint (bulk isolation names addresses).

An older agent refuses a grant naming a range and then applies nothing, while
the hub would report it isolated, and a Windows agent before 1.8.120 reports the
capability and then drops every range. So the hub treats an agent as taking ranges
only if its version is at least 1.8.65 (Windows 1.8.120) and it reports the capability; a report
is dropped when the agent changes version and has not repeated it, because a
downgraded agent left a capability behind that it did not have. For such an
agent a range of up to 16 addresses is spelled out, wider ranges are listed as
not enforced and stay closed, and a request naming a range is refused before the
hub signs it. Spelled-out addresses take up list entries, so several small ranges
can push a name's answers off an older agent's list; those are listed as not
enforced like anything else that does not fit. Port- or direction-scoped allows
are withheld on every agent, since the allow list carries addresses only.

### On the agent

A new grant replaces the rules in one step, so changing the list never opens the
host: Linux builds new chains and swaps them in, keeping the old ones if the new
ones are refused, and Windows replaces its filters in one transaction. A Linux
rule set missing its loopback or DHCP permit is not swapped in. An entry or permit
the agent cannot install is reported rather than dropped in silence: the hub
audits each change (`AGENT_APPLY_REPORT`) and shows the report in
`trust/effective` (`agent_report`) and on the machine page. The `enforced` list is
what the hub signed; only this report says what the agent could not do with it.

The rules outlive the agent. After a restart it recognises the isolation from its
own rules and keeps it. An agent that can't reach its hub lifts the isolation itself
after five minutes if nobody supervised it (a detector's or one adopted at first
start) and after twelve hours if it is an owner's. That is waking time, however long
each failed heartbeat takes: time asleep doesn't count, and an agent restart starts it
over. It removes only the default deny, so a block on a peer stays where it was, and
if the hub comes back still wanting the isolation it goes straight back on.

A hub that changes address while a machine is isolated is followed. While the hub
isn't answering, the agent looks its name up again and adds any new address beside
the old, on the hub's TCP port only, below the blocks, and closed to other programs
(on Linux, programs not running as the agent's user, root; on Windows, any other
program). It stays that way through this isolation, since a lookup alone could come
from whoever is keeping the hub quiet; the next policy change rebuilds from a fresh
lookup, as any apply does. This needs rules this run of the agent built and a name it
can look up, which under isolation means a resolver in the baseline; after a restart,
or with no resolver, the dead-man timer still decides. With no resolver, an agent
enrolled by name also can't reconnect after a hub restart once its DNS cache runs out.
An agent enrolled against an IP has no name to look up, so it has nothing to follow.

### Names

An `fqdn` rule names one host exactly, with no wildcards, and can only allow: a
deny has to hold before a name resolves and while its resolver is down, so it
names an address or a range. Whoever controls a name's DNS chooses its answers, so
an answer inside a deny that applies to the endpoint is dropped, whatever the
deny's scope or width. The hub resolves a name
when the rule is created, when an isolation needs it and every
`trust_name_refresh_seconds` (default 300) while an active rule or isolation uses
it. Agents never resolve a trusted name and get only addresses, in the signed
grant. Answers that are unspecified, loopback, multicast or link-local never
open anything, and at most 16 addresses are kept per name. A name with no answer
yet stays closed and is listed as not enforced.

When the answer changes, each selective isolation using the name gets a new grant
under the same isolation id (`TRUST_NAME_REGRANTED`), built from the rules, the
endpoint's scope and capabilities and the signed baseline as they stood when the
isolation started; only the addresses change, except that an agent that has since
lost range support gets ranges spelled out or closed. Addresses a name no longer returns stay open
for `trust_name_retain_minutes` (default 60, 0 closes them at once) so established
clients and cached answers keep working; only then are they re-signed out. A
lookup failure closes nothing and signs nothing; the error is kept with the name.

What this does not do: the agent filters addresses, so a name opens everything
else hosted on those addresses, and the hub's answer may differ from what a
geo-aware resolver would tell the endpoint, in which case the endpoint's own
answer stays closed. Run the hub against the same resolver as the endpoints when
that matters.

### DNS under isolation

There is no permit for DNS to any resolver left in an agent, on either platform:
an isolated host reaches a resolver only if the signed baseline or the allow list
names it. The Windows hand-run recovery tool, which has no hub to ask, keeps DHCP
to any server and has no DNS permit. Linux agents report the upstream resolver
behind systemd-resolved's local stub, so the readiness check refuses (unless
overridden) when a baseline does not cover it. A named resolver still answers any
query, so DNS tunnelling through it is not closed.

### Audit

Each isolation gets an id; the fabric as it stood is recorded under it
(`ISOLATION_FABRIC_SNAPSHOT`), and a rule created or deleted while it is in
force is recorded against it (`TRUST_RULE_DURING_ISOLATION`) without changing
it. An endpoint allow rule written while that endpoint is isolated expires
after four hours unless it names its own expiry.
