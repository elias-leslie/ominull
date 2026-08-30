# Isolation readiness — proving a host can be released before cutting it off

Status: built as of v1.7.11, on all three platforms and in the console.

## The problem

Isolation is a default-deny with a small set of permits under it. If any permit in that
set is wrong, the host does not become "contained" — it becomes unreachable, including
by the hub, which is the only thing that can lift the isolation. There is no way back
from that except physical or hypervisor access.

Three things make it worse than it sounds:

- **The failure is delayed.** A missing DHCP permit does not break anything until the
  lease expires, hours later. By then nobody connects it to the isolation.
- **The failure is silent.** An agent that cannot apply a rule set reports honestly, but
  an agent that applies a rule set with a hole in it reports success, because from its
  side the rules loaded.
- **It is per-platform.** Every defect fixed in v1.7.10 existed on exactly one of the
  three platforms. Testing on the platform in front of you proves nothing about the
  other two — the bash 3.2 empty-array bug shipped in v1.7.9 because it does not
  reproduce on the build host's bash 5.

Before this, the answer was "the maintainers tested it." That is not a control.

## The floor, stated as a contract

One definition, enforced identically by all three agents, in this precedence:

    hub pinhole > loopback > DHCP > peer quarantine > DNS > allow list > deny

- **hub pinhole** — both directions, both families where the hub literal is one.
  Above the peer blocks so a quarantine cannot sever the release path. The hub also
  refuses to quarantine its own address (409).
- **loopback** — both directions; local software talking to itself.
- **DHCP** — both directions, to the servers the baseline names. v4 UDP 67, v6 UDP 547;
  the remote port is the server port in both directions, because a reply is a new
  inbound flow. The broadcast fallbacks (`255.255.255.255`, `ff02::1:2`) ride along
  only when DHCP is permitted at all — a REBIND or DISCOVER after a failed renewal is
  a broadcast.
- **DNS** — both directions, UDP only, to the resolvers the baseline names. TCP/53 is
  deliberately not permitted: that is a general-purpose tunnel, not a lookup.
- **allow list** — `isolation_allow_ips`, below a peer block so quarantine wins.
- **deny** — everything else, both directions, both families.

The hub pinhole and loopback are compiled in and cannot be removed from the console.
Everything between them and the deny comes from the **baseline isolation policy**
(`docs/TRUST_FABRIC.md`, D2), which is why DNS and DHCP no longer say "any".

## The gate

### 1. The endpoint answers, on every heartbeat

The agent reports an `isolation_readiness` object and an `observed_services` list
alongside the telemetry it already sends.

| field | what it establishes | how |
|---|---|---|
| `enforcement_engine` | the agent can apply rules at all | Windows: `FwpmEngineOpen0` succeeds. Linux: `iptables` and `ip6tables` are present and the chains can be created. macOS: the helper exists, is root-owned, implements the verb this daemon calls, and `pf` accepts the anchor. |
| `hub_literal` | the pinhole can be written | the hub URL reduces to an address literal. |
| `address_origin` | whether DHCP is load-bearing here | DHCP-assigned or static. Static means the DHCP permit is not on the critical path. |
| `last_applied` | whether this host let itself out | empty in normal operation; set when the dead-man timer released an isolation, and carrying the reason, so a containment that did not hold says so on the first beat that gets through. |
| `observed_services` | what the baseline is checked against | the resolvers, DHCP servers and time sources this host actually uses, each with the file or API it was read from. |

`enforcement_engine` and `hub_literal` are gated on. The rest are shown, not gated —
an operator has to be able to isolate a statically addressed host.

### 2. The hub records it

Stored per endpoint with the time the hub received it — the hub stamps it, so a wrong
clock on an endpoint cannot forge a fresh report. Read back through
`GET /api/v1/baseline/endpoint?endpoint_id=…`, which returns the resolved rule set, the
wire expansion the agent is handed, what the host observed, and what of that the
baseline does not cover.

### 3. The order is refused without it

`POST /api/v1/endpoints/isolate` and the bulk form return **409** when the report is
stale (older than ten minutes), failing, or when the baseline does not cover a service
the host is using. The body carries the uncovered list, the rules that would be
applied, and the readiness object — the refusal is the screen, not a log line.
`"force": true` overrides and is audited as `ISOLATE_HOST_FORCED` with the reason it
overrode: an operator containing an actively compromised host must never be blocked by
a stale probe, but the override has to be a decision someone made, with their name on
it.

**An endpoint that has never reported is allowed, with a warning**, and audited as
`ISOLATE_HOST_UNVERIFIED`. This is a deliberate departure from the original design,
and the reasoning is load-bearing: reporting readiness and honouring the baseline
arrive in the same agent release and are the same code path. An endpoint that has not
reported is an endpoint still enforcing the compiled-in floor — DNS and DHCP to any
destination — so isolating it is exactly as safe as it was before this policy existed,
and no safer. Refusing would take the Isolate button away from the entire fleet for
the length of a rollout, during which the only way to contain a host would be an
override that means nothing.

**Anyone splitting readiness reporting and baseline enforcement into separate releases
has to revisit this.** The coupling is what makes it sound.

### 4. The dead-man rollback

The check above is a prediction. This is the backstop, and it is the part that makes
the whole thing safe: an agent that has applied an isolation and then fails N
consecutive heartbeats lifts **this host's isolation only**, records why, and reports
it on the first beat it gets through. It rebuilds the rule set rather than tearing it
down, so a mesh quarantine of a peer survives the rollback.

| platform | beats | interval | window |
|---|---|---|---|
| Linux | 100 | 3s | 5 min |
| macOS | 100 | 3s | 5 min |
| Windows | 120 | 2500ms | 5 min |

This inverts the failure. Without it, a floor defect means a host is lost until someone
notices and reaches it out of band. With it, a floor defect means a host un-isolates
itself after five minutes and tells you the floor is broken. The worst case becomes a
containment that did not hold — recoverable and loud — rather than an endpoint that is
gone.

N is deliberately not 1: a hub restart, a brief network event, or a rolling release
must not lift every quarantine in the fleet. Five minutes outlasts all three and is
short enough that the person who just isolated the host is still watching.

### 5. The console shows the rule set, not a warning about it

The Isolate dialog lists every permit that will remain — the two that are always there
and every baseline rule, expanded to the protocol and port the agent is actually
handed — and, separately, anything the host reported using that the baseline does not
cover. When the gate refuses, the dialog is the refusal: it names what is uncovered,
offers **Fix the baseline** (which opens the policy editor pre-filled from what the
host reported, for a person to edit and approve) and **Isolate anyway**, which is the
audited override.

An analyst sees all of it and can isolate and override; only an administrator can
author a policy. The person deciding whether to cut a host off must not be the one
person who cannot see the rules.

## Why the rollback is not enough on its own

It is tempting to skip the gate and rely on the rollback. The gate is what stops a
predictable failure from happening at all, and it is what puts the residual risk in
front of a person before they cut a host off rather than after. The rollback is what
catches the failure nobody predicted. Both, or neither is worth much.
