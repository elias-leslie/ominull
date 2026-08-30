# Isolation readiness — proving a host can be released before cutting it off

Status: designed, not built. The floor it tests is built and verified as of v1.7.10.

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

Today the answer is "the maintainers tested it." That is not a control. What follows is.

## The floor, stated as a contract

One definition, enforced identically by all three agents, in this precedence:

    hub pinhole > loopback > DHCP > peer quarantine > DNS > allow list > deny

- **hub pinhole** — both directions, both families where the hub literal is one.
  Above the peer blocks so a quarantine cannot sever the release path. The hub also
  refuses to quarantine its own address (409).
- **loopback** — both directions; local software talking to itself.
- **DHCP** — both directions. v4 UDP 67:68, v6 UDP 546:547.
- **DNS** — both directions, UDP only, any resolver. A stated hole (see
  `docs/TRUST_FABRIC.md`, D2).
- **allow list** — `isolation_allow_ips`, below a peer block so quarantine wins.
- **deny** — everything else, both directions, both families.

## The gate

### 1. The endpoint answers, on every heartbeat

The agent reports an `isolation_readiness` object alongside the telemetry it already
sends. Each check is `ok` or a named reason:

| check | what it establishes | how |
|---|---|---|
| `enforcement_engine` | the agent can apply rules at all | Windows: `FwpmEngineOpen0` succeeds. Linux: `iptables` and `ip6tables` are present and the chains can be created. macOS: the helper exists, is root-owned, implements the verb this daemon calls, and `pf` accepts the anchor. |
| `hub_literal` | the pinhole can be written | the hub URL reduces to an address literal, and it is the address this heartbeat actually reached. |
| `address_origin` | whether DHCP is load-bearing here | DHCP-assigned or static. Static means the DHCP permit is not on the critical path; DHCP means it is. |
| `resolvers` | what the DNS permit is protecting | the resolvers this host is configured with, reported so the hole is visible rather than assumed. |
| `last_applied` | the rules the agent believes are in the kernel | read back from the kernel, not from the agent's own state — the check that would have caught a half-written anchor. |

`enforcement_engine` and `hub_literal` are required. The rest are informational and
are shown, not gated on — an operator has to be able to isolate a statically addressed
host.

### 2. The hub records it

Stored per endpoint with a timestamp. Exposed on the endpoint row and on
`GET /api/v1/endpoints`.

### 3. The order is refused without it

`POST /api/v1/endpoints/isolate` and the bulk form return **409** when readiness is
absent, stale (older than one heartbeat interval × 5), or failing, and the body names
the check that failed and what it means. `"force": true` overrides and is audited as a
distinct action — an operator containing an actively compromised host must never be
blocked by a stale probe, but the override has to be a decision someone made, with
their name on it.

### 4. The dead-man rollback

The check above is a prediction. This is the backstop, and it is the part that makes
the whole thing safe: an agent that has applied an isolation and then fails **N
consecutive heartbeats** lifts the isolation itself, records why, and reports it on the
first beat it gets through.

This inverts the failure. Today, a floor defect means a host is lost until someone
notices and reaches it out of band. With the rollback, a floor defect means a host
un-isolates itself after a few minutes and tells you the floor is broken. The worst
case becomes a containment that did not hold — which is recoverable and loud — rather
than an endpoint that is gone.

N is deliberately not 1: a hub restart, a brief network event, or a rolling release must
not lift every quarantine in the fleet. It should be long enough to outlast a hub
restart and short enough that a person is still in front of the screen.

### 5. The console states the residual risk

The confirm dialog names what stays open at the floor — DNS to any resolver, DHCP to
any server — and what the endpoint reported. Accepting is accepting those, explicitly.

## Why the rollback is not enough on its own

It is tempting to skip the gate and rely on the rollback. The gate is what stops a
predictable failure from happening at all, and it is what puts the residual risk in
front of a person before they cut a host off rather than after. The rollback is what
catches the failure nobody predicted. Both, or neither is worth much.
