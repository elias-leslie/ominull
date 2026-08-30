# The Trust Fabric — decisions of record

Design plan for one allow-list, authored at whatever level of the business owns the
decision, resolved down to rules a kernel can hold. This file is the decisions record;
the reasoning behind each is in the design draft, and the status line below says how
much of the plan exists.

Status as of v1.7.11: the enforcement floor the fabric sits on is built and verified
on all three platforms (`agent/windows/wfp_user.c`, `agent/linux/main.c`,
`agent/macos/pf_engine.sh`), and the first policy authored above it — the baseline
isolation policy of D2 — is built end to end: hub, all three agents, and the console.
The rest of sections 1–11 of the design is not built.

## D1 — Who may author rules: provider-only for v1

**Decided: provider-only.** A client admin cannot author rules; the provider authors
client-scoped rules on their behalf.

Not because client-authoring is wrong — it is what clients ask for the moment they see
the screen — but because the thing that makes it safe does not exist yet. Roles are
enforced (`admin` / `analyst` / `auditor`, v1.7.8) but they are *fleet-wide*: an
administrator is an administrator of everything. Client-authoring without a
tenant-scoped role means every client admin is a fleet admin.

Revisit when a role can be bound to one tenant. That is the real prerequisite, and it
is worth building on its own merits.

## D2 — Default isolation mode for a human clicking "Isolate": full

**Decided: full.** Automated detections were already going to default to full; a human
click now does too, and the two modes differ only in what sits *above* the floor.

This was open because of a real fear: that "full" would cut the host off from the
things it needs to stay reachable and releasable. As of v1.7.10 that is measured
rather than assumed. Both modes preserve the same floor —

    hub pinhole > loopback > DHCP > peer quarantine > DNS > allow list > deny

— and under a live default-deny on all three platforms the hub stayed reachable, the
agent heartbeat never broke, DNS resolved, and a forced DHCP renewal completed with
the lease intact. A fully isolated host is still a managed host.

Two residual risks were accepted here in v1.7.10 — **DNS permitted to any
resolver** and **DHCP permitted to any server**. Both were compiled into the agents,
which meant the most important question about an isolation, "what can this host still
reach?", had an answer nobody could see or change. Neither is accepted any longer.

**Decided: a baseline isolation policy replaces both** (v1.7.11). Named services with
named destinations, authored in the console at global, tenant, location or endpoint
scope, resolved per endpoint by the hub and handed to the agent as the exact set it may
permit. Scopes are *unioned, never overriding*: a location policy adds to the global
one, so a rule cannot be silently removed by adding another policy somewhere else.

The two permits that make an isolation reversible — the hub pinhole and loopback — stay
compiled in and are not listed as policy. An allow-list an operator can empty by
accident is a way to lose a host.

TCP/53 remains deliberately unpermitted: that is a general-purpose tunnel, not a name
lookup. DHCP's broadcast fallbacks ride along only where DHCP is permitted at all,
because a REBIND or DISCOVER after a failed renewal is a broadcast.

The compatibility hinge is `baselineKnown`. An agent that receives no baseline key from
the hub is talking to a hub that predates the policy and keeps the old permissive floor;
an agent that receives an *empty* baseline has been told "hub and loopback only" and
obeys it. The two are not the same case, and all three agents distinguish them.

## D3 — Where the shipped catalogue lives: in the repo

**Decided: in-repo.** Versioned with the hub, reviewable in a pull request, and it
works on an airgapped deployment. The fleet already self-updates through the hub, so
"updatable without a release" — the one advantage of serving it from an endpoint —
buys little that a release does not already buy.

## D4 — Who may author a baseline rule: administrators only

**Decided: administrators author, everyone who can isolate can read.** A baseline rule
is a standing hole in every isolation its scope covers, so authoring one is an
administrator's action. Reading is not: an analyst deciding whether to isolate a host
has to see what the isolation would still permit, and hiding the rules from them would
mean the person making the call is the one person who cannot see them.

This is narrower than D1 and does not wait on it. Tenant-scoped roles would let a client
admin author rules *for their own tenant*; until they exist, the console shows the whole
list to any authenticated operator and admits only an administrator to change it.

## D5 — What happens when the baseline does not cover what a host uses

**Decided: refuse, name the gap, and make the override a separate audited action.** The
hub returns 409 with the uncovered services in the body; the console turns that into a
choice — fix the baseline from what the host reported, or isolate anyway.

An endpoint whose agent predates the readiness check is allowed with a warning rather
than refused. It is still running the old permissive floor, so isolating it is exactly
as safe as it was before and no safer, and refusing would take the button away from the
whole fleet for the length of a rollout. That argument depends on readiness reporting
and baseline enforcement shipping in the same release; the coupling is written down in
`docs/ISOLATION_READINESS.md`, and anyone splitting them has to revisit this.

## Still open

- **Sections 1–11 of the design** beyond the baseline policy: the general rule kinds,
  the resolution engine for policy that is not isolation, and the client-facing
  authoring surface D1 defers until a role can be bound to one tenant.
