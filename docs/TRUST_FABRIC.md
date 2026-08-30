# The Trust Fabric — decisions of record

Design plan for one allow-list, authored at whatever level of the business owns the
decision, resolved down to rules a kernel can hold. Proposed, not built. This file is
the decisions record; the reasoning behind each is in the design draft.

Status as of v1.7.10: the enforcement floor the fabric sits on is built and verified
on all three platforms (`agent/windows/wfp_user.c`, `agent/linux/main.c`,
`agent/macos/pf_engine.sh`). Nothing in sections 1–11 of the design is built yet.

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

Two residual risks are accepted rather than solved, and are stated wherever isolation
is offered:

- **DNS is permitted to any resolver**, UDP only. An isolated host can still talk out
  over UDP/53. This is the price of being able to re-resolve a hub named by DNS after
  a reboot. Narrowing it to the resolvers a host is configured with is what the
  trusted-resolver rule kind exists to do. TCP/53 is deliberately *not* permitted —
  that is a general-purpose tunnel, not a name lookup.
- **DHCP is permitted to any server.** Without it a lease expires and the host loses
  the address the hub reaches it on, which is a worse outcome than the hole.

## D3 — Where the shipped catalogue lives: in the repo

**Decided: in-repo.** Versioned with the hub, reviewable in a pull request, and it
works on an airgapped deployment. The fleet already self-updates through the hub, so
"updatable without a release" — the one advantage of serving it from an endpoint —
buys little that a release does not already buy.

## Still open

- **A readiness gate before isolation is allowed.** The floor is now uniform and
  proven, but it is proven *by this repository's tests and by a live check run by
  hand*, not by the endpoint itself at the moment it is asked to isolate. What is
  missing is the endpoint answering "can I still be released after this?" before it
  cuts anything, the hub recording that answer, and the console refusing to offer the
  button — or requiring an explicit override — when the answer is stale or no. See
  `docs/ISOLATION_READINESS.md`.
