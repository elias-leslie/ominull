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
`endpoint`), an `ip` or `cidr` value, `allow` or `deny`, and optionally a
port and protocol, a direction, `locked`, `expires_at` and a justification.
Precedence (`hub/pkg/trustfabric`): the hub, loopback and DHCP are always
reachable; a locked rule cannot be overridden from below (the least specific
locked scope wins); otherwise the most specific rule wins (scope, then prefix
length, then port/protocol), deny on a tie; no match means not trusted.

- `GET|POST /api/v1/trust/rules`, `DELETE /api/v1/trust/rules?id=` (admin).
- `GET /api/v1/trust/effective?endpoint_id=ID[&addr=A&port=P&proto=tcp]`:
  the compiled allow list, which part agents enforce, and one decision.
- `POST /api/v1/endpoints/isolate` takes `mode`: `full` reaches only the hub
  and refuses `allow_ips`; `selective` adds the endpoint's effective policy to
  `allow_ips` before the owner approves, so the signed grant carries exactly
  what was approved. Without `mode` only the request's own `allow_ips` apply.
  Detector isolation is always full.

Agents enforce single addresses: only addresses a rule names (`ip`, or a
`/32` / `/128`) and the policy allows are added; a trusted range is listed as
not enforced in the approval summary and stays closed. The expansion is kept
under the approval id, so a rule changed while the owner decides does not
void the approval (after a hub restart it is expanded again and refused if it
differs). Port- or
direction-scoped allows are withheld for the same reason. Each isolation gets
an id; the fabric as it stood is recorded under it
(`ISOLATION_FABRIC_SNAPSHOT`), and a rule created or deleted while it is in
force is recorded against it (`TRUST_RULE_DURING_ISOLATION`) without changing
it. An endpoint allow rule written while that endpoint is isolated expires
after four hours unless it names its own expiry.
