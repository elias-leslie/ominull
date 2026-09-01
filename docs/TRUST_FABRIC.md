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
