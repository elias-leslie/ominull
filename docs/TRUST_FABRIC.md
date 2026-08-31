# Trust fabric

Ominull has three deliberate trust layers: operator authorization, endpoint
identity, and signed release identity.

## Operator and tenant roles

The admin key may manage tenants, scans, containment, enrolment windows, and
release jobs. A tenant key is scoped to its tenant and cannot perform those
fleet-wide actions. Route tests exercise both sides of this boundary.

Bootstrap generation is authenticated. A generated command carries a tenant
credential and a single-use enrollment token, not the admin credential. The
self-service portal may mint the same ticket only when the source address is
inside an open, bounded enrollment window.

## Endpoint identity

The hub CA issues a certificate for each endpoint. The telemetry request must
use the endpoint identity named by the certificate when client-certificate mode
is enabled. Heartbeat recency determines online status. Retired endpoints keep
their rows, telemetry, certificates, and audit history, but a late heartbeat is
rejected and cannot revive them.

## Release identity

Each Debian package and MSI has a detached ECDSA signature and SHA-256 digest.
The agent verifies both against the public key compiled into its release. Hub
artifact serving requires both sidecars. Package manager registration is
reported independently from the compiled binary version so a copied binary
cannot look like a native install.

## Containment

The hub stores desired isolation, baseline, mesh, and recovery state. Agents
apply only authenticated state from their heartbeat response and report whether
the local mechanism is ready and what it applied. Linux uses iptables or
ip6tables; Windows uses user-mode Windows Filtering Platform rules. Recovery
tools clear only Ominull-owned state and preserve unrelated host rules.

## Data preservation

Removing a product role retires its endpoint record instead of deleting durable
telemetry or audit data. Old feature tables and settings may remain as inert
legacy rows during schema upgrade. New databases do not recreate retired
feature tables. Retention bounds raw events, communication profiles, alerts,
anomalies, and audit data according to the configured policy.
