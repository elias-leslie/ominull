# Console contract

The embedded console is a thin view over the hub API. It shows evidence already
stored by the hub and labels measured, inferred-from-scan, and absent values
separately. It does not invent endpoint identity or enforcement state.

## Main views

- Overview: tenant, location, endpoint, alert, and retention summaries.
- Assets: agent and scanner provenance, identity confidence, and quiet hosts.
- Traffic: flow counts, measured byte coverage, countries, processes, and
  cached analytics.
- Containment: readiness, baseline isolation, host release, and mesh quarantine.
- Detection: stored behavioral tuning, exclusions, alerts, and acknowledgements.
- Enrolment: retained Linux/Windows installer commands and bounded self-service
  enrolment windows.
- Updates: desired version, pending jobs, package identity, registered version,
  and provenance issues.

## Evidence rules

Agent reports outrank scanner observations for managed identity. Scanner results
remain scanner evidence. A flow-only address may be visible in traffic and
topology, but it is not promoted to a current asset identity without agent or
scan evidence. Historical claims remain visible as history and cannot change
current identity.

Byte totals include the number of flows that supplied measured counters. The UI
must not present partial counters as total traffic.

## Control rules

Isolation is a persisted desired state. The readiness gate checks observed
services and the resolved baseline before allowing a normal isolate operation;
an explicit emergency override is audited. The next authenticated heartbeat
reconciles desired state, update state, mesh state, and baseline rules on the
endpoint.

Update status distinguishes queued, outdated, retired, and provenance failure.
Retired endpoints preserve history but do not block convergence.

## Demo mode

Demo mode uses synthetic scan, endpoint, flow, alert, baseline, and enrolment
data. It must expose the same retained route names and labels as live mode. It
must not advertise a removed platform, a removed control channel, unsupported
enforcement, or a model-generated conclusion.
