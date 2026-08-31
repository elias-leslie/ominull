# Security model

Ominull treats telemetry, containment state, enrollment credentials, and signed
updates as security-sensitive.

## Trust boundaries

- The hub authenticates operators and tenant agents with API keys and can
  require endpoint client certificates issued by its local CA.
- The endpoint certificate identity must match the reported endpoint. Retired
  endpoints cannot be revived by a late heartbeat.
- Bootstrap tickets are short-lived and single-use. Bootstrap fetches the CA,
  validates package digest and detached ECDSA signature, then invokes the native
  package manager.
- The release public key is compiled into agents. The private signing key stays
  in the operations vault.
- Isolation state is persisted and returned by authenticated heartbeat. Agents
  reconcile it locally and report enforcement readiness and outcome.

## Credentials

Keep admin keys, tenant keys, endpoint keys, certificates, and deployment values
outside the repository. Prefer an admin-key file with mode `0600`; command-line
credentials are visible in local process metadata. Do not put secrets in logs,
fixtures, issue text, package metadata, or shell history.

## Enforcement truth

Linux uses socket inspection for collection and iptables/ip6tables for host
isolation. Windows uses user-mode management of Windows Filtering Platform
rules. Flow telemetry is not packet-content inspection. Byte fields are
reported only when measured by the collector, and analytics label partial
coverage.

## Reporting

Do not open public issues for an exploitable flaw. Send a private report to the
maintainer with reproduction steps, affected version, impact, and a proposed
fix. Avoid attaching live credentials or private endpoint data.
