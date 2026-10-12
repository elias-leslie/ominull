# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities using
[GitHub's private vulnerability reporting](https://github.com/elias-leslie/ominull/security/advisories/new).

Include:

- affected component (hub, Linux agent, Windows agent, packaging, or router collector) and version
- reproduction steps or proof of concept
- expected impact
- any known workaround or mitigation

Do not open a public GitHub issue for a suspected security problem, and do not
attach live credentials or private endpoint data.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest `main` | Yes |
| older commits and snapshots | No |

Reports are handled on a best-effort basis. No formal SLA is offered.

## Security model

Ominull treats telemetry, containment state, enrollment credentials, and signed
updates as security-sensitive.

### Trust boundaries

- The hub authenticates operators with protected admin/session identities and
  agents with unique per-device credentials. It can additionally require
  endpoint client certificates issued by its local CA.
- The endpoint certificate identity must match the reported endpoint. Retired
  endpoints cannot be revived by a late heartbeat.
- Enrollment codes are scoped and bounded. Bootstrap validates package digest
  and detached ECDSA signature, then invokes the registered native package
  manager without placing enrollment material in a URL or service argument.
- The release public key is compiled into agents. The private signing key is
  kept outside the repository, the hub, and CI.
- Isolation state is persisted and returned by authenticated heartbeat. Agents
  reconcile it locally and report enforcement readiness and outcome.

### Credentials

Keep admin keys, legacy tenant keys, device credentials, certificates, and
deployment values outside the repository. Prefer an admin-key file with mode
`0600`; command-line credentials are visible in local process metadata. Do not
put secrets in logs, fixtures, issue text, package metadata, or shell history.
Legacy shared tenant-key authentication exists only during an explicit migration
and must be disabled after retained agents adopt unique device credentials.

### Enforcement truth

Linux uses socket inspection for TCP, an embedded eBPF CO-RE program for UDP
observations, and iptables/ip6tables for host isolation. Windows uses kernel
network ETW events for UDP and user-mode management of Windows Filtering
Platform rules for isolation. Flow telemetry is not packet-content inspection. Byte fields are
reported only when measured by the collector, and analytics label partial
coverage.
