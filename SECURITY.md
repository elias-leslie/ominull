# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities using GitHub private vulnerability reporting:

https://github.com/elias-leslie/ominull/security/advisories/new

Include:

- Affected component (Windows WFP driver, Linux eBPF daemon, Hub API, or Copilot engine)
- Detailed reproduction steps or proof of concept
- Expected vs observed security impact
- Any proposed remediation or mitigation

Do not open a public GitHub issue for a suspected security vulnerability.

## Security Design Invariants

Ominull is built around several core security invariants:

1. **Microsecond Kernel Isolation:** The WFP callout driver (`ominull.sys`) and Linux eBPF classifier execute at the highest priority ALE sublayer (`0xFFFF`), enforcing default-deny quarantine before packets reach the user-mode socket layer.
2. **Encrypted Forensic Pinholing:** When an endpoint is quarantined, all normal network communication is severed, while maintaining a secure, unidirectional pinhole allowing the management Hub to perform forensic memory dumps and incident remediation.
3. **Fail-Closed Subnet Mesh Shield:** When rogue or unmanaged devices without agents are quarantined via `MESH_ISOLATE_PEER`, all managed network peers enforce strict hardware/kernel packet drops across the entire broadcast domain.
4. **Least-Privilege Token Boundaries:** Three credentials, three reaches, and no route accepts a weaker one than it needs. The **admin key** is an operator's and never leaves the hub or an operator's terminal: fleet-wide controls (tenant administration, mesh quarantine, push deploy, discovery sweeps, copilot configuration, agent releases) require it. The **tenant key** is what an enrolled agent holds, so it can do only what an agent does — report telemetry, poll its own configuration, act on its own tenant's endpoints. A **single-use enrolment token** authorises exactly one client-certificate issuance and expires in an hour. Cloudflare Service Tokens remain barred from the web console.
5. **Endpoint Identity Is Issued, Not Claimed:** With `--client-certs required`, an endpoint is identified by a certificate the hub's CA signed for its endpoint id, read only from `r.TLS.VerifiedChains`. The requirement holds on the plain listener too, which has no handshake to enforce it in: a request that claims an endpoint id without a verified certificate is refused there as well.
6. **Nothing From The Network Reaches A Shell:** Values that fan out to agents — a quarantined peer's address, an isolation allow list — are validated as addresses at the hub and again at the agent, and are applied through an explicit argument vector rather than a constructed command line. The same holds inbound: an agent's telemetry carries process paths it observed on its host, and it is posted through an argument vector with the body on stdin, so a path a local user chose is never a fragment of a command line.
7. **A Credential Is Never An Argument:** Every argument of every process is readable by every local account — `/proc/<pid>/cmdline` on Linux, `ps` on macOS, `sc qc` on Windows. The tenant key is shared by the whole fleet, so an agent that carried it in its argv handed it to anyone with a shell on that endpoint. Each platform's service definition names a 0600 file instead, and the key reaches subprocesses down a pipe. It is never in a URL either: a query string is copied into every access log on the path.
8. **Zero WFP Object Leaks:** Driver unload routines dynamically unregister all callouts, sublayers, and ALE filter rules, guaranteeing clean state restoration on service teardown.

## Supported Versions

| Version | Supported |
|---|---|
| latest `main` | Yes |
| older snapshots | No |

## Response Expectations

Security vulnerability disclosures are investigated on a best-effort basis.
