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
4. **Least-Privilege Token Boundaries:** Cloudflare Service Tokens and administrative API keys are strictly separated; service tokens used for automated telemetry delivery are explicitly barred from console mutations.
5. **Zero WFP Object Leaks:** Driver unload routines dynamically unregister all callouts, sublayers, and ALE filter rules, guaranteeing clean state restoration on service teardown.

## Supported Versions

| Version | Supported |
|---|---|
| latest `main` | Yes |
| older snapshots | No |

## Response Expectations

Security vulnerability disclosures are investigated on a best-effort basis.
