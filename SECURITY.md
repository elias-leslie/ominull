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
2. **Enforcement Is Proven In The Kernel, Not Reported From User Space:** An agent reads back what the kernel is actually holding before it records an order as applied, and an order it could not apply is left unapplied so the next heartbeat retries it. Every platform had a way of reporting a quarantine it had not imposed. macOS loaded its rules into a `pf` anchor that no ruleset referenced, so nothing evaluated them; it also shipped a daemon that had learned a new enforcement verb without the helper that implements it. Windows asked for filter weights outside the 0-15 that `FWP_UINT8` allows and named four layer and condition GUIDs that do not exist, so `FwpmFilterAdd0` refused the first filter and aborted the transaction; releasing a host then tried to delete a sublayer that still held filters, which cannot succeed, and returned success anyway. In each case the hub, the console and the agent's own log all said the host was isolated while it stayed on the network.
3. **An Order Reaches The Endpoint Or It Is Not An Order:** Isolation and mesh quarantine travel on the reply to the telemetry every agent is already sending, and are reconciled against the hub's answer on every heartbeat — so an endpoint that was offline when it was cut off applies it when it returns, and one that was offline when it was released comes back. They used to be WebSocket commands on a route that was never registered, which meant the hub recorded the decision, answered `200 {"status":"isolated"}`, and told nobody. An agent refuses to isolate at all if it cannot resolve the hub's address, because a quarantine with no hole for the hub can never be lifted by the hub.
4. **Encrypted Forensic Pinholing:** When an endpoint is quarantined, all normal network communication is severed, while maintaining a secure, unidirectional pinhole allowing the management Hub to perform forensic memory dumps and incident remediation.
5. **Fail-Closed Subnet Mesh Shield:** When rogue or unmanaged devices without agents are quarantined via `MESH_ISOLATE_PEER`, all managed network peers enforce strict hardware/kernel packet drops across the entire broadcast domain.
6. **Least-Privilege Token Boundaries:** Three credentials, three reaches, and no route accepts a weaker one than it needs. The **admin key** is an operator's and never leaves the hub or an operator's terminal: fleet-wide controls (tenant administration, mesh quarantine, push deploy, discovery sweeps, copilot configuration, agent releases) require it. The **tenant key** is what an enrolled agent holds, so it can do only what an agent does — report telemetry, poll its own configuration, act on its own tenant's endpoints. A **single-use enrolment token** authorises exactly one client-certificate issuance and expires in an hour. Cloudflare Service Tokens remain barred from the web console.
7. **Endpoint Identity Is Issued, Not Claimed:** With `--client-certs required`, an endpoint is identified by a certificate the hub's CA signed for its endpoint id, read only from `r.TLS.VerifiedChains`. The requirement holds on the plain listener too, which has no handshake to enforce it in: a request that claims an endpoint id without a verified certificate is refused there as well.
8. **Nothing From The Network Reaches A Shell:** Values that fan out to agents — a quarantined peer's address, an isolation allow list — are validated as addresses at the hub and again at the agent, and are applied through an explicit argument vector rather than a constructed command line. The same holds inbound: an agent's telemetry carries process paths it observed on its host, and it is posted through an argument vector with the body on stdin, so a path a local user chose is never a fragment of a command line.
9. **A Credential Is Never An Argument:** Every argument of every process is readable by every local account — `/proc/<pid>/cmdline` on Linux, `ps` on macOS, `sc qc` on Windows. The tenant key is shared by the whole fleet, so an agent that carried it in its argv handed it to anyone with a shell on that endpoint. Each platform's service definition names a 0600 file instead, and the key reaches subprocesses down a pipe. The hub holds itself to the same rule: `--admin-key-file` names a file whose mode it checks before reading, and starting with `--admin-key` warns that the credential is now in `/proc/<pid>/cmdline` and in `systemctl show`. It is not in a URL either. The console gate posts the key and exchanges it for a short-lived signed session cookie, and a request that still arrives with `?key=` is redirected to a clean URL before anything renders — as a GET form it wrote the admin key into the address bar, and from there into browser history, into bookmarks, and into the access log of every proxy and CDN on the path, none of which a cache purge reaches. Responses whose body *is* a credential — the three bootstrap installers, which carry the tenant key and a live enrolment token — are sent `Cache-Control: no-store`, as is the console document itself.
10. **What Root Runs, Only Root Writes:** An agent runs as root, so every file it executes and every unit that starts it is owned by root and writable by root alone. The packages enforce it at build time — the `.deb` is built `--root-owner-group` and the archives are written `--owner=root`, each checked before it is signed, because `dpkg-deb` and `tar` otherwise record the build account and shipped a fleet-wide local escalation. The installers set it again on anything they download, and the macOS daemon re-checks the packet-filter helper's owner and mode before running it as root.
11. **Signing In Is Not The Same As Being Trusted:** Cloudflare Access decides who reaches the hub; the operator list decides what they are once they arrive, and the two are separate on purpose — widening an Access policy, or pointing a second Access application at this hostname, must not by itself hand anyone the fleet. Only the signed `Cf-Access-Jwt-Assertion` is checked, never the plaintext `CF-Access-Authenticated-User-Email` header, because the hub also answers directly on the LAN where any caller can assert whatever address it likes; the `aud` claim is pinned to one application, and only RS256 is accepted. The role comes from the operator list rather than from any claim in the token, is re-read on every request so a revocation takes effect immediately rather than when the session expires, and the last administrator cannot be demoted or removed. A read-only role is refused every request that is not a read, enforced once for the whole API rather than route by route. The console embeds the admin key only for the caller who already presented it: an operator identified by Access gets a session cookie scoped to their own role, so granting someone the auditor role does not also post them the credential that runs the entire fleet.
12. **Zero WFP Object Leaks:** Driver unload routines dynamically unregister all callouts, sublayers, and ALE filter rules, guaranteeing clean state restoration on service teardown.

## Supported Versions

| Version | Supported |
|---|---|
| latest `main` | Yes |
| older snapshots | No |

## Response Expectations

Security vulnerability disclosures are investigated on a best-effort basis.
