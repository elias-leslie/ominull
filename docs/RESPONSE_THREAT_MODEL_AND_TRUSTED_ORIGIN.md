# Ominull Response Threat Model, Trusted-Origin Specification, and Platform Floor

**Document ID:** SEC-OMINULL-P0-3  
**Status:** Accepted Architecture Standard (Slice 0.3)  
**Date:** 2026-09-03  
**Classification:** Technical Security Architecture  

---

## 1. Executive Summary

This document establishes the formal threat model, cryptographic trust boundaries, browser origin policy, and operating system support baselines for the Ominull Remote Response and Forensics Subsystem.

As Ominull expands from network telemetry and autonomous ring-0 containment into interactive forensic collection, script execution, and pseudoterminals, endpoint mutation privileges transition from automated reactive isolation to operator-driven administrative commands. Because an endpoint response agent runs with local system supervisor privileges (`root` on Linux, `LocalSystem` on Windows), an authorization failure or compromised hub must never allow an attacker to pivot into arbitrary fleet code execution.

This specification enforces cryptographic non-repudiation, strict domain separation, proof-to-grant binding, and zero-trust isolation between the fleet hub and response authorization authorities.

---

## 2. Architecture & The Three Disjoint Trust Fabrics

Ominull separates operational concerns into three independent, non-interchangeable trust fabrics. Conflating these three systems is strictly forbidden:

```
+-----------------------------------------------------------------------------+
|                               TRUST FABRICS                                 |
+------------------------------------+----------------------------------------+
| 1. AGENT TRANSPORT PKI (mTLS)      | Internal CA; mutual TLS machine-to-    |
|    Port :9443                      | machine communication. No browsers.    |
+------------------------------------+----------------------------------------+
| 2. CONSOLE SECURE ORIGIN (TLS)     | Web server certificate. Satisfies      |
|    Dedicated HTTPS Port            | browser WebCrypto & WebAuthn standards.|
+------------------------------------+----------------------------------------+
| 3. RESPONSE AUTHORITY (Ed25519)    | Per-tenant offline/daemon signing keys.|
|    Restricted Unix Domain Socket   | Authorizes endpoint grants. Hub cannot |
|                                    | read keys or forge grants.             |
+------------------------------------+----------------------------------------+
```

### 2.1 Fabric 1: Agent Transport PKI (mTLS)
- **Scope:** Communication channel between endpoints and the central hub on `:9443`.
- **Mechanism:** The hub's internal CA issues an X.509 leaf certificate to each registered endpoint during bootstrap. Endpoints authenticate the hub leaf certificate against their pinned CA root and present their client certificate on every TLS handshake.
- **Invariants:**
  - Transport encryption and endpoint authentication are strictly decoupled from action authorization.
  - An established mTLS connection proves only that a host is an enrolled agent; it provides zero authorization to execute response jobs or interactive shells.

### 2.2 Fabric 2: Console Secure Origin (TLS)
- **Scope:** Communication channel between the operator's browser and the web console.
- **Mechanism:** Standard server TLS terminating on a dedicated console HTTPS port.
- **Invariants:**
  - Required solely to satisfy the browser's **Secure Context** requirements (RFC 6454 / W3C WebAppSec) for WebCrypto (`crypto.subtle`) and WebAuthn (`navigator.credentials`).
  - Console TLS provides privacy and integrity between browser and hub, but does *not* act as an endpoint authorization boundary. A valid console session cannot authorize endpoint execution without an explicit response authorization event.

### 2.3 Fabric 3: Tenant Response Authority (Ed25519)
- **Scope:** Cryptographic authorization of typed endpoint grants.
- **Mechanism:** Each tenant possesses an independent Ed25519 response private key held exclusively by a separate, unprivileged Response Authority daemon (`ominull-response-authority`) listening on a mode `0660` Unix domain socket.
- **Invariants:**
  - The main hub process, administrative API keys, database records, and cross-tenant operators never have access to the raw signing key.
  - The authority holds three Ed25519 keys per tenant: the **response key** (owner-approved grants), a narrow **auto-isolate key** (the detector's automatic isolation only) and a **policy key** (capability manifests only). The slot keys are never reachable as a tenant (tenant ids with `#`, `/` or `\` are refused).
  - Agents pin all three in their key directory (`/etc/ominull` root-owned and not group/world-writable; `C:\ProgramData\Ominull` with a protected SYSTEM/Administrators DACL, no reparse points) only from a **trust bundle signed by the release key**: the statement `OMINULL-TRUST-BUNDLE-V1\ntenant=..\nepoch=..\nresponse_key=..\nauto_isolate_key=..\npolicy_key=..\n` (lowercase hex), ECDSA P-256 / SHA-256, verified against the release key compiled into the agent (openssl CLI on Linux, CNG on Windows). The owner signs it with `scripts/sign-trust-bundle.sh`, which compares the hub's statement (`GET /api/v1/trust/statement`) with one read on the authority host (`ominull-response-authority -trust-statement TENANT`) before signing, and posts it (`POST /api/v1/trust/bundle`; the hub keeps only a signature that verifies over the authority's current keys). The hub cannot make that signature, so it cannot get an agent to pin keys of its own; nothing is pinned from enrollment or on first use. The bundle is pinned whole (one atomic `trust.pin`: tenant, epoch, three keys), only for the agent's own tenant (`default`), and only at an epoch no lower than the highest ever pinned on that host. The epoch is the authority's, not the hub's: it starts at 1, rises by one whenever a tenant's keys change, and root on the authority host can raise its floor (`-trust-epoch-floor` / `OMINULL_AUTH_TRUST_EPOCH_FLOOR`); the hub only accepts a bundle signed at the authority's current epoch. Agents enforce it (`trust.epoch`, kept across `--repin-trust`) or than the build's floor (`TRUST_MIN_EPOCH`, raised in the release after a key rotation, so even a fresh install refuses a bundle for retired keys). Manifests and grants for another tenant are refused. A pinned key is never replaced; a mismatch is reported (`GET /api/v1/fleet/trust`, which also shows whether each tenant's bundle is signed) and re-pinning is an explicit local `--repin-trust`, after which the agent again pins only a signed bundle, and only from an epoch strictly above the revoked one (the re-pin raises `trust.epoch` before it removes the pin; the authority moves its epoch whenever the keys change). Grant verification uses the keys held in memory from that pin, never a separate key file. A pin is only reported as removed when its files are actually gone.
  - Endpoints verify a grant against the pinned keys before every disruptive action: terminal sessions, forensic collection, scripts, isolation and release, mesh quarantine, and agent update. Isolation, release and mesh grants carry the routed payload (`{"baselines","body","route","targets"}`, canonical JSON, lower-case keys, no other members) and a strictly increasing `issued_at` (the authority keeps one clock per tenant, fsynced before a time is used, never more than 5 minutes ahead of real time; a corrupt clock stops signing, and the detector cannot sign for a tenant that has no response key); agents keep a per-slot watermark that only a genuine grant advances (and only up to 60 s ahead of the agent's clock), so an older grant cannot be replayed to undo a newer decision.
  - **An isolation's exceptions are part of what the owner approves.** The hub resolves each target's baseline (DNS, DHCP, NTP, custom rules) into `baselines: [{endpoints, rules:[{destination,port,protocol,service}]}]` inside the signed payload; the authority checks that every entry names only targets, at most once, with rules an agent accepts, and shows them in the summary. While isolated, an agent permits only those rules (kept in its enforcement state), never the heartbeat's baseline, so a hub cannot widen a contained host's holes. The detector's auto-isolation grant carries the host's own exceptions the same way.

### 2.4 Owner approval for disruptive actions (phone passkey)
- **Scope:** Isolate and release (single and bulk), agent update, mesh quarantine and release, and opening a terminal session. Routine reads and policy routes stay on scoped credentials; the detector's automatic isolation stays in-process and needs no approval.
- **Flow:** The hub answers such a request with `202 {approval_id, action, summary, targets, expires_at}`. The authority records the approval (in memory; a restart fails closed) and signs a statement with the tenant response key. The signed bytes are the line OMINULL-OWNER-APPROVAL-V1, a newline, then the statement JSON (v, id, tenant, requester, kind, action, summary, targets, digest, created, expires). A relay with its own key (`/api/v1/integrations/nightshift/approvals`, no admin fallback; the same key may also answer open maintenance decisions at `/integrations/nightshift/decisions/answer` and read lock facts at `/integrations/nightshift/locks`, never read the fleet or approve an action) carries the statement to one external approval origin that verifies the signature, shows only the signed fields and asks the owner's passkey to sign `sha256(challenge_hex ":" decision)`, where `challenge = sha256(prefix || statement)`. The relay posts the decision and raw assertion back; **the authority verifies the assertion itself** (exact origin, RP ID hash, user presence and verification, counter, ES256) against approvers pinned on the authority host (`-approvers`, `{"approvers":[{id,label,rp_id,origin,credential_id,x,y}]}`). The requester then resends the same request with `X-Approval-ID`; the authority signs grants once, only if kind, payload digest, the resolved target set and the requester match exactly, within 10 minutes of the approval. The action name and summary the owner sees are derived by the authority from the digested payload (route, canonical body, targets; or the terminal's typed payload), never taken from the hub's text, and a route that does not match its kind is refused. Handlers act only on the endpoints named in the grants, so a fleet change between approval and use cannot widen a bulk action or an update.
- **Where the gate holds:** every gated action is verified on the endpoint. A compromised hub cannot open a terminal, isolate or release a host, quarantine a peer or install an update without a grant the authority signed after the owner's tap. The detector's automatic isolation uses the auto-isolate key: isolate only (never release, never mesh), 10-minute grants, at most 6 per hour per tenant and one per endpoint per 10 minutes, each audited. A hub that holds only that key can cut a host off, not reopen one or run anything on it.
- **Residuals, stated plainly:** (1) until the owner signs a tenant's trust bundle its agents pin nothing and refuse every gated action (fail closed; the fleet trust view shows `trust_bundle: unsigned`); the release key that signs bundles is the same key that signs packages, so its custody (operations: release key custody) bounds both; (2) an agent upgrading from a pre-grant release bootstraps its isolation/quarantine state once from the hub's last word, with the 5-minute dead-man (a bootstrapped isolation is not an owner isolation) and watermarks set from the agent's own clock, never from hub-sent marks; (3) threat-intel indicators are still hub-sent data, not grants: agents apply them only to globally routable addresses (never private, loopback, link-local, CGNAT, multicast, documentation ranges or a local resolver from `/etc/resolv.conf`; the hub's own addresses are permitted ahead of any drop), so a hub can at worst block public destinations; Windows agents do not apply them; (4) an isolation's dead-man is 12 hours for an owner-approved isolation (5 minutes otherwise), after which an unreachable hub releases the host locally; (5) local root on an endpoint can always release it (`--cleanup` / `--release-local`).
- **Why one external origin:** the owner already approves privileged host actions with one phone passkey on one origin. A second passkey store and a second approval page would split what the owner has to trust; the authority still verifies every assertion, so the origin cannot approve on its own and a relay that mislabels a request fails the signature.
- **Delivery follows the action:** an approved action's grants are stored as pending before its handler runs (no handler runs if they cannot be stored) and become deliverable only after it succeeded; a failed action's grants are withdrawn without ever reaching an agent. If the hub stops between the handler and that step, a reconciler (at start and every minute, for grants pending over 2 minutes) compares the hub's state with each grant (isolation on or off with exactly the grant's allow list and the exceptions the hub would grant now, mesh quarantine, the update job's version) and releases or withdraws it; an expired grant is never released (audited: the owner repeats the action). At start this runs before any listener opens, for every pending grant. Addresses (allow list, mesh target) are normalized before the owner is asked, so the owner, the authority, the hub and the agent all see one spelling.
- **Without a pinned approver** every gated action answers 503; nothing falls back to API keys or console sessions.
- **Capability manifest:** each endpoint holds a manifest signed by the policy key (`OMINULL-CAPABILITY-MANIFEST-V1`, increasing `seq`) naming a profile: `monitor` (update only), `respond` (collect, isolate, mesh, terminal, update) or `engagement` (respond plus scripts). The agent refuses any new restriction or response offer the manifest does not allow, even with a valid grant; releases are always accepted, so narrowing never strands an isolated host. The first manifest is at most `respond` (`monitor` for a monitor-only host); narrowing is signed without approval, widening only through an owner-approved `capability_change` (`POST /api/v1/endpoints/capabilities`) or the owner lifting monitor-only. A manifest is refused unless its `seq` is above the highest taken under the same policy key (`manifest.floor`, one line per recent policy key (up to 8), kept across `--repin-trust`; written after the manifest itself, and raised from the stored manifest at start), so an older, wider manifest cannot come back after a re-pin, an epoch change or a policy key that returns. Only a grant naming this endpoint (and readable as an action for it) moves its isolation watermark. When the policy key changes, the authority re-signs each stored manifest at the next `seq`. Root on the endpoint can set a **local ceiling** (`ominulld --capability-ceiling monitor|isolate|signed-scripts|monitor-signed-scripts|respond|engagement|none`; levels in docs/HOST_AUTHORITY.md; `capability.ceiling` in the key directory; an unreadable ceiling counts as `monitor`); the agent applies the narrower of manifest and ceiling and reports it in the fleet trust view. Residual: a host without a ceiling accepts the hub's first manifest up to `respond` (the owner's choice for home machines, which keep the terminal); set `monitor` on hosts that must never be acted on.
- **Capabilities, not OS names:** agents report `response_capabilities {isolate, collect, terminal:{programs}}`. The hub chooses terminal programs from that list and never branches on the OS string, so a new platform (macOS) only reports its own capabilities; each PTY backend (forkpty, ConPTY) sits behind the same terminal protocol.

---

## 3. Response Threat Model

### 3.1 Threat Actors & Capabilities

| Threat Actor | Assumed Access Level | Goal |
|---|---|---|
| **External Attacker** | Network visibility; internet access | Intercept traffic, inject commands, compromise fleet |
| **Malicious Operator / Compromised Analyst** | Authenticated console session; stolen password | Run unauthorized scripts, open rogue shells, pivot to endpoints |
| **Compromised Hub Web Process** | Code execution inside `ominull-hub` daemon | Forge commands to fleet, exfiltrate data, bypass auditing |
| **Compromised Fleet Endpoint** | Root / LocalSystem on a single managed node | Compromise hub, forge results, issue commands to other endpoints |
| **Infrastructure / Host Compromise** | Root on LXC container host / Proxmox hypervisor | Full host takeover |

---

### 3.2 Threat Scenarios & Mitigations

#### Threat 1: Stolen Console Cookies & Persistent Sessions
- **Threat:** An attacker steals an operator's session cookie via XSS, browser malware, or network interception.
- **Mitigation:**
  - **Dual-Session Model:** Normal console login grants read/audit access only. Response operations require entering an active **Response Session**, capped at an absolute lifetime of 8 hours with a strict 30-minute idle lock.
  - **Hardware Token / WebAuthn Step-Up:** Opening a Response Session requires a hardware token (FIDO2/WebAuthn) or TOTP step-up proof signed by an ephemeral browser key generated in WebCrypto.
  - **Proof-of-Possession:** Mutation requests (`job_create`, `shell_create`) require a signed `ActionProof` generated by the browser's ephemeral private key. A stolen session cookie without the non-exportable browser key is rejected.

#### Threat 2: Static Hub API Key Compromise
- **Threat:** An automated admin API key (e.g. `admin.key`) or service token is leaked from CI/CD or disk.
- **Mitigation:**
  - Static API keys are strictly restricted to fleet ingestion, status diagnostics, and inventory queries.
  - The Response Authority rejects static API keys. Grants can only be signed when presented with a valid, non-expired `ActionProof` originating from a live human response session.
  - Disruptive actions (section 2.4) additionally need the owner's passkey approval, verified by the authority; an admin key or a console session alone only creates a pending approval.

#### Threat 3: Hub Process Compromise (`ominull-hub`)
- **Threat:** An attacker discovers an RCE vulnerability in the Go hub web daemon.
- **Mitigation:**
  - **Privilege Separation:** The hub runs under an unprivileged `ominull` service identity. It cannot read the private response signing keys stored in `/var/lib/ominull-response-authority/keys/` (owned by `ominull-authority:ominull-authority`, mode `0700`).
  - **Socket Enforcement:** Communication with the authority occurs strictly over a local Unix domain socket with credential passing (`SO_PEERCRED`).
  - **Digest Recomputation:** The authority requires typed action payloads, independently recomputes the canonical SHA-256 action digest, and verifies that the operator's proof explicitly binds to that exact tenant, action kind, and target endpoint set. The hub cannot ask the authority to sign an arbitrary pre-computed digest.
  - **Residual risk:** every disruptive action is grant-verified on the endpoint (2.3, 2.4). Hub code execution can still withhold commands, delay delivery, auto-isolate within the narrow key's rate limits, and send threat-intel data; the residuals listed in 2.4 apply.

#### Threat 4: Root / Hypervisor Host Compromise
- **Threat:** An adversary gains `root` on the LXC container (LXC 150) or physical hypervisor.
- **Mitigation & Boundary Statement:**
  - Software cannot defend itself against a compromised kernel or hypervisor under which it executes. If root inside the container is compromised, the authority daemon's memory and keys can be inspected.
  - **Defensive Posture:** The threat model explicitly distinguishes between *hub-process compromise* (which Ominull's architecture contains for grant-verified actions, with the residual risk listed under Threat 3) and *hypervisor/root host compromise* (which requires hypervisor-level isolation, hardware HSMs, or remote signer nodes).
  - To mitigate host risk in high-assurance environments, Ominull supports deploying `ominull-response-authority` on a physically separate signer host or air-gapped hardware appliance.

#### Threat 5: Response Signer Key Compromise & Key Rotation
- **Threat:** A tenant's response signing key is compromised or needs planned retirement.
- **Mitigation:**
  - Each grant specifies `signer_key_id` (the SHA-256 fingerprint of the authorized Ed25519 public key).
  - Endpoints cache active tenant trust bundles. A signed trust-rotation manifest signed by the tenant's root revocation key updates the active key set and immediately blacklists retired key IDs.
  - Expired grants (enforced with max 1-hour validity) ensure past captured grants cannot be reused.

#### Threat 6: Malicious Operator / Insider Threat
- **Threat:** An authorized analyst attempts to execute unapproved commands on unassigned endpoints.
- **Mitigation:**
  - **Strict Target Binding:** The browser proof signed by the operator binds to an explicit list of `target_endpoints`. The authority refuses to issue grants for endpoints not listed in the proof.
  - **Multi-Party / 4-Eyes Policy (Optional):** The architecture supports requiring two distinct operator signatures for high-risk actions (e.g. whole-drive collection or remote shell).
  - **Append-Only Immutable Audit Log:** Every grant issuance, verification, and terminal frame is logged with operator identity, timestamps, and cryptographic proofs to an append-only audit table.

#### Threat 7: Tenant Crossover & Replay Attacks
- **Threat:** An attacker captures a grant intended for Tenant A or Endpoint 1 and replays it against Tenant B or Endpoint 2.
- **Mitigation:**
  - **Domain Separation:** Length-prefixed canonical encoding (`OMINULL-ENDPOINT-GRANT-V2`) embeds `tenant_id`, `endpoint_id`, and `version` into the signed preimage.
  - **Replay Nonce Cache:** Every grant carries a 128-bit cryptographic nonce. Endpoints maintain a local SQLite replay cache of seen grant IDs and nonces. Replayed grants are rejected immediately.
  - **Clock Skew Limits:** Grants enforce `issued_at` and `expires_at` with strict clock skew tolerances (±60 seconds).

#### Threat 8: Compromised Fleet Endpoint
- **Threat:** An endpoint running `ominulld` is completely seized by an attacker.
- **Mitigation:**
  - Endpoints are strictly consumers of grants, never authorities. A compromised endpoint cannot mint grants, validate other endpoints, or pivot hub privileges.
  - Inbound telemetry from the compromised endpoint is quarantined; the hub isolates network communications via peer quarantine lists pushed to the rest of the fleet.

#### Threat 9: Authenticator Recovery & Enrollment Hijacking
- **Threat:** An attacker attempts to enroll an unauthorized WebAuthn passkey or reset TOTP secrets.
- **Mitigation:**
  - Initial enrollment requires the installation master secret or out-of-band administrative invitation.
  - Modifying enrolled authenticators requires an existing valid response session or recovery token.
  - Rate limiting (maximum 5 failed attempts per minute) with exponential lockout prevents brute-force verification.

#### Threat 10: Supply Chain & Update Tampering
- **Threat:** An attacker attempts to push a malicious update package to endpoints.
- **Mitigation:**
  - Agent self-updates verify the authentic release key hardcoded in `agent/include/release_key.h`, both over the package and over a release statement (`OMINULL-RELEASE-V1`, package name, version, SHA-256) shipped as `<package>.release.sig`.
  - **Artifact name pinned:** the statement must name the agent's own artifact (`ominull-agent_<version>_amd64.deb` on Linux, `ominull-agent-windows-<version>.msi` on Windows), so a signed hub package or another platform's package is never installed as an agent update.
  - **No downgrades:** the agent installs only a strictly newer version than it runs, and only with an owner-approved `agent_update` grant naming that version, so an older, genuinely signed package cannot be replayed onto the fleet.
  - **Signing custody:** `scripts/sign-release.sh` has swappable backends: `file` (including an AES-256 encrypted PEM on removable media, written by `scripts/release-key-offline.sh`) and `command` (a token or HSM that never exports the key). Manifests are signed by the separate policy key, never the release key; the release key also signs each tenant's trust bundle (`scripts/sign-trust-bundle.sh`, same backends). `release-key-offline.sh export` refuses a destination on the key's or the root filesystem (device ids).
  - Package builds require byte-for-byte reproducibility against published SHA-256 release manifests.

---

## 4. The Trusted-Origin Decision & Specification

### 4.1 Browser API Requirements
The response console relies fundamentally on modern web security primitives:
1. **WebCrypto API (`crypto.subtle`):** Used to generate ephemeral, non-exportable ECDSA/Ed25519 keypairs in browser memory for signing `ActionProof` payloads.
2. **WebAuthn API (`navigator.credentials`):** Used for hardware FIDO2 keys and platform passkeys (Touch ID, Windows Hello).

According to W3C specifications, browsers **disable WebCrypto and WebAuthn on non-secure origins**. Browsing to `http://<ip-address>:port` completely disables these APIs, making remote response cryptographically impossible.

### 4.2 Binding Decisions

1. **No External Reverse Proxy Requirement in Default Install:**
   - Per the Ominull Installability Constraint, Ominull must install from its native packages and work out-of-the-box.
   - Customers must *not* be required to provision Nginx, Caddy, HAProxy, or external identity providers to achieve a functional console.
2. **No Interim Stopgap Proxies:**
   - No temporary or development reverse proxies on analyst workstations will be used as a production dependency.
3. **Dedicated In-Hub Console TLS Listener:**
   - The Ominull hub provides a dedicated HTTPS console listener separate from the `:9443` agent mTLS listener.

### 4.3 Supported Certificate Provisioning Modes

The installer prompts for the console fully-qualified domain name (FQDN) and configures one of three certificate modes:

| Mode | Target Deployment | Mechanism | Operator Setup |
|---|---|---|---|
| **Mode A: Custom / Corporate** | Enterprise environments | Operator provides PEM certificate and private key | Provide path to `.crt` and `.key` files |
| **Mode B: Automated ACME** | Internet-facing domains | Built-in ACME client utilizing DNS-01 challenges | Provide Cloudflare/Route53/DNS API credentials |
| **Mode C: Self-Issued Root** | Air-gapped / LAN-only | Hub generates dedicated internal Console CA | One-click export script to install root in browser/OS trust store |

### 4.4 WebAuthn Relying Party ID (RP ID) Invariant
- Under W3C WebAuthn Level 2 (§5.4.3), an `rpId` must be a valid domain name matching the origin's effective domain or a registrable domain suffix.
- **IP addresses are invalid RP IDs.** An operator navigating to `https://192.0.2.58` cannot register or authenticate a WebAuthn passkey.
- **Hostname Immutability Rule:** The installer explicitly warns the operator that changing the console FQDN at a later date invalidates all previously enrolled WebAuthn passkeys and requires re-enrollment.

---

## 5. Platform Capabilities & Operating System Support Floor

### 5.1 Linux Agent Support Floor
- **Architectures:** `amd64` (x86_64).
- **C Runtime:** GNU `glibc >= 2.17` or `musl >= 1.2`.
- **System Requirements:**
  - Standard socket collection / procfs `/proc`.
  - Standard pseudo-terminal support (`openpty` / `forkpty` in `libutil` or C runtime).
  - `iptables` / `nftables` for autonomous peer quarantine.
  - `libcurl` with TLS 1.2/1.3 for telemetry and download streams.

### 5.2 Windows Agent Support Floor & ConPTY Baseline
- **Architectures:** `x86_64`.
- **Operating System Floor:**
  - Interactive pseudoterminals on Windows require the **Windows Pseudo Console (ConPTY)** subsystem (`CreatePseudoConsole`, `ResizePseudoConsole`, `ClosePseudoConsole`).
  - ConPTY was introduced in **Windows 10 Version 1809 (Build 17763)** and **Windows Server 2019**.
  - Windows headers require `NTDDI_VERSION >= 0x0A000006` (`NTDDI_WIN10_RS5`) and `_WIN32_WINNT >= 0x0A00`.
- **Support Matrix:**
  - **Full Capability (Telemetry, Forensic Collection, Interactive Shell):**
    - Windows 10 (Version 1809 and later)
    - Windows 11 (all versions)
    - Windows Server 2019
    - Windows Server 2022 / 2025
  - **Legacy Limited Capability (Telemetry & Forensic Snapshots Only; Shell Disabled):**
    - Windows Server 2016 / 2012 R2
    - Windows 10 (pre-1809 builds)
- **Containment:**
  - All Windows child processes launched for response actions are assigned to a restrictive Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, memory limits, process count restrictions).

---

## 6. Verification & Acceptance Criteria

To satisfy Phase 0.3 acceptance:
1. **Threat Model Completeness:** Names all 10 threat scenarios and distinguishes between hub-process resistance and hypervisor/root boundaries.
2. **Trusted-Origin Standard:** Enforces three distinct trust fabrics, establishes the in-hub TLS listener architecture, and documents WebAuthn RP ID constraints.
3. **Platform Baselines:** Formally pins Linux runtime requirements and the Windows 10 Version 1809 (`0x0A000006`) ConPTY OS floor.
