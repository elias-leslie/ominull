# Ominull Response Threat Model, Trusted-Origin Specification, and Platform Floor

**Document ID:** SEC-OMINULL-P0-3  
**Status:** Accepted Architecture Standard (Slice 0.3)  
**Date:** 2026-09-03  
**Classification:** Technical Security Architecture  

---

## 1. Executive Summary

This document establishes the formal threat model, cryptographic trust boundaries, browser origin policy, and operating system support baselines for the Ominull Remote Response and Forensics Subsystem.

As Ominull expands from network telemetry and autonomous ring-0 containment into interactive forensic collection, script execution, and pseudoterminals, endpoint mutation privileges transition from automated reactive isolation to operator-driven administrative commands (signed by the hub, with no approval step in front of the owner). Because an endpoint response agent runs with local system supervisor privileges (`root` on Linux, `LocalSystem` on Windows), an authorization failure or compromised hub must never allow an attacker to pivot into arbitrary fleet code execution.

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
|    Dedicated HTTPS Port            | Protects the console login and session.|
+------------------------------------+----------------------------------------+
| 3. RESPONSE KEYS (Ed25519)         | Per-tenant keys held by the hub.       |
|    /var/lib/ominull/grants         | Sign endpoint grants. Agents verify    |
|                                    | them against keys pinned from a bundle.|
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
  - Keeps the console login and its session cookie private; browsers mark the cookie secure only on a secure origin.
  - Console TLS provides privacy and integrity between browser and hub. It is not an endpoint authorization boundary: endpoints trust only signed grants.

### 2.3 Fabric 3: Tenant Response Keys (Ed25519)
- **Scope:** Cryptographic authorization of typed endpoint grants.
- **Mechanism:** Each tenant has an independent Ed25519 response key. The hub holds the keys and signs grants in its own process (`hub/pkg/grants`), from files under `/var/lib/ominull/grants/keys/` (owner `ominull`, directory `0700`, set by `OMINULL_GRANT_STATE_DIR`).
- **Invariants:**
  - Admin API keys, database records and cross-tenant operators never see the raw signing key, but the hub process does. The keys are backed up with the rest of the hub secrets.
  - The hub holds three Ed25519 keys per tenant: the **response key** (ordinary grants), a narrow **auto-isolate key** (the detector's automatic isolation only) and a **policy key** (capability manifests only). The slot keys are never reachable as a tenant (tenant ids with `#`, `/` or `\` are refused).
  - Agents pin all three in their key directory (`/etc/ominull` root-owned and not group/world-writable; `C:\ProgramData\Ominull` with a protected SYSTEM/Administrators DACL, no reparse points) only from a **trust bundle signed by the release key**: the statement `OMINULL-TRUST-BUNDLE-V1\ntenant=..\nepoch=..\nresponse_key=..\nauto_isolate_key=..\npolicy_key=..\n` (lowercase hex), ECDSA P-256 / SHA-256, verified against the release key compiled into the agent (openssl CLI on Linux, CNG on Windows). The owner signs it with `scripts/sign-trust-bundle.sh`, which reads the hub's statement (`GET /api/v1/trust/statement`), signs it and posts it (`POST /api/v1/trust/bundle`; the hub keeps only a signature that verifies over its current keys). The hub cannot make that signature, so it cannot get an agent to pin keys of its own; nothing is pinned from enrollment or on first use. The bundle is pinned whole (one atomic `trust.pin`: tenant, epoch, three keys), only for the agent's own tenant (`default`), and only at an epoch no lower than the highest ever pinned on that host. The epoch starts at 1, rises by one whenever a tenant's keys change, and root on the hub can raise its floor (`OMINULL_GRANT_TRUST_EPOCH_FLOOR`); the hub only accepts a bundle signed at its current epoch. Agents enforce it (`trust.epoch`, kept across `--repin-trust`) or than the build's floor (`TRUST_MIN_EPOCH`, raised in the release after a key rotation, so even a fresh install refuses a bundle for retired keys). Manifests and grants for another tenant are refused. A pinned key is never replaced; a mismatch is reported (`GET /api/v1/fleet/trust`, which also shows whether each tenant's bundle is signed) and re-pinning is an explicit local `--repin-trust`, after which the agent again pins only a signed bundle, and only from an epoch strictly above the revoked one (the re-pin raises `trust.epoch` before it removes the pin; the hub moves its epoch whenever the keys change). Grant verification uses the keys held in memory from that pin, never a separate key file. A pin is only reported as removed when its files are actually gone.
  - Endpoints verify a grant against the pinned keys before every disruptive action: terminal sessions, forensic collection, scripts, isolation and release, mesh quarantine, and agent update. Isolation, release and mesh grants carry the routed payload (`{"baselines","body","route","targets"}`, canonical JSON, lower-case keys, no other members) and a strictly increasing `issued_at` (the hub keeps one clock per tenant, fsynced before a time is used, never more than 5 minutes ahead of real time; a corrupt clock stops signing, and the detector cannot sign for a tenant that has no response key); agents keep a per-slot watermark that only a genuine grant advances (and only up to 60 s ahead of the agent's clock), so an older grant cannot be replayed to undo a newer decision.
  - **An isolation's exceptions are part of what is signed.** The hub resolves each target's baseline (DNS, DHCP, NTP, custom rules) into `baselines: [{endpoints, rules:[{destination,port,protocol,service}]}]` inside the signed payload; the signer checks that every entry names only targets, at most once, with rules an agent accepts, and shows them in the summary. While isolated, an agent permits only those rules (kept in its enforcement state), never the heartbeat's baseline, so a hub cannot widen a contained host's holes. The detector's auto-isolation grant carries the host's own exceptions the same way.

### 2.4 Authorizing disruptive actions (no owner approval)
- **Rule (2026-10-24):** approval taps are only for GitHub admin. OmniNull never puts an approval in front of the owner: no passkey tap, no phone prompt, no pending-approval rows. The older design (hub answers `202` with an approval id, the owner's phone passkey signs, a separate service verifies the assertion against pinned approvers) is gone, along with the `-approvers` flag and the approval relay routes. Old audit rows named OWNER_APPROVAL_* appear only in history.
- **Scope:** Isolate and release (single and bulk), agent update and staged rollouts, mesh quarantine and release, terminal sessions, screen sessions, one-off scripts, `script_exec` package runs and playbooks, capability changes. Routine reads and policy routes stay on scoped credentials and apply at once with an audit row (detection policy also runs the floor drill); the detector's automatic isolation stays in-process.
- **Flow:** The caller (the static admin key, a console session, or a JWT minted from the admin key) sends the request once. The hub works out what it would do (route, canonical body, resolved targets; the terminal's or screen's typed payload) and its signer (`hub/pkg/grants`) validates the payload, puts the action in plain words for the audit and signs one grant per target with the tenant response key (ed25519). Then the handler runs. `X-Approval-ID` is set by the hub from the authorization id; a caller cannot supply it. Handlers act only on the endpoints named in the grants, so a fleet change between authorization and use cannot widen a bulk action or an update.
- **What the signer refuses** (the caller gets an HTTP error and the hub audits `ACTION_REFUSED`; the console and alerts show it): an invalid or oversized payload, more than 50 targets, a route that does not match its kind, an agent label that is not a valid label or that comes from anything but the admin key. These are checks against mistakes, not a boundary: they run in the hub. The hub refuses quarantining its own address, and endpoints refuse what their lock, monitor-only mode or manifest forbids, even with a valid grant. Descriptions over 300 characters are cut with an ellipsis.
- **Where safety sits now:** every action is still verified on the endpoint. Agents accept only grants signed with the tenant response key, check kind, digest, target, tenant, expiry and replay themselves, and apply their capability manifest, local ceiling and host lock on top. The audit records who asked (the admin key's self-declared agent label is shown as a claim, not an identity), what was signed and for whom. There is no second human check. An admin-key holder, or anyone who can use a console session, can cause any of the actions above within those limits.
- **Hub compromise, restated:** a hub that is fully compromised holds the keys, so it can sign grants for any action (isolate or release a host, quarantine a peer, install a release signed with the release key, open a terminal or screen session, run a script on any number of targets) and can sign new capability manifests. Agents still enforce what the hub does not control: it cannot make an agent accept an unsigned package, pin a key it chose, or run anything the agent's local ceiling or host lock forbids. Audit rows are the hub's own, so a compromised hub can leave them out. The detector's automatic isolation uses the auto-isolate key: isolate only (never release, never mesh), 10-minute grants, at most 6 per hour per tenant and one per endpoint per 10 minutes, each audited; this brake stops a detector mistake from cutting off the fleet.
- **Residuals, stated plainly:** (1) until the owner signs a tenant's trust bundle its agents pin nothing and refuse every signed action (fail closed; the fleet trust view shows `trust_bundle: unsigned`); the release key that signs bundles is the same key that signs packages, so its custody (operations: release key custody) bounds both; (2) an agent upgrading from a pre-grant release bootstraps its isolation/quarantine state once from the hub's last word, with the 5-minute dead-man (a bootstrapped isolation is not a signed isolation) and watermarks set from the agent's own clock, never from hub-sent marks; (3) threat-intel indicators are still hub-sent data, not grants: agents apply them only to globally routable addresses (never private, loopback, link-local, CGNAT, multicast, documentation ranges or a local resolver from `/etc/resolv.conf`; the hub's own addresses are permitted ahead of any drop), so a hub can at worst block public destinations; Windows agents do not apply them; (4) an isolation's dead-man is 12 hours for an isolation whose grant carries the source `owner` (any isolation asked for by a person or agent; 5 minutes otherwise), after which an unreachable hub releases the host locally; (5) local root on an endpoint can always release it (`--cleanup` / `--release-local`); (6) with no owner tap, the admin key is the credential that matters most: whoever holds it can ask for any of the actions above.
- **Delivery follows the action:** an authorized action's grants are stored as pending before its handler runs (no handler runs if they cannot be stored; the audit says `ACTION_UNDELIVERABLE`) and become deliverable only after it succeeded; a failed action's grants are withdrawn without ever reaching an agent. If the action ran but the grants could not be released, the audit says `ACTION_UNDELIVERED`. If the hub stops between the handler and that step, a reconciler (at start and every minute, for grants pending over 2 minutes) compares the hub's state with each grant (isolation on or off with exactly the grant's allow list and the exceptions the hub would grant now, mesh quarantine, the update job's version) and releases or withdraws it; an expired grant is never released (audited: the action must be repeated). At start this runs before any listener opens, for every pending grant. Addresses (allow list, mesh target) are normalized before they are signed, so the hub and the agent see one spelling.
- **Without the keys** the hub does not start: an unreadable key or manifest file, or a missing key once a trust bundle is signed, stops it rather than minting keys agents would refuse. Only a hub with no signed bundle creates keys.
- **Capability manifest:** each endpoint holds a manifest signed by the policy key (`OMINULL-CAPABILITY-MANIFEST-V1`, increasing `seq`) naming a profile: `monitor` (update only), `monitor-scripts` (collect, script, update: a monitor-only hypervisor under the `monitor-signed-scripts` lock level; it adds no isolation, so it stands while the hub keeps the host monitor-only), `respond` (collect, isolate, mesh, screen, terminal, update) or `engagement` (respond plus scripts). Profiles are not a line: narrowing means a strict subset of capabilities, so `respond` to `monitor-scripts` is a raise. The agent refuses any new restriction or response offer the manifest does not allow, even with a valid grant; releases are always accepted, so narrowing never strands an isolated host. The first manifest is at most `respond` (`monitor` for a monitor-only host); narrowing is signed on the hub's request, widening only through a signed `capability_change` (`POST /api/v1/endpoints/capabilities`, authorized on the first request like the other actions) or by lifting monitor-only. A manifest is refused unless its `seq` is above the highest taken under the same policy key (`manifest.floor`, one line per recent policy key (up to 8), kept across `--repin-trust`; written after the manifest itself, and raised from the stored manifest at start), so an older, wider manifest cannot come back after a re-pin, an epoch change or a policy key that returns. Only a grant naming this endpoint (and readable as an action for it) moves its isolation watermark. When the policy key changes, the hub re-signs each stored manifest at the next `seq`. Root on the endpoint can set a **local ceiling** (`ominulld --capability-ceiling monitor|isolate|signed-scripts|monitor-signed-scripts|respond|engagement|none`; levels in docs/HOST_AUTHORITY.md; `capability.ceiling` in the key directory; an unreadable ceiling counts as `monitor`); the agent applies the narrower of manifest and ceiling and reports it in the fleet trust view. Residual: a host without a ceiling accepts the hub's first manifest up to `respond` (the owner's choice for home machines, which keep the terminal); set `monitor` on hosts that must never be acted on.
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
  - **No step-up:** a console login can ask for every action in 2.4, so a stolen session cookie is as strong as the admin key until it expires. The cookie is HttpOnly.

#### Threat 2: Static Hub API Key Compromise
- **Threat:** An automated admin API key (e.g. `admin.key`) or service token is leaked from CI/CD or disk.
- **Mitigation:**
  - A static admin key can ask for every disruptive action (section 2.4). Ingestion and diagnostics keys are narrower.
  - An admin-key holder (or a console session, or a JWT minted from the admin key) can therefore cause any action in 2.4; agents verify the grant and the audit records it. Protect the admin key as the credential that matters most; there is no owner tap behind it.

#### Threat 3: Hub Process Compromise (`ominull-hub`)
- **Threat:** An attacker discovers an RCE vulnerability in the Go hub web daemon.
- **Mitigation:**
  - **Privilege separation, what is left:** the hub runs under an unprivileged `ominull` service identity, so hub code execution is not root in the container. It does reach the signing keys in `/var/lib/ominull/grants/keys/`, which that identity owns.
  - **Residual risk, stated plainly:** hub code execution can sign grants for any action on the agents that pin its keys (see "Hub compromise, restated" in 2.4). The owner chose this on 2026-11-06: the separate signer had signed everything automatically since 2026-10-24, shared the hub's container and added no check. What still holds is on the agent: the release key behind trust bundles and packages stays off the hub, and local ceilings and host locks refuse what the hub may not do. Put a ceiling or host lock on machines a hub compromise must not reach.

#### Threat 4: Root / Hypervisor Host Compromise
- **Threat:** An adversary gains `root` on the LXC container (LXC 150) or physical hypervisor.
- **Mitigation & Boundary Statement:**
  - Software cannot defend itself against a compromised kernel or hypervisor under which it executes. If root inside the container is compromised, the hub's memory and keys can be inspected.
  - **Defensive Posture:** local ceilings, host locks and the off-hub release key are what bound this, the same as for Threat 3.

#### Threat 5: Response Signer Key Compromise & Key Rotation
- **Threat:** A tenant's response signing key is compromised or needs planned retirement.
- **Mitigation:**
  - Each grant specifies `signer_key_id` (the SHA-256 fingerprint of the authorized Ed25519 public key).
  - Endpoints cache active tenant trust bundles. A signed trust-rotation manifest signed by the tenant's root revocation key updates the active key set and immediately blacklists retired key IDs.
  - Expired grants (enforced with max 1-hour validity) ensure past captured grants cannot be reused.

#### Threat 6: Malicious Operator / Insider Threat
- **Threat:** An authorized analyst attempts to execute unapproved commands on unassigned endpoints.
- **Mitigation:**
  - **Strict Target Binding:** handlers act only on the endpoints named in the signed grants, and each grant names one endpoint.
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

#### Threat 10: Supply Chain & Update Tampering
- **Threat:** An attacker attempts to push a malicious update package to endpoints.
- **Mitigation:**
  - Windows agent self-updates verify the authentic release key hardcoded in `agent/include/release_key.h`, both over the package and over a release statement (`OMINULL-RELEASE-V1`, package name, version, SHA-256) shipped as `<package>.release.sig`.
  - Linux agents do not self-update. The operator's `scripts/update-linux-agents.sh` checks the release signature, then installs over root access that does not depend on the agent; the target checks the digest of what it downloads.
  - **Artifact name pinned:** the statement must name the agent's own artifact (`ominull-agent-windows-<version>.msi`), so a signed hub package or another platform's package is never installed as an agent update.
  - **No downgrades:** the agent installs only a strictly newer version than it runs, and only with a signed `agent_update` grant naming that version, so an older, genuinely signed package cannot be replayed onto the fleet.
  - **Signing custody:** `scripts/sign-release.sh` has swappable backends: `file` (including an AES-256 encrypted PEM on removable media, written by `scripts/release-key-offline.sh`) and `command` (a token or HSM that never exports the key). Manifests are signed by the separate policy key, never the release key; the release key also signs each tenant's trust bundle (`scripts/sign-trust-bundle.sh`, same backends). `release-key-offline.sh export` refuses a destination on the key's or the root filesystem (device ids).
  - Package builds require byte-for-byte reproducibility against published SHA-256 release manifests.

---

## 4. The Trusted-Origin Decision & Specification

### 4.1 Why a secure origin
The console signs nothing in the browser (WebCrypto and WebAuthn are no longer used). HTTPS protects the login and the session cookie, and browsers keep a Secure cookie off plain HTTP.

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
1. **Threat Model Completeness:** Names its threat scenarios and distinguishes between hub-process resistance and hypervisor/root boundaries.
2. **Trusted-Origin Standard:** Enforces three distinct trust fabrics, establishes the in-hub TLS listener architecture.
3. **Platform Baselines:** Formally pins Linux runtime requirements and the Windows 10 Version 1809 (`0x0A000006`) ConPTY OS floor.
