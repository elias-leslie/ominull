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
  - Endpoints verify grants against pinned tenant response public keys before executing any action.

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

#### Threat 3: Hub Process Compromise (`ominull-hub`)
- **Threat:** An attacker discovers an RCE vulnerability in the Go hub web daemon.
- **Mitigation:**
  - **Privilege Separation:** The hub runs under an unprivileged `ominull` service identity. It cannot read the private response signing keys stored in `/var/lib/ominull-response-authority/keys/` (owned by `ominull-authority:ominull-authority`, mode `0700`).
  - **Socket Enforcement:** Communication with the authority occurs strictly over a local Unix domain socket with credential passing (`SO_PEERCRED`).
  - **Digest Recomputation:** The authority requires typed action payloads, independently recomputes the canonical SHA-256 action digest, and verifies that the operator's proof explicitly binds to that exact tenant, action kind, and target endpoint set. The hub cannot ask the authority to sign an arbitrary pre-computed digest.

#### Threat 4: Root / Hypervisor Host Compromise
- **Threat:** An adversary gains `root` on the LXC container (LXC 150) or physical hypervisor.
- **Mitigation & Boundary Statement:**
  - Software cannot defend itself against a compromised kernel or hypervisor under which it executes. If root inside the container is compromised, the authority daemon's memory and keys can be inspected.
  - **Defensive Posture:** The threat model explicitly distinguishes between *hub-process compromise* (which Ominull's architecture completely neutralizes) and *hypervisor/root host compromise* (which requires hypervisor-level isolation, hardware HSMs, or remote signer nodes).
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
  - Agent self-updates verify the authentic release key hardcoded in `agent/include/release_key.h`.
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
- **IP addresses are invalid RP IDs.** An operator navigating to `https://10.0.0.58` cannot register or authenticate a WebAuthn passkey.
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
  - Windows headers require `NTDDI_VERSION >= 0x0A000006` (`NTDDI_WIN10_RS5`) and `_WIN32_WINNT >= 0x0600`.
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
