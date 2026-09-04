# Ominull Remote Terminal Transport, Reverse Proxy Specification, and Protocol Contracts

**Document ID:** SPEC-OMINULL-P3-0D  
**Status:** Accepted Architecture Specification (Slice 3.0d)  
**Date:** 2026-09-03  
**Classification:** Technical Security Architecture & Protocol Contract  

---

## 1. Executive Summary

This document establishes the official operational requirements, failure diagnostics, and reference configurations for deploying the Ominull Remote Terminal subsystem behind reverse proxies, alongside the formal protocol contracts governing session state, token security, canonical signing, and relay framing for Phase 3.

---

## 2. Reverse Proxy Invariants & Specification

Ominull ships with native TLS termination for both its console (`:8443`) and agent transport (`:9443`). Deploying an external reverse proxy (e.g., Caddy, Nginx, HAProxy, AWS ALB, Cloudflare Tunnel) is fully supported for enterprise ingress, but the proxy **must** strictly satisfy four invariant requirements.

### 2.1 The Four Invariant Proxy Requirements

1. **Hop-by-Hop Header Passthrough (`Upgrade` and `Connection`):**
   - The WebSocket handshake relies on HTTP/1.1 connection upgrade semantics (RFC 6455 §4.1).
   - The reverse proxy must forward `Upgrade: websocket` and `Connection: Upgrade` to the hub upstream.
   - Proxies must *not* strip or overwrite these headers.

2. **No Interactive Handshake Redirects:**
   - The terminal WebSocket endpoints (`/api/v1/terminal/ws/operator/*` and `/api/v1/terminal/ws/agent/*`) must never be intercepted with HTTP `302` or `307` redirects to login portals, Captchas, or OIDC identity provider consent screens.
   - Authentication is performed via one-use relay tokens (HttpOnly cookies or signed grant tokens). If unauthenticated, the hub immediately returns HTTP `401 Unauthorized` or `403 Forbidden`. A redirect causes WebSocket client implementations to fail abruptly without surfacing root causes.

3. **Per-Connection Idle Timeout $\ge$ Terminal Idle Timeout:**
   - The Ominull terminal idle timeout is **15 minutes (900 seconds)**.
   - The reverse proxy's connection read/write timeout must be set to at least 900 seconds, OR the proxy/hub must exchange regular ping/pong frames every 30 seconds to maintain state across intermediate NATs and stateful firewalls.

4. **Zero Buffer / Immediate Frame Flushing:**
   - Interactive terminal streams require sub-millisecond character-at-a-time round-trip latency.
   - Proxies must disable upstream response buffering (`proxy_buffering off` in Nginx, `flush_interval -1` in Caddy). Proxies that buffer data until reaching 4 KB or 16 KB chunks render full-screen TUIs (`htop`, `vim`) and interactive shells unusable.

---

### 2.2 Observable Failure Modes & Diagnostics

The following diagnostic matrix specifies the observable symptoms when intermediate proxies violate transport invariants:

| Violated Invariant | Proxy Behavior | Observable Endpoint / Browser Symptom | Hub Diagnostic Log |
|---|---|---|---|
| **Header Stripping** | Strips `Upgrade` / `Connection` headers | Browser receives HTTP `400 Bad Request` or `200 OK` (static response); WS fails with `Error during WebSocket handshake: Unexpected response code` | `[-] terminal: invalid websocket handshake from <ip>: missing Upgrade header` |
| **Auth Redirect** | Returns `302 Found` to login/SSO URL | Browser WS terminates immediately: `Error during WebSocket handshake: Unexpected response code: 302` | None (request never reaches Ominull terminal handler) |
| **Aggressive Timeout** | Kills idle connection at 30s/60s | Terminal disconnects silently during operator think-time with WS close code `1006 (Abnormal Closure)` | `[*] terminal session <id>: connection closed by peer (EOF / broken pipe)` |
| **Response Buffering** | Holds chunks until buffer fills | Keystrokes produce no visual echo; output bursts in jarring blocks; cursor positioning broken | None (packets delayed in upstream proxy kernel buffer) |
| **Argo / Dynamic Reroute** | Edge proxy restarts or reroutes route mid-stream | Sudden connection reset (RST); session drops unexpectedly | `[-] terminal session <id>: connection reset by peer` |

---

### 2.3 Reference Configurations

#### A. Caddy (Tested Reference)
```caddyfile
# Reference Caddyfile for Ominull Console and Terminal Relay
console.example.invalid {
    reverse_proxy 10.0.0.58:8443 {
        transport http {
            # Trust internal hub CA if self-issued
            tls_trusted_ca_certs /etc/caddy/trusted-ca/ominull-ca.crt
            read_timeout 900s
            write_timeout 900s
        }
        # Disable buffering for instantaneous interactive terminal relay
        flush_interval -1
    }
}
```

#### B. Nginx (Tested Reference)
```nginx
# Map for clean WebSocket upgrade handling
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name console.example.invalid;

    ssl_certificate /etc/ssl/certs/console.crt;
    ssl_certificate_key /etc/ssl/private/console.key;

    location / {
        proxy_pass https://10.0.0.58:8443;
        proxy_http_version 1.1;

        # WebSocket header preservation
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Host and remote identity
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Disable buffering for interactive pseudoterminal
        proxy_buffering off;
        proxy_cache off;

        # Match 15-minute terminal idle timeout
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }
}
```

#### C. Cloudflare Tunnel / Access Settings
When fronting Ominull with Cloudflare Tunnel (`cloudflared`):
1. **Network Settings:** Ensure **WebSockets** toggle is explicitly **ON** in Cloudflare Dashboard (Network -> WebSockets).
2. **Argo Smart Routing:** Ensure **Argo Smart Routing is OFF** for the terminal hostname. Argo dynamic rerouting causes unexpected TCP resets mid-session.
3. **Session Duration:** Configure Cloudflare Access application session duration to be greater than or equal to the 8-hour maximum Response Session duration.
4. **Application Heartbeats:** Cloudflare terminates idle WebSockets at 100 seconds. An application-layer ping/pong heartbeat (every 30 seconds) is maintained across the tunnel.

---

## 3. Phase 3 Protocol & Cryptographic Contracts

### 3.1 Canonical Signing Bytes
All cryptographic proofs (`ActionProof`) and grants (`EndpointGrant`) utilize deterministic length-prefixed big-endian binary encoding. Free-form string concatenations (e.g. `fmt.Sprintf("%s:%s", a, b)`) are strictly prohibited to prevent field-splice ambiguity.

```
+-------------------------------------------------------------------------+
|                  CANONICAL LENGTH-PREFIXED ENCODING                     |
+------------------------------------+------------------------------------+
| Field                              | Format                             |
+------------------------------------+------------------------------------+
| Domain Separation Tag              | ASCII String (e.g., "OMINULL...")  |
| Field Length                       | uint32 (Big-Endian, 4 bytes)       |
| Field Payload                      | Raw Byte Array                     |
| Numeric / Timestamp Values         | uint64 (Big-Endian, 8 bytes)       |
+------------------------------------+------------------------------------+
```

- **Endpoint Grant V2 Domain Tag:** `OMINULL-ENDPOINT-GRANT-V2`
- **Action Proof V2 Domain Tag:** `OMINULL-ACTION-PROOF-V2`

---

### 3.2 Action Digest Definition for Terminal Sessions
The exact typed action payload digested for a remote terminal request is computed as:

$$\text{Digest} = \text{SHA-256}(\text{CanonicalActionBytes})$$

Where `CanonicalActionBytes` encodes:
1. `DomainTag`: `"OMINULL-ACTION-DIGEST-V1"`
2. `Version`: `uint32(1)`
3. `TenantID`: String
4. `EndpointID`: String
5. `ActionKind`: `"terminal_session"`
6. `TerminalSessionID`: String (UUIDv4)
7. `Program`: String (Must be member of fixed allowlist: `/bin/sh`, `/bin/bash`, `powershell.exe`, `cmd.exe`)
8. `TTLSeconds`: `uint32` (Requested lifetime, default 3600)
9. `ResponseSessionID`: String

**Contract Rule:** The hub computes this digest directly from its validated typed request and presents it to the Response Authority. The authority independently validates that the caller's proof matches this exact computed digest.

---

### 3.3 Proof & Grant Replay State
- **Action Proof Nonces:** Ephemeral 128-bit random nonces. The hub records seen proof nonces in memory with a 5-minute freshness sliding window. Replayed nonces are rejected with HTTP `409 Conflict`.
- **Grant Nonces & IDs:** Every issued grant carries a unique `grant_id` and 128-bit cryptographic nonce. Endpoints maintain a local SQLite / file-locked replay cache (`replay_cache.state`) persisting seen grant IDs for their full TTL. An endpoint refuses to process any grant whose ID or nonce exists in the replay cache.

---

### 3.4 Relay Token Handling & Zero-Exposure Invariant
Connecting to the terminal relay requires a high-entropy 256-bit one-use connection token (`ConnectToken`).
- **Agent Delivery:** Delivered exclusively inside the signed `EndpointGrant` payload via the authenticated heartbeat.
- **Operator Delivery:** Delivered exclusively as a one-use `HttpOnly`, `SameSite=Strict`, `Secure` cookie (`ominull_terminal_token`) scoped to the response origin.
- **Hub Storage:** Stored at the hub **exclusively as a SHA-256 hash** (`ConnectTokenHash`). The plaintext token is discarded immediately after initial issuance.
- **Zero-Exposure Enforcement:**
  - Plaintext tokens are forbidden in REST API DTOs, session summaries, database rows, CLI outputs, error messages, and logs.
  - Test suites enforce automated regex/grep scanning across all API responses and logs to ensure tokens are never leaked.

---

### 3.5 Session State Machine & Revocation Semantics
Terminal sessions follow a strict single-direction state machine:

```
[closed] (initial)
   │
   ▼
[waiting] ──────(Agent fails to connect within 30s)──────► [failed]
   │
   ├─► [connecting] (Agent or operator attached)
   │        │
   │        ▼
   └─► [active] (Both agent and operator attached)
            │
            ├─► (Operator closes, exit code, or idle/max timeout) ─► [closing] ─► [closed]
            │
            └─► (Daemon restart, SIGKILL, or network drop) ───────► [failed] / [expired]
```

- **Process Termination Invariant:** On transition to any terminal state (`closed`, `failed`, `expired`), the endpoint worker immediately terminates the entire child process tree (`SIGKILL` to process group on Linux; `TerminateJobObject` on Windows).
- **Restart Invariant:** On hub or agent daemon restart, all active sessions transition immediately to `failed` with recorded reason `daemon_restarted`. Dangling pseudoterminals are cleaned up on startup.

---

### 3.6 Resource Limits & Throttling (Contract Caps)
The following resource bounds are hard invariants:
1. **Per-Endpoint Concurrency:** Maximum **1** active terminal session per endpoint.
2. **Per-Tenant Concurrency:** Maximum **4** active terminal sessions per tenant.
3. **Connect Timeout:** **30 seconds** (Session transitions to `failed` if agent does not connect within 30s of issuance).
4. **Idle Timeout:** **15 minutes** (Session closes if no input/output frames are recorded for 15 minutes).
5. **Maximum Duration:** **60 minutes** (Hard ceiling; session terminates unconditionally after 1 hour).
6. **Queue Buffer Cap:** Maximum **1 MiB** of queued relay buffer per direction. If an operator or agent sends data faster than the receiver consumes, the connection is throttled; exceeding 1 MiB aborts the session to prevent memory exhaustion.

---

### 3.7 Frame Schema Ownership
The canonical wire frame schema is owned by `hub/pkg/terminal`:

```json
{
  "type": "stdin | stdout | resize | close",
  "timestamp": "2026-09-03T20:56:00.000000000Z",
  "data": "base64-encoded-payload",
  "rows": 24,
  "cols": 80
}
```

- A frame failing schema validation is rejected immediately, counted as a malformed frame violation, and closes the connection.
- Recording empty frames or swallowing deserialization errors is strictly forbidden.
