# Host authority, lock levels and signed jobs

Some machines must not take orders from the hub alone: the workstation and the Proxmox host. On them an
administrator sets a lock level (capability ceiling) at the host, and may pin a **host authority**: Ed25519 keys
held outside OmniNull (Nightshift's). Where a host authority is pinned, scripts run only on grants it signed; the
hub carries those grants and never signs them.

Agents from 1.8.81 implement everything here. Code: `agent/include/agent_trust.h` (ceilings, host files, offer
checks, report), `agent/include/response_canonical.h` (grant bytes), `agent/include/response_dispatcher.h` (grant
parsing, replay cache), `hub/pkg/response/dto.go` (grant bytes), `hub/pkg/server/signed_jobs.go` (courier).

## Lock levels (capability ceiling)

Set at the host, never by the hub: `ominulld --capability-ceiling LEVEL` as root (Linux) or
`ominulld.exe --capability-ceiling LEVEL` as Administrator (Windows), then restart the agent. `none` removes
the ceiling. An unknown level is refused (exit 1) and nothing is written; an unreadable ceiling file reads as
`monitor`. The ceiling caps the hub-signed capability manifest: an action needs both.

| Level | Allows | Use |
|---|---|---|
| `monitor` | agent updates | hosts that must never be cut off |
| `isolate` | isolation, mesh quarantine, evidence collection, updates | the workstation |
| `signed-scripts` | `isolate` plus scripts, and scripts only while a host-authority key is pinned | the workstation with Nightshift-signed upkeep |
| `respond` | everything except scripts | |
| `engagement` | everything | |

Terminal and remote screen are refused by the agent under `monitor`, `isolate` and `signed-scripts`.

Capability names (manifest and ceiling): `update`, `isolate`, `mesh`, `collect`, `script`, `terminal`, `screen`.
Under `signed-scripts` the manifest must still carry `script`, so the endpoint's hub profile must be `engagement`
(one owner tap on the hub); the ceiling then cuts it down.

## Host authority files

Both live in the agent's key directory: `/etc/ominull/` on Linux, `C:\ProgramData\Ominull\` on Windows. They must be
owned by root and not group- or world-writable (Linux), or owned by SYSTEM or Administrators (Windows); a file that
fails the owner check is not used. The agent reads them at start and **never writes them**; `--repin-trust` leaves
them alone. Restart the agent after changing them.

`host_authority.json`, at most 4 keys:

```json
{"v":1,"keys":[{"id":"<signer_key_id>","role":"tap","ed25519":"<64 hex>"},
               {"id":"<signer_key_id>","role":"auto","ed25519":"<64 hex>"}]}
```

- `ed25519` is the raw 32-byte public key in hex. `id` must equal the lowercase hex SHA-256 of those 32 bytes (the
  `signer_key_id` grants carry); a key whose id is not its fingerprint, a duplicate id, or any malformed entry
  makes the whole file unusable.
- `role`: `tap` grants may run any script; `auto` grants only allow-listed packages.
- **Fails closed**: once `host_authority.json` exists, scripts take only host-authority grants. If the file is
  unreadable, fails the owner check or is malformed, no key loads and every script is refused until it is fixed or
  removed. Removing the file returns scripts to the hub's response key (subject to the ceiling).

`host_auto_allow.json`, at most 16 packages:

```json
{"v":1,"packages":[{"name":"zfs-scrub","sha256":"<64 hex>","modes":["audit","enforce"]}]}
```

- `sha256` is the SHA-256 of the package source bytes: the payload's `script_digest`, the same key as
  `hub/pkg/responseauth/released_packages.json`. `modes`: 1 to 4 lowercase names (`a-z`, `_`, `-`, under 16 bytes).
- Missing or unusable: auto grants run nothing (tap grants are unaffected).

## Endpoint grants: canonical bytes

The signature (Ed25519, 64 bytes, hex in `signature`) is over these bytes. Encoding: `string` = uint32 big-endian
byte length, then the bytes; `hex` = the same as a string after ASCII-lowercasing (the hex text itself, not decoded
bytes); `u32`/`i64` = big-endian two's complement.

| # | V2 (`OMINULL-ENDPOINT-GRANT-V2`) | V3 (`OMINULL-ENDPOINT-GRANT-V3`) |
|---|---|---|
| 1 | string domain tag | string domain tag |
| 2 | u32 version (2) | u32 version (3) |
| 3 | string grant_id | string grant_id |
| 4 | string tenant_id | string tenant_id |
| 5 | string endpoint_id | string endpoint_id |
| 6 | string action_kind | string action_kind |
| 7 | hex action_digest | hex action_digest |
| 8 | string operator_id | string operator_id |
| 9 | string response_session_id | string response_session_id |
| 10 | i64 issued_at (unix s) | i64 issued_at (unix s) |
| 11 | i64 expires_at (unix s) | i64 expires_at (unix s) |
| 12 | hex nonce | hex nonce |
| 13 | hex signer_key_id | **string job_id** |
| 14 | | hex signer_key_id |

V3 is V2 with `job_id` (the hub job the grant is for) after the nonce. JSON form: the V2 fields plus `"job_id"`.
A pinned test vector (both encoders check it): grant_id `g-1`, tenant `default`, endpoint `ep-1`, kind
`script_exec`, digest `AB`×32, operator `nightshift:tap`, empty session, issued 1760000000, expires 1760000600,
nonce `00FF`, job `job-1`, signer `cd`×32 gives the bytes in `hub/pkg/server/signed_jobs_test.go`
(`grantV3Golden`).

Agent checks on a response offer (`Trust_OfferRefusal`, then `Trust_OfferGrantRefusal`):

- the offer's kind equals the grant's, and the manifest and ceiling allow it;
- version 2 or 3; a V3 grant must name the offered job (`job_id` equals the offer's `job_id`);
- endpoint, time window (±60 s around issued/expires) and payload digest, then the signature;
- `script_exec` where a host authority is pinned: V3 only, signed by a pinned host key, `operator_id`
  `nightshift:tap` for a tap key or `nightshift:auto` for an auto key, and for auto the allow-list: the payload's
  `script_digest` is listed and `parameters.mode` is one of its modes. For an auto grant, `"script_digest"`,
  `"parameters"` and `"source"` must each occur exactly once in the payload text;
- everything else verifies against the pinned OmniNull response key.

A refused offer gets no ack and no result; the reason is the trust report's `refused`. The OmniNull authority
still signs V2; it can move to V3 once the fleet runs 1.8.81.

### Replay cache

An accepted grant's id and nonce are each refused again while its entry is kept: until `expires_at` + 60 s, the
verifier's whole grace. At most 4096 live entries; when full, or when the cache cannot be read, allocated or
written, the new grant is refused, never an old entry dropped. Files: `/var/lib/ominull/replay_cache.state`,
`C:\ProgramData\Ominull\replay_cache.state`.

## Courier: signed jobs through the hub

For endpoints whose latest trust report (under 15 minutes old) says `"host_authority":true`. Admin API key
(`X-API-Key`). The hub never calls the OmniNull authority on this path and never signs.

1. **Reserve** a job id for the payload:

   `POST /api/v1/endpoints/{id}/jobs/signed/reserve` with `{"payload":{...}}`, a `script_exec` payload object:
   `script_id`, `script_version` (≥ 1), `script_digest` (sha256 of `source`), `interpreter`, `source` (≤ 64 KiB),
   optional `parameters` (string map), `timeout_seconds` (1 to 3600), `max_output_bytes` (0 to 5 MiB); unknown
   fields are refused. Answer:

   ```json
   {"job_id":"<uuid>","payload_json":"<canonical payload>","action_digest":"<sha256 of payload_json>",
    "tenant_id":"default","endpoint_id":"<id>","expires_at":1760000900}
   ```

   `payload_json` is the exact text the agent will digest (Go's encoding: fixed field order, `<`, `>`, `&`
   escaped). Show the owner that text and sign over `action_digest`; never re-encode the payload yourself.
   The reservation is single-use and lapses after 15 minutes.

2. **Sign** a V3 grant: `version` 3, `grant_id` (unique), `tenant_id` and `endpoint_id` from the answer,
   `action_kind` `script_exec`, `action_digest` from the answer, `operator_id` `nightshift:tap` or
   `nightshift:auto` (matching the key's role), `response_session_id` empty, `issued_at`/`expires_at` at most one
   hour apart, a random hex `nonce`, `job_id` from the answer, `signer_key_id` the key's id.

3. **Submit**: `POST /api/v1/endpoints/{id}/jobs/signed` with `{"payload":<the payload_json object>,"grant":{...}}`.
   The hub re-encodes the payload, checks the digest, the grant's shape, binding and time, that the signer is a key
   the endpoint reports with the role the operator claims, and that the reservation is live and matches; then it
   queues the job under `job_id`. Answer `{"job_id":"..","state":"queued"}`. Errors: 400 (payload or grant), 403
   (no host authority on that endpoint), 404 (no such endpoint), 409 (no fresh trust report; reservation unknown,
   used, lapsed or for another payload).

The job then runs like any script job: supervised (docs/RESPONSE_SUPERVISOR.md), `maint wait` works on its id, and
the console's job history shows it as "signed by Nightshift (owner tap)" or "(allow-listed package)". The hub audits
`SIGNED_JOB_QUEUED`.

## Trust report

Each heartbeat's `trust` object adds:

```json
"host_authority":true,
"host_keys":[{"id":"<signer_key_id>","role":"tap"}],
"host_allow":[{"name":"zfs-scrub","sha256":"<64 hex>","modes":["audit"]}],
"host_error":"<why a host file was not used>"
```

`host_keys`, `host_allow` and `host_error` appear only when `host_authority.json` exists. `host_authority` is true
when at least one key loaded. The fleet trust view (`GET /api/v1/fleet/trust`) carries the same fields.
