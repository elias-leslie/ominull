# Agent transport TLS

Endpoint telemetry and control use the hub HTTPS listener. Enrollment obtains
the hub device CA through the approved bootstrap channel for direct self-issued
deployments. Later requests pin the hub against that CA. Operator-supplied public
certificates and Cloudflare edge endpoints use the host operating-system public certificate
trust instead; their agent route still requires the unique device credential,
and direct native mTLS can add the hub-issued client certificate.

## Hub

`--tls-listen` defaults to `:9443`. Without an operator certificate the hub
serves a leaf signed by its local device CA and includes configured hostnames
and reachable interface names. An operator may supply a public certificate and
key through setup.

`optional` client-certificate mode verifies a certificate when an agent offers
one. `required` rejects endpoints without a verified certificate and should be
enabled only after the retained fleet has converged. `off` disables the extra
proof explicitly; the unique device credential still binds the endpoint.

The plain listener may serve local operator traffic, but new agents refuse
cleartext unless `allow_plaintext` is explicitly set. Both listeners share the
same authorization route table. A listener port never changes endpoint scope.

## Enrollment and identity

Every successful profile redemption creates a unique Ominull device credential
and a client certificate for one endpoint. The credential is sent in
`X-Ominull-Device-Credential`; its hash is stored by the hub and the plaintext
is returned only once in the protected enrollment response. A direct native
client certificate is an additional matching proof, not a replacement for the
credential. Its subject must equal the endpoint named by the credential.

Retained 1.7.x agents may use the shared tenant key only while the explicit
`legacy_agent_auth=migration` setting is open. The updated native binary adopts
the unique credential from a successful heartbeat and rewrites its protected
configuration. Disable that setting after canary and fleet proof.

The initial CA fetch is trust-on-first-use and must use an operator-approved
channel. After enrollment, an agent refuses a missing CA, unknown issuer,
mismatched name, expired certificate, or untrusted peer. There is no silent
cleartext fallback.

## Client certificate renewal

Client certificates are issued for one year. From 1.8.104 the hub renews them
over the agent's own authenticated heartbeat, so an endpoint never has to be
re-enrolled because its certificate aged out:

- Agents that can install a renewed certificate send `"cert_renewal": true` in
  each heartbeat. Older agents never get one, so the hub does not generate keys
  for them on every beat.
- The hub records the certificate each endpoint presents on a verified
  handshake (expiry and serial, `endpoint_certificates`). Within
  `agent_cert_renew_days` of expiry (hub setting, default 60, 7 to 300) it puts
  a new certificate and key in the heartbeat reply (`client_certificate`), at
  most once every `agent_cert_offer_cooldown_minutes` (hub setting, default 60,
  10 to 1440) until the agent presents the new one. The reply carries a private
  key, so it only ever goes out over TLS.
- The agent proves the new certificate against the hub on a fresh connection
  before using it. Linux writes it beside the old files and renames it into
  place; Windows imports it into the machine store and replaces its archive.
  On any failure the agent keeps the certificate it has, which stays valid
  until its own expiry, and the hub offers again after the cooldown. A Linux
  agent stopped between its two renames finishes the swap when it starts.
- `POST /api/v1/endpoints/cert-renewal` with `{"endpoint_id": "..."}` (admin)
  asks for a renewal on the endpoint's next heartbeat whatever its expiry
  (202; 400 without `endpoint_id`, 404 for an unknown endpoint, 409 for a
  retired one). `GET` on the same route lists each endpoint's recorded
  certificate: `not_after`, `days_left`, `serial`, `seen_at`, and
  `renew_requested_at` / `offered_at` when set. A Windows endpoint whose
  certificate has already expired, and which reports with its device
  credential alone, is offered a new one too. A Linux agent always presents its
  certificate, so one whose certificate expired while it was off cannot
  reconnect and needs re-enrolment.
- Renewal is not revocation. Nothing revokes the old certificate, and whoever
  holds a certificate can renew it, so a leaked key is answered by re-enrolling
  the endpoint, not by asking for a renewal.

Nightshift sees this as the `ominull.agents.certificate` finding. It turns
medium when a certificate is within half the renewal window of expiry, or
expired, and still not renewed. Its message never names a machine, since it may
reach a push; the machines are its resources. It counts the certificates not
renewed and the expired ones, and each such machine once by what it needs:
offline for over two days (it renews when back; re-enrol it if it cannot
reconnect, as a Linux agent cannot once its certificate expired), on an agent
too old to renew (never offered one: update the agent), or sent a new one that
did not install (its agent log says why).
Otherwise it is informational and says when the next certificate expires and
how many were sent a renewal. Endpoints the hub has not seen present a
certificate since it began recording are counted as unknown (and listed in
`unknown` and the resources), not as fine; they do not raise
the finding, because a laptop that is off would keep it open.

## Linux and Windows

Linux uses libcurl with the enrolled CA or operating-system trust, and does not
follow redirects. Windows uses WinHTTP without certificate-ignore flags,
attaches the endpoint PKCS#12 certificate when present, and verifies the
response peer before consuming control or update data.

## Verification

Use the enrolled CA and actual listener:

```bash
curl --cacert /etc/ominull/ca.crt https://<hub-host>:9443/api/v1/pki/ca.crt
```

An unrelated CA must fail. A certificate for another endpoint must fail the
identity check. A retired endpoint's late heartbeat returns `410 Gone` and
cannot revive its stored status. Record route, endpoint status, credential
state, and package provenance without printing secret material.
