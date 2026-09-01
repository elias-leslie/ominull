# Agent transport TLS

Endpoint telemetry and control use the hub HTTPS listener. Enrollment obtains
the hub device CA through the approved bootstrap channel for direct self-issued
deployments. Later requests pin the hub against that CA. Public ACME and
Cloudflare edge endpoints use the host operating-system public certificate
trust instead; their agent route still requires the unique device credential,
and direct native mTLS can add the hub-issued client certificate.

## Hub

`--tls-listen` defaults to `:9443`. Without an operator certificate the hub
serves a leaf signed by its local device CA and includes configured hostnames
and reachable interface names. An operator may supply a public ACME or custom
certificate and key through setup.

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
