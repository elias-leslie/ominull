# Agent transport TLS

Endpoint telemetry and control responses use the hub's HTTPS listener. The hub
issues its listener certificate from its local CA and serves that CA at
`/api/v1/pki/ca.crt`. Enrollment stores the CA beside the endpoint
configuration; subsequent requests verify the hub against that CA.

## Hub

`--tls-listen` defaults to `:9443`. The hub's certificate includes its reachable
interface addresses, hostname, public URL host, and `--tls-hosts` values. The
plain listener may remain available for the operator console and reverse-proxy
origin. Both listeners use the same authenticated route table; the listener
does not change authorization.

Set `--client-certs required` after all endpoints present their certificates.
In `optional` mode a valid client certificate is checked when supplied and the
tenant API key remains the fallback enrollment credential. `off` is for an
explicitly controlled migration only.

## Enrollment

Bootstrap obtains the CA over the operator-approved enrollment channel, checks
that it parses as a certificate, then obtains a one-use endpoint certificate.
The generated package configuration contains the TLS URL, API key, endpoint
identity, CA path, and client certificate path. Credentials are not placed in a
service command line.

The initial CA fetch is trust-on-first-use and must run over an already trusted
channel. After enrollment, an agent refuses to send telemetry when the URL is
not HTTPS, the CA is missing, or the peer cannot be verified. There is no silent
cleartext fallback.

## Linux and Windows checks

The Linux transport uses libcurl with the enrolled CA and HTTPS-only redirects.
The same libcurl handle is reused across heartbeat requests, so TLS sessions and
connections are not recreated every sample.

The Windows transport uses WinHTTP without certificate-ignore flags. It performs
a public CA preflight before sending the API key, attaches the client
certificate when available, and verifies the response peer before accepting
control or update data.

## Verification

Use the enrolled CA and the actual TLS listener:

```bash
curl --cacert /etc/ominull/ca.crt https://<hub-host>:9443/api/v1/pki/ca.crt
```

An unrelated CA must fail. A client certificate for another endpoint must fail
endpoint identity checks. A late heartbeat from a retired endpoint returns
`410 Gone` and cannot revive its stored status.

The TLS tests cover certificate issuance, CA validation, SAN coverage, client
certificate identity, and failure-closed transport behavior. Production checks
must also record the hub route, endpoint status, and package provenance without
printing credentials.
