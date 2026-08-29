# Agent transport: TLS on the hub's own PKI

Until v1.4.0 every agent talked to the hub over plain HTTP on the LAN. The
telemetry batch, the `X-API-Key` header that authenticated it, the isolation
commands read back from the response and the `agent_update` descriptor all
crossed the wire in the clear, readable and modifiable by anyone on the path.

The release signature shipped in v1.3.0 is what made that survivable: a package
cannot be forged even on a hostile path, which is why the signature and not the
digest is the control that matters. But the signature protects the package and
nothing else. It never protected the key, the telemetry, or the ability to
isolate a host.

This is that gap closed. It reuses the CA the hub already had (`hub/pkg/pki`,
served at `/api/v1/pki/ca.crt`) rather than introducing a second mechanism.

## What the hub does

The hub signs its own leaf certificate with that CA and serves HTTPS on
`--tls-listen` (`:9443` by default), alongside the existing plain listener on
`--listen`.

Two listeners rather than one because they answer different callers. The plain
one is the origin a reverse proxy terminates against and the address an operator
CLI uses; the TLS one is what the fleet talks to. Both serve the same mux — which
port a request arrives on decides whether it was encrypted, never what it is
allowed to do, because a per-listener policy would be a second surface to keep in
step with the first. An operator who has moved every endpoint across can pass
`--listen ""` and be TLS-only.

The certificate's SANs are what make it usable on a LAN: agents dial the hub by
IP, and a certificate without that IP is rejected by curl, WinHTTP and Go alike,
with an error that reads like a CA problem. So the hub enumerates its own
interface addresses, adds `localhost`, its hostname, the host from `--hub-url`
and anything in `--tls-hosts`, and issues for all of them. The leaf is kept on
disk beside the CA and reused across restarts; it is reissued only when it stops
covering an address the hub is reachable on, or comes within 30 days of expiry.
The SAN set is computed at startup, so a hub whose address changes needs a
restart to reissue — a deliberate trade against enumerating interfaces on every
handshake.

`--tls-cert` / `--tls-key` override all of this with an operator-supplied pair,
for a hub published under a real domain with a publicly-trusted certificate.

## What enrolment does

`--agent-hub-url` is separate from `--hub-url` on purpose. The hub is published
to operators and installers at one address, typically through a reverse proxy,
and reached by agents at another — the TLS listener whose certificate they pin.
Bootstrap writes the second into the agent's configuration:

```
--hub-url        https://omi.example.com     # installers, console, operators
--agent-hub-url  https://10.0.0.58:9443      # the fleet
```

Every bootstrap script now fetches the CA, proves it parses as a certificate
before trusting it — an error page saved to `ca.crt` would otherwise become an
anchor — installs it in the system trust store, and leaves a copy the agent pins
explicitly:

| Platform | Pinned CA path | Passed as |
|---|---|---|
| Linux | `/etc/ominull/ca.crt` | `--ca` in `/etc/ominull/agent.conf` |
| macOS | `/opt/ominull/ca.crt` | sixth LaunchDaemon argument |
| Windows | `C:\Program Files\Ominull\ca.crt` | `--ca` in the service binPath |

Linux keeps it under `/etc` rather than the install prefix because an upgrade
replaces `/opt/ominull` and the trust anchor has to survive that. The `.deb`
never overwrites `agent.conf`, so a self-updating endpoint keeps the CA path it
was enrolled with.

The one moment not covered is the fetch itself: an installer with no CA yet
cannot verify the hub it is asking for one. `--hub-url` should therefore be a
channel that is already trusted — a public URL with a publicly-trusted
certificate, or a LAN address on a network the operator controls at the time of
enrolment. That is trust-on-first-use, and it is the only such moment. Every
connection afterwards is pinned.

## What the agents do

All three refuse rather than degrade. An agent that cannot verify the hub keeps
enforcing locally and repeats the reason at most once a minute; it never retries
in the clear, because a silent downgrade to HTTP is precisely what an on-path
attacker would be trying to provoke. Two conditions refuse:

- the configured hub URL is not `https://`, unless a cleartext transport was
  asked for deliberately (`--allow-plaintext`, or `OMINULL_ALLOW_PLAINTEXT=1` on
  macOS);
- the pinned CA is missing, unreadable, or not a certificate.

**Linux** passes `--cacert` to curl, which trusts that CA and no other, and
`--proto =https --proto-redir =https`, without which a redirect to `http://`
would carry the API key to the next hop in the clear. curl fails the handshake
before sending anything, so no secret ever reaches an unverified peer.

**macOS** passes the same flags, and on this platform they are not a pin. Apple's
curl is built MultiSSL (`curl 8.7.1 ... (SecureTransport) LibreSSL/3.3.6`) and
defaults to Secure Transport, which accepts `--cacert` and then ignores it —
trust comes from the system keychain instead. This is not theoretical: on a live
endpoint, `curl --cacert <an-unrelated-CA> https://<hub>:9443/...` returns 200,
and so does the same command against `https://www.apple.com/`. Setting
`CURL_SSL_BACKEND=openssl` does not change it. An agent that believed `--cacert`
was pinning it would have been exactly the silent downgrade this change exists to
prevent.

So macOS proves the pin separately, before anything carrying the API key is sent.
`openssl` *does* enforce `-CAfile`, so `hub_pin_ok` fetches the hub's certificate
with `openssl s_client` and checks it against the enrolled CA with `openssl
verify`, caching a success for 15 minutes. `openssl verify` checks the chain, not
the name; the name is what Secure Transport checks on the request itself, so
between them both halves are covered.

Both agents also stopped discarding curl's stderr: a rejected certificate is the
one failure they must not swallow, and it used to look identical to the hub being
down.

**Windows** is the awkward one. WinHTTP had four overrides — `IGNORE_UNKNOWN_CA`,
`IGNORE_CERT_WRONG_USAGE`, `IGNORE_CERT_CN_INVALID`, `IGNORE_CERT_DATE_INVALID` —
set on every HTTPS request. They existed because there was no trusted anchor to
check against. They are gone, so an unknown issuer, a mismatched name or an
expired certificate now fails the handshake.

That alone is not the pin: Windows would accept a certificate from any anchor in
the machine store. `agent/src/hub_tls.c` adds the pin by building the chain for
the certificate the hub presented and comparing its root, byte for byte, with
the CA on disk. Comparing the encoded certificate rather than a name or a serial
is deliberate — those are chosen by whoever issued the certificate, and an
impostor picks its own.

The pin runs as a **preflight**, and this is the subtle part. WinHTTP hands out
the negotiated certificate only after the request has been sent, so a check made
on the telemetry request would detect an impostor only once the API key had
already been given to it. Instead the agent first fetches
`/api/v1/pki/ca.crt` — a public endpoint carrying no secret — pins that answer,
and only then makes the real request. A successful preflight is cached for 15
minutes so the telemetry loop is not re-handshaking every few seconds. Every
response is *also* pinned before its body is read, so a hub that changes identity
mid-session cannot steer an endpoint with an isolation command or an update
descriptor.

`Service_Install` had to change with it. The SCM command line is the only place
the service's configuration exists — `ServiceMain` receives SCM's argv, not
`main`'s — and it used to carry only the hub URL and the key, silently dropping
the role and location an operator enrolled with. The CA path would have gone the
same way, leaving a service that could not verify the hub it was installed to
talk to. It now writes the full configuration, with the CA path quoted because
`Program Files` contains a space.

## Verifying it

```bash
# The hub serves a leaf its own CA signed, on the address agents dial.
curl --cacert /etc/ominull/ca.crt https://<hub-ip>:9443/api/v1/pki/ca.crt

# The wrong anchor is refused rather than warned about. On Linux. Run this on a
# Mac and it returns 200, which is the whole reason hub_pin_ok exists - use the
# openssl form there instead.
curl --cacert /path/to/some-other-ca.crt https://<hub-ip>:9443/api/v1/pki/ca.crt

# The check that holds on every platform, including macOS.
openssl s_client -connect <hub-ip>:9443 -showcerts </dev/null 2>/dev/null |
    openssl x509 |
    openssl verify -CAfile /path/to/ca.crt /dev/stdin
```

`TestHubTLSListenerPinsToItsOwnCA` covers the same three cases in Go: the hub's
own CA verifies it, a different CA does not, and trusting nothing does not
either. `TestServerCertificateReuseAndReissue` covers the leaf surviving a
restart and being replaced when it stops covering the hub's address.

## Where the key lives at rest

TLS took the API key off the wire. It was still sitting in the clear at each
endpoint, and on Windows it was sitting somewhere readable.

| Platform | Location | Mode |
|---|---|---|
| Linux | `/etc/ominull/agent.conf` (`OMINULL_ARGS`) | `0600 root:root` |
| macOS | the LaunchDaemon plist | `0600 root:wheel` |
| Windows | `agent.key` beside the binary, `--key-file` in the binPath | SYSTEM + Administrators, inheritance off |

Windows is the one that had to change. Until v1.4.4 the key was an argument in
the service registration, and a service registration is not private: `sc qc`
needs only `SERVICE_QUERY_CONFIG`, which the default DACL grants to Interactive
Users, so any logged-on account could read it. The SCM also writes the whole
binPath into a System event log 7045 record at install, and nothing can redact
that afterwards — which is why moving the key is only half the fix and rotating
it is the other half.

`Service_Install` now writes the key to a file and registers `--key-file`
instead. Program Files alone is not enough: it is administrator-*write* but
user-*read*, so the file gets an explicit `D:P(A;;FA;;;SY)(A;;FA;;;BA)` — SYSTEM
and Administrators, inheritance broken. If that DACL cannot be applied the file
is deleted and the install fails, because a key file believed private and
readable by everyone is worse than the command line it replaced.

Enrolment did not change shape. The bootstrap script still passes `--key` to
`--install`; the installer is what moves it. And because self-update replaces
the binary but never the registration, `Service_MigrateKeyToFile` runs on every
service start and repairs an endpoint enrolled before this existed.

## Which endpoint is calling (v1.5.0)

TLS proves the hub to the agent. Until v1.5.0 nothing proved the agent to the
hub. The API key is issued per *tenant*, not per host, so every agent on the
fleet carries the same one — and the hub believed the `endpoint_id` in the
request body. A key lifted from any endpoint could therefore post telemetry as
any other host, read another host's configuration, or take its update
descriptor. That was not a transport problem, so encrypting the transport did
not fix it.

Enrolment now issues each endpoint a certificate from the hub's own CA, with the
endpoint id as the common name.

| Platform | Material | Presented by |
|---|---|---|
| Linux | `/etc/ominull/client.crt` + `client.key` (`0600`) | `curl --cert/--key` |
| macOS | `/opt/ominull/client.crt` + `client.key` (`0600`) | `curl --cert/--key`, paths in the plist |
| Windows | `client.pfx` beside the binary, SYSTEM + Administrators | `WINHTTP_OPTION_CLIENT_CERT_CONTEXT` |

Windows needs the PKCS#12 form because WinHTTP wants a certificate context that
already has its private key attached, and `PFXImportCertStore` is the only way
to build one from a file. The archive has no password: it is written where only
SYSTEM and Administrators can read it, and a password stored beside the thing it
protects would add nothing. `PKCS12_NO_PERSIST_KEY` keeps the key in the
process's memory instead of leaving a container in the machine key store on
every load.

On the hub, `endpointIdentityOK` refuses any request whose `endpoint_id`
disagrees with the common name in a verified client certificate — 403, on
`/api/v1/events` and `/api/v1/agent/config` alike. The name comes from
`r.TLS.VerifiedChains`, never `PeerCertificates`: the latter is what the client
sent, the former is what the hub verified. `authMiddleware` deletes an inbound
`X-Client-CN` before setting its own, so the header cannot be used to claim an
identity the handshake did not establish.

Two deliberate softnesses, both about being able to migrate a live fleet:

- The listener runs `VerifyClientCertIfGiven`, not `RequireAndVerifyClientCert`.
  A presented certificate is fully verified either way; what "if given" buys is
  that an endpoint which has not enrolled one yet keeps reporting instead of
  being cut off by a hub it can no longer reach to be told to enrol.
  `--require-client-certs` closes that, and the safe order is: ship
  certificates, confirm every endpoint presents one, then require them.
- An enrolment that fails warns and carries on rather than aborting the install.
  A host with a trust anchor and no running agent is worse than one reporting
  under the API key alone.

`TestClientCertificateBindsARequestToOneEndpoint` covers reporting as itself,
being refused as another host, the same binding on the update descriptor, and a
forged `X-Client-CN` changing nothing.
`TestClientCertificateFromAnotherCAIsRefused` covers a certificate from a
foreign CA and the `--require-client-certs` handshake.

```bash
# What an enrolled endpoint does on every request.
curl --cacert /etc/ominull/ca.crt \
     --cert /etc/ominull/client.crt --key /etc/ominull/client.key \
     -H "X-API-Key: $TENANT_KEY" -d '{"type":"telemetry","endpoint_id":"<its own id>","events":[]}' \
     https://<hub-ip>:9443/api/v1/events

# The same call naming a different host: 403, certificate does not name this endpoint.
```

## Still open

- **The hub still accepts the API key on its plain listener.** Closing that means
  running with `--listen ""`, which an operator can do once every endpoint has
  moved across, but it is not the default while the console and CLI use it.
