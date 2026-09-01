# OIDC and ACME

Both are optional. Ominull remains usable with the local admin key and direct
LAN/WAN access.

## Native OIDC

Configure an HTTPS issuer, client ID, redirect URL, and (when required by the
provider) client secret in the setup wizard. Register the exact callback URL
with the provider. The hub discovers the provider metadata and JWKS from the
issuer's standard OpenID Connect discovery document, then uses authorization
code flow with state, nonce, and S256 PKCE.

The callback accepts only a live, short-lived state record. The ID token must
match the discovered issuer, configured client ID, signature key, time claims,
nonce, and required subject. The hub maps a stable `(issuer, subject)` pair to
an explicit Ominull operator row; an email claim alone never grants a role.
The client secret is written only to a root-owned `oidc-client.secret` file
beside the package environment file. It is not returned by setup status or
diagnostics.

The protocol requirements are defined by [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
and [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).

## ACME server certificate

ACME is for the hub's public server certificate. The device CA used for native
endpoint certificates is separate and remains local to the hub. The operator
must complete the selected HTTP-01 or DNS-01 challenge with the approved ACME
client, install the resulting certificate and private key with root-only
permissions, then enter their paths in the wizard and restart the package
service.

Ominull does not create DNS records, edit router forwarding, answer a challenge
through an unapproved path, or store an ACME account key in the repository. The
certificate must cover the configured console and/or agent hostname as used by
the relevant listener. The ACME protocol is specified by [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555).

If public certificate preparation is not wanted, use the self-issued native CA
for LAN access. In that mode agents pin the hub CA during enrollment and verify
later connections. With ACME, agents use the operating-system public trust
store; the hub-issued device credential and optional direct client certificate
remain separate from the public server certificate.
