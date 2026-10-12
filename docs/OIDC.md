# OIDC

OIDC is optional. Ominull remains usable with the local admin key on the LAN.

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

## Server certificate

The hub no longer obtains certificates itself; automated ACME was removed. To
use a publicly trusted certificate, obtain it with your own client (for example
an ACME client), install the certificate and key with root-only permissions,
choose the operator-supplied certificate source in the wizard, and restart the
package service. The device CA used for native endpoint certificates is separate
and remains local to the hub.

With the self-issued native CA, agents pin the hub CA during enrollment and
verify later connections. With an operator-supplied certificate, agents use the
operating-system public trust store; the hub-issued device credential and
optional direct client certificate remain separate from the server certificate.
