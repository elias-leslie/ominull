# Optional Cloudflare adapter

Ominull does not require Cloudflare. LAN-only and direct-WAN HTTPS remain full
supported paths. Cloudflare is an optional adapter for the existing Proxmox
host: the hub stays where it is, and `cloudflared` makes an outbound Tunnel
connection to Cloudflare. Cloudflare documents the outbound connector and
public-hostname model in [Cloudflare Tunnel documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/).

## Free-tier-supported shape

Create two separate public hostnames in the Cloudflare dashboard:

- `console.example.invalid` -> the hub console origin, protected by a normal
  Cloudflare Access application and operator policy.
- `agent.example.invalid` -> the hub agent HTTPS origin, with no interactive
  Access login redirect.

The second hostname is a transport route, not a browser application. It must
return the hub's bounded JSON responses to an unauthenticated probe rather than
an HTML Access login page. The Ominull wizard checks this property but does not
create or change the Tunnel, DNS record, Access application, or policy.

The supported path uses the free-tier Tunnel and Access capabilities available
to the account. It does not require Cloudflare Enterprise, BYOCA, Access mTLS,
Workers, Spectrum, paid load balancing, or another paid feature. Confirm
current provider limits in the [Cloudflare plan documentation](https://www.cloudflare.com/plans/).

## Operator action

The operator, outside Ominull, supplies the Tunnel connector and route in the
Cloudflare dashboard or the approved Cloudflare control plane. Point both
origins at the hub's existing local listener as appropriate for the chosen
TLS mode. Keep provider credentials outside the Ominull repository and outside
agent configuration.

Do not use a shared Cloudflare service token for an agent. Every enrollment
creates a unique Ominull `omd_...` device credential. A directly connected
agent may also present its Ominull client certificate; the hub checks that its
subject matches the device endpoint. Credential rotation and revocation happen
through Ominull, not through a Cloudflare token shared by the fleet.

## Console authentication

Cloudflare Access assertions are accepted only for the configured Access team,
application audience, expected issuer, valid time claims, and a mapped Ominull
operator identity. The hub validates the signed JWT using the team's published
JWKS; it does not trust an email header. See Cloudflare's
[JWT validation guidance](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/).

The console and agent hostnames remain separate even when both use the same
Tunnel connector. The agent route must never inherit a console redirect policy.
If the provider configuration cannot preserve that split, use direct WAN or
LAN mode instead.

For a Cloudflare agent URL, the bootstrap and native agents validate the public
edge certificate with the host operating-system trust store. They do not pin
the hub's private server CA because the Tunnel edge is the TLS peer. The
hub-issued device CA is still returned for the optional direct native mTLS
proof, and the `omd_...` credential remains the required steady-state device
authentication.

## What Ominull changes

Nothing outside the hub host. Setup stores a redacted network-mode record and
renders operator guidance. It does not call Cloudflare APIs, alter DNS, alter
router forwarding, install `cloudflared`, or change an Access policy. Those are
external security-boundary actions and require an operator decision.
