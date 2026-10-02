# Production observer

`scripts/st-ominull` implements the public ST extension wire using Python's
standard library. It imports no private ST application or CLI modules. Run it
through the registered ST dispatcher, which supplies `ST_EXTENSION_CONTEXT`,
pins the accepted Git executable and code tree, and launches an immutable
archive. The observer also checks its tracked code bytes and executable modes
against that accepted commit.

The only operation is a read-only production observation. It performs local
artifact/Git reads, fixed SSH reads through the approved alias into the container
selected by the protected private configuration,
and HTTP GETs. It does not deploy, restart, configure, queue work, or reset data.

The owner supplies `production.local.json` in the registered project root's
`scripts/st_extension` directory. This file is ignored, must be owned by the
invoking UID with mode `0600`, and must not be a symlink. The sample contains
stand-ins only, including illustrative container ID `100`. The credential file
has the same permission requirements.
The approved credential source has the admin token on line one and tenant token
on line two; only the admin token is sent. Both lines must contain printable
tokens without whitespace. A single-token file is also supported. No environment
or shell assignment parsing is performed.
Caller requests cannot replace infrastructure, paths, credentials, hashes,
timeouts, or source projection rules.

## Wire

Send one JSON object on stdin, or use a single `--request` JSON argument:

```json
{
  "contract_version": 1,
  "operation": "observe_deployment",
  "challenge": "11111111111111111111111111111111",
  "project": "ominull",
  "task_id": "task-example",
  "acceptance_id": "acceptance-example",
  "accepted_source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

Unknown fields, duplicate JSON keys, incorrect versions, malformed bindings,
and symbolic Git revisions are rejected. Full lowercase Git SHA-1 and SHA-256
commit IDs are supported. stdout is one JSON object; subprocess diagnostics
and response bodies are discarded. Exit status is `0` for every completed
structured observation, including failed checks, and `2` for invalid input.
ST decides gate acceptance from check states and retains failed evidence.

The response has `schema_version: 1`, echoes the challenge/project/task/
acceptance/accepted-source bindings, and includes the fixed opaque `target_id`,
the actual `deployed_source_commit`, `runtime_policy_path`,
`runtime_exclusions`, and exactly these three checks. Check states are
`success` or `failed`; evidence is an object.

- `production_binary`: signed hub package, digest sidecar and release manifest;
  public key pinned in accepted source; package/local/installed/running hashes
  for both hub and response authority; actual running Go build metadata with
  `vcs.modified=false`; installed package version and genuine deployed source.
- `production_health`: both systemd services active/running with PID, restart
  count and monotonic start identity, plus a successful JSON console-status GET.
- `production_routes`: authenticated console, hierarchy and diagnostics GETs;
  JavaScript asset with the installed version and bytes matching actual deployed
  source; anonymous hierarchy `401`; unchanged process identities across the
  observation.

Each successful check includes the private configuration's SHA-256 digest and
accepted executable/policy blob identities. Credentials, private hostnames and
paths, remote stdout/stderr, HTML, JSON response bodies and service environment
contents are not retained. A failed check includes a fixed error code; an
unobserved deployed source is `null`.

The deployed build's original source identity is retained even when a later
accepted commit contains only permitted publication or observer changes.
`runtime-inputs.json` defines the reviewed rule, not a caller option. ST owns
Git ancestry and runtime-source equivalence: it independently pins the policy
blob and compares all other tracked entries by path, Git mode and blob identity.
The observer reports genuine deployment evidence and check durations; it does
not substitute the accepted source identity for the build's source identity.

Required local tools are `git`, `ssh`, `go`, `dpkg-deb` and `openssl`. Go automatic
toolchain downloads are disabled. SSH uses batch mode, a five-second connection
timeout and bounded keepalives; each subprocess has a 60-second timeout. HTTP
GETs have a ten-second socket timeout, follow no redirects, use system HTTPS
trust, and request identity encoding. Running binary reads are capped at 64 MiB.

## Tests

Run the owned check through the managed gate:

```bash
st check cleanroom -- scripts/st_extension/check.sh
```

Tests use isolated fixtures and signed temporary packages. They make no
production requests. Include `scripts/st_extension/check.sh` in the registered
project gate before accepting this extension.
