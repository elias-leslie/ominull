# Agent self-update

The supported endpoint updates are native Debian packages on Linux and an MSI
on Windows. Every package has a detached ECDSA P-256 signature and a SHA-256
sidecar. The release public key is compiled into each agent; the private key is
kept in the operations vault.

The hub advertises an update only when the package, digest, and signature are
present in its configured artifact directory. Agents use only the path from the
hub descriptor and never follow a descriptor to another host.

## Common sequence

1. Receive a signed descriptor in an authenticated telemetry response.
2. Validate the package path and digest.
3. Verify the detached signature against the pinned public key.
4. Stage in a package-owned, administrator-only location.
5. Invoke the platform package manager.
6. Restart the one package-owned service and report the resulting binary and
   package provenance.

Any failure leaves the current installation running. The hub does not count an
endpoint as converged from its reported binary version alone: package identity,
registered package version, install type, and provenance status must agree.

## Linux

The agent stages under `/var/lib/ominull/updates`, owned by root and mode `0700`,
then invokes `dpkg -i`. The package owns `/opt/ominull/bin/ominulld`,
`/etc/ominull/agent.conf`, and `ominull-agent.service`. The maintainer scripts
create and enable the unit, preserve enrollment identity on upgrade, refuse a
downgrade, and remove endpoint identity only on purge. They never remove the
hub database or PKI.

The update is launched independently of the current daemon because the package
transaction stops that daemon. A failed package transaction is logged and the
existing executable remains authoritative. The agent's release version and
`dpkg-query` result are reported separately so manual or partial installs are
visible.

## Windows

The MSI owns `C:\Program Files\Ominull\ominulld.exe`, the user-mode WFP recovery
tool, the `ominulld` service registration, and Windows Installer uninstall
metadata. The MSI major-upgrade transaction preserves `C:\ProgramData\Ominull`
identity files. A full removal runs the recovery tool before removing package
files, then Windows Installer removes the service registration.

The agent invokes `msiexec.exe /i <package> /qn /norestart` only after digest and
signature verification. The service registration uses the package-installed
binary and package-owned configuration. MSI `DisplayName=Ominull Agent` and
`DisplayVersion` provide the registered provenance reported to the hub.

The service has explicit SCM recovery actions, configured on every start. MSI
owns file replacement and rollback; the agent only waits for its service to
stop, invokes Windows Installer, and starts the package-owned service after a
successful transaction. A failed transaction leaves the prior MSI installation
authoritative.

## Rollback and dead-man behavior

An update job remains pending until the endpoint reports the target version and
native package provenance. A failed digest, signature, installer, restart, or
heartbeat does not clear the job. The hub exposes remaining jobs and provenance
issues rather than presenting a queued update as complete.

Isolation has its own dead-man release and readiness checks. Update failure
must not release or widen containment. Standalone Windows recovery clears only
Ominull-owned WFP filters and sublayer state; it is safe to run without the main
service.

## Bootstrap boundary

Bootstrap may fetch CA material and signed package sidecars, call `dpkg` or
Windows Installer, and ask the package-installed executable to write enrollment
configuration. It may not copy a privileged executable, create a service,
register a second service, or install a raw archive.

## Release procedure

Run `scripts/release.sh`. It builds and signs the retained artifacts, verifies
the isolated lifecycle harness, installs the hub package first, and rolls a
retained canary before the rest of the fleet. Releases serve the MSI and Debian
packages only.
