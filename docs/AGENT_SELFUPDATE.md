# Agent self-update

Every package has a detached ECDSA P-256 signature and a SHA-256 sidecar, made
with the one release key. Its public half is compiled into each agent; the
private key stays in the operator's key store.

Windows agents update themselves from the MSI the hub offers. Linux agents do
not self-update: the operator installs the Debian package with
`scripts/update-linux-agents.sh` over root access that does not depend on the
agent.

The hub advertises a Windows update only when the package, digest, and
signature are present in its configured artifact directory. Agents use only the
path from the hub descriptor and never follow a descriptor to another host.

## Windows sequence

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

`scripts/update-linux-agents.sh VERSION [--canary IDS] [--only IDS] [--reinstall]`
checks the package signature against the release key, then goes machine by
machine (canaries first). On each it runs `scripts/lib/install-agent-deb.sh` as
root over Proxmox (`pct exec`, `qm guest exec`, or ssh to the host) or locally
with sudo. That script downloads the package from the hub the agent already
talks to, checks the digest the operator verified, runs `dpkg -i`, and waits for
the service to stay up; otherwise the previous binary goes back. The hub must
then hear the new version from the machine, or the previous binary goes back
too. The first failure stops the run. Powered-off machines are listed for a rerun
and are never started for this. The signature is checked against the key in
`agent/include/release_key.h`, the one the agents pin.

The package owns `/opt/ominull/bin/ominulld`, `/etc/ominull/agent.conf`, and
`ominull-agent.service`. The maintainer scripts create and enable the unit,
preserve enrollment identity on upgrade, refuse a downgrade, and remove endpoint
identity only on purge. They never remove the hub database or PKI. New
configuration uses a unique device credential file.

The hub refuses a Linux endpoint in an agent update and drops any Linux update
still queued from an older release. The agent still reports the `deb` capability
so the console and the status API know how the machine is packaged.

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
