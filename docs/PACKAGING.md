# Native package contract

Ominull ships registered native packages only:

- `ominull-hub_<version>_amd64.deb`
- `ominull-agent_<version>_amd64.deb`
- `ominull-agent-windows-<version>.msi`

The hub `.deb` owns `/opt/ominull/bin/ominull-hub`, `/usr/bin/ominullctl`,
embedded web assets, bundled signed Linux/Windows endpoint artifacts, and one
`ominull-hub.service`. The Linux agent `.deb` owns `ominulld` and one
`ominull-agent.service`. The MSI owns `ominulld.exe`, the user-mode WFP
recovery tool, the `ominulld` service registration, and Windows Installer
metadata.

Package post-install creates directories, applies root/private permissions,
registers the service, and starts it only when a usable package configuration
exists. Enrollment invokes the package-installed executable through a protected
stdin contract. Bootstrap never copies a privileged executable, creates a
service, writes a unit file, or places a credential in process arguments.

## Persistent data

Hub upgrade, remove, reinstall, and purge preserve the SQLite database, device
PKI, release artifacts, backups, and operator configuration. Hub `postrm` only
reloads systemd. Endpoint remove stops and unregisters the endpoint service;
endpoint purge explicitly removes only endpoint configuration, credential,
certificate, and update staging files. It never removes co-installed hub data.

Upgrades preserve configuration and enrolled identity. Debian preinst and MSI
major-upgrade rules refuse downgrades. A failed install leaves the previous
package authoritative. These boundaries follow Debian's
[maintainer-script policy](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
and Windows Installer's service/package model.

## Release proof

`scripts/build-packages.sh` compiles both retained agents and the hub, builds
the three native package types, and checks ownership and writable modes.
`scripts/sign-release.sh` signs every package and sidecar with the release key,
bundles already-signed endpoint artifacts into the hub package, then verifies
the final hub signature. Agents verify the digest and pinned release signature
before self-update.

`scripts/test-package-lifecycle.sh` exercises clean install, upgrade,
downgrade refusal, remove, reinstall, purge, service registration, and durable
state preservation in an isolated package root. The actual production release
workflow deploys the hub first, then retained Linux and Windows canaries, then
the remaining agents after native provenance and heartbeat convergence.
