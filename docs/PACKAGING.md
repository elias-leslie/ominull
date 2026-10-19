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

### Session signing (routine release keys)

Inside the owner's work session, Nightshift's signer can sign with a routine
release key instead of the tap key: run the release with
`OMINULL_SIGNING_ROUTINE=1`. The signing backend asks the signer for
`pubkey routine` and refuses a key that is not on the hub's list signed by the
pinned release key (`GET /api/v1/trust/routine-keys`). It verifies every
signature against that routine key and writes the signed list to
`dist/routine-keys.json`. `deploy-hub.sh` sends that file with the hub package,
and `ominull-hub-install` on Proxmox (from 1.8.89) accepts the routine key only
for that package and never lets it move the release key pin. Such a release
rolls out canaries first (`OMINULL_ROUTINE_CANARIES`, default the lab VM), and
the hub and the authority refuse a routine-signed rollout without canaries.
Agents from 1.8.89 accept routine keys for agent packages only.

An agent running as the `agent` user uses its own hub-install SSH key; the
owner's key stays in place. As `agent`, create an ed25519 key with
`ssh-keygen -t ed25519 -f ~/.ssh/ominull-hub-install.ed25519` and supply only
the `.pub` file to the owner. Through the approved admin path, the owner runs
`scripts/pve/install.sh --hub-install-extra-pubkey FILE` with the usual
`PVE_HOST` and `OMINULL_PVE_FROM` environment. The file must contain exactly
one `ssh-ed25519` public key line, with an optional comment and no SSH options.
The extra key gets the same `restrict`, `from=` address and forced
`/usr/local/sbin/ominull-hub-install` command as the owner's hub-install key.
Re-running with the same key adds nothing; a different key replaces the extra
key. Omitting the flag preserves a previously installed extra key, including
when refreshing the other keys. To remove it, the owner removes only the line
ending ` ominull-hub-install-extra` from `/root/.ssh/authorized_keys` on
Proxmox through the approved admin path. A later run without the flag keeps
it removed.

Add this alias to `~agent/.ssh/config`, replacing `<PVE host>` with the
deployment's Proxmox hostname or address and keeping the key private to `agent`:

```sshconfig
Host ominull-hub-install
    HostName <PVE host>
    User root
    IdentityFile ~/.ssh/ominull-hub-install.ed25519
    IdentitiesOnly yes
    IdentityAgent none
    BatchMode yes
```

The agent also needs its own trusted Proxmox host-key entry in
`~agent/.ssh/known_hosts` and its private key available without an interactive
prompt. Inside an active owner work session:

```bash
st elevate request ominull-admin --reason 'OmniNull release X.Y.Z' --wait
OMINULL_SIGNING_ROUTINE=1 OMINULL_SIGNING_BACKEND=command \
OMINULL_SIGNING_COMMAND=~/.local/lib/nightshift/bin/nightshift-release-signer \
OMINULL_HUB_URL=https://<hub>:9443 \
st elevate run ominull-admin -- scripts/release.sh ...
st elevate revoke ominull-admin
```

The session authorizes routine signing and the `ominull-admin` grant without
owner taps. Use the actual release arguments in place of `...`.

New installs take a routine-signed package too. The bootstrap scripts
(`/bootstrap.sh`, `/bootstrap.ps1` and the enrolment pages' scripts) install a
package the embedded release key signed as before; otherwise they fetch
`/download/routine-keys.json` (the hub's held list, the heartbeat's
`{epoch, keys, sig}`, no credential) and the package's `.release.sig`, and
install only when the list is strictly formed, signed by the embedded release
key, not empty, at an epoch no lower than the one the hub held when it rendered
the script, and one listed key signed both the package and its
`OMINULL-RELEASE-V1` statement. No list, a bad signature or an older or empty
list refuses. The release gate (`TestPublishedPackagesVerifyForFreshInstall`)
runs both scripts' check on `dist/` with `dist/routine-keys.json` (the Windows
one under PowerShell 7 when `OMINULL_PWSH` or `pwsh` is found).
