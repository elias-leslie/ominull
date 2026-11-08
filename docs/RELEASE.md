# Release runbook

A hub change goes live with `scripts/deploy-hub.sh` alone. An agent release is
`scripts/release.sh`:

```bash
OMINULL_SIGNING_BACKEND=command \
OMINULL_SIGNING_COMMAND=~/.local/bin/ominull-release-signer \
BPFTOOL=/usr/sbin/bpftool \
scripts/release.sh --version X.Y.Z [--canary IDS]
```

`release.sh --help` lists its options. It refuses when nothing the agents ship changed
since the last `Release X.Y.Z` commit, and when anything uncommitted would ship, since the
gates and package builds read the working tree. With other work in the checkout, release
from a worktree, then commit the version bump `release.sh` leaves there:

```bash
git worktree add --detach DIR HEAD
cp -a agent/hubinput/vendor DIR/agent/hubinput/
cp -a screen/helper/vendor DIR/screen/helper/
cp -a screen/viewer/vendor DIR/screen/viewer/
cp -p scripts/st_extension/production.local.json DIR/scripts/st_extension/
ln -s "$PWD/.dev-tools" DIR/.dev-tools   # st browser writes its results to the registered checkout
```

## Order

1. Gates: gofmt, hub tests and vet, script tests, BPF build, collector feedback
   loops, fuzz replay, the Rust hub-input comparison.
2. `scripts/build-packages.sh` builds the agents and hub and the three native
   packages, and checks ownership and writable modes.
3. `scripts/sign-release.sh` signs every package and sidecar with the release key
   and bundles the signed endpoint packages into the hub package.
4. The fresh-install check (`TestPublishedPackagesVerifyForFreshInstall`) runs both
   bootstrap scripts' verification on `dist/`; `scripts/test-package-lifecycle.sh`
   runs install, upgrade, downgrade refusal, remove, reinstall and purge in an
   isolated root.
5. `scripts/deploy-hub.sh`, then `scripts/publish-agents.sh`.
6. `scripts/update-linux-agents.sh` installs on the Linux machines.
7. The hub rolls the Windows agents, canaries first when named.

When `OMINULL_HUB_URL` or `OMINULL_ADMIN_KEY` is unset, `scripts/lib/hub-admin-key.sh`
fills them in: the URL from `hub_base_url` in the ignored
`scripts/st_extension/production.local.json`, the key from the first line of
`/etc/ominull/admin.key` in the hub container, read into the environment only.

## Signing

Every package has a detached ECDSA P-256 signature and a SHA-256 sidecar, made with
the one release key. Its public half is compiled into each agent
(`agent/include/release_key.h`); the private key stays in the operator's key store.

`ominull-release-signer` (`hub/cmd/ominull-release-signer`; install with
`scripts/install-release-signer.sh`) signs without asking anyone. Its root half runs
through `sudo -n`, opens the key from `OMINULL_SIGNING_STORE`, and signs only what
`begin` froze: each package once, then its release statement once.

Bootstrap (`/bootstrap.sh`, `/bootstrap.ps1`, the enrolment pages) installs only a
package the embedded release key signed.

## Linux updates

Linux agents do not self-update and the hub refuses them in update requests.

`scripts/update-linux-agents.sh VERSION [--canary IDS] [--only IDS] [--reinstall]`
checks the package signature against the pinned key, then goes machine by machine,
canaries first. On each it runs `scripts/lib/install-agent-deb.sh` as root over
Proxmox (`pct exec`, `qm guest exec`, ssh to the host) or locally with sudo. That
script downloads the package from the hub the agent talks to, checks the digest the
operator verified, runs `dpkg -i`, and waits for the service to stay up; otherwise
the previous binary goes back. The hub must then hear the new version from the
machine, or the previous binary goes back too. The first failure stops the run.
Powered-off machines are listed for a rerun and are never started for this.
Endpoints not named `linux-<machine>` are mapped in `linux_agent_machines` in the
production config.

The package owns `/opt/ominull/bin/ominulld`, `/etc/ominull/agent.conf` and
`ominull-agent.service`. Its scripts create and enable the unit, preserve enrolled
identity on upgrade, refuse a downgrade and remove identity only on purge.

## Windows updates

The agent receives a signed descriptor in an authenticated telemetry response and
uses only the path in it, never another host. It validates the path and digest,
verifies the package and its release statement against the pinned key, stages in an
administrator-only folder and runs `msiexec.exe /i <package> /qn /norestart`.

The MSI owns `C:\Program Files\Ominull\ominulld.exe`, the user-mode WFP recovery
tool, the `ominulld` service registration and the uninstall metadata. A major upgrade
preserves the identity files in `C:\ProgramData\Ominull`. A full removal runs the
recovery tool first. The service has SCM recovery actions set on every start. MSI
owns file replacement and rollback; a failed transaction leaves the prior install
authoritative.

An update job stays pending until the endpoint reports the target version and native
package provenance: package identity, registered version, install type and provenance
status must agree, not the binary version alone. A failed digest, signature,
installer, restart or heartbeat does not clear the job. Update failure must not release
or widen containment.

## Build requirements

Linux needs `clang`, `bpftool`, `libbpf-dev`, `libelf-dev` and `pkg-config`.
`scripts/build-bpf.sh` generates ignored skeletons under `build/bpf` from
`/sys/kernel/btf/vmlinux` or `OMINULL_VMLINUX_BTF`; `BPFTOOL` names the tool. Host builds
serve the tests only. The shipped agent is built by `scripts/build-linux-agent.sh` in a
pinned Ubuntu 24.04 container (`OMINULL_AGENT_BUILD_IMAGE`), because the skeleton must
come from the oldest supported libbpf headers; `scripts/check-agent-libbpf.sh` enforces
that. Live kernel and ETW fixtures (`scripts/test-native-telemetry.sh`,
`scripts/test-windows-udp.ps1`) need an isolated lab.
