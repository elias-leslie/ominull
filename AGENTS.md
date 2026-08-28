# Working on Ominull

Orientation for coding agents and new contributors. Deeper detail lives in
[`README.md`](README.md) (architecture, CLI, REST API) and [`PLAN.md`](PLAN.md) (roadmap).

## Shape of the repo

| Path | What |
| :--- | :--- |
| `hub/` | Go control hub — single binary, REST + WebSocket, embedded web console |
| `agent/linux/` | Linux eBPF/TC daemon (C) |
| `agent/src/`, `agent/include/` | Windows agent + WFP driver client (C) |
| `agent/macos/` | macOS pfctl daemon (shell) |
| `driver/`, `ebpf/` | Kernel-side enforcement |
| `scripts/` | Build, packaging, release, and the `ominull-cli` tool surface |

## Rules that are easy to get wrong

1. **The hub ships before the agents.** The hub serves the packages and decides who is
   outdated, so a release that updates agents first is offering a package nothing serves.
   `scripts/release.sh` enforces the order — do not hand-roll the two hops.
2. **`VERSION` is the single source of truth.** It is compiled into the hub, all three
   agents, and the package filenames. `scripts/version.sh check` is a CI gate; run it after
   touching any version string.
3. **Keep the three Linux install paths converged.** The `.deb`, the bootstrap installer,
   and whatever is deployed must agree on the unit name, binary path, and config file.
   Enrolment config (`/etc/ominull/agent.conf`) is created once and never overwritten on
   upgrade — that is what makes self-update safe.
4. **Sort endpoint lists on stable identity, never on last-seen.** A row that moves under
   the operator between refreshes turns an isolate click into the wrong machine.
5. **No environment specifics in tracked files.** No usernames, real domains, real LAN
   IPs, hostnames, or keys. The check is against the *real* values, not against private
   ranges — RFC1918 addresses in docs and demo data are deliberate:

   ```bash
   git grep -niE "kasadis|davion|192\.168\.86\.|summitflow\.dev"
   ```

   The `10.0.0.x` addresses throughout the docs and console are a stand-in subnet, and
   `10.0.4.x` / `172.16.x` belong to the demo fixtures. Keep it that way: substitute, do
   not delete, when a real address would otherwise appear.

   Local operator tooling (`scripts/connect-*.sh`, `scripts/deploy_remote.sh`) holds the
   real addresses and is gitignored on purpose; see `scripts/deploy_remote.sh.example`.

## Gates

```bash
cd hub && go test -race ./...
gcc -O2 -Wall -Wextra -o /tmp/test_dpi agent/tests/test_dpi.c && /tmp/test_dpi
gcc -O2 -Wall -Wextra -o /tmp/agent agent/linux/main.c          # must be warning-free
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o /tmp/ominulld.exe \
  agent/src/main.c agent/src/hub_client.c agent/src/service.c agent/src/driver_client.c \
  -lws2_32 -lwinhttp -liphlpapi -ladvapi32
./scripts/version.sh check
```

The console has a demo mode (`/?demo=true`) that seeds synthetic fleet data — use it for
screenshots rather than real telemetry.

## Maintainers

Deployment topology, credentials, live access paths, and the incident history behind the
rules above are in the private ops vault at `wiki/projects/ominull/operations.md`. Read it
before touching a live fleet.
