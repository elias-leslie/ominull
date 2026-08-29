# Ominull Console Redesign

Visual, UX and information-architecture overhaul of the hub's embedded web console.
Design direction approved 2026-08-28. Companion mock:
`https://claude.ai/code/artifact/a2a93a09-28bb-4a6f-83b0-81b7e02a4696`

## Goal

The console is read for hours and acted on in seconds. Optimise for that: least
clicks, least eye fatigue, highest information density that stays legible. Fold
Fleet, Asset Scanner and Topology into one asset graph so every host on the network
appears in one list — whether it runs an agent, answered a probe, or was deduced
from its neighbours' traffic.

## Approved decisions

1. **All four palettes ship**, operator-selectable from the console. Not a single choice.
2. **Split `dashboard.go`.** The console moves to real files served through `//go:embed`.
3. **Two passes.** Pass 1 is the UI over today's data. Pass 2 adds asset persistence
   and flow inference. Pass 1 must not be blocked on Pass 2.

## Why the current console is the way it is

Measured in `hub/pkg/server/dashboard.go` (3,474 lines, 209 KB, one Go string constant):

| Finding | Value |
| :--- | :--- |
| Body text contrast | 18.7:1 (`#f8fafc` on `#080c14`) — glare, not legibility |
| Emoji used as the icon language | 154 |
| Inline `style=` attributes | 326 |
| `@media` queries | 0 |
| Distinct font sizes | 11, no scale |
| Top-level flat tabs | 9, labels up to 38 chars |

The font stack on `*` is `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
"Helvetica Neue", monospace` — `monospace` sits last after four proportional faces,
so it never applies. There is no typographic system to inherit.

---

## Pass 1 — Design system, layout, single pane over current data

### 1.1 Extract the console from the Go string

Target layout:

```
hub/pkg/server/web/
  index.html
  app.css
  app.js
  fonts/            # subset woff2, embedded
```

Served with `//go:embed web`. **Non-negotiable invariants:** single binary, no build
step, no npm, no CDN at runtime. The hub must render correctly on an airgapped fleet,
so fonts are embedded, never fetched from Google Fonts.

Keep `dashboard.go` as the embed + handler shim, or delete it and move the handler
into `server.go` — implementer's call. `scripts/version.sh check` must still pass.

### 1.2 Token system

Replace all 326 inline styles with tokens. Four palettes, identical token names,
selected by `data-theme` on `<html>`.

**Shared scale** (no other values permitted):

- Space: `4 8 12 16 24 32` px.
- Type: `10.5 11.5 12.5 14 17 22` px. Below 11.5px is uppercase labels only.
- Radius: `2px` controls, `3px` containers. Nothing rounder.
- Border: `1px` always.
- **No `box-shadow` glow anywhere.** Shadows are permitted only on overlays
  (context menus, modals, command palette).

**Neutrals + brand:**

| Token | Graphite | Bunker | Ash | Phosphor |
| :--- | :--- | :--- | :--- | :--- |
| `--ground` | `#17150F` | `#0F1719` | `#14161A` | `#0D0F0D` |
| `--panel` | `#1E1B15` | `#152023` | `#1A1D23` | `#131613` |
| `--raised` | `#26231C` | `#1C2A2D` | `#22262E` | `#1A1E19` |
| `--line` | `#332F27` | `#26383C` | `#2C313A` | `#262B24` |
| `--ink` | `#DDD8D0` | `#D3DEDC` | `#DADDE3` | `#C8D3BE` |
| `--ink-2` | `#9C948A` | `#8CA0A0` | `#949BA8` | `#87947F` |
| `--ink-3` | `#8A8278` | `#7A8D8D` | `#808793` | `#7B8775` |
| `--brand` | `#C98A5E` | `#4FB3A5` | `#8FA9E8` | `#9FCF86` |

**State (reserved — see rule below):**

| Token | Graphite | Bunker | Ash | Phosphor |
| :--- | :--- | :--- | :--- | :--- |
| `--ok` | `#7CB675` | `#6CB882` | `#73B87D` | `#86B46D` |
| `--warn` | `#EBBB6E` | `#EABC6E` | `#E6BE6D` | `#F0B871` |
| `--crit` | `#CD776C` | `#CD7670` | `#CD7670` | `#CC7867` |
| `--info` | `#51A1D5` | `#4AA3D2` | `#689BDB` | `#3AA6CB` |
| `--crit-hot` | `#D35A4F` | `#D35A55` | `#D35A55` | `#D35C47` |

Measured, not estimated. `--ink` lands 11.7–12.4:1 on `--panel`; `--ink-2` 5.7–6.1:1;
`--ink-3` 4.5–4.8:1; every state colour ≥5.1:1. The state sets are OKLCH
`C=0.11, L=[.72 .82 .66 .68]` — the point where all pairs clear ΔE ≥ 15 normal-vision
and ≥ 8 under simulated protan/deutan/tritan. Do not hand-tune these without re-running
the check; dropping chroma to "calm it down" breaks colour-vision separation.

### 1.3 The five fatigue rules

These are why the palettes look the way they do. Do not relax them.

1. **Ground, not black.** Base sits at L\* 4–8. Never `#000` — pure black smears light text.
2. **Ink, not white.** Body text 12–13:1, never 18:1.
3. **Hue means state.** Chrome is neutral. `--ok/--warn/--crit/--info` are reserved for
   asset state and never spent on buttons, headers, nav or links. This is the single
   biggest fix: today cyan chrome competes with red alerts.
4. **No bloom.** Zero glow on text or borders.
5. **State is never colour alone.** Every state renders a 3px stripe + a glyph + a word.
   Must survive deuteranopia, a glare-washed screen, and a screenshot in a ticket.

### 1.4 Theme switcher

- Lives in the rail footer, under the hub-health dot. Not in a settings page.
- Cycles/selects across Graphite, Bunker, Ash, Phosphor. Show swatches, not just names.
- Persists per-operator in `localStorage`; wrap read and write in `try/catch` and render
  correctly with no stored value.
- Default is **Ash** — closest to the current console, least jarring for existing operators.
- Applies instantly, no reload. Every colour must come from a token or the switch will
  half-apply; a hard-coded hex anywhere is a bug.

### 1.5 Typography and icons

- **IBM Plex Sans** for chrome, **IBM Plex Sans Condensed** for labels and column headers,
  **IBM Plex Mono** for all data (hostnames, IPs, ports, versions, timestamps).
- Subset to Latin, embed as woff2, declare real fallback stacks.
- `font-variant-numeric: tabular-nums` on every column of digits.
- **Delete all 154 emoji.** Replace with an inline SVG sprite: 16px, 1.6 stroke,
  `currentColor`, no fills. Icons never carry their own hue.

### 1.6 Information architecture

- Nine flat tabs → **six rail sections**: Assets, Discovery, Topology, Traffic, Policy, Audit.
  Rail is 52px, icon-only, labelled on hover.
- **Copilot and alerts become drawers**, available from any section. Asking Copilot about
  the alert you are looking at must not require navigating away from it.
- **Command palette on `⌘K` / `Ctrl+K`** resolving hosts, IPs, clients and verbs in one
  field. This is where most of the click saving comes from — it makes the rail a fallback.
- **Every stat tile is a filter.** Clicking `Quarantined 3` filters the table to those
  three. The ribbon stops being decoration and becomes navigation.
- Header keeps hub identity, health and version. **Delete the marketing subtitle**
  ("Kernel-Native Cross-Platform Threat Nullification & Fleet Mesh") and every other
  line of copy that does not carry state.
- Keyboard row ops: `j/k` move, `x` select, `i` isolate, `r` rescan, `/` filter, `↵` open,
  `y` copy address.
- Add real `@media` breakpoints. Wide content scrolls in its own `overflow-x:auto`
  container; the page body never scrolls sideways.

### 1.7 Single pane — the merged asset view

Fold Fleet Hierarchy and Asset Scanner into one **Assets** table listing agented and
unagented hosts together.

- Columns: select, Asset, Address, Identity, **Known by**, State, Exposure, Last seen, `⋯`.
- **Known by** is a 3-cell provenance strip: agent · scan · inferred.
- **Row click expands in place** — identity claims, observed ports, and (Pass 2) the
  inference rationale. `↵` or "Open full view" promotes it to a full-screen asset route.
- **Actions move to a context menu** on right-click and on `⋯`, grouped Asset / Discovery /
  Act. A menu grows as capability grows; a row of buttons cannot. Destructive items
  (quarantine, isolate) sit in their own group and carry `--crit-hot`.
- Sorting stays on **stable identity, never `last_seen_at`** — the existing rule survives
  the redesign. Selection must also survive a refresh.
- Tenant/location grouping is preserved as collapsible group rows.

In Pass 1 this renders from the current endpoints API plus the in-memory scanner assets.
It will lose scanner rows on hub restart — that is expected and is what Pass 2 fixes.
**Build the UI against the merged shape now** so Pass 2 changes the source, not the view.

### 1.8 Pass 1 acceptance

- Console renders from `web/`, hub still builds and ships as one binary with no network access.
- All four themes switch instantly and persist; no hard-coded colour survives anywhere.
- Zero emoji, zero inline `style=`, zero glow.
- Fleet + Scanner are one view with expandable rows and context menus.
- `⌘K` resolves a hostname and an IP to an asset.
- Every stat tile filters the table.
- Verified in a real browser at `/?demo=true`, all four themes, at 1280px and 1920px.

---

## Pass 2 — One asset graph

### 2.1 The problem

Two identity models with no join:

- Agented hosts are `Endpoint` rows in SQLite, keyed by id.
- Scanned hosts are `scanner.DiscoveredAsset`, keyed by IP, held in
  `scanner.cachedAssets` — **an in-memory map**. A hub restart erases every discovery,
  and nothing else in the system can join against them.

`Store.GetTopologyGraph` (`hub/pkg/storage/storage.go:2284`) builds nodes from
`ListEndpoints` plus whatever IPs appear in `events`. It never consults the scanner.
Nodes invented from flow IPs get the literal label `"Unmanaged Internal Host"`.
The default window is 1h, so a known asset that was quiet last hour does not exist
to the graph at all.

Those three facts are the whole reason Fleet, Scanner and Topology are separate pages
and the graph looks empty. The merge cannot be UI-only.

### 2.2 The asset record

Add an `assets` table, keyed on stable identity — MAC where known, else IP+subnet —
with a nullable `agent_endpoint_id`. Every field carries **provenance and confidence**.
Three evidence sources:

| Source | Confidence | Supplies |
| :--- | :--- | :--- |
| `agent` | 1.0 | hostname, OS build, agent version, containment state, process-attributed flows |
| `scan` | 0.0–1.0 | open ports, banners, OUI vendor, TTL / app-delta fingerprint, OS guess |
| `inferred` | 0.0–1.0 | role deduced from neighbours' observed flows |

**Merge rule: highest confidence wins per _field_, never per record.** Losing claims stay
visible in the expanded row — an operator must be able to see that the scanner said
"Linux" while the agent says "Ubuntu 24.04". An agent installing on a known asset
**enriches that row**; it never creates a second one.

Migration must be additive and must not disturb existing `endpoints` rows.

### 2.3 Role inference from flow

`events` already carries `src_ip, dst_ip, protocol, dst_port, action, bytes, timestamp`
and **`process_path`**. That is enough.

**Fan-in is identity.** When many agented endpoints open sessions to one static address
on 389/636, 88, 135 and 445 originating from `lsass.exe` and `svchost.exe`, in bursts at
logon, with no corresponding fan-out — that address is a domain controller, with no scan
and no agent needed. The same shape names file servers (445 fan-in, sustained bytes),
print servers (9100), hypervisors (902), and internal CAs.

Requirements:

- Every inference must produce a **human-readable rationale** rendered in the expanded
  row ("41 agented endpoints across 3 locations, from `lsass.exe`, on 389/88/135/445;
  fan-in without fan-out; nothing else on the subnet answers 88").
- Every inference is **operator-correctable** — Confirm / Not a DC. A correction outranks
  the inference permanently and feeds signature training.
- Never let an inference silently overwrite agent or scan ground truth.
- Inference runs on a schedule against the events table, not on every request.

### 2.4 Topology wiring

- **Node source becomes `assets ∪ flow endpoints`**, not flow endpoints alone. Every node
  then carries identity, evidence and role instead of a bare IP.
- **Default window 24h.** Render known-but-quiet assets as dimmed nodes rather than
  omitting them — absence is information on a security graph.
- **Aggregate to asset-pair edges** and expand ports on selection. The current query groups
  by 5-tuple with no cap; at fleet scale that is thousands of edges and an unreadable graph.
- Edge width by flow volume, colour by verdict, dashed for blocked. Port label on the
  heaviest edge per pair only.
- **Selection is shared with the asset table.** Topology is a lens on the current selection,
  not a separate destination.

### 2.5 Pass 2 acceptance

- Discovered assets survive a hub restart.
- One asset row per host regardless of how many sources know it; installing an agent on a
  discovered asset enriches rather than duplicates.
- A DC-shaped host with no agent and no scan is identified from flow alone, with a rationale
  an operator can read and correct.
- Topology draws every known asset, not only those that spoke in the window.
- Coverage becomes the fleet's real question: what is on this network that we cannot see.

---

## Constraints that outrank the design

- **Repo hygiene.** No usernames, real domains, real LAN IPs, hostnames or keys in tracked
  files. `10.0.0.x` is the deliberate stand-in; demo fixtures use `10.0.4.x` / `172.16.x`.
  Substitute, never delete. The check greps for the real values, so the pattern itself
  belongs in the private ops brief, not here -- writing it down in the public repo leaks
  exactly what it exists to catch.
- **`VERSION` is the single source of truth**; `scripts/version.sh check` is a CI gate.
- **Hub ships before agents.** Use `scripts/release.sh`; never hand-roll the two hops.
- **Offline first.** No CDN, no npm, no runtime network dependency in the console.
- Deployment topology, credentials and live access live in the private ops vault, not here.

## Gates

```
cd hub && go test -race ./...
gcc -O2 -Wall -Wextra -o /tmp/t agent/tests/test_dpi.c && /tmp/t
gcc -O2 -Wall -Wextra -o /tmp/a agent/linux/main.c            # must be warning-free
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o /tmp/w.exe \
  agent/src/{main,hub_client,service,driver_client}.c \
  -lws2_32 -lwinhttp -liphlpapi -ladvapi32
scripts/version.sh check
gitleaks detect --source .
```

Build, tests and types are not runtime evidence. Exercise the real console at
`/?demo=true` — which seeds synthetic fleet data and is the correct source for
screenshots — in all four themes, and cite what you saw.

## Out of scope

Agent-side changes, driver work, the REST API contract for existing endpoints, and the
release process. Pass 2 adds tables and handlers; it does not change how agents report.
