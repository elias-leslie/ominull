# Topology workspace

Topology separates machine identity, addresses and observed communication.
Known assets use their retained asset IDs. Traffic-only addresses remain separate
address nodes; a matching hostname or domain never merges hosts. Arrows preserve
recorded source and destination, including opposite directions. They do not prove
which side initiated a session. Counts are telemetry observations and can include
multiple reporters, not deduplicated network sessions.

The workspace opens at network groups. Select a group to inspect or expand its
hosts. Each expansion adds up to 100 hosts, ordered by activity. At most 1,500
individual hosts and 3,000 directed links are drawn; omitted counts remain visible.
Search matches host names, IPs, roles, OS, observed domains and process paths.
Search selects matching host pairs; link totals retain their window observations.
Protocol filters recompute totals from matching ports. Link-status filters select
pairs containing the selected finding, rather than counting only blocked events.

The inspector distinguishes reported domains from TLS SNI and identifies the
endpoint reporting a process. Missing evidence is explicit. These observations
are associations within the selected interval, not proof of domain ownership or
an alias suitable for merging asset identities. Traffic and asset links lead to
the existing investigation views. List view provides keyboard access to the same
visible hosts and groups.

Pan mode drags the background. Select mode draws a selection box. Shift-click
adds hosts to a selection. Drag a group or selected hosts to move them together.
Pins protect positions during arrangement; Undo restores prior positions and pins.
Unpin a collapsed group before expanding it; expanded hosts can be pinned together.
Focus group enlarges an expanded cluster without hiding the rest of the graph.
Layout changes never invoke containment or policy APIs.

Saved views belong to the authenticated operator. Explicit Save records filters,
relative time window, expanded groups, positions, pins and viewport. Revision
checks reject stale writes with HTTP 409. Save as can preserve a conflicting edit
as another view. Auditors can explore but cannot write saved views. Endpoint
credentials cannot access workspace or saved-view routes.

## Implementation

The existing plain-JavaScript console mounts a separate topology module. Its DOM
and Cytoscape instance survive polling. A worker runs fCoSE layout; stale worker
results are ignored after a new layout or drag. Poll updates retain positions,
and data arriving during a drag waits until release. Navigation destroys the
worker and canvas, retaining an in-memory draft when returning from another
console section. Reloading the page requires a saved view. Graph failures retain the last successful graph and show an
error rather than replacing the graph with a false empty state.

Dependencies are pinned in `web-build/package-lock.json`. Run `npm ci` and
`npm run build` from `web-build` to regenerate the two embedded bundles. Runtime
requires no CDN or package installation. Dependency licenses ship beside bundles.
The existing CSP permits same-origin workers; no policy relaxation is required.

Graph and evidence queries use one frozen interval against canonical events.
No lifetime or daily cube is used for these window totals. Evidence is bounded
to 20,000 recent grouped relations and explicitly reports truncation. The graph
retains its complete host-pair totals when evidence is truncated; domain/process
search is then partial. Detailed Traffic remains the raw observation route.

The first release keeps canonical event queries and the existing short response
cache. It does not introduce another rollup projection: exact window semantics
remain auditable, and a new projection needs measured query pressure to justify
its migration and reconciliation cost. Graph layout runs independently of that
query on a worker. Performance evidence records query and rendering separately.

A collapsed overview uses a compact card arrangement when a force layout would
reduce labels below 11 screen pixels in the current viewport. This avoids tiny
labels on wide disconnected networks. Expanded hosts keep fCoSE layout. Compact
arrangement never overrides pins or fixed nodes outside an arrangement selection.
At widths below 1,200 pixels the inspector starts hidden to leave room for the
graph. Details toggles it; selecting a host, group or link opens it automatically.

## Logical regions and hover evidence

New workspaces separate internal networks, explicitly classified virtual networks,
external destinations and discovery traffic. Multicast and unclaimed link-local
peers seen only communicating with multicast enter Discovery, initially collapsed.
Known assets stay in the estate. Private ranges alone never imply virtualization.
An optional `kind: "virtual"` or `kind: "physical"` on an operator-configured network
provides explicit classification. Existing network settings need no migration.

The worker arranges each region independently, then packs region bounds with clear
gutters. Cross-region links cannot distort the layout within a region. Drag a
region's background to move its contents. Select it to pin all visible leaves,
collapse it or focus it. Pinned contents must be unpinned before collapsing the
region. The network group inspector offers a personal visual-region override.
This changes the saved view, never network policy or asset identity.

Saved views retain regions, overrides, collapsed regions, positions and pins.
Older views open in their original flat layout to preserve their coordinates.
Enable “Separate logical regions” under Filters to convert an old view, then Save.

Canvas labels omit repeated unknown-scope and quiet-window text. Hover or inspect
an item for full scope and activity evidence. Counts describe addresses, including
multicast destinations, rather than claiming every address is a physical host.

Incoming links are blue and outgoing links teal relative to the hovered or selected
node or region. Arrowheads and the text key retain direction without relying on
color. With no node reference, links retain neutral/status colors. Blocked links
remain dashed when direction colors apply; findings also appear in link evidence.

Link tooltips show observed protocols/ports, counts, measured bytes, domains and
short executable names with reporting hosts. Full executable paths and attribution
remain in the inspector. Evidence follows protocol filtering. Domain associations
do not establish machine identity. List view exposes the same tooltips on keyboard
focus and provides buttons to inspect every drawn link. Tooltips remain hoverable,
can be dismissed with Escape and have no interactive controls inside them.

Design references: W3C requires information beyond color alone and predictable,
dismissible, hoverable content. See [Use of Color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html)
and [Content on Hover or Focus](https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html).
Graphviz's [tooltip reference](https://graphviz.org/docs/attrs/tooltip/) also
recommends explicit tooltip content when derived labels are unhelpful. These
principles informed the implementation; they are not a claim of a full WCAG audit.
