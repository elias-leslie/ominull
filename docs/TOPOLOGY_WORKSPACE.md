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
