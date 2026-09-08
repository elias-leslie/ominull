const cytoscape = require("cytoscape");
cytoscape.use(require("cytoscape-fcose"));
const styles = [
  { selector: "node", style: { width: 150, height: 50 } },
  { selector: "node[groupNode]", style: { width: 190, height: 74 } },
  { selector: "node[regionNode]", style: { width: 260, height: 100 } },
  { selector: ":parent", style: { padding: 32 } },
];
function create(elements) {
  return cytoscape({
    headless: true,
    styleEnabled: true,
    elements,
    style: styles,
  });
}
function layoutSingle(cy, fixed, viewport) {
  cy.layout({
    name: "fcose",
    animate: false,
    fit: false,
    quality: "default",
    randomize: true,
    packComponents: false,
    numIter: 700,
    nodeSeparation: 100,
    idealEdgeLength: 100,
    nodeRepulsion: 9000,
    fixedNodeConstraint: fixed || [],
  }).run();
  let compact = false;
  // A wide disconnected overview can fit geometrically while its labels become
  // unreadable. Compact only collapsed groups, never user-pinned layouts.
  if (
    viewport &&
    !(fixed || []).length &&
    cy.nodes().every((n) => n.data("groupNode") && !n.isParent())
  ) {
    const width = Math.max(1, viewport.width - 50);
    const height = Math.max(1, viewport.height - 50);
    const bounds = cy.nodes().boundingBox();
    if (15 * Math.min(width / bounds.w, height / bounds.h) < 11) {
      const nodes = cy.nodes();
      let columns = 1,
        best = 0;
      for (let c = 1; c <= nodes.length; c++) {
        const scale = Math.min(
          width / (c * 230 - 38),
          height / (Math.ceil(nodes.length / c) * 110 - 34),
        );
        if (scale > best) {
          best = scale;
          columns = c;
        }
      }
      nodes.forEach((n, i) => {
        const row = Math.floor(i / columns);
        const rowCount = Math.min(columns, nodes.length - row * columns);
        n.position({
          x: ((i % columns) + (columns - rowCount) / 2) * 230,
          y: row * 110,
        });
      });
      compact = true;
    }
  }

  return compact;
}
function layoutRegions(cy, fixed, viewport) {
  const order = [
    "region:internal",
    "region:virtual",
    "region:external",
    "region:unknown",
    "region:discovery",
  ];
  const chunks = [];
  for (const region of cy
    .nodes()
    .filter((n) => n.data("regionNode"))
    .sort((a, b) => order.indexOf(a.id()) - order.indexOf(b.id()))) {
    const members = region.isParent() ? region.descendants() : region;
    const ids = new Set(members.map((n) => n.id()));
    const elements = members.map((n) => ({
      data: {
        ...n.data(),
        parent: n.data("parent") === region.id() ? undefined : n.data("parent"),
      },
      position: { ...n.position() },
    }));
    cy.edges()
      .filter((e) => ids.has(e.source().id()) && ids.has(e.target().id()))
      .forEach((e) => elements.push({ data: { ...e.data() } }));
    const local = create(elements),
      localFixed = (fixed || []).filter((p) => ids.has(p.nodeId));
    try {
      if (
        !localFixed.length &&
        local
          .nodes()
          .every(
            (n) =>
              !n.isParent() && (n.data("groupNode") || n.data("regionNode")),
          )
      ) {
        const nodes = local.nodes(),
          cols = Math.min(3, Math.ceil(Math.sqrt(nodes.length * 0.65)));
        nodes.forEach((n, i) =>
          n.position({ x: (i % cols) * 230, y: Math.floor(i / cols) * 120 }),
        );
      } else layoutSingle(local, localFixed, null);
      const b = local.nodes().boundingBox(),
        positions = {};
      local
        .nodes()
        .filter((n) => !n.isParent())
        .forEach((n) => (positions[n.id()] = { ...n.position() }));
      chunks.push({
        id: region.id(),
        positions,
        bounds: b,
        insetX: region.isParent() ? 48 : 8,
        insetY: region.isParent() ? 64 : 8,
        width: b.w + (region.isParent() ? 96 : 16),
        height: b.h + (region.isParent() ? 112 : 16),
        fixed: !!localFixed.length,
        x: b.x1 - (region.isParent() ? 48 : 8),
        y: b.y1 - (region.isParent() ? 64 : 8),
      });
    } finally {
      local.destroy();
    }
  }
  const gap = 120,
    moving = chunks.filter((c) => !c.fixed),
    placed = chunks.filter((c) => c.fixed);
  // At most five regions. Compare horizontal shelves and vertical stacks.
  let best = null;
  for (const vertical of [false, true]) {
    for (let mask = 0; mask < 1 << Math.max(0, moving.length - 1); mask++) {
      let x = 0,
        y = 0,
        rowHeight = 0,
        width = 0;
      const rects = [];
      moving.forEach((c, i) => {
        if (i && mask & (1 << (i - 1))) {
          y += rowHeight + gap;
          x = 0;
          rowHeight = 0;
        }
        rects.push({ ...c, x: vertical ? y : x, y: vertical ? x : y });
        x += (vertical ? c.height : c.width) + gap;
        rowHeight = Math.max(rowHeight, vertical ? c.width : c.height);
        width = Math.max(width, x - gap);
      });
      const height = y + rowHeight;
      const score = Math.min(
        Math.max(1, (viewport?.width || 1000) - 50) /
          Math.max(1, vertical ? height : width),
        Math.max(1, (viewport?.height || 650) - 80) /
          Math.max(1, vertical ? width : height),
      );
      if (!best || score > best.score) best = { score, rects };
    }
  }
  for (const c of best?.rects || []) {
    let hit;
    while (
      (hit = placed.find(
        (p) =>
          c.x < p.x + p.width + gap &&
          c.x + c.width + gap > p.x &&
          c.y < p.y + p.height + gap &&
          c.y + c.height + gap > p.y,
      ))
    )
      c.y = hit.y + hit.height + gap;
    placed.push(c);
  }
  const positions = {};
  for (const c of placed) {
    const dx = c.fixed ? 0 : c.x + c.insetX - c.bounds.x1,
      dy = c.fixed ? 0 : c.y + c.insetY - c.bounds.y1;
    for (const [id, p] of Object.entries(c.positions))
      positions[id] = { x: p.x + dx, y: p.y + dy };
  }
  return positions;
}
function layoutScope(cy, fixed, viewport, scope) {
  const leaves = cy.nodes().filter((n) => !n.isParent());
  const positions = Object.fromEntries(
    (fixed || []).map((p) => [p.nodeId, { ...p.position }]),
  );
  const detail = scope === "host" || scope === "process";
  const left = leaves.filter((n) =>
    detail ? !!n.data("parent") : !n.data("context"),
  );
  const right = leaves.filter((n) => !left.has(n));
  const occupied = Object.values(positions);
  function grid(nodes, start, columns) {
    let cell = 0;
    nodes.forEach((n) => {
      if (positions[n.id()]) return;
      let p;
      do {
        p = {
          x: start + (cell % columns) * 190,
          y: Math.floor(cell / columns) * 125,
        };
        cell++;
      } while (
        occupied.some(
          (q) => Math.abs(q.x - p.x) < 155 && Math.abs(q.y - p.y) < 100,
        )
      );
      positions[n.id()] = p;
      occupied.push(p);
    });
  }
  const cols = detail
    ? Math.min(2, Math.max(1, Math.ceil(Math.sqrt(left.length / 2))))
    : Math.min(
        5,
        Math.max(
          1,
          Math.ceil(
            Math.sqrt(
              (left.length * (viewport?.width || 1000)) /
                (viewport?.height || 500),
            ),
          ),
        ),
      );
  grid(left, 0, cols);
  const leftMax = Math.max(0, ...left.map((n) => positions[n.id()].x));
  grid(
    right,
    leftMax + 300,
    detail
      ? Math.min(3, Math.max(1, Math.ceil(Math.sqrt(right.length))))
      : Math.min(2, Math.max(1, Math.ceil(Math.sqrt(right.length / 2)))),
  );
  return positions;
}
self.onmessage = function (event) {
  const { id, elements, fixed, viewport, scope } = event.data;
  let cy;
  try {
    cy = create(elements);
    if (scope && scope !== "overview") {
      self.postMessage({
        id,
        positions: layoutScope(cy, fixed, viewport, scope),
      });
    } else if (cy.nodes().some((n) => n.data("regionNode"))) {
      self.postMessage({
        id,
        positions: layoutRegions(cy, fixed, viewport),
        regioned: true,
      });
    } else {
      const compact = layoutSingle(cy, fixed, viewport),
        positions = {};
      cy.nodes().forEach((n) => (positions[n.id()] = { ...n.position() }));
      self.postMessage({ id, positions, compact });
    }
  } catch (e) {
    self.postMessage({ id, error: String(e.message || e) });
  } finally {
    if (cy) cy.destroy();
  }
};
