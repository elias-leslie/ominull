const { test } = require("node:test");
const assert = require("node:assert/strict");
let result;
global.self = {
  postMessage: (value) => {
    result = value;
  },
};
require("./layout.cjs");
test("disconnected overview retains readable labels in the requested viewport", () => {
  const nodes = Array.from({ length: 17 }, (_, i) => ({
    data: { id: "g" + i, groupNode: true },
  }));
  const edges = nodes.flatMap((n, i) =>
    i === 0 || i === 11
      ? []
      : [
          {
            data: {
              id: "e" + i,
              source: i < 11 ? "g0" : "g11",
              target: n.data.id,
            },
          },
        ],
  );
  self.onmessage({
    data: {
      id: 1,
      elements: [...nodes, ...edges],
      fixed: [],
      viewport: { width: 886, height: 525 },
    },
  });
  assert.equal(result.error, undefined);
  const p = Object.values(result.positions);
  assert.equal(p.length, 17);
  const width =
    Math.max(...p.map((p) => p.x)) - Math.min(...p.map((p) => p.x)) + 192;
  const height =
    Math.max(...p.map((p) => p.y)) - Math.min(...p.map((p) => p.y)) + 76;
  const zoom = Math.min(836 / width, 475 / height);
  assert.ok(15 * zoom >= 11, `overview labels shrink to ${15 * zoom}px`);
});
test("compact overview never overrides a pinned position", () => {
  const nodes = Array.from({ length: 17 }, (_, i) => ({
    data: { id: "p" + i, groupNode: true },
  }));
  const fixed = [{ nodeId: "p0", position: { x: 123, y: 456 } }];
  self.onmessage({
    data: {
      id: 2,
      elements: nodes,
      fixed,
      viewport: { width: 886, height: 525 },
    },
  });
  assert.equal(result.error, undefined);
  assert.equal(result.compact, false);
  assert.deepEqual(result.positions.p0, fixed[0].position);
});
test("logical regions keep clear space despite cross-region traffic", () => {
  const elements = [
    { data: { id: "region:internal", regionNode: true } },
    { data: { id: "region:external", regionNode: true } },
    ...["a", "b"].map((id) => ({
      data: { id, parent: "region:internal", groupNode: true },
    })),
    ...["c", "d"].map((id) => ({
      data: { id, parent: "region:external", groupNode: true },
    })),
    ...[
      ["a", "c"],
      ["a", "d"],
      ["b", "c"],
      ["b", "d"],
    ].map(([source, target], i) => ({
      data: { id: "cross" + i, source, target },
    })),
  ];
  self.onmessage({
    data: {
      id: 3,
      elements,
      fixed: [],
      viewport: { width: 1200, height: 700 },
    },
  });
  assert.equal(result.error, undefined);
  const box = (ids) => ({
    left: Math.min(...ids.map((id) => result.positions[id].x)) - 128,
    right: Math.max(...ids.map((id) => result.positions[id].x)) + 128,
    top: Math.min(...ids.map((id) => result.positions[id].y)) - 80,
    bottom: Math.max(...ids.map((id) => result.positions[id].y)) + 64,
  });
  const a = box(["a", "b"]),
    b = box(["c", "d"]);
  assert.ok(
    a.right + 100 <= b.left ||
      b.right + 100 <= a.left ||
      a.bottom + 100 <= b.top ||
      b.bottom + 100 <= a.top,
    "regions do not have a clear gutter",
  );
});
test("cross-region links do not pull apart a region's internal arrangement", () => {
  const elements = [
    { data: { id: "region:internal", regionNode: true } },
    { data: { id: "region:external", regionNode: true } },
    ...["a", "b", "c"].map((id) => ({
      data: { id, parent: "region:internal", groupNode: true },
    })),
    { data: { id: "d", parent: "region:external", groupNode: true } },
  ];
  self.onmessage({
    data: {
      id: 4,
      elements,
      fixed: [],
      viewport: { width: 1200, height: 700 },
    },
  });
  const before = {
    x: result.positions.a.x - result.positions.b.x,
    y: result.positions.a.y - result.positions.b.y,
  };
  self.onmessage({
    data: {
      id: 5,
      elements: [
        ...elements,
        { data: { id: "traffic", source: "a", target: "d" } },
      ],
      fixed: [],
      viewport: { width: 1200, height: 700 },
    },
  });
  assert.ok(
    Math.abs(result.positions.a.x - result.positions.b.x - before.x) < 0.01 &&
      Math.abs(result.positions.a.y - result.positions.b.y - before.y) < 0.01,
    "cross-region traffic changed the internal arrangement",
  );
});
test("arranging other regions retains every pinned region member", () => {
  const elements = [
    { data: { id: "region:internal", regionNode: true } },
    { data: { id: "region:external", regionNode: true } },
    ...["a", "b"].map((id, i) => ({
      data: { id, parent: "region:internal", groupNode: true },
      position: { x: 350 + i * 250, y: 400 },
    })),
    { data: { id: "c", parent: "region:external", groupNode: true } },
  ];
  const fixed = elements
    .filter((e) => e.position)
    .map((e) => ({ nodeId: e.data.id, position: e.position }));
  self.onmessage({
    data: { id: 6, elements, fixed, viewport: { width: 1200, height: 700 } },
  });
  assert.equal(result.error, undefined);
  fixed.forEach((p) =>
    assert.deepEqual(result.positions[p.nodeId], p.position),
  );
});
test("default regions retain readable group labels on a narrow console", () => {
  const elements = [
    { data: { id: "region:internal", regionNode: true } },
    { data: { id: "region:external", regionNode: true } },
    { data: { id: "region:discovery", regionNode: true } },
    ...Array.from({ length: 6 }, (_, i) => ({
      data: { id: "lan" + i, parent: "region:internal", groupNode: true },
    })),
    { data: { id: "wan", parent: "region:external", groupNode: true } },
  ];
  self.onmessage({
    data: { id: 7, elements, fixed: [], viewport: { width: 946, height: 378 } },
  });
  assert.equal(result.error, undefined);
  const boxes = Object.entries(result.positions).map(([id, p]) => ({
    left: p.x - (id.startsWith("region:") ? 131 : 139),
    right: p.x + (id.startsWith("region:") ? 131 : 139),
    top: p.y - (id.startsWith("region:") ? 51 : 111),
    bottom: p.y + (id.startsWith("region:") ? 51 : 81),
  }));
  const w =
      Math.max(...boxes.map((b) => b.right)) -
      Math.min(...boxes.map((b) => b.left)),
    h =
      Math.max(...boxes.map((b) => b.bottom)) -
      Math.min(...boxes.map((b) => b.top));
  const size = 15 * Math.min(896 / w, 328 / h);
  assert.ok(size >= 11, `labels shrink to ${size}px`);
});
