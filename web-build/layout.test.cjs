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
