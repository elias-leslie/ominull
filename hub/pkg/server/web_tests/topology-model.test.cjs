const { test } = require("node:test");
const assert = require("node:assert/strict");
const model = require("../web/topology-model.js");
const data = {
  nodes: [
    {
      id: "a",
      label: "Client",
      ip: "10.0.4.2",
      network_id: "lan",
      network_label: "LAN",
      type: "managed",
    },
    {
      id: "b",
      label: "API",
      ip: "2001:db8::9",
      network_id: "wan",
      network_label: "External",
      type: "cloud",
    },
  ],
  edges: [
    {
      id: "ab",
      source: "a",
      target: "b",
      flow_count: 3,
      total_bytes: 17,
      verdict: "clean",
    },
    {
      id: "ba",
      source: "b",
      target: "a",
      flow_count: 2,
      total_bytes: 23,
      verdict: "blocked",
    },
  ],
  conversations: [
    {
      source: "a",
      target: "b",
      domain: "api.example.invalid",
      process: "/usr/bin/client",
      port: 443,
    },
  ],
};
test("collapsed graph preserves opposite directions and totals", () => {
  const g = model.project(data, {});
  assert.equal(g.nodes.length, 2);
  assert.equal(g.edges.length, 2);
  assert.notEqual(g.edges[0].source, g.edges[1].source);
  assert.equal(
    g.edges.reduce((n, e) => n + e.total_bytes, 0),
    40,
  );
});
test("domain search keeps only observed matching direction", () => {
  const g = model.project(data, { query: "api.example.invalid" });
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].total_bytes, 17);
});
test("expansion retains neighbors as groups and uses stable host identity", () => {
  const g = model.project(data, { expanded: { lan: 50 } });
  assert.ok(g.nodes.some((n) => n.id === "a"));
  assert.ok(g.nodes.some((n) => n.id === "group:wan"));
  assert.ok(g.edges.some((e) => e.source === "a" && e.target === "group:wan"));
});
test("10k hosts expand progressively with explicit hidden count", () => {
  const nodes = Array.from({ length: 10000 }, (_, i) => ({
    id: "host" + i,
    network_id: "lan",
  }));
  const g = model.project({ nodes, edges: [] }, { expanded: { lan: 100 } });
  assert.equal(g.nodes.filter((n) => !n.is_group).length, 100);
  assert.equal(g.hidden, 9900);
});
test("protocol filters count only matching observations on a mixed link", () => {
  const d = {
    nodes: data.nodes,
    edges: [
      {
        id: "ab",
        source: "a",
        target: "b",
        flow_count: 7,
        total_bytes: 90,
        ports: [
          {
            protocol: "TCP",
            flow_count: 3,
            total_bytes: 30,
            measured_flows: 3,
            verdict: "clean",
          },
          {
            protocol: "UDP",
            flow_count: 4,
            total_bytes: 60,
            measured_flows: 4,
            verdict: "clean",
          },
        ],
      },
    ],
  };
  const g = model.project(d, { protocol: "TCP" });
  assert.equal(g.edges[0].flow_count, 3);
  assert.equal(g.edges[0].total_bytes, 30);
});
