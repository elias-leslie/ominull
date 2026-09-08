const { test } = require("node:test");
const assert = require("node:assert/strict");
const M = require("../web/topology-model.js");
const nodes = [
  {
    id: "a",
    label: "Workstation",
    endpoint_id: "agent-a",
    network_id: "lan",
    address_scope: "private",
  },
  {
    id: "b",
    label: "Remote",
    ip: "203.0.113.8",
    network_id: "wan",
    address_scope: "public",
  },
  { id: "c", label: "Other", network_id: "lan", address_scope: "private" },
];
const relation = (endpoint_id, process, flow_count) => ({
  source: "a",
  target: "b",
  endpoint_id,
  process,
  flow_count,
  total_bytes: 10,
  protocol: 6,
  port: 443,
  domain: "api.example.invalid",
});
const data = {
  nodes,
  edges: [
    {
      id: "ab",
      source: "a",
      target: "b",
      flow_count: 9,
      total_bytes: 30,
      ports: [{ protocol: "TCP", port: 443, flow_count: 9 }],
      verdict: "clean",
    },
  ],
  conversations: [
    relation("agent-a", "/usr/bin/browser", 4),
    relation("agent-other", "/usr/bin/foreign", 2),
  ],
};
test("host scene attributes only processes reported by that host and retains residual traffic", () => {
  const p = M.scene(data, {
    scope: { kind: "host", id: "a" },
    group: "network",
  });
  const processes = p.nodes.filter((n) => n.type === "process");
  assert.equal(processes.length, 1);
  assert.equal(processes[0].process, "/usr/bin/browser");
  assert.equal(processes[0].endpoint_id, "agent-a");
  assert.equal(
    p.edges.reduce((s, e) => s + e.flow_count, 0),
    9,
  );
  assert.ok(p.nodes.some((n) => n.label === "api.example.invalid"));
  assert.ok(
    p.edges.every(
      (e) =>
        p.nodes.some((n) => n.id === e.source) &&
        p.nodes.some((n) => n.id === e.target),
    ),
  );
});
test("group drill shows members and explicit neighboring context, not unrelated hosts", () => {
  const overview = M.project(data, { group: "network", regions: true });
  const g = overview.groups.find((g) => g.members.some((n) => n.id === "a"));
  const p = M.scene(data, {
    group: "network",
    regions: true,
    scope: { kind: "group", id: g.id },
  });
  assert.ok(p.nodes.some((n) => n.id === "a"));
  assert.ok(p.nodes.some((n) => n.id === "c"));
  assert.ok(p.nodes.some((n) => n.context));
  assert.equal(
    p.edges.reduce((s, e) => s + e.flow_count, 0),
    9,
  );
});
test("process drill retains full-path identity and excludes other reporter records", () => {
  const p = M.scene(data, {
    scope: { kind: "process", id: "a", process: "/usr/bin/browser" },
  });
  assert.equal(
    p.edges.reduce((s, e) => s + e.flow_count, 0),
    4,
  );
  assert.ok(
    p.edges.every((e) => e.relations.every((r) => r.endpoint_id === "agent-a")),
  );
});
test("missing selected host produces an explicit empty scene", () => {
  const p = M.scene(data, { scope: { kind: "host", id: "gone" } });
  assert.equal(p.nodes.length, 0);
  assert.match(p.notice, /no longer/);
});
test("incoming domain evidence is not reassigned to the remote source", () => {
  const p = M.scene(
    {
      ...data,
      edges: [{ ...data.edges[0], source: "b", target: "a", flow_count: 4 }],
      conversations: [
        {
          ...relation("agent-a", "/bin/listener", 4),
          source: "b",
          target: "a",
        },
      ],
    },
    { scope: { kind: "host", id: "a" } },
  );
  assert.ok(!p.nodes.some((n) => n.type === "domain"));
  assert.equal(p.edges[0].source, "b");
  assert.ok(p.edges[0].target.startsWith("process:"));
  assert.equal(p.edges[0].relations[0].domain, "api.example.invalid");
});
test("host peer focus and limits disclose omitted links without changing totals", () => {
  const p = M.scene(data, {
    scope: { kind: "host", id: "a", peer: "b" },
    scopeLimit: 1,
  });
  assert.equal(p.edges.length, 1);
  assert.equal(p.omittedEdges, 1);
  const none = M.scene(data, { scope: { kind: "host", id: "a", peer: "c" } });
  assert.equal(none.edges.length, 0);
});
test("host scene has no stale grouping parents on remote destinations", () => {
  const p = M.scene(data, { scope: { kind: "host", id: "a" } });
  assert.ok(
    p.nodes.every(
      (n) => !n.parent || p.nodes.some((parent) => parent.id === n.parent),
    ),
  );
  assert.equal(p.nodes.filter((n) => !n.parent && n.id !== "a").length, 2);
});
