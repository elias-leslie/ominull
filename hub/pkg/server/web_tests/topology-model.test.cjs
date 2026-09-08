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
test("logical regions separate discovery from hosts without losing directed traffic", () => {
  const nodes = [
    {
      id: "lan",
      network_id: "lan",
      address_scope: "private",
      asset_id: "known",
    },
    {
      id: "ula",
      network_id: "ula",
      address_scope: "private",
      asset_id: "same-estate",
    },
    { id: "ll", network_id: "ll", address_scope: "link-local" },
    { id: "mc", network_id: "mc", address_scope: "multicast" },
    { id: "wan", network_id: "wan", address_scope: "public" },
    {
      id: "virtual",
      network_id: "bridge",
      address_scope: "private",
      network_kind: "virtual",
    },
  ];
  const edges = [
    { id: "lm", source: "ll", target: "mc", flow_count: 2, total_bytes: 20 },
    { id: "lw", source: "lan", target: "wan", flow_count: 3, total_bytes: 30 },
  ];
  const g = model.project({ nodes, edges }, { regions: true });
  assert.equal(g.regions.length, 4);
  assert.equal(
    g.groups.find((g) => g.members.some((n) => n.id === "ll")).parent,
    "region:discovery",
  );
  assert.equal(
    g.groups.find((g) => g.members.some((n) => n.id === "ula")).parent,
    "region:internal",
  );
  assert.equal(
    g.groups.find((g) => g.members.some((n) => n.id === "virtual")).parent,
    "region:virtual",
  );
  assert.equal(
    g.edges.reduce((s, e) => s + e.total_bytes, 0),
    50,
  );
  assert.equal(g.hostCount, 5);
  assert.equal(g.destinationCount, 1);
});
test("compact labels retain scope in evidence and link hover respects protocol", () => {
  assert.equal(
    model.shortLabel({
      is_group: true,
      label: "link-local IPv6 (segment unknown) · 12",
      members: [{ network_id: "link-local:ipv6:12" }],
    }),
    "Scoped peers · 12",
  );
  assert.equal(
    model.shortLabel({ label: "workstation", quiet: true }),
    "workstation",
  );
  const fixture = {
    ...data,
    conversations: [
      {
        source: "a",
        target: "b",
        protocol: 6,
        port: 443,
        process: "/usr/bin/client",
      },
      {
        source: "a",
        target: "b",
        protocol: 17,
        port: 53,
        process: "/usr/bin/resolver",
      },
    ],
    edges: [
      {
        ...data.edges[0],
        ports: [
          { protocol: "TCP", port: 443, flow_count: 1 },
          { protocol: "UDP", port: 53, flow_count: 1 },
        ],
      },
    ],
  };
  const p = model.project(fixture, { protocol: "TCP" });
  assert.deepEqual(
    p.edges[0].relations.map((r) => r.process),
    ["/usr/bin/client"],
  );
});
test("region collapse and personal overrides preserve host identities and external evidence", () => {
  const fixture = {
    ...data,
    nodes: data.nodes.map((n, i) => ({
      ...n,
      address_scope: i ? "public" : "private",
    })),
  };
  const p = model.project(fixture, {
    regions: true,
    regionOverrides: { lan: "virtual" },
    collapsedRegions: { virtual: true },
  });
  assert.deepEqual(
    p.regions.find((r) => r.key === "virtual").members.map((n) => n.id),
    ["a"],
  );
  assert.equal(
    p.nodes.some((n) => n.id === "group:virtual|lan"),
    false,
  );
  assert.equal(p.edges[0].source, "region:virtual");
  assert.equal(
    p.edges.reduce((n, e) => n + e.total_bytes, 0),
    data.edges.reduce((n, e) => n + e.total_bytes, 0),
  );
});
