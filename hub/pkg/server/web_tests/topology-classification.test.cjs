const { test } = require("node:test");
const assert = require("node:assert/strict");
const { groupKey } = require("../web/topology-model.js");
test("network grouping preserves server scope and does not infer identity from addresses or names", () => {
  for (const n of [
    { ip: "fd12::2", network_id: "private:ipv6:" },
    { ip: "2001:db8:4::2", network_id: "2001:db8:4::/64" },
    { ip: "2001:db8:5::2", network_id: "2001:db8:5::/64" },
  ])
    assert.equal(groupKey(n, "network"), n.network_id);
  assert.equal(
    groupKey({ label: "hub", ip: "10.0.0.58", type: "unmanaged" }, "coverage"),
    "unmanaged",
  );
  assert.equal(
    groupKey({ label: "router", role: "workstation" }, "role"),
    "workstation",
  );
});
