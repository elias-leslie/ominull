/* Pure view projection shared by browser and behavioral tests. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.OminullTopologyModel = factory();
})(typeof window === "object" ? window : globalThis, function () {
  "use strict";
  function coverage(n) {
    return n.endpoint_id || n.type === "managed" ? "managed" : "unmanaged";
  }
  function groupKey(n, mode) {
    return mode === "coverage"
      ? coverage(n)
      : mode === "role"
        ? n.role || "Unknown role"
        : n.network_id || "unknown";
  }
  function project(data, options) {
    const o = options || {},
      all = data.nodes || [],
      relations = data.conversations || [],
      query = (o.query || "").trim().toLowerCase();
    const direct = new Set(
      all
        .filter((n) =>
          [n.label, n.ip, n.os, n.role].join(" ").toLowerCase().includes(query),
        )
        .map((n) => n.id),
    );
    const matching = new Set(
      relations
        .filter((r) =>
          [r.domain, r.process].join(" ").toLowerCase().includes(query),
        )
        .map((r) => JSON.stringify([r.source, r.target])),
    );
    let edges = (data.edges || [])
      .map((e) => {
        if (!o.protocol) return e;
        const ports = (
          e.ports || [
            {
              protocol: e.protocol,
              flow_count: e.flow_count,
              total_bytes: e.total_bytes,
              measured_flows: e.measured_flows,
              verdict: e.verdict,
            },
          ]
        ).filter((p) => p.protocol === o.protocol);
        return {
          ...e,
          ports,
          flow_count: ports.reduce((s, p) => s + (p.flow_count || 0), 0),
          total_bytes: ports.reduce((s, p) => s + (p.total_bytes || 0), 0),
          measured_flows: ports.reduce(
            (s, p) => s + (p.measured_flows || 0),
            0,
          ),
          verdict: ports.some((p) => p.verdict === "blocked")
            ? "blocked"
            : ports.some((p) => p.verdict === "anomalous")
              ? "anomalous"
              : "clean",
        };
      })
      .filter(
        (e) =>
          (!o.verdict || e.verdict === o.verdict) &&
          (!o.protocol || e.ports.length),
      );
    if (query)
      edges = edges.filter(
        (e) =>
          direct.has(e.source) ||
          direct.has(e.target) ||
          matching.has(JSON.stringify([e.source, e.target])),
      );
    const touched = new Set(edges.flatMap((e) => [e.source, e.target]));
    const nodes = all.filter(
      (n) =>
        (!o.activeOnly || !n.quiet) &&
        (!o.coverage || coverage(n) === o.coverage) &&
        (!query || direct.has(n.id) || touched.has(n.id)),
    );
    const keep = new Set(nodes.map((n) => n.id));
    edges = edges.filter((e) => keep.has(e.source) && keep.has(e.target));
    const nodeByID = new Map(nodes.map((n) => [n.id, n]));
    const groups = new Map(),
      weights = new Map();
    edges.forEach((e) =>
      [e.source, e.target].forEach((id) =>
        weights.set(id, (weights.get(id) || 0) + (e.flow_count || 0)),
      ),
    );
    nodes.forEach((n) => {
      const k = groupKey(n, o.group);
      if (!groups.has(k))
        groups.set(k, {
          id: "group:" + k,
          key: k,
          label:
            o.group && o.group !== "network"
              ? o.group === "coverage"
                ? k === "managed"
                  ? "Agent installed"
                  : "No agent"
                : k
              : n.network_label || "Unknown segment",
          members: [],
          is_group: true,
          type: "group",
          total_bytes: 0,
          flow_count: 0,
          internal_flows: 0,
        });
      groups.get(k).members.push(n);
    });
    const result = [],
      mapping = new Map();
    let hidden = 0,
      budget = 1500;
    [...groups.values()]
      .sort((a, b) => a.label.localeCompare(b.label))
      .forEach((g) => {
        g.members.sort(
          (a, b) =>
            (weights.get(b.id) || 0) - (weights.get(a.id) || 0) ||
            a.id.localeCompare(b.id),
        );
        const count = Math.min(
          (o.expanded || {})[g.key] || 0,
          budget,
          g.members.length,
        );
        g.expanded = count > 0;
        g.shown = count;
        g.count = g.members.length;
        result.push(g);
        g.members.forEach((n, i) => {
          if (i < count) {
            result.push({ ...n, parent: g.id });
            mapping.set(n.id, n.id);
          } else mapping.set(n.id, g.id);
        });
        if (count) {
          hidden += g.members.length - count;
          budget -= count;
        }
      });
    const merged = new Map();
    edges.forEach((e) => {
      const source = mapping.get(e.source),
        target = mapping.get(e.target);
      if (!source || !target) return;
      if (source === target) {
        const g = groups.get(groupKey(nodeByID.get(e.source), o.group));
        if (g) {
          g.internal_flows += e.flow_count || 0;
          g.total_bytes += e.total_bytes || 0;
        }
        return;
      }
      const id = JSON.stringify([source, target]);
      if (!merged.has(id))
        merged.set(id, {
          id,
          source,
          target,
          flow_count: 0,
          total_bytes: 0,
          measured_flows: 0,
          verdict: "clean",
          ports: [],
          originals: [],
        });
      const m = merged.get(id);
      m.flow_count += e.flow_count || 0;
      m.total_bytes += e.total_bytes || 0;
      m.measured_flows += e.measured_flows || 0;
      m.originals.push(e.id);
      m.ports.push(...(e.ports || []));
      if (
        e.verdict === "blocked" ||
        (e.verdict === "anomalous" && m.verdict === "clean")
      )
        m.verdict = e.verdict;
    });
    const drawnEdges = [...merged.values()].sort(
      (a, b) => b.flow_count - a.flow_count || a.id.localeCompare(b.id),
    );
    return {
      nodes: result,
      edges: drawnEdges.slice(0, 3000),
      groups: [...groups.values()],
      hidden,
      omittedEdges: Math.max(0, drawnEdges.length - 3000),
      matched: nodes.length,
      total: all.length,
    };
  }
  return { project, groupKey, coverage };
});
