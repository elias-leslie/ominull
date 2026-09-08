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
  const regionDefinitions = {
    internal: {
      label: "Internal networks",
      description:
        "Known estate and local address space. Address scope alone does not prove a routed LAN.",
    },
    virtual: {
      label: "Virtual / container networks",
      description:
        "Explicitly classified networks or a personal view override.",
    },
    external: {
      label: "External destinations",
      description:
        "Public addresses outside the known estate. Domains remain observed associations.",
    },
    discovery: {
      label: "Discovery & multicast",
      description:
        "Multicast destinations and unclaimed link-local peers observed only communicating with multicast.",
    },
    unknown: {
      label: "Unclassified",
      description: "Insufficient address or estate evidence.",
    },
  };
  function regionAssignments(data, options) {
    const all = data.nodes || [],
      byID = new Map(all.map((n) => [n.id, n]));
    const peers = new Map();
    (data.edges || []).forEach((e) => {
      for (const [a, b] of [
        [e.source, e.target],
        [e.target, e.source],
      ]) {
        if (!peers.has(a)) peers.set(a, []);
        peers.get(a).push(byID.get(b));
      }
    });
    return new Map(
      all.map((n) => {
        const override = (options.regionOverrides || {})[
          n.network_id || "unknown"
        ];
        let region = "unknown";
        if (regionDefinitions[override]) region = override;
        else if (n.address_scope === "multicast") region = "discovery";
        else if (n.network_kind === "virtual") region = "virtual";
        else if (
          n.address_scope === "link-local" &&
          !n.asset_id &&
          !n.endpoint_id &&
          !n.estate_member &&
          (peers.get(n.id) || []).length &&
          peers.get(n.id).every((p) => p && p.address_scope === "multicast")
        )
          region = "discovery";
        else if (
          n.estate_member ||
          n.asset_id ||
          n.endpoint_id ||
          ["private", "shared", "link-local"].includes(n.address_scope) ||
          n.type === "managed"
        )
          region = "internal";
        else if (n.address_scope === "public" || n.type === "cloud")
          region = "external";
        return [n.id, region];
      }),
    );
  }
  function shortLabel(n) {
    if (n.is_region) return regionDefinitions[n.key].label;
    const label = n.label || n.ip || n.id;
    if (!n.is_group) return label;
    const member = (n.members || [])[0] || {};
    const net = member.network_id || "";
    // Only shorten generated labels. Operator-supplied names remain intact.
    if (label.includes("(segment unknown)")) {
      const zone = net.split(":").slice(2).join(":");
      if (net.startsWith("link-local:"))
        return "Scoped peers" + (zone ? " · " + zone : "");
      if (net.startsWith("multicast:")) return "Multicast";
      if (net.startsWith("private:")) return "Local addresses";
      if (net === "estate-unassigned") return "Known estate";
    }
    return label
      .replace(" (address group)", "")
      .replace(/^Unknown (role|segment)$/, "Unclassified");
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
    const assignments = regionAssignments(data, o),
      regionMap = new Map(),
      groupByNode = new Map();
    const groups = new Map(),
      weights = new Map();
    edges.forEach((e) =>
      [e.source, e.target].forEach((id) =>
        weights.set(id, (weights.get(id) || 0) + (e.flow_count || 0)),
      ),
    );
    nodes.forEach((n) => {
      const region = assignments.get(n.id);
      const baseKey = groupKey(n, o.group);
      const k = o.regions ? region + "|" + baseKey : baseKey;
      groupByNode.set(n.id, k);
      if (o.regions && !regionMap.has(region))
        regionMap.set(region, {
          id: "region:" + region,
          key: region,
          ...regionDefinitions[region],
          is_region: true,
          type: "region",
          members: [],
          count: 0,
          collapsed: !!(o.collapsedRegions || {})[region],
        });
      if (o.regions) {
        regionMap.get(region).members.push(n);
        regionMap.get(region).count++;
      }

      if (!groups.has(k))
        groups.set(k, {
          id: "group:" + k,
          key: k,
          baseKey,
          parent: o.regions ? "region:" + region : undefined,
          region: region,
          label:
            o.group && o.group !== "network"
              ? o.group === "coverage"
                ? baseKey === "managed"
                  ? "Agent installed"
                  : "No agent"
                : baseKey
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
        const region = regionMap.get(g.region);
        if (region && region.collapsed) {
          g.members.forEach((n) => mapping.set(n.id, region.id));
          return;
        }
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
        const g = groups.get(groupByNode.get(e.source));
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
          relations: [],
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
    const keptPairs = new Set(
      edges.map((e) => JSON.stringify([e.source, e.target])),
    );
    relations.forEach((r) => {
      if (!keptPairs.has(JSON.stringify([r.source, r.target]))) return;
      const protocol =
        r.protocol === 6
          ? "TCP"
          : r.protocol === 17
            ? "UDP"
            : [1, 58].includes(r.protocol)
              ? "ICMP"
              : String(r.protocol);
      if (o.protocol && o.protocol !== protocol) return;
      const edge = merged.get(
        JSON.stringify([mapping.get(r.source), mapping.get(r.target)]),
      );
      if (edge) edge.relations.push(r);
    });
    const drawnEdges = [...merged.values()].sort(
      (a, b) => b.flow_count - a.flow_count || a.id.localeCompare(b.id),
    );
    return {
      nodes: [...regionMap.values(), ...result],
      regions: [...regionMap.values()],
      hostCount: nodes.filter((n) => n.address_scope !== "multicast").length,
      destinationCount: nodes.filter((n) => n.address_scope === "multicast")
        .length,
      edges: drawnEdges.slice(0, 3000),
      groups: [...groups.values()],
      hidden,
      omittedEdges: Math.max(0, drawnEdges.length - 3000),
      matched: nodes.length,
      total: all.length,
    };
  }
  return { project, groupKey, coverage, regionDefinitions, shortLabel };
});
