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
  // Scope changes are explicit navigation. Zoom only changes magnification.
  function scene(data, options = {}) {
    const scope = options.scope;
    if (!scope || scope.kind === "overview") return project(data, options);
    const empty = {
      nodes: [],
      edges: [],
      groups: [],
      regions: [],
      matched: 0,
      total: (data.nodes || []).length,
      hidden: 0,
      omittedEdges: 0,
    };
    if (scope.kind === "group" || scope.kind === "region") {
      const base = project(data, {
        ...options,
        expanded: {},
        collapsedRegions: {},
      });
      const targets = base.groups.filter((g) =>
        scope.kind === "group"
          ? g.id === scope.id
          : "region:" + g.region === scope.id,
      );
      if (!targets.length)
        return {
          ...empty,
          notice: "This group has no addresses matching the current filters.",
        };
      const expanded = {};
      targets.forEach(
        (g) =>
          (expanded[g.key] =
            scope.kind === "group"
              ? options.scopeLimit || 60
              : g.count <= 12
                ? g.count
                : 0),
      );
      const p = project(data, { ...options, expanded, collapsedRegions: {} });
      const targetGroups = new Set(targets.map((g) => g.id));
      const inside = new Set(
        p.nodes
          .filter((n) => targetGroups.has(n.id) || targetGroups.has(n.parent))
          .map((n) => n.id),
      );
      const edges = p.edges.filter(
        (e) => inside.has(e.source) || inside.has(e.target),
      );
      const touched = new Set(edges.flatMap((e) => [e.source, e.target]));
      const nodes = p.nodes
        .filter((n) => !n.is_region && (inside.has(n.id) || touched.has(n.id)))
        .map((n) => ({
          ...n,
          parent: targetGroups.has(n.parent) ? n.parent : undefined,
          context: !inside.has(n.id),
        }));
      // In group view the title/breadcrumb identifies the scope; no redundant box.
      if (scope.kind === "group")
        nodes.forEach((n) => {
          if (n.parent === scope.id) delete n.parent;
        });
      if (scope.kind === "group")
        nodes.forEach((n) => {
          if (n.id === scope.id) {
            n.count = Math.max(0, n.count - n.shown);
            n.label = "More addresses";
            n.remainder = true;
          }
        });
      const retained = nodes.filter(
        (n) =>
          !(scope.kind === "group" && n.id === scope.id && !touched.has(n.id)),
      );
      return {
        ...p,
        nodes: retained,
        edges,
        regions: [],
        groups: p.groups.filter((g) => targetGroups.has(g.id)),
        matched: targets.reduce((s, g) => s + g.count, 0),
        hidden: targets.reduce(
          (s, g) => s + Math.max(0, g.count - (expanded[g.key] || 0)),
          0,
        ),
        notice:
          "Connected groups provide context. Arrows represent observed communication.",
      };
    }
    const host = (data.nodes || []).find((n) => n.id === scope.id);
    if (!host)
      return {
        ...empty,
        notice: "This host is no longer present in the current window.",
      };
    const adjacent = (data.edges || []).filter(
      (e) =>
        (e.source === host.id || e.target === host.id) &&
        (!scope.peer || e.source === scope.peer || e.target === scope.peer),
    );
    const ids = new Set([
      host.id,
      ...adjacent.flatMap((e) => [e.source, e.target]),
    ]);
    const local = {
      ...data,
      nodes: data.nodes.filter((n) => ids.has(n.id)),
      edges: adjacent,
    };
    const grouped = project(local, {
      ...options,
      regions: false,
      expanded: {},
    });
    const expanded = Object.fromEntries(
      grouped.groups.map((g) => [g.key, 100000]),
    );
    const raw = project(local, { ...options, regions: false, expanded });
    const rawNodes = new Map(
      raw.nodes.filter((n) => !n.is_group).map((n) => [n.id, n]),
    );
    const nodes = new Map([[host.id, { ...host }]]),
      links = new Map();
    const proto = (r) =>
      ({ 6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6" })[r.protocol] ||
      String(r.protocol || "");
    function add(e, r, owned) {
      const outgoing = e.source === host.id;
      const remoteID = outgoing ? e.target : e.source;
      const remote = rawNodes.get(remoteID);
      if (!remote) return;
      const localID = owned
        ? "process:" + JSON.stringify([host.id, r.process])
        : "unattributed:" + host.id;
      if (!nodes.has(localID))
        nodes.set(
          localID,
          owned
            ? {
                id: localID,
                label: r.process.split(/[\\/]/).pop(),
                process: r.process,
                endpoint_id: host.endpoint_id,
                host_id: host.id,
                type: "process",
                parent: host.id,
              }
            : {
                id: localID,
                label: "Other traffic",
                type: "traffic",
                host_id: host.id,
                parent: host.id,
                description:
                  "Traffic without process ownership established on this host.",
              },
        );
      const domain = outgoing ? r.domain : "";
      const remoteKey = domain
        ? "domain:" + JSON.stringify([remoteID, domain])
        : remoteID;
      nodes.set(remoteKey, {
        ...remote,
        parent: undefined,
        id: remoteKey,
        host_id: remoteID,
        ...(domain
          ? {
              label: domain,
              domain,
              type: "domain",
              description:
                "Observed domain association; not a separate verified device.",
            }
          : {}),
      });
      const source = outgoing ? localID : remoteKey,
        target = outgoing ? remoteKey : localID;
      const key = JSON.stringify([source, target]);
      if (!links.has(key))
        links.set(key, {
          id: key,
          source,
          target,
          flow_count: 0,
          total_bytes: 0,
          ports: [],
          relations: [],
          verdict: e.verdict,
        });
      const link = links.get(key);
      link.flow_count += r.flow_count || 0;
      link.total_bytes += r.total_bytes || 0;
      if (r.process !== undefined) link.relations.push(r);
      if (r.remainingRelations) link.relations.push(...r.remainingRelations);
      if (r.protocol) link.ports.push({ protocol: proto(r), port: r.port });
      else link.ports.push(...(e.ports || []));
      if (
        e.verdict === "blocked" ||
        (e.verdict === "anomalous" && link.verdict !== "blocked")
      )
        link.verdict = e.verdict;
    }
    raw.edges
      .filter((e) => e.source === host.id || e.target === host.id)
      .forEach((e) => {
        const records = e.relations || [];
        const owned = records.filter(
          (r) =>
            !!host.endpoint_id &&
            r.endpoint_id === host.endpoint_id &&
            !!r.process,
        );
        const chosen =
          scope.kind === "process"
            ? owned.filter((r) => r.process === scope.process)
            : owned;
        chosen.forEach((r) => add(e, r, true));
        if (scope.kind !== "process") {
          const remaining = Math.max(
            0,
            e.flow_count - owned.reduce((s, r) => s + (r.flow_count || 0), 0),
          );
          if (remaining)
            add(
              e,
              {
                remainingRelations: records.filter((r) => !owned.includes(r)),
                flow_count: remaining,
                total_bytes: Math.max(
                  0,
                  e.total_bytes -
                    owned.reduce((s, r) => s + (r.total_bytes || 0), 0),
                ),
              },
              false,
            );
        }
      });
    const sorted = [...links.values()].sort(
      (a, b) => b.flow_count - a.flow_count || a.id.localeCompare(b.id),
    );
    const shown = [],
      keep = new Set([host.id]);
    let capacityReached = false;
    for (const e of sorted.slice(0, options.scopeLimit || 60)) {
      const added = [e.source, e.target].filter((id) => !keep.has(id));
      if (keep.size + added.length > 1500) {
        capacityReached = true;
        break;
      }
      shown.push(e);
      added.forEach((id) => keep.add(id));
    }
    return {
      ...empty,
      nodes: [...nodes.values()].filter((n) => keep.has(n.id)),
      edges: shown,
      matched: raw.matched,
      omittedEdges: Math.max(0, sorted.length - shown.length),
      detail: true,
      capacityReached,
      hidden: raw.hidden,
      notice: shown.length
        ? "Processes are grouped inside their reporting host. Domains are observed associations. Other traffic has no established local process."
        : "No matching process or communication evidence in this window.",
    };
  }
  function iconKind(n) {
    if (n.type === "process" || n.type === "domain") return n.type;
    if (n.is_region)
      return n.key === "external"
        ? "domain"
        : n.key === "discovery"
          ? "broadcast"
          : "network";
    if (n.is_group)
      return n.region === "external"
        ? "domain"
        : n.region === "discovery"
          ? "broadcast"
          : "network";
    if (n.address_scope === "multicast") return "broadcast";
    if (n.address_scope === "public" || n.type === "cloud") return "domain";
    const role = (n.role || n.type || "").toLowerCase();
    if (/gateway|router/.test(role)) return "router";
    if (/server/.test(role)) return "server";
    if (/workstation|desktop|laptop/.test(role)) return "computer";
    if (/phone|mobile|tablet/.test(role)) return "mobile";
    if (/printer/.test(role)) return "printer";
    return "endpoint";
  }
  return {
    project,
    scene,
    iconKind,
    groupKey,
    coverage,
    regionDefinitions,
    shortLabel,
  };
});
