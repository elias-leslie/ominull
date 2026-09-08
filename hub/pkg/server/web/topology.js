/* Topology owns its canvas lifecycle; polling never replaces its DOM. */
(function () {
  "use strict";
  const M = window.OminullTopologyModel;
  function el(tag, props, ...children) {
    const n = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    });
    children
      .flat()
      .filter(Boolean)
      .forEach((c) => n.append(c));
    return n;
  }
  function button(text, fn, title) {
    return el("button", {
      type: "button",
      class: "tg-button",
      text,
      onclick: fn,
      title: title || text,
    });
  }
  function select(label, values, fn) {
    const s = el("select", {
      "aria-label": label,
      onchange: () => fn(s.value),
    });
    values.forEach(([value, text]) => s.append(el("option", { value, text })));
    return el("label", { class: "tg-field" }, el("span", { text: label }), s);
  }
  const bytes = (n) => {
    n = Number(n) || 0;
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < 3) {
      n /= 1024;
      i++;
    }
    return (n < 10 && i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
  };
  const num = (n) => (Number(n) || 0).toLocaleString();
  const time = (t) => (t ? new Date(t).toLocaleString() : "Not observed");
  function mount(container, api) {
    let data = { nodes: [], edges: [], conversations: [] },
      projection,
      reporterLabels = new Map(),
      cy,
      worker,
      layoutID = 0,
      lastStructure = "",
      first = true,
      fitNext = false,
      selected = "",
      dirty = false,
      views = [],
      currentView = null,
      history = [],
      dragBefore = null,
      pendingData = null,
      dragging = false,
      destroyed = false,
      saveError = "";
    let state = {
      group: "network",
      regions: true,
      regionOverrides: {},
      collapsedRegions: { discovery: true },
      query: "",
      expanded: {},
      positions: {},
      pins: [],
      window: api.window || "24h",
      mode: "pan",
      list: false,
      scope: null,
      scopeLabel: "Overview",
      scopeLimit: 60,
      trail: [],
      activeOnly: false,
      coverage: "",
      protocol: "",
      verdict: "",
      viewport: null,
    };
    if (api.draft) {
      state = { ...state, ...api.draft.state };
      currentView = api.draft.currentView;
      dirty = api.draft.dirty;
      first = false;
    }
    const root = el("section", {
      class: "tg-workspace",
      "aria-label": "Network topology",
    });
    const status = el("div", {
        class: "tg-status",
        role: "status",
        "aria-live": "polite",
      }),
      summary = el("div", { class: "tg-summary" }),
      chips = el("div", { class: "tg-chips" }),
      crumbs = el("nav", {
        class: "tg-crumbs",
        "aria-label": "Topology navigation",
      });
    const search = el("input", {
      type: "search",
      placeholder: "Host, IP, domain or process",
      "aria-label": "Search topology",
      class: "tg-search",
    });
    let searchTimer;
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        state.query = search.value;
        change();
      }, 160);
    });
    const group = select(
      "Group by",
      [
        ["network", "Network"],
        ["role", "Role"],
        ["coverage", "Agent coverage"],
      ],
      (v) => {
        state.group = v;
        state.expanded = {};
        change(true);
      },
    );
    const windowSelect = select(
      "Time window",
      [
        ["1h", "Last hour"],
        ["6h", "Last 6 hours"],
        ["24h", "Last 24 hours"],
        ["7d", "Last 7 days"],
      ],
      (v) => {
        state.window = v;
        api.onWindow(v);
        markDirty();
      },
    );
    windowSelect.querySelector("select").value = state.window;
    const saved = select("Saved view", [["", "Unsaved workspace"]], loadView);
    const save = button("Save", () => saveView(false)),
      saveAs = button("Save as…", () => saveView(true));
    if (api.role === "auditor") {
      save.disabled = true;
      saveAs.disabled = true;
      save.title = saveAs.title = "Auditors can explore but cannot save views";
    }
    const removeView = button("Delete view", deleteView);
    removeView.hidden = true;
    const heading = el(
      "div",
      { class: "tg-heading" },
      el(
        "div",
        {},
        el("h1", { text: "Network topology" }),
        el("p", {
          text: "Observed communication · double-click to explore · scroll to zoom",
        }),
      ),
      el("div", { class: "tg-saved" }, saved, save, saveAs, removeView),
    );
    const filterPanel = el(
      "details",
      { class: "tg-filters" },
      el("summary", { text: "Filters" }),
    );
    const coverage = select(
      "Agent coverage",
      [
        ["", "All hosts"],
        ["managed", "Agent installed"],
        ["unmanaged", "No agent"],
      ],
      (v) => {
        state.coverage = v;
        change();
      },
    );
    const protocol = select(
      "Protocol",
      [
        ["", "All protocols"],
        ["TCP", "TCP"],
        ["UDP", "UDP"],
        ["ICMP", "ICMP"],
      ],
      (v) => {
        state.protocol = v;
        change();
      },
    );
    const verdict = select(
      "Link status",
      [
        ["", "All links"],
        ["blocked", "Contains blocks"],
        ["anomalous", "Contains anomalies"],
        ["clean", "No finding"],
      ],
      (v) => {
        state.verdict = v;
        change();
      },
    );
    const active = el("input", {
      type: "checkbox",
      onchange: () => {
        state.activeOnly = active.checked;
        change();
      },
    });
    const regions = el("input", {
      type: "checkbox",
      onchange: () => {
        state.regions = regions.checked;
        change(true);
      },
    });
    filterPanel.append(
      el(
        "div",
        { class: "tg-filter-body" },
        el("label", { class: "tg-check" }, regions, "Separate logical regions"),
        coverage,
        protocol,
        verdict,
        el("label", { class: "tg-check" }, active, "Active in window only"),
        button("Clear filters", () => {
          state.query = "";
          state.coverage = "";
          state.protocol = "";
          state.verdict = "";
          state.activeOnly = false;
          syncControls();
          change();
        }),
      ),
    );
    const toolbar = el(
      "div",
      { class: "tg-toolbar" },
      search,
      group,
      windowSelect,
      filterPanel,
    );
    const canvas = el("div", {
        class: "tg-canvas",
        role: "group",
        "aria-label":
          "Interactive communication graph. Use List view for keyboard access.",
      }),
      list = el("div", { class: "tg-list", hidden: "" });
    const tooltip = el("div", {
      class: "tg-tooltip",
      id: "topology-tooltip",
      role: "tooltip",
      hidden: "",
    });
    const directionKey = el(
      "div",
      { class: "tg-direction-key" },
      el("span", { class: "tg-incoming", text: "← Incoming" }),
      el("span", { class: "tg-outgoing", text: "Outgoing →" }),
      el("span", {
        class: "tg-direction-reference",
        text: "Hover or select a node",
      }),
    );
    const context = el("div", {
      class: "tg-context",
      "aria-label": "Selected item actions",
    });
    const stage = el(
      "div",
      { class: "tg-stage" },
      el(
        "div",
        { class: "tg-graph-area" },
        canvas,
        list,
        directionKey,
        tooltip,
      ),
      context,
    );
    const pan = button(
      "Pan",
      () => setMode("pan"),
      "Drag background to pan. Shift-click selects multiple hosts.",
    );
    const box = button(
      "Select",
      () => setMode("select"),
      "Drag a box to select hosts. Drag selected hosts to move them together.",
    );
    const listButton = button("List view", () => {
      state.list = !state.list;
      canvas.hidden = state.list;
      list.hidden = !state.list;
      listButton.textContent = state.list ? "Graph view" : "List view";
      if (!state.list) {
        cy.resize();
      }
      renderList();
      markDirty();
    });
    const undo = button("Undo", () => {
      if (!history.length) return;
      const before = history.pop();
      state.positions = before.positions;
      state.pins = before.pins;
      restorePositions();
      updatePins();
      markDirty();
      undo.disabled = !history.length;
    });
    undo.disabled = true;
    const pin = button("Pin selection", () => {
      remember();
      const ids = selectedLeaves().map((n) => n.id());
      state.pins = [...new Set([...state.pins, ...ids])];
      updatePins();
      markDirty();
      inspect();
    });
    const unpin = button("Unpin", () => {
      remember();
      const ids = new Set(selectedLeaves().map((n) => n.id()));
      state.pins = state.pins.filter((id) => !ids.has(id));
      updatePins();
      markDirty();
      inspect();
    });
    const controls = el(
      "div",
      { class: "tg-canvas-tools" },
      pan,
      box,
      button("Fit", () => cy.fit(undefined, 25)),
      button("Arrange", () => arrange(false)),
      button("Arrange selection", () => arrange(true)),
      pin,
      unpin,
      undo,
      button("−", () => zoomBy(1 / 1.25), "Zoom out"),
      button("+", () => zoomBy(1.25), "Zoom in"),
      listButton,
    );
    root.append(
      heading,
      toolbar,
      chips,
      summary,
      crumbs,
      controls,
      stage,
      status,
    );
    container.replaceChildren(root);
    const iconPaths = {
      endpoint:
        '<circle cx="24" cy="21" r="12"/><path d="M18 39h12M24 33v6"/><circle cx="24" cy="21" r="3"/>',
      computer:
        '<rect x="5" y="7" width="38" height="27" rx="3"/><path d="M17 42h14M24 34v8M6 28h36"/>',
      server:
        '<rect x="10" y="4" width="28" height="40" rx="3"/><path d="M10 17h28M10 30h28M16 11h2M16 24h2M16 37h2M25 11h7M25 24h7M25 37h7"/>',
      mobile:
        '<rect x="13" y="3" width="22" height="42" rx="4"/><path d="M21 9h6M21 39h6"/>',
      router:
        '<rect x="5" y="22" width="38" height="17" rx="3"/><path d="M11 22V8M37 22V8M12 31h2M21 31h2M30 31h6"/>',
      network:
        '<rect x="16" y="3" width="16" height="12" rx="2"/><rect x="3" y="32" width="14" height="12" rx="2"/><rect x="31" y="32" width="14" height="12" rx="2"/><path d="M24 15v9M10 32v-8h28v8"/>',
      domain:
        '<circle cx="24" cy="24" r="19"/><ellipse cx="24" cy="24" rx="8" ry="19"/><path d="M6 17h36M6 31h36"/>',
      process:
        '<rect x="8" y="8" width="32" height="32" rx="6"/><path d="M18 17l7 7-7 7M27 31h6M17 3v5M31 3v5M17 40v5M31 40v5M3 17h5M3 31h5M40 17h5M40 31h5"/>',
      broadcast:
        '<circle cx="24" cy="35" r="3"/><path d="M15 26a13 13 0 0 1 18 0M8 19a23 23 0 0 1 32 0M2 12a32 32 0 0 1 44 0"/>',
      printer:
        '<path d="M13 16V4h22v12M12 35H5V16h38v19h-7M13 28h22v16H13zM34 22h2"/>',
    };
    const iconCache = new Map();
    function icon(n) {
      const kind = M.iconKind(n),
        color =
          n.type === "process"
            ? "#64d5ba"
            : n.context || kind === "domain"
              ? "#a8bcea"
              : "#b4d6d9";
      const key = kind + color;
      if (!iconCache.has(key))
        iconCache.set(
          key,
          "data:image/svg+xml;utf8," +
            encodeURIComponent(
              '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48"><g fill="none" stroke="' +
                color +
                '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                iconPaths[kind] +
                "</g></svg>",
            ),
        );
      return iconCache.get(key);
    }
    function zoomBy(factor) {
      cy.zoom({
        level: Math.max(
          cy.minZoom(),
          Math.min(cy.maxZoom(), cy.zoom() * factor),
        ),
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
      markDirty();
    }
    cy = window.OminullCytoscape({
      container: canvas,
      elements: [],
      minZoom: 0.12,
      maxZoom: 2.8,
      selectionType: "additive",
      userZoomingEnabled: true,
      zoomingEnabled: true,
      boxSelectionEnabled: false,
      style: [
        {
          selector: "node",
          style: {
            shape: "ellipse",
            width: 52,
            height: 52,
            "background-opacity": 0,
            "background-image": "data(icon)",
            "background-fit": "contain",
            "background-clip": "none",
            "border-width": 0,
            label: "data(display)",
            "font-family": "IBM Plex Sans",
            "font-size": 13,
            color: "#e6edf2",
            "text-wrap": "wrap",
            "text-max-width": 160,
            "text-valign": "bottom",
            "text-margin-y": 9,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "node[groupNode], node[regionNode]",
          style: {
            width: 64,
            height: 64,
            "font-size": 15,
            "text-max-width": 200,
          },
        },
        {
          selector: ":parent",
          style: {
            shape: "round-rectangle",
            "background-image": "none",
            "background-color": "#253b42",
            "background-opacity": 0.18,
            "border-color": "#68858c",
            "border-width": 1,
            "border-opacity": 0.4,
            padding: 38,
            "text-valign": "top",
            "text-margin-y": -12,
            "font-size": 15,
            "text-max-width": 300,
          },
        },
        {
          selector: 'node[regionKey="external"]:parent',
          style: { "background-color": "#394565" },
        },
        {
          selector: 'node[regionKey="virtual"]:parent',
          style: { "background-color": "#34564b" },
        },
        {
          selector: 'node[regionKey="discovery"]:parent',
          style: { "background-color": "#4b4055" },
        },
        {
          selector: "node[?quiet]",
          style: { "background-image-opacity": 0.5 },
        },
        {
          selector: "node[?isolated]",
          style: {
            "border-color": "#e89786",
            "border-width": 2,
            "border-style": "dashed",
          },
        },
        {
          selector: "node[pinned]",
          style: { "border-color": "#e0bf76", "border-width": 2 },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)",
            "line-color": "#627782",
            "target-arrow-color": "#627782",
            "target-arrow-shape": "triangle",
            "arrow-scale": 1.1,
            "curve-style": "unbundled-bezier",
            "control-point-distances": "data(bend)",
            "control-point-weights": 0.5,
            label: "data(edgeLabel)",
            "font-size": 11,
            color: "#aebdc5",
            "text-background-color": "#101719",
            "text-background-opacity": 0.95,
            "text-background-padding": 3,
            "text-rotation": "autorotate",
            opacity: 0.72,
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'edge[verdict="blocked"]',
          style: {
            "line-color": "#e89786",
            "target-arrow-color": "#e89786",
            "line-style": "dashed",
          },
        },
        {
          selector: 'edge[verdict="anomalous"]',
          style: { "line-color": "#e0bf76", "target-arrow-color": "#e0bf76" },
        },
        {
          selector: ":selected",
          style: {
            "border-color": "#f0d68f",
            "border-width": 3,
            "line-color": "#f0d68f",
            "target-arrow-color": "#f0d68f",
            opacity: 1,
          },
        },
        { selector: ".muted", style: { opacity: 0.18 } },
        {
          selector: "edge.incoming",
          style: {
            "line-color": "#81adff",
            "target-arrow-color": "#81adff",
            opacity: 1,
          },
        },
        {
          selector: "edge.outgoing",
          style: {
            "line-color": "#64d5ba",
            "target-arrow-color": "#64d5ba",
            opacity: 1,
          },
        },
      ],
    });
    pin.disabled = unpin.disabled = true;
    worker = new Worker(
      "vendor/topology-layout.js?v=" + encodeURIComponent(api.version || ""),
    );
    worker.onmessage = (e) => {
      if (destroyed || e.data.id !== layoutID) return;
      if (e.data.error) {
        status.textContent =
          "Layout failed: " + e.data.error + ". Existing positions retained.";
        return;
      }
      cy.batch(() => {
        Object.entries(e.data.positions).forEach(([id, p]) => {
          const n = cy.getElementById(id);
          if (n.length && !n.isParent() && !state.pins.includes(id))
            n.position(p);
        });
      });
      capture();
      if (first || fitNext) {
        cy.fit(undefined, 25);
        first = false;
        fitNext = false;
      }
      status.textContent =
        projection?.notice ||
        (e.data.regioned ? "Regions arranged" : "Layout ready");
      if (projection?.omittedEdges)
        status.textContent +=
          " " +
          num(projection.omittedEdges) +
          " additional links; use Show more.";
    };
    worker.onerror = () => {
      status.textContent =
        "Layout worker unavailable. Drag nodes manually or use List view.";
    };
    let hoverTimer,
      hideTimer,
      hoverID = "",
      tooltipTrigger = null,
      tooltipState = null,
      restoringListFocus = false;
    function hideTooltip() {
      clearTimeout(hoverTimer);
      clearTimeout(hideTimer);
      tooltip.hidden = true;
      if (tooltipTrigger) tooltipTrigger.removeAttribute("aria-describedby");
      tooltipTrigger = null;
      tooltipState = null;
    }
    function deferHide() {
      hideTimer = setTimeout(() => {
        if (
          !tooltip.matches(":hover") &&
          !hoverID &&
          !(tooltipTrigger && tooltipTrigger === document.activeElement)
        )
          hideTooltip();
      }, 150);
    }
    tooltip.addEventListener("mouseenter", () => clearTimeout(hideTimer));
    tooltip.addEventListener("mouseleave", deferHide);
    function escapeTooltip(e) {
      if (e.key === "Escape") hideTooltip();
    }
    root.addEventListener("keydown", escapeTooltip);
    // Canvas hover does not imply DOM focus, so Escape also works from the page.
    document.addEventListener("keydown", escapeTooltip);
    function highlight(id) {
      cy.elements().removeClass("incoming outgoing muted");
      const hovered = cy.getElementById(id || "");
      const ref =
        hovered.length && hovered.isNode()
          ? hovered
          : cy.getElementById(
              selected || (projection?.detail ? state.scope?.id : ""),
            );
      const caption = directionKey.querySelector(".tg-direction-reference");
      if (!ref.length || !ref.isNode()) {
        caption.textContent = "Hover or select a node";
        return;
      }
      const members = new Set(ref.union(ref.descendants()).map((n) => n.id()));
      cy.edges().forEach((e) => {
        const source = members.has(e.source().id()),
          target = members.has(e.target().id());
        e.addClass(
          source && !target
            ? "outgoing"
            : target && !source
              ? "incoming"
              : source && target
                ? ""
                : "muted",
        );
      });
      const n = projection.nodes.find((n) => n.id === ref.id());
      caption.textContent = "At " + (n ? M.shortLabel(n) : ref.id());
    }
    function showTooltip(id, point, trigger) {
      hideTooltip();
      const n = projection.nodes.find((n) => n.id === id);
      const edge = projection.edges.find((e) => "edge:" + e.id === id);
      if (!n && !edge) return;
      tooltip.replaceChildren();
      if (n) {
        tooltip.append(el("strong", { text: M.shortLabel(n) }));
        const lines = n.is_region
          ? [
              n.description,
              num(n.count) + (n.count === 1 ? " address" : " addresses"),
              n.collapsed
                ? "Double-click to explore"
                : "Drag region to move its groups",
            ]
          : n.is_group
            ? [
                n.label,
                num(n.count) + (n.count === 1 ? " address" : " addresses"),
                "Double-click to explore",
              ]
            : [
                n.description,
                n.process,
                n.type === "process"
                  ? "Reported by " +
                    (reporterLabels.get(n.endpoint_id) || n.endpoint_id)
                  : "",
                n.ip,
                n.role && !/^unknown$/i.test(n.role) ? "Role: " + n.role : "",
                n.os && !/^unknown$/i.test(n.os) ? "OS: " + n.os : "",
                n.risk && n.risk !== "CLEAN" ? "Risk: " + n.risk : "",
                n.evidence?.length ? "Evidence: " + n.evidence.join(", ") : "",
                n.address_scope ? "Scope: " + n.address_scope : "",
                n.quiet
                  ? "No observed traffic in this window"
                  : "Traffic observed in this window",
                ["process", "domain", "traffic"].includes(n.type)
                  ? ""
                  : M.coverage(n) === "managed"
                    ? "Agent installed"
                    : "No agent",
                n.is_isolated ? "Isolated" : "",
              ];
        lines
          .filter(Boolean)
          .filter((v, i, a) => a.indexOf(v) === i && v !== M.shortLabel(n))
          .forEach((text) => tooltip.append(el("div", { text })));
      } else {
        const source = projection.nodes.find((n) => n.id === edge.source),
          target = projection.nodes.find((n) => n.id === edge.target);
        tooltip.append(
          el("strong", {
            text: M.shortLabel(source) + " → " + M.shortLabel(target),
          }),
        );
        tooltip.append(
          el("div", {
            text:
              num(edge.flow_count) +
              " observations · " +
              bytes(edge.total_bytes) +
              " measured",
          }),
        );
        const ports = [
          ...new Set(
            edge.ports.map((p) => p.protocol + (p.port ? "/" + p.port : "")),
          ),
        ];
        if (ports.length)
          tooltip.append(
            el("div", {
              text:
                ports.slice(0, 5).join(" · ") +
                (ports.length > 5 ? " +" + (ports.length - 5) : ""),
            }),
          );
        const records = edge.relations || [];
        const domains = [
          ...new Set(records.map((r) => r.domain).filter(Boolean)),
        ];
        const processes = [
          ...new Set(
            records
              .filter((r) => r.process)
              .map((r) => {
                const reporter = reporterLabels.get(r.endpoint_id);
                return (
                  r.process.split(/[\\/]/).pop() +
                  " · " +
                  (reporter || r.endpoint_id || "Unattributed reporter")
                );
              }),
          ),
        ];
        for (const [label, values] of [
          ["Domains", domains],
          ["Processes / reporter", processes],
        ])
          if (values.length)
            tooltip.append(
              el("div", {
                text:
                  label +
                  ": " +
                  values.slice(0, 2).join("; ") +
                  (values.length > 2 ? " +" + (values.length - 2) : ""),
              }),
            );
        if (edge.verdict !== "clean")
          tooltip.append(
            el("div", {
              class: "tg-tooltip-finding",
              text:
                edge.verdict === "blocked"
                  ? "Contains blocked observations"
                  : "Contains anomalous observations",
            }),
          );
        tooltip.append(
          el("small", { text: "Double-click to explore · Esc to dismiss" }),
        );
      }
      tooltip.hidden = false;
      tooltipState = { id, point, trigger };
      const area = canvas.parentElement.getBoundingClientRect();
      tooltip.style.left =
        Math.max(
          8,
          Math.min(point.x + 12, area.width - tooltip.offsetWidth - 8),
        ) + "px";
      tooltip.style.top =
        Math.max(
          8,
          Math.min(point.y + 12, area.height - tooltip.offsetHeight - 40),
        ) + "px";
      if (trigger) {
        tooltipTrigger = trigger;
        trigger.setAttribute("aria-describedby", tooltip.id);
      }
    }
    cy.on("mouseover", "node, edge", (e) => {
      hoverID = e.target.id();
      clearTimeout(hideTimer);
      clearTimeout(hoverTimer);
      if (e.target.isNode()) highlight(hoverID);
      const point = e.renderedPosition || e.target.renderedPosition();
      hoverTimer = setTimeout(() => showTooltip(e.target.id(), point), 200);
    });
    cy.on("mouseout", "node, edge", () => {
      hoverID = "";
      clearTimeout(hoverTimer);
      deferHide();
      highlight();
    });
    cy.on("pan zoom grab", hideTooltip);
    cy.on("tap", "node, edge", (e) => {
      selected = e.target.id();
      inspect();
    });
    let lastDoubleTap = 0;
    cy.on("dbltap", "node, edge", (e) => {
      lastDoubleTap = Date.now();
      drill(e.target.id());
    });
    // Native double-click events can arrive without two separate tap events.
    canvas.addEventListener("dblclick", () => {
      if (selected && Date.now() - lastDoubleTap > 500) drill(selected);
    });
    cy.on("tap", (e) => {
      if (e.target === cy) {
        selected = "";
        cy.elements().unselect();
        inspect();
      }
    });
    cy.on("grab", "node", () => {
      dragging = true;
      dragBefore = snapshot();
      ++layoutID;
    });
    cy.on("free", "node", () => {
      dragging = false;
      if (dragBefore) {
        history.push(dragBefore);
        if (history.length > 30) history.shift();
        undo.disabled = false;
        dragBefore = null;
      }
      capture();
      markDirty();
      if (pendingData) {
        const d = pendingData;
        pendingData = null;
        update(d);
      }
    });
    cy.on("select unselect", () => {
      pin.disabled = unpin.disabled = selectedLeaves().length === 0;
    });
    cy.on("dragpan scrollzoom pinchzoom", markDirty);
    cy.on("pan zoom", () => {
      state.viewport = { zoom: cy.zoom(), pan: cy.pan() };
    });
    canvas.tabIndex = 0;
    canvas.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && selected) {
        e.preventDefault();
        drill(selected);
      }
    });
    const observer = new ResizeObserver(() => cy.resize());
    observer.observe(canvas);
    setMode(state.mode);
    syncControls();
    canvas.hidden = state.list;
    list.hidden = !state.list;
    listButton.textContent = state.list ? "Graph view" : "List view";
    if (dirty) save.textContent = "Save *";
    refreshViews();
    inspect();
    function setMode(mode) {
      state.mode = mode;
      cy.boxSelectionEnabled(mode === "select");
      cy.userPanningEnabled(mode === "pan");
      pan.setAttribute("aria-pressed", String(mode === "pan"));
      box.setAttribute("aria-pressed", String(mode === "select"));
    }
    function markDirty() {
      dirty = true;
      save.textContent = "Save *";
    }
    function capture() {
      cy.nodes()
        .filter((n) => !n.isParent())
        .forEach((n) => {
          state.positions[n.id()] = { ...n.position() };
        });
    }
    function snapshot() {
      capture();
      return {
        positions: JSON.parse(JSON.stringify(state.positions)),
        pins: state.pins.slice(),
      };
    }
    function remember() {
      history.push(snapshot());
      if (history.length > 30) history.shift();
      undo.disabled = false;
    }
    function selectedLeaves() {
      return cy
        .nodes(":selected")
        .union(cy.nodes(":selected").descendants())
        .filter((n) => !n.isParent());
    }
    function updatePins() {
      cy.nodes().forEach((n) => {
        const fixed = state.pins.includes(n.id());
        if (fixed) {
          n.data("pinned", true);
          n.lock();
        } else {
          n.removeData("pinned");
          n.unlock();
        }
      });
    }
    function restorePositions() {
      cy.batch(() =>
        cy
          .nodes()
          .filter((n) => !n.isParent())
          .forEach((n) => {
            const p = state.positions[n.id()];
            if (p) {
              n.unlock();
              n.position(p);
            }
          }),
      );
    }
    function change(rearrange) {
      markDirty();
      renderGraph();
      if (rearrange) arrange(false);
    }
    function syncControls() {
      search.value = state.query;
      group.querySelector("select").value = state.group;
      windowSelect.querySelector("select").value = state.window;
      coverage.querySelector("select").value = state.coverage;
      protocol.querySelector("select").value = state.protocol;
      verdict.querySelector("select").value = state.verdict;
      active.checked = state.activeOnly;
      regions.checked = state.regions;
    }
    function renderGraph(skipCapture) {
      if (dragging) return;
      const previousTooltip = tooltipState;
      if (!skipCapture) capture();
      projection = M.scene(data, state);
      const elements = projection.nodes.map((n, i) => ({
        group: "nodes",
        data: {
          id: n.id,
          parent: n.parent || undefined,
          kind: n.type,
          icon: icon(n),
          detailNode: !!projection.detail,
          context: !!n.context,
          display:
            M.shortLabel(n) +
            (n.is_group || (n.is_region && n.collapsed)
              ? "\n" +
                num(n.count) +
                (n.count === 1 ? " address" : " addresses")
              : ""),
          ...(n.is_group ? { groupNode: true } : {}),
          ...(n.is_region ? { regionNode: true, regionKey: n.key } : {}),
          agent: !!n.endpoint_id || n.type === "managed",
          quiet: !!n.quiet,
          isolated: !!n.is_isolated,
        },
        position: state.positions[n.id] || {
          x: (i % 8) * 210,
          y: Math.floor(i / 8) * 130,
        },
      }));
      projection.edges.forEach((e, edgeIndex) =>
        elements.push({
          group: "edges",
          data: {
            id: "edge:" + e.id,
            source: e.source,
            target: e.target,
            verdict: e.verdict,
            bend: 35 + (edgeIndex % 4) * 18,
            width: Math.min(5, 1 + Math.log10(1 + e.flow_count)),
            edgeLabel: projection.detail
              ? [
                  ...new Set(
                    (e.ports || []).map(
                      (p) => p.protocol + (p.port ? "/" + p.port : ""),
                    ),
                  ),
                ]
                  .slice(0, 2)
                  .join(" · ")
              : "",
          },
        }),
      );
      const structure = elements
        .map((e) => e.data.id + ":" + (e.data.parent || ""))
        .join("|");
      if (structure !== lastStructure) {
        ++layoutID;
        const selection = cy.$(":selected").map((n) => n.id());
        cy.json({ elements });
        selection.forEach((id) => cy.getElementById(id).select());
        restorePositions();
        lastStructure = structure;
        // Telemetry must not move the operator's viewport. Fit is explicit.
      } else
        cy.batch(() =>
          elements.forEach((e) => cy.getElementById(e.data.id).data(e.data)),
        );
      updatePins();
      summary.replaceChildren(
        el(
          "span",
          {},
          el("strong", {
            text: num(
              projection.detail
                ? projection.nodes.filter(
                    (n) => !n.parent && n.id !== state.scope.id,
                  ).length
                : projection.matched,
            ),
          }),
          projection.detail
            ? " destinations shown"
            : " of " + num(projection.total) + " addresses",
        ),
        el(
          "span",
          {},
          el("strong", {
            text: num(
              projection.detail
                ? projection.nodes.filter((n) => n.type === "process").length
                : projection.groups.length,
            ),
          }),
          projection.detail ? " processes" : " groups",
        ),
        el(
          "span",
          {},
          el("strong", { text: num(projection.edges.length) }),
          " of " +
            num(projection.edges.length + projection.omittedEdges) +
            " links",
        ),
        el("span", {
          class: "tg-window",
          text: data.to
            ? "Observed through " + new Date(data.to).toLocaleTimeString()
            : "Waiting for observations",
        }),
      );
      chips.replaceChildren();
      [
        ["query", state.query],
        ["coverage", state.coverage],
        ["protocol", state.protocol],
        ["verdict", state.verdict],
        ["activeOnly", state.activeOnly ? "Active only" : ""],
      ].forEach(([key, value]) => {
        if (value)
          chips.append(
            button(
              value + " ×",
              () => {
                state[key] = key === "activeOnly" ? false : "";
                syncControls();
                change();
              },
              "Remove " + value + " filter",
            ),
          );
      });
      crumbs.replaceChildren();
      if (state.trail?.length) crumbs.append(button("← Back", () => goBack()));
      (state.trail || []).forEach((entry, i) =>
        crumbs.append(button(entry.label, () => goBack(i))),
      );
      crumbs.append(
        el("span", {
          text: state.scopeLabel || "Overview",
          "aria-current": "page",
        }),
      );
      if (
        state.scope &&
        state.scope.kind !== "region" &&
        !projection.capacityReached &&
        (state.scopeLimit || 0) < 1500 &&
        (projection.hidden || projection.omittedEdges)
      )
        crumbs.append(
          button("Show more", () => {
            state.scopeLimit = Math.min(1500, (state.scopeLimit || 60) + 60);
            change(true);
          }),
        );
      status.textContent =
        (projection.hidden
          ? num(projection.hidden) +
            " addresses grouped. Double-click to explore. "
          : "") +
        (projection.omittedEdges
          ? num(projection.omittedEdges) +
            " lower-volume links omitted; narrow filters. "
          : "") +
        (data.evidence_truncated
          ? "Evidence limited to 20,000 recent relations; domain/process search is partial. "
          : "") +
        (state.query
          ? "Search finds hosts and observed relations; link totals cover the matching host pairs. "
          : "") +
        "";
      if (projection.notice) status.textContent += projection.notice;
      if (projection.capacityReached)
        status.textContent +=
          " Drawing limit reached; narrow filters to see other relations.";
      if (saveError) status.textContent = saveError;
      renderList();
      inspect();
      if (previousTooltip) {
        const trigger = state.list
          ? [...list.querySelectorAll("button")].find(
              (b) => b.dataset.topologyId === previousTooltip.id,
            )
          : null;
        if (!state.list || trigger)
          showTooltip(previousTooltip.id, previousTooltip.point, trigger);
        else hideTooltip();
      }
      if (first && projection.nodes.length) arrange(false);
    }
    function arrange(selectionOnly) {
      if (!first) {
        remember();
        markDirty();
      }
      capture();
      const movable = selectionOnly
        ? new Set(selectedLeaves().map((n) => n.id()))
        : null;
      if (movable && !movable.size) {
        status.textContent = "Select hosts or groups to arrange first.";
        return;
      }
      const fixed = cy
        .nodes()
        .filter(
          (n) =>
            !n.isParent() &&
            (state.pins.includes(n.id()) || (movable && !movable.has(n.id()))),
        )
        .map((n) => ({ nodeId: n.id(), position: n.position() }));
      fitNext = !selectionOnly;
      worker.postMessage({
        scope: state.scope?.kind,
        viewport: { width: cy.width(), height: cy.height() },
        id: ++layoutID,
        elements: cy.elements().map((e) => ({
          data: e.data(),
          position: e.isNode() ? e.position() : undefined,
        })),
        fixed,
      });
      status.textContent = "Arranging graph… You can keep using the controls.";
    }
    function focus(id) {
      const n = (data.nodes || []).find(
        (n) => n.id === id || n.asset_id === id || n.ip === id,
      );
      if (n) navigate({ kind: "host", id: n.id }, M.shortLabel(n));
    }
    function renderList() {
      if (!state.list) return;
      const focusedID = list.contains(document.activeElement)
        ? document.activeElement.dataset.topologyId
        : null;
      list.replaceChildren();
      const table = el(
        "table",
        { class: "tg-table" },
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            ...["Host / group", "Address", "Coverage", "Inspect"].map((t) =>
              el("th", { scope: "col", text: t }),
            ),
          ),
        ),
      );
      const body = el("tbody");
      projection.nodes.forEach((n) =>
        body.append(
          el(
            "tr",
            {},
            el("td", { text: n.label || n.id }),
            el("td", {
              text: n.ip || num(n.count) + (n.count === 1 ? " host" : " hosts"),
            }),
            el("td", {
              text: n.is_region
                ? "Region"
                : n.is_group
                  ? "Group"
                  : M.coverage(n) === "managed"
                    ? "Agent installed"
                    : "No agent",
            }),
            el(
              "td",
              {},
              button("Inspect", () => {
                selected = n.id;
                inspect();
              }),
            ),
          ),
        ),
      );
      function evidenceButton(id) {
        const b = button("Inspect", () => {
          selected = id;
          inspect();
        });
        b.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            drill(id);
          }
        });
        b.dataset.topologyId = id;
        const show = () => {
          if (restoringListFocus) return;
          highlight(id);
          const r = b.getBoundingClientRect(),
            area = list.getBoundingClientRect();
          showTooltip(id, { x: r.left - area.left, y: r.bottom - area.top }, b);
        };
        b.addEventListener("focus", show);
        b.addEventListener("mouseenter", show);
        b.addEventListener("blur", deferHide);
        b.addEventListener("mouseleave", deferHide);
        return b;
      }
      [...body.rows].forEach((row, i) =>
        row.lastElementChild.replaceChildren(
          evidenceButton(projection.nodes[i].id),
        ),
      );
      projection.edges.forEach((e) => {
        const source = projection.nodes.find((n) => n.id === e.source),
          target = projection.nodes.find((n) => n.id === e.target);
        body.append(
          el(
            "tr",
            {},
            el("td", {
              text: M.shortLabel(source) + " → " + M.shortLabel(target),
            }),
            el("td", { text: num(e.flow_count) + " observations" }),
            el("td", { text: "Directed link" }),
            el("td", {}, evidenceButton("edge:" + e.id)),
          ),
        );
      });
      table.append(body);
      list.append(table);
      if (focusedID) {
        const target = [...list.querySelectorAll("button")].find(
          (b) => b.dataset.topologyId === focusedID,
        );
        restoringListFocus = true;
        target?.focus({ preventScroll: true });
        restoringListFocus = false;
        if (target && tooltipState?.id === focusedID) {
          tooltipTrigger = target;
          tooltipState.trigger = target;
          target.setAttribute("aria-describedby", tooltip.id);
        }
      }
    }
    function navigate(scope, label) {
      capture();
      state.trail = [
        ...(state.trail || []),
        {
          scope: state.scope,
          label: state.scopeLabel || "Overview",
          positions: state.positions,
          pins: state.pins,
          viewport: state.viewport,
          scopeLimit: state.scopeLimit,
        },
      ].slice(-12);
      state.scope = scope;
      state.scopeLabel = label;
      state.scopeLimit =
        scope.kind === "host" || scope.kind === "process" ? 12 : 24;
      state.positions = {};
      state.pins = [];
      state.viewport = null;
      selected = "";
      history = [];
      undo.disabled = true;
      lastStructure = "";
      first = true;
      hideTooltip();
      renderGraph(true);
      markDirty();
    }
    function goBack(index = (state.trail || []).length - 1) {
      const entry = state.trail?.[index];
      if (!entry) return;
      ++layoutID;
      state.trail = state.trail.slice(0, index);
      Object.assign(state, entry, { scopeLabel: entry.label });
      selected = "";
      history = [];
      undo.disabled = true;
      lastStructure = "";
      first = false;
      hideTooltip();
      const viewport = state.viewport;
      renderGraph(true);
      if (viewport) {
        cy.zoom(viewport.zoom);
        cy.pan(viewport.pan);
      }
      markDirty();
    }
    function drill(id) {
      const n = projection?.nodes.find((n) => n.id === id);
      if (!n) {
        const e = projection?.edges.find((e) => "edge:" + e.id === id);
        if (e) {
          const source = projection.nodes.find((n) => n.id === e.source);
          const target = projection.nodes.find((n) => n.id === e.target);
          const host =
            source?.host_id ||
            (!source?.is_group && !source?.is_region && source?.id);
          if (host)
            navigate(
              { kind: "host", id: host, peer: target?.host_id || target?.id },
              M.shortLabel(source) + " → " + M.shortLabel(target),
            );
          else if (source) drill(source.id);
        }
        return;
      }
      if (n.remainder) {
        state.scopeLimit = Math.min(1500, (state.scopeLimit || 24) + 60);
        change(true);
        return;
      }
      if (n.is_region) navigate({ kind: "region", id: n.id }, M.shortLabel(n));
      else if (n.is_group)
        navigate({ kind: "group", id: n.id }, M.shortLabel(n));
      else if (n.type === "process")
        navigate(
          { kind: "process", id: n.host_id, process: n.process },
          n.label,
        );
      else if (n.type !== "traffic")
        navigate({ kind: "host", id: n.host_id || n.id }, M.shortLabel(n));
    }
    function inspect() {
      context.replaceChildren();
      if (cy && projection) highlight(hoverID);
      const n = projection?.nodes.find((n) => n.id === selected);
      const edge = projection?.edges.find((e) => "edge:" + e.id === selected);
      if (!n && !edge) return;
      context.append(
        el("strong", { text: n ? M.shortLabel(n) : "Observed communication" }),
      );
      if (n?.ip) context.append(el("span", { text: n.ip }));
      if (n?.type !== "traffic")
        context.append(
          button(
            "Explore",
            () => drill(selected),
            "Double-click an item to explore it",
          ),
        );
      if (n?.asset_id && n.type !== "process")
        context.append(button("Open asset", () => api.onAsset(n)));
      if (n?.type === "process")
        context.append(
          button("Traffic records", () =>
            api.onTraffic({ process: n.process, endpoint_id: n.endpoint_id }),
          ),
        );
      else if (n?.ip) {
        context.append(
          button("Outgoing records", () => api.onTraffic({ src_ip: n.ip })),
          button("Incoming records", () => api.onTraffic({ dst_ip: n.ip })),
        );
      }
      if (n?.is_group && state.group === "network") {
        const choice = select(
          "Region",
          [
            ["", "Automatic"],
            ...Object.entries(M.regionDefinitions).map(([k, v]) => [
              k,
              v.label,
            ]),
          ],
          (value) => {
            state.regionOverrides[n.baseKey || n.key] = value;
            if (state.scope?.kind === "group" && state.scope.id === n.id) {
              const moved = M.project(data, state).groups.find(
                (g) => g.baseKey === n.baseKey,
              );
              if (moved) state.scope.id = moved.id;
            }
            change(true);
          },
        );
        choice.querySelector("select").value =
          state.regionOverrides[n.baseKey || n.key] || "";
        context.append(choice);
      }
      context.append(
        button(
          "×",
          () => {
            selected = "";
            cy.elements().unselect();
            inspect();
          },
          "Clear selection",
        ),
      );
    }
    function refreshViews() {
      return api
        .request("/api/v1/topology/views")
        .then((d) => {
          views = d.views || [];
          const s = saved.querySelector("select");
          s.replaceChildren(
            el("option", { value: "", text: "Unsaved workspace" }),
          );
          views.forEach((v) =>
            s.append(el("option", { value: v.id, text: v.name })),
          );
          s.value = currentView ? currentView.id : "";
        })
        .catch((e) => {
          status.textContent = "Saved views unavailable: " + e.message;
        });
    }
    function applyView(v) {
      saveError = "";
      currentView = v;
      state = {
        ...state,
        ...v.state,
        regions: v.state.regions ?? false,
        scope: v.state.scope || null,
        scopeLabel: v.state.scopeLabel || "Overview",
        scopeLimit: v.state.scopeLimit || 60,
        trail: v.state.trail || [],
        collapsedRegions: v.state.collapsedRegions || {},
        regionOverrides: v.state.regionOverrides || {},
      };
      state.expanded = state.expanded || {};
      state.positions = state.positions || {};
      state.pins = state.pins || [];
      syncControls();
      setMode(state.mode);
      lastStructure = "";
      first = false;
      const viewport = state.viewport;
      renderGraph(true);
      restorePositions();
      updatePins();
      if (viewport) {
        cy.zoom(viewport.zoom);
        cy.pan(viewport.pan);
      }
      canvas.hidden = state.list;
      list.hidden = !state.list;
      listButton.textContent = state.list ? "Graph view" : "List view";
      renderList();
      api.onWindow(state.window);
      dirty = false;
      save.textContent = "Save";
      removeView.hidden = api.role === "auditor";
    }
    function loadView(id) {
      const v = views.find((v) => v.id === id);
      if (!v) return;
      if (dirty) {
        confirmDialog("Discard unsaved layout changes?", () => applyView(v));
      } else applyView(v);
    }
    function confirmDialog(title, done) {
      const d = el("dialog", { class: "tg-dialog" }, el("h2", { text: title }));
      d.append(
        button("Keep editing", () => {
          d.close();
          d.remove();
        }),
        button("Continue", () => {
          d.close();
          d.remove();
          done();
        }),
      );
      root.append(d);
      d.showModal();
    }
    function saveView(asNew) {
      if (api.role === "auditor") return;
      capture();
      if (currentView && !asNew) {
        persist(currentView.name, currentView.id, currentView.revision);
        return;
      }
      const input = el("input", {
        maxlength: "100",
        "aria-label": "View name",
        placeholder: "e.g. Application dependencies",
      });
      const d = el(
        "dialog",
        { class: "tg-dialog" },
        el("h2", { text: "Save personal view" }),
        el("p", {
          text: "Stores filters, time window, positions, pins and zoom for your operator account.",
        }),
        input,
      );
      const go = button("Save view", () => {
        if (!input.value.trim()) {
          input.focus();
          return;
        }
        const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
          b.toString(16).padStart(2, "0"),
        ).join("");
        persist(input.value.trim(), id, 0);
        d.close();
        d.remove();
      });
      d.append(
        button("Cancel", () => {
          d.close();
          d.remove();
        }),
        go,
      );
      root.append(d);
      d.showModal();
      input.focus();
    }
    function persist(name, id, revision) {
      api
        .request("/api/v1/topology/views", "PUT", { id, name, revision, state })
        .then((v) => {
          currentView = v;
          saveError = "";
          dirty = false;
          save.textContent = "Save";
          removeView.hidden = false;
          status.textContent = "Personal view saved.";
          refreshViews();
        })
        .catch((e) => {
          status.textContent = saveError =
            "View not saved: " +
            e.message +
            ". Your layout is still here; use Save as to keep a separate copy.";
        });
    }
    function deleteView() {
      if (!currentView || api.role === "auditor") return;
      confirmDialog("Delete this saved view?", () =>
        api
          .request("/api/v1/topology/views", "DELETE", {
            id: currentView.id,
            revision: currentView.revision,
          })
          .then(() => {
            currentView = null;
            removeView.hidden = true;
            markDirty();
            refreshViews();
          })
          .catch((e) => {
            status.textContent = saveError = e.message;
          }),
      );
    }
    function update(next, error) {
      if (destroyed) return;
      if (error) {
        status.textContent =
          "Refresh failed: " + error + ". Last graph retained.";
        return;
      }
      if (!next) return;
      if (dragging) {
        pendingData = next;
        return;
      }
      data = next;
      reporterLabels = new Map(
        (data.nodes || [])
          .filter((n) => n.endpoint_id)
          .map((n) => [n.endpoint_id, n.label || n.ip]),
      );
      const restoreDraft = api.draft;
      const viewport = restoreDraft && state.viewport;
      renderGraph(!!restoreDraft);
      if (viewport) {
        cy.zoom(viewport.zoom);
        cy.pan(viewport.pan);
      }
      api.draft = null;
    }
    return {
      update,
      focus,
      getDraft() {
        capture();
        return JSON.parse(JSON.stringify({ state, currentView, dirty }));
      },
      destroy() {
        destroyed = true;
        clearTimeout(searchTimer);
        hideTooltip();
        document.removeEventListener("keydown", escapeTooltip);
        observer.disconnect();
        worker.terminate();
        cy.destroy();
        root.remove();
      },
    };
  }
  window.OminullTopology = { mount };
})();
