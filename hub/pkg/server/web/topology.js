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
      details: false,
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
          text: "Observed communication",
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
    const inspector = el("aside", {
      class: "tg-inspector",
      "aria-label": "Topology inspector",
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
      inspector,
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
    const detailsButton = button(
      "Details",
      () => {
        state.details = !state.details;
        updateDetails();
        cy.fit(undefined, 25);
        markDirty();
      },
      "Show or hide the inspector",
    );
    function updateDetails() {
      inspector.hidden = !state.details;
      detailsButton.setAttribute("aria-expanded", String(!!state.details));
      if (cy) cy.resize();
    }
    function revealInspector() {
      state.details = true;
      updateDetails();
    }
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
      detailsButton,
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
    cy = window.OminullCytoscape({
      container: canvas,
      elements: [],
      minZoom: 0.12,
      maxZoom: 2.8,
      selectionType: "additive",
      boxSelectionEnabled: false,
      style: [
        {
          selector: "node",
          style: {
            shape: "round-rectangle",
            width: 150,
            height: 50,
            "background-color": "#263640",
            "border-color": "#75b8c7",
            "border-width": 1.5,
            label: "data(display)",
            "font-family": "IBM Plex Sans",
            "font-size": 13,
            color: "#e6edf2",
            "text-wrap": "wrap",
            "text-max-width": 138,
            "text-valign": "center",
            "text-halign": "center",
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'node[kind="cloud"]',
          style: {
            "background-color": "#293145",
            "border-color": "#819ccc",
            shape: "round-diamond",
          },
        },
        {
          selector: "node[!groupNode][!regionNode][!agent]",
          style: {
            "background-color": "#30343b",
            "border-color": "#979fa9",
            "border-style": "dashed",
          },
        },
        {
          selector: 'node[kind="gateway"]',
          style: {
            "background-color": "#333b32",
            "border-color": "#a8bf82",
            shape: "hexagon",
          },
        },
        {
          selector: "node[groupNode]",
          style: {
            width: 190,
            height: 74,
            "background-color": "#243a40",
            "border-color": "#6ea5b1",
            "border-width": 2,
            "font-size": 15,
            "text-max-width": 175,
          },
        },
        {
          selector: ":parent",
          style: {
            "background-color": "#22323b",
            "background-opacity": 0.35,
            "border-color": "#617984",
            "border-style": "solid",
            "border-width": 1,
            padding: 32,
            "text-valign": "top",
            "text-margin-y": -10,
            "font-size": 14,
            "text-max-width": 260,
          },
        },
        {
          selector: "node[regionNode]",
          style: {
            width: 260,
            height: 100,
            "background-color": "#263945",
            "background-opacity": 0.55,
            "border-color": "#829daa",
            "border-width": 1.5,
            "border-style": "solid",
            "font-size": 18,
            "font-weight": 500,
            "text-max-width": 320,
            padding: 0,
          },
        },
        { selector: "node[regionNode]:parent", style: { padding: 42 } },
        {
          selector: 'node[regionKey="external"]',
          style: { "background-color": "#30374b", "border-color": "#909fc0" },
        },
        {
          selector: 'node[regionKey="discovery"]',
          style: { "background-color": "#3a3740", "border-color": "#a49aae" },
        },
        {
          selector: 'node[regionKey="virtual"]',
          style: { "background-color": "#293f39", "border-color": "#83aa99" },
        },
        {
          selector: "node[?quiet]",
          style: { "background-opacity": 0.4 },
        },
        {
          selector: "node[?isolated]",
          style: { "border-color": "#e89786", "border-width": 3 },
        },
        {
          selector: "node[pinned]",
          style: { "border-width": 3, "border-color": "#e0bf76" },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)",
            "line-color": "#627782",
            "target-arrow-color": "#627782",
            "target-arrow-shape": "triangle",
            "arrow-scale": 1.1,
            "curve-style": "bezier",
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
      status.textContent = e.data.regioned
        ? "Regions arranged"
        : "Layout ready";
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
          : cy.getElementById(selected);
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
                ? "Click to expand or inspect"
                : "Drag region to move its groups",
            ]
          : n.is_group
            ? [
                n.label,
                num(n.count) + (n.count === 1 ? " address" : " addresses"),
                "Click to expand or inspect",
              ]
            : [
                n.ip,
                n.address_scope ? "Scope: " + n.address_scope : "",
                n.quiet
                  ? "No observed traffic in this window"
                  : "Traffic observed in this window",
                M.coverage(n) === "managed" ? "Agent installed" : "No agent",
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
          el("small", { text: "Click for full evidence · Esc to dismiss" }),
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
      revealInspector();
      inspect();
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
    const observer = new ResizeObserver(() => cy.resize());
    observer.observe(canvas);
    setMode(state.mode);
    updateDetails();
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
      projection = M.project(data, state);
      const elements = projection.nodes.map((n, i) => ({
        group: "nodes",
        data: {
          id: n.id,
          parent: n.parent || undefined,
          kind: n.type,
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
      projection.edges.forEach((e) =>
        elements.push({
          group: "edges",
          data: {
            id: "edge:" + e.id,
            source: e.source,
            target: e.target,
            verdict: e.verdict,
            width: Math.min(6, 1 + Math.log10(1 + e.flow_count)),
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
        if (!first && !skipCapture) cy.fit(undefined, 25);
      } else
        cy.batch(() =>
          elements.forEach((e) => cy.getElementById(e.data.id).data(e.data)),
        );
      updatePins();
      summary.replaceChildren(
        el(
          "span",
          {},
          el("strong", { text: num(projection.matched) }),
          " of " + num(projection.total) + " addresses",
        ),
        el(
          "span",
          {},
          el("strong", { text: num(projection.groups.length) }),
          " groups",
        ),
        el(
          "span",
          {},
          el("strong", { text: num(projection.edges.length) }),
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
      crumbs.replaceChildren(
        button("All groups", () => {
          state.expanded = {};
          selected = "";
          change(true);
        }),
      );
      projection.groups
        .filter((g) => g.expanded)
        .forEach((g) =>
          crumbs.append(
            button(
              g.label + " · " + g.shown + "/" + g.count + " ×",
              () => {
                delete state.expanded[g.key];
                selected = "";
                change(true);
              },
              "Collapse " + g.label,
            ),
          ),
        );
      status.textContent =
        (projection.hidden
          ? num(projection.hidden) +
            " hosts remain collapsed. Expand more from the group inspector. "
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
      if (!n) return;
      const group = M.project(data, {
        ...state,
        query: "",
        coverage: "",
        activeOnly: false,
      }).groups.find((g) => g.members.some((m) => m.id === n.id));
      if (!group) return;
      state.collapsedRegions[group.region] = false;
      state.expanded[group.key] = Math.max(100, state.expanded[group.key] || 0);
      state.query = n.ip || n.label;
      syncControls();
      renderGraph();
      selected = n.id;
      revealInspector();
      cy.elements().unselect();
      cy.getElementById(n.id).select();
      cy.fit(cy.getElementById(n.id).closedNeighborhood(), 80);
      inspect();
      markDirty();
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
                revealInspector();
                inspect();
              }),
            ),
          ),
        ),
      );
      function evidenceButton(id) {
        const b = button("Inspect", () => {
          selected = id;
          revealInspector();
          inspect();
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
    function detail(label, value) {
      if (value == null || value === "" || /^unknown$/i.test(String(value)))
        return null;
      return el(
        "div",
        { class: "tg-detail" },
        el("dt", { text: label }),
        el("dd", { text: String(value || "Unknown") }),
      );
    }
    function inspect() {
      inspector.replaceChildren();
      if (cy && projection) highlight(hoverID);
      const n = projection && projection.nodes.find((n) => n.id === selected),
        edge =
          projection &&
          projection.edges.find((e) => "edge:" + e.id === selected);
      if (!n && !edge) {
        inspector.append(
          el("p", { class: "tg-eyebrow", text: "Explore the network" }),
          el("h2", { text: "Start with a group" }),
          el("p", {
            text: "Select a group to see its hosts. Expand it to arrange hosts and inspect their observed communication.",
          }),
          el(
            "div",
            { class: "tg-legend" },
            el("p", { text: "Host solid border · agent installed" }),
            el("p", {
              text: "Host dashed border · no agent. Dim fill · no traffic in this window.",
            }),
            el("p", {
              text: "Arrows follow recorded source → destination. Counts are observations, not unique sessions.",
            }),
            el("p", { text: "Amber border · pinned position" }),
          ),
          el("p", {
            class: "tg-muted",
            text: "Domain labels are evidence from observations. They do not establish machine identity. Layout changes never change network policy.",
          }),
        );
        return;
      }
      inspector.append(
        el("p", {
          class: "tg-eyebrow",
          text: edge
            ? "Directed communication"
            : n.is_region
              ? "Visual region"
              : n.is_group
                ? "Network group"
                : "Host",
        }),
        el("h2", { text: edge ? "Observed link" : M.shortLabel(n) }),
        button("Clear selection", () => {
          selected = "";
          cy.elements().unselect();
          inspect();
        }),
      );
      if (n && n.is_region) {
        inspector.append(
          el("p", { text: n.description }),
          el("p", {
            text: num(n.count) + (n.count === 1 ? " address" : " addresses"),
          }),
          button(n.collapsed ? "Expand region" : "Collapse region", () => {
            const node = cy.getElementById(n.id);
            if (
              node
                .union(node.descendants())
                .some((x) => state.pins.includes(x.id()))
            ) {
              status.textContent =
                "Unpin region contents before changing their grouping.";
              return;
            }
            state.collapsedRegions[n.key] = !n.collapsed;
            change(true);
          }),
          button("Focus region", () => {
            cy.fit(
              cy
                .getElementById(n.id)
                .union(cy.getElementById(n.id).descendants()),
              35,
            );
            markDirty();
          }),
        );
        return;
      }
      if (n && n.is_group) {
        if (state.regions && state.group === "network") {
          const regionChoice = select(
            "Visual region",
            [
              ["", "Automatic"],
              ...Object.entries(M.regionDefinitions).map(([key, v]) => [
                key,
                v.label,
              ]),
            ],
            (v) => {
              state.regionOverrides[n.baseKey] = v;
              selected = "";
              change(true);
            },
          );
          regionChoice.querySelector("select").value =
            state.regionOverrides[n.baseKey] || "";
          inspector.append(regionChoice);
        }
        inspector.append(
          el("p", {
            text:
              num(n.count) +
              (n.count === 1 ? " host · " : " hosts · ") +
              num(n.internal_flows) +
              " observations inside collapsed group",
          }),
          (!n.expanded || n.shown < n.count) &&
            button(n.expanded ? "Show more hosts" : "Expand group", () => {
              if (state.pins.includes(n.id)) {
                status.textContent =
                  "Unpin this group before expanding it. Expanded hosts can then be pinned together.";
                return;
              }
              state.expanded[n.key] = Math.min(
                n.count,
                (state.expanded[n.key] || 0) + 100,
              );
              change(true);
            }),
        );
        if (n.expanded)
          inspector.append(
            button("Focus group", () => {
              cy.fit(
                cy
                  .getElementById(n.id)
                  .union(cy.getElementById(n.id).descendants()),
                30,
              );
              markDirty();
            }),
            button("Collapse group", () => {
              delete state.expanded[n.key];
              change(true);
            }),
          );
        const members = el("div", { class: "tg-members" });
        n.members
          .slice(0, 100)
          .forEach((m) =>
            members.append(
              button(m.label || m.ip, () => focus(m.id), m.ip || m.id),
            ),
          );
        inspector.append(members);
        if (n.count > 100)
          inspector.append(
            el("p", {
              text: "First 100 by activity shown. Search to find another host.",
            }),
          );
        return;
      }
      let ids, records;
      if (n) {
        ids = new Set([n.id]);
        records = (data.conversations || []).filter(
          (r) => ids.has(r.source) || ids.has(r.target),
        );
        inspector.append(
          el(
            "dl",
            {},
            detail("Address", n.ip),
            detail(
              "Agent coverage",
              M.coverage(n) === "managed" ? "Agent installed" : "No agent",
            ),
            detail("Address scope", n.address_scope),
            detail(
              "Estate membership",
              n.estate_member ? "Known / configured" : "Not established",
            ),
            detail("Role", n.role),
            detail("Recorded risk", n.risk),
            detail("Containment", n.is_isolated ? "Isolated" : "Not isolated"),
            detail("Evidence", (n.evidence || []).join(", ")),
            detail(
              "Activity",
              n.quiet ? "Quiet in this window" : "Observed in window",
            ),
          ),
        );
        inspector.append(
          button("Open asset", () => api.onAsset(n)),
          button("Outgoing traffic", () => api.onTraffic({ src_ip: n.ip })),
          button("Incoming traffic", () => api.onTraffic({ dst_ip: n.ip })),
        );
      } else {
        const source = projection.nodes.find((x) => x.id === edge.source),
          target = projection.nodes.find((x) => x.id === edge.target);
        inspector.append(
          el("p", {
            class: "tg-direction",
            text:
              (source.label || source.ip) + " → " + (target.label || target.ip),
          }),
          el(
            "dl",
            {},
            detail("Observations", num(edge.flow_count)),
            detail("Measured volume", bytes(edge.total_bytes)),
            detail(
              "With byte counts",
              num(edge.measured_flows) + " / " + num(edge.flow_count),
            ),
            detail("Verdict", edge.verdict),
          ),
        );
        records = edge.relations || [];
      }
      const domains = new Map(),
        processes = new Map();
      records.forEach((r) => {
        if (r.domain) domains.set(r.domain + " · " + r.domain_source, r);
        if (r.process) processes.set(r.endpoint_id + "\0" + r.process, r);
      });
      inspector.append(el("h3", { text: "Observed domains" }));
      if (!domains.size)
        inspector.append(
          el("p", {
            class: "tg-muted",
            text: "No domain evidence in this window.",
          }),
        );
      [...domains].slice(0, 30).forEach(([label, r]) =>
        inspector.append(
          button(
            label,
            () => {
              search.value = state.query = r.domain;
              change();
            },
            "Filter communication for " + r.domain,
          ),
        ),
      );
      inspector.append(el("h3", { text: "Processes" }));
      if (!processes.size)
        inspector.append(
          el("p", {
            class: "tg-muted",
            text: "No process attribution reported.",
          }),
        );
      [...processes.values()].slice(0, 30).forEach((r) =>
        inspector.append(
          el(
            "div",
            { class: "tg-process" },
            button(
              r.process,
              () => {
                search.value = state.query = r.process;
                change();
              },
              "Find this executable path across reporters",
            ),
            el("small", { text: "Reported by " + r.endpoint_id }),
            button("Traffic details", () =>
              api.onTraffic({ process: r.process, endpoint_id: r.endpoint_id }),
            ),
          ),
        ),
      );
      inspector.append(el("h3", { text: "Recent relations" }));
      records.slice(0, 20).forEach((r) =>
        inspector.append(
          el("p", {
            class: "tg-relation",
            text:
              (r.protocol === 6
                ? "TCP"
                : r.protocol === 17
                  ? "UDP"
                  : r.protocol) +
              "/" +
              r.port +
              " · " +
              num(r.flow_count) +
              " observations · " +
              bytes(r.total_bytes) +
              "\n" +
              time(r.last_seen),
          }),
        ),
      );
      if (domains.size > 30 || processes.size > 30 || records.length > 20)
        inspector.append(
          el("p", {
            class: "tg-muted",
            text: "Inspector lists are shortened. Use Traffic details for individual observations.",
          }),
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
        collapsedRegions: v.state.collapsedRegions || {},
        regionOverrides: v.state.regionOverrides || {},
      };
      state.expanded = state.expanded || {};
      state.positions = state.positions || {};
      state.pins = state.pins || [];
      syncControls();
      setMode(state.mode);
      updateDetails();
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
