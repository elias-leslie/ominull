/* Topology owns its canvas lifecycle; polling never replaces its DOM. */
(function () {
  "use strict";
  const M = window.OminullTopologyModel;
  // A small estate is drawn host by host; a large one as groups. A phone
  // cannot read many labels, so its limit is lower.
  const AUTO_HOSTS = 60,
    AUTO_HOSTS_NARROW = 16,
    HOST_BUDGET = 400,
    LIST_ROWS = 300;
  function el(tag, props, ...children) {
    const n = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === false) return;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    });
    children
      .flat()
      .filter(Boolean)
      .forEach((c) => n.append(c));
    return n;
  }
  function button(text, fn, title, cls) {
    return el("button", {
      type: "button",
      class: "btn tg-button" + (cls ? " " + cls : ""),
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
  // A filter chip is the filter and its count; it is built once and updated in
  // place so a refresh never steals keyboard focus.
  function chip(label, fn, title) {
    const count = el("b"),
      b = el(
        "button",
        { type: "button", class: "tg-chip", onclick: fn, title: title || "" },
        el("span", { text: label }),
        count,
      );
    return {
      node: b,
      set(n, on, tone) {
        count.textContent = n === null ? "" : num(n);
        b.setAttribute("aria-pressed", String(!!on));
        b.dataset.tone = n && tone ? tone : "";
        b.disabled = n === 0 && !on;
      },
    };
  }
  const bytes = (n) => {
    n = Number(n) || 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < 4) {
      n /= 1024;
      i++;
    }
    return (n < 10 && i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
  };
  const num = (n) => (Number(n) || 0).toLocaleString();
  const plural = (n, one, many) => num(n) + " " + (n === 1 ? one : many);
  const portText = (p) => p.protocol + (p.port ? "/" + p.port : "");
  const uniq = (list) => [...new Set(list)];
  const cssVar = (name, fallback) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim() ||
    fallback;
  // The graph is drawn by a canvas, which cannot read CSS variables, so the
  // console's tokens are read here and again when the theme changes.
  function palette() {
    return {
      ink: cssVar("--ink", "#dadde3"),
      ink2: cssVar("--ink-2", "#949ba8"),
      ink3: cssVar("--ink-3", "#878e9b"),
      line: cssVar("--line", "#2c313a"),
      ground: cssVar("--ground", "#14161a"),
      panel: cssVar("--panel", "#1a1d23"),
      brand: cssVar("--brand", "#8fa9e8"),
      ok: cssVar("--ok", "#73b87d"),
      warn: cssVar("--warn", "#e6be6d"),
      crit: cssVar("--crit", "#cd7670"),
      info: cssVar("--info", "#689bdb"),
    };
  }
  // Flows carry bytes only where the collector could read a counter, so a
  // figure is qualified when only part of the traffic was measured.
  function volume(e) {
    const flows = e.flow_count || 0,
      measured = e.measured_flows;
    if (measured === undefined || measured >= flows)
      return bytes(e.total_bytes) + " measured";
    if (!measured) return "no byte counts";
    return (
      bytes(e.total_bytes) +
      " on " +
      num(measured) +
      " of " +
      plural(flows, "flow", "flows")
    );
  }
  function mount(container, api) {
    let data = { nodes: [], edges: [], conversations: [] },
      loaded = false,
      loadError = "",
      projection,
      nodeMap = new Map(),
      rawNodes = new Map(),
      adjacency = new Map(),
      reporterLabels = new Map(),
      cy,
      worker,
      pal = palette(),
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
      saveError = "",
      listRows = LIST_ROWS,
      noticeTimer,
      transient = "",
      pinBtn,
      unpinBtn,
      arrangeBtn;
    const selection = { node: false };
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
      detail: "auto",
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

    /* ---- controls ---- */
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
    const detail = select(
      "Show",
      [
        ["auto", "Automatic"],
        ["groups", "Groups only"],
        ["hosts", "All hosts"],
      ],
      (v) => {
        state.detail = v;
        change(true);
      },
    );
    const windowSelect = select(
      "Window",
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
    const dirtyDot = el("span", {
      class: "tg-dirty",
      title: "Unsaved changes",
      text: "●",
      hidden: "",
    });
    const views_ = el(
      "details",
      { class: "tg-views" },
      el(
        "summary",
        { class: "btn tg-button" },
        "Views",
        dirtyDot,
      ),
      el("div", { class: "tg-pop" }, saved, el("div", { class: "tg-row" }, save, saveAs, removeView)),
    );
    const helpText = el(
      "div",
      { class: "tg-help-text", id: "tg-help-text", hidden: "" },
      el("p", {
        text: "Boxes group addresses; arrows show who talked to whom in the chosen window. Click to select, double-click to explore, Shift-click to select several, scroll or pinch to zoom.",
      }),
      el("p", {
        text: "With something selected, green arrows leave it and blue arrows arrive at it. Dim icons were quiet in this window. List view shows the same data for keyboard use.",
      }),
    );
    const help = el("button", {
      type: "button",
      class: "btn tg-button tg-help",
      "aria-controls": "tg-help-text",
      "aria-expanded": "false",
      "aria-label": "About this page",
      title: "About this page",
      text: "?",
      onclick: () => {
        helpText.hidden = !helpText.hidden;
        help.setAttribute("aria-expanded", String(!helpText.hidden));
      },
    });
    // Phones: the selects and chips fold behind one button so the graph gets the screen.
    const filterToggle = el("button", {
      type: "button",
      class: "btn tg-button tg-filter-toggle",
      "aria-expanded": "false",
      onclick: () => {
        const open = root.dataset.controls !== "open";
        root.dataset.controls = open ? "open" : "closed";
        filterToggle.setAttribute("aria-expanded", String(open));
      },
    });
    const bar = el(
      "div",
      { class: "tg-bar" },
      search,
      filterToggle,
      group,
      detail,
      windowSelect,
      el("span", { class: "tg-fill" }),
      views_,
      help,
    );

    /* ---- filter chips ---- */
    const chipCover = {
      managed: chip("Agent installed", () => toggle("coverage", "managed")),
      unmanaged: chip("No agent", () => toggle("coverage", "unmanaged")),
    };
    const chipQuiet = chip(
      "Hide quiet",
      () => {
        state.activeOnly = !state.activeOnly;
        change();
      },
      "Hide known hosts that sent or received nothing in this window",
    );
    const chipVerdict = {
      blocked: chip("Blocked", () => toggle("verdict", "blocked"), "Links with blocked flows"),
      anomalous: chip("Anomalous", () => toggle("verdict", "anomalous"), "Links with anomalous flows"),
      clean: chip("Clean", () => toggle("verdict", "clean"), "Links with no finding"),
    };
    const chipRegions = chip(
      "Regions",
      () => {
        state.regions = !state.regions;
        change(true);
      },
      "Separate internal, virtual, external and discovery networks",
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
    const shown = el("span", { class: "tg-shown", "aria-live": "polite" });
    const clear = button("Clear filters", clearFilters, "Clear search and filters", "tg-clear");
    const chips = el(
      "div",
      { class: "tg-filters", role: "group", "aria-label": "Filters" },
      el("div", { class: "tg-set" }, chipCover.managed.node, chipCover.unmanaged.node, chipQuiet.node),
      el("span", { class: "tg-sep" }),
      el("div", { class: "tg-set" }, chipVerdict.blocked.node, chipVerdict.anomalous.node, chipVerdict.clean.node),
      el("span", { class: "tg-sep" }),
      protocol,
      chipRegions.node,
      el("span", { class: "tg-fill" }),
      shown,
      clear,
    );
    function toggle(key, value) {
      state[key] = state[key] === value ? "" : value;
      change();
    }
    function clearFilters() {
      state.query = "";
      state.coverage = "";
      state.protocol = "";
      state.verdict = "";
      state.activeOnly = false;
      syncControls();
      change();
    }
    function filtered() {
      return !!(
        state.query ||
        state.coverage ||
        state.protocol ||
        state.verdict ||
        state.activeOnly
      );
    }

    /* ---- scope row, canvas tools ---- */
    const crumbs = el("nav", {
      class: "tg-crumbs",
      "aria-label": "Topology navigation",
    });
    const pan = button(
      "Pan",
      () => setMode("pan"),
      "Drag the background to pan. Shift-click selects several hosts.",
    );
    const box = button(
      "Select",
      () => setMode("select"),
      "Drag a box to select hosts. Drag selected hosts to move them together.",
    );
    const listButton = button("List view", () => {
      state.list = !state.list;
      applyListMode();
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
    const controls = el(
      "div",
      { class: "tg-canvas-tools" },
      el("div", { class: "tg-seg" }, pan, box),
      button("Fit", () => cy.fit(undefined, 25), "Fit the whole graph in view"),
      button("Arrange", () => arrange(false), "Lay the graph out again"),
      undo,
      button("−", () => zoomBy(1 / 1.25), "Zoom out", "tg-zoom"),
      button("+", () => zoomBy(1.25), "Zoom in", "tg-zoom"),
      listButton,
    );
    const scope = el("div", { class: "tg-scope" }, crumbs, controls);

    /* ---- stage ---- */
    const canvas = el("div", {
        class: "tg-canvas",
        role: "group",
        "aria-label":
          "Interactive communication graph. Use List view for keyboard access.",
      }),
      list = el("div", { class: "tg-list", hidden: "" }),
      empty = el("div", { class: "tg-empty", hidden: "" }),
      notice = el("div", {
        class: "tg-notice",
        role: "status",
        "aria-live": "polite",
        hidden: "",
      });
    const tooltip = el("div", {
      class: "tg-tooltip",
      id: "topology-tooltip",
      role: "tooltip",
      hidden: "",
    });
    const directionRef = el("span", {
      class: "tg-direction-reference",
      text: "Select a host to see its direction",
    });
    const summary = el("div", { class: "tg-summary" });
    const strip = el(
      "div",
      { class: "tg-direction-key" },
      el(
        "span",
        { class: "tg-legend", "aria-label": "Legend" },
        el("span", { class: "tg-key tg-key-agent", text: "Agent" }),
        el("span", { class: "tg-key tg-key-plain", text: "No agent" }),
        el("span", { class: "tg-key tg-key-risk", text: "High risk" }),
        el("span", { class: "tg-key tg-key-iso", text: "Isolated" }),
      ),
      el("span", { class: "tg-incoming", text: "← Incoming" }),
      el("span", { class: "tg-outgoing", text: "Outgoing →" }),
      directionRef,
      summary,
    );
    const viewport = el(
      "div",
      { class: "tg-viewport" },
      canvas,
      list,
      empty,
      notice,
      tooltip,
    );
    const context = el("aside", {
      class: "tg-context",
      "aria-label": "Selected item",
    });
    const stage = el(
      "div",
      { class: "tg-stage" },
      el("div", { class: "tg-graph-area" }, viewport, strip),
      context,
    );
    root.append(bar, helpText, chips, scope, stage);
    container.replaceChildren(root);

    /* ---- graph ---- */
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
    // Colour carries one fact: green is a process, blue a host with an agent,
    // red a flagged destination, dim an address the estate does not know.
    function iconColor(n, kind) {
      if (n.type === "process") return pal.ok;
      if (n.context || kind === "domain") return pal.ink2;
      if (n.type === "threat") return pal.crit;
      if (!n.is_group && !n.is_region && M.coverage(n) === "managed")
        return pal.brand;
      return pal.ink;
    }
    function icon(n) {
      const kind = M.iconKind(n),
        color = iconColor(n, kind),
        key = kind + color;
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
    }
    function graphStyle(c) {
      return [
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
            color: c.ink,
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
            "background-color": c.line,
            "background-opacity": 0.45,
            "border-color": c.ink3,
            "border-width": 1,
            "border-opacity": 0.45,
            padding: 38,
            "text-valign": "top",
            "text-margin-y": -12,
            "font-size": 15,
            "text-max-width": 300,
          },
        },
        {
          selector: 'node[regionKey="external"]:parent',
          style: { "background-color": c.info, "background-opacity": 0.12 },
        },
        {
          selector: 'node[regionKey="virtual"]:parent',
          style: { "background-color": c.ok, "background-opacity": 0.12 },
        },
        {
          selector: 'node[regionKey="discovery"]:parent',
          style: { "background-color": c.warn, "background-opacity": 0.1 },
        },
        {
          selector: "node[?quiet]",
          style: { "background-image-opacity": 0.45, "text-opacity": 0.6 },
        },
        {
          selector: 'node[risk="HIGH"], node[risk="CRITICAL"]',
          style: {
            "border-color": c.crit,
            "border-width": 2,
            "border-opacity": 0.9,
          },
        },
        {
          selector: "node[?isolated]",
          style: {
            "border-color": c.warn,
            "border-width": 2,
            "border-style": "dashed",
            "border-opacity": 1,
          },
        },
        {
          selector: "node[pinned]",
          style: { "border-color": c.warn, "border-width": 2, "border-opacity": 1 },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)",
            "line-color": c.ink3,
            "target-arrow-color": c.ink3,
            "target-arrow-shape": "triangle",
            "arrow-scale": 1.1,
            "curve-style": "unbundled-bezier",
            "control-point-distances": "data(bend)",
            "control-point-weights": 0.5,
            label: "data(edgeLabel)",
            "font-size": 11,
            color: c.ink2,
            "text-background-color": c.ground,
            "text-background-opacity": 0.95,
            "text-background-padding": 3,
            "text-rotation": "autorotate",
            opacity: 0.7,
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'edge[verdict="blocked"]',
          style: {
            "line-color": c.crit,
            "target-arrow-color": c.crit,
            "line-style": "dashed",
            opacity: 0.9,
          },
        },
        {
          selector: 'edge[verdict="anomalous"]',
          style: { "line-color": c.warn, "target-arrow-color": c.warn, opacity: 0.9 },
        },
        {
          selector: ":selected",
          style: {
            "border-color": c.brand,
            "border-width": 3,
            "border-style": "solid",
            "border-opacity": 1,
            "line-color": c.brand,
            "target-arrow-color": c.brand,
            opacity: 1,
          },
        },
        { selector: ".muted", style: { opacity: 0.16 } },
        {
          selector: "edge.incoming",
          style: { "line-color": c.info, "target-arrow-color": c.info, opacity: 1 },
        },
        {
          selector: "edge.outgoing",
          style: { "line-color": c.ok, "target-arrow-color": c.ok, opacity: 1 },
        },
      ];
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
      style: graphStyle(pal),
    });
    worker = new Worker(
      "vendor/topology-layout.js?v=" + encodeURIComponent(api.version || ""),
    );
    worker.onmessage = (e) => {
      if (destroyed || e.data.id !== layoutID) return;
      viewport.removeAttribute("aria-busy");
      if (e.data.error) {
        say("Layout failed: " + e.data.error + ". Existing positions retained.");
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
      renderNotice();
    };
    worker.onerror = () => {
      viewport.removeAttribute("aria-busy");
      say("Layout worker unavailable. Drag nodes manually or use List view.");
    };
    // Theme changes repaint the graph with the new tokens.
    const themeWatch = new MutationObserver(() => {
      pal = palette();
      iconCache.clear();
      cy.style(graphStyle(pal));
      if (projection) renderGraph(true);
    });
    themeWatch.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
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
    function escapeKey(e) {
      if (e.key !== "Escape") return;
      if (!tooltip.hidden) hideTooltip();
      else if (views_.open) views_.open = false;
      else if (selected && root.contains(document.activeElement)) clearSelection();
    }
    document.addEventListener("keydown", escapeKey);
    // A click outside the views panel closes it.
    function closeViews(e) {
      if (views_.open && !views_.contains(e.target)) views_.open = false;
    }
    document.addEventListener("click", closeViews);
    function highlight(id) {
      cy.elements().removeClass("incoming outgoing muted");
      const hovered = cy.getElementById(id || "");
      const ref =
        hovered.length && hovered.isNode()
          ? hovered
          : cy.getElementById(
              selected || (projection?.detail ? state.scope?.id : ""),
            );
      if (!ref.length || !ref.isNode()) {
        directionRef.textContent = "Select a host to see its direction";
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
      const n = nodeMap.get(ref.id());
      directionRef.textContent = "At " + (n ? M.shortLabel(n) : ref.id());
    }
    function nodeLines(n) {
      if (n.is_region)
        return [
          n.description,
          plural(n.count, "address", "addresses"),
          n.collapsed
            ? "Double-click to explore"
            : "Drag region to move its groups",
        ];
      if (n.is_group)
        return [
          n.label,
          plural(n.count, "address", "addresses"),
          "Double-click to explore",
        ];
      return [
        n.description,
        n.process,
        n.type === "process"
          ? "Reported by " + (reporterLabels.get(n.endpoint_id) || n.endpoint_id)
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
    }
    function relationLines(edge, limit) {
      const records = edge.relations || [];
      const domains = uniq(records.map((r) => r.domain).filter(Boolean));
      const processes = uniq(
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
      );
      return [
        ["Domains", domains],
        ["Processes / reporter", processes],
      ]
        .filter(([, values]) => values.length)
        .map(
          ([label, values]) =>
            label +
            ": " +
            values.slice(0, limit).join("; ") +
            (values.length > limit ? " +" + (values.length - limit) : ""),
        );
    }
    function showTooltip(id, point, trigger) {
      hideTooltip();
      const n = nodeMap.get(id);
      const edge = projection.edges.find((e) => "edge:" + e.id === id);
      if (!n && !edge) return;
      tooltip.replaceChildren();
      if (n) {
        tooltip.append(el("strong", { text: M.shortLabel(n) }));
        nodeLines(n)
          .filter(Boolean)
          .filter((v, i, a) => a.indexOf(v) === i && v !== M.shortLabel(n))
          .forEach((text) => tooltip.append(el("div", { text })));
      } else {
        const source = nodeMap.get(edge.source),
          target = nodeMap.get(edge.target);
        tooltip.append(
          el("strong", {
            text: M.shortLabel(source) + " → " + M.shortLabel(target),
          }),
        );
        tooltip.append(
          el("div", {
            text:
              plural(edge.flow_count, "flow", "flows") + " · " + volume(edge),
          }),
        );
        const ports = uniq(edge.ports.map(portText));
        if (ports.length)
          tooltip.append(
            el("div", {
              text:
                ports.slice(0, 5).join(" · ") +
                (ports.length > 5 ? " +" + (ports.length - 5) : ""),
            }),
          );
        relationLines(edge, 2).forEach((text) =>
          tooltip.append(el("div", { text })),
        );
        if (edge.verdict !== "clean")
          tooltip.append(
            el("div", {
              class: "tg-tooltip-finding",
              text:
                edge.verdict === "blocked"
                  ? "Contains blocked flows"
                  : "Contains anomalous flows",
            }),
          );
        tooltip.append(
          el("small", { text: "Double-click to explore · Esc to dismiss" }),
        );
      }
      tooltip.hidden = false;
      tooltipState = { id, point, trigger };
      const area = viewport.getBoundingClientRect();
      tooltip.style.left =
        Math.max(
          8,
          Math.min(point.x + 12, area.width - tooltip.offsetWidth - 8),
        ) + "px";
      tooltip.style.top =
        Math.max(
          8,
          Math.min(point.y + 12, area.height - tooltip.offsetHeight - 8),
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
      if (e.target === cy) clearSelection();
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
      if (selection.node) syncSelectionActions();
    });
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
    applyListMode();
    refreshViews();
    inspect();
    function applyListMode() {
      canvas.hidden = state.list;
      list.hidden = !state.list;
      listButton.textContent = state.list ? "Graph view" : "List view";
      pan.disabled = box.disabled = state.list;
      if (!state.list && cy) cy.resize();
      renderList();
    }
    function setMode(mode) {
      state.mode = mode;
      cy.boxSelectionEnabled(mode === "select");
      cy.userPanningEnabled(mode === "pan");
      pan.setAttribute("aria-pressed", String(mode === "pan"));
      box.setAttribute("aria-pressed", String(mode === "select"));
    }
    // Moving the view is not a change worth saving; moving or pinning hosts,
    // filters and the window are.
    function markDirty() {
      dirty = true;
      dirtyDot.hidden = false;
    }
    function markClean() {
      dirty = false;
      dirtyDot.hidden = true;
    }
    if (dirty) dirtyDot.hidden = false;
    function say(text, keep) {
      clearTimeout(noticeTimer);
      transient = keep ? "" : text;
      renderNotice();
      if (!keep && text)
        noticeTimer = setTimeout(() => {
          transient = "";
          renderNotice();
        }, 6000);
    }
    function noticeText() {
      if (saveError) return saveError;
      if (transient) return transient;
      if (loadError && loaded)
        return (
          "Refresh failed: " +
          loadError +
          ". Showing the last graph" +
          (data.to ? " from " + new Date(data.to).toLocaleTimeString() : "") +
          "."
        );
      if (!projection) return "";
      return [
        projection.hidden
          ? plural(projection.hidden, "address", "addresses") +
            " grouped. Double-click a group to explore it."
          : "",
        projection.omittedEdges
          ? plural(projection.omittedEdges, "lower-volume link", "lower-volume links") +
            " left out; narrow the filters."
          : "",
        data.evidence_truncated
          ? "Evidence is limited to the 20,000 most recent relations, so domain and process search is partial."
          : "",
        state.query
          ? "Search matches hosts and observed relations; link totals cover the matching host pairs."
          : "",
        projection.notice && projection.detail ? projection.notice : "",
        projection.capacityReached
          ? "Drawing limit reached; narrow the filters to see other relations."
          : "",
      ]
        .filter(Boolean)
        .join(" ");
    }
    function renderNotice() {
      const text = noticeText();
      notice.textContent = text;
      notice.hidden = !text;
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
      syncControls();
      renderGraph();
      if (rearrange) arrange(false);
    }
    function syncControls() {
      search.value = state.query;
      group.querySelector("select").value = state.group;
      detail.querySelector("select").value = state.detail;
      windowSelect.querySelector("select").value = state.window;
      protocol.querySelector("select").value = state.protocol;
      renderFilters();
    }
    function renderFilters() {
      const c = M.counts(data);
      chipCover.managed.set(c.managed, state.coverage === "managed");
      chipCover.unmanaged.set(c.unmanaged, state.coverage === "unmanaged", "warn");
      chipQuiet.set(c.quiet, state.activeOnly);
      chipVerdict.blocked.set(c.blocked, state.verdict === "blocked", "crit");
      chipVerdict.anomalous.set(c.anomalous, state.verdict === "anomalous", "warn");
      chipVerdict.clean.set(c.clean, state.verdict === "clean");
      chipRegions.set(null, state.regions);
      clear.hidden = !filtered();
      const active = [state.coverage, state.protocol, state.verdict, state.activeOnly].filter(Boolean).length;
      filterToggle.textContent = active ? `Filters (${active})` : "Filters";
    }
    function sceneOptions() {
      const o = { ...state };
      const overview = !state.scope || state.scope.kind === "overview";
      if (overview && state.detail !== "groups") {
        const narrow = canvas.clientWidth > 0 && canvas.clientWidth < 640;
        if (
          state.detail === "hosts" ||
          M.shouldExpand(data, o, narrow ? AUTO_HOSTS_NARROW : AUTO_HOSTS)
        ) {
          o.expandAll = true;
          o.budget = HOST_BUDGET;
        }
      }
      return o;
    }
    function renderGraph(skipCapture) {
      if (dragging) return;
      const previousTooltip = tooltipState;
      if (!skipCapture) capture();
      projection = M.scene(data, sceneOptions());
      nodeMap = new Map(projection.nodes.map((n) => [n.id, n]));
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
              ? "\n" + plural(n.count, "address", "addresses")
              : ""),
          ...(n.is_group ? { groupNode: true } : {}),
          ...(n.is_region ? { regionNode: true, regionKey: n.key } : {}),
          agent: !!n.endpoint_id || n.type === "managed",
          quiet: !!n.quiet,
          isolated: !!n.is_isolated,
          risk: String(n.risk || "").toUpperCase(),
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
              ? uniq((e.ports || []).map(portText)).slice(0, 2).join(" · ")
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
      renderSummary();
      renderFilters();
      renderCrumbs();
      renderEmpty();
      renderNotice();
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
    function renderSummary() {
      const hosts = projection.detail
        ? projection.nodes.filter((n) => !n.parent && n.id !== state.scope.id)
            .length
        : projection.matched;
      const parts = [
        projection.detail
          ? plural(hosts, "destination", "destinations")
          : num(hosts) + " of " + plural(projection.total, "address", "addresses"),
        projection.detail
          ? plural(
              projection.nodes.filter((n) => n.type === "process").length,
              "process",
              "processes",
            )
          : plural(projection.groups.length, "group", "groups"),
        num(projection.edges.length) +
          " of " +
          plural(projection.edges.length + projection.omittedEdges, "link", "links"),
      ];
      summary.replaceChildren(
        el("span", { text: parts.join(" · ") }),
        el("span", {
          class: "tg-window",
          text: data.to
            ? "Through " + new Date(data.to).toLocaleTimeString()
            : "Waiting for observations",
        }),
      );
      shown.textContent = filtered()
        ? num(projection.matched) + " of " + num(projection.total) + " match"
        : "";
    }
    function renderCrumbs() {
      crumbs.replaceChildren();
      if (state.trail?.length) crumbs.append(button("← Back", () => goBack()));
      (state.trail || []).forEach((entry, i) =>
        crumbs.append(button(entry.label, () => goBack(i), "", "tg-crumb")),
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
    }
    // The graph says why it is empty and what to do, instead of leaving a
    // blank canvas.
    function renderEmpty() {
      empty.replaceChildren();
      const none = !projection || !projection.nodes.length;
      let title = "",
        body = "",
        actions = [];
      if (!loaded && !loadError) {
        title = "Loading topology…";
      } else if (!loaded) {
        title = "Topology did not load";
        body = loadError;
        actions = [button("Try again", () => api.onWindow(state.window))];
      } else if (none && filtered()) {
        title = "Nothing matches these filters";
        actions = [button("Clear filters", clearFilters)];
      } else if (none && state.scope && state.scope.kind !== "overview") {
        title = projection?.notice || "Nothing to show for this selection.";
        actions = [button("← Back", () => goBack())];
      } else if (none) {
        title = "No traffic observed in this window";
        body =
          "Hosts appear here once an agent or the scanner sees them talking.";
        if (state.window !== "7d")
          actions = [
            button("Try the last 7 days", () => {
              state.window = "7d";
              syncControls();
              api.onWindow("7d");
            }),
          ];
      }
      empty.hidden = !title;
      if (title)
        empty.append(
          el("strong", { text: title }),
          body ? el("p", { text: body }) : null,
          actions.length ? el("div", { class: "tg-row" }, ...actions) : null,
        );
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
        say("Select hosts or groups to arrange first.");
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
      viewport.setAttribute("aria-busy", "true");
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
    }
    function focus(id) {
      const n = (data.nodes || []).find(
        (n) => n.id === id || n.asset_id === id || n.ip === id,
      );
      if (n) navigate({ kind: "host", id: n.id }, M.shortLabel(n));
    }

    /* ---- list view ---- */
    function renderList() {
      if (!state.list || !projection) return;
      const focusedID = list.contains(document.activeElement)
        ? document.activeElement.dataset.topologyId
        : null;
      const scrollTop = list.scrollTop;
      list.replaceChildren();
      function evidenceButton(id) {
        const b = button(
          "Inspect",
          () => {
            selected = id;
            inspect();
          },
          "Show details",
        );
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
            area = viewport.getBoundingClientRect();
          showTooltip(id, { x: r.left - area.left, y: r.bottom - area.top }, b);
        };
        b.addEventListener("focus", show);
        b.addEventListener("mouseenter", show);
        b.addEventListener("blur", deferHide);
        b.addEventListener("mouseleave", deferHide);
        return b;
      }
      const table = (caption, heads, rows, more) =>
        el(
          "table",
          { class: "tg-table" },
          el("caption", { text: caption }),
          el(
            "thead",
            {},
            el("tr", {}, ...heads.map((t) => el("th", { scope: "col", text: t }))),
          ),
          el("tbody", {}, rows),
        );
      const visibleNodes = projection.nodes.slice(0, listRows),
        visibleEdges = projection.edges.slice(0, listRows);
      const nodeRows = visibleNodes.map((n) =>
        el(
          "tr",
          { "aria-selected": String(n.id === selected) },
          el("td", { class: "c-name", text: M.shortLabel(n) }),
          el("td", {
            class: "c-addr",
            text: n.ip || plural(n.count, "host", "hosts"),
          }),
          el("td", {
            class: "c-role",
            text:
              n.is_region || n.is_group
                ? ""
                : n.role && !/^unknown$/i.test(n.role)
                  ? n.role
                  : "",
          }),
          el("td", {
            class: "c-cov",
            text: n.is_region
              ? "Region"
              : n.is_group
                ? "Group"
                : ["process", "domain", "traffic"].includes(n.type)
                  ? n.type === "process" ? "Process" : n.type === "domain" ? "Domain" : "Traffic"
                  : M.coverage(n) === "managed"
                    ? "Agent installed"
                    : "No agent",
          }),
          el("td", { class: "c-act" }, evidenceButton(n.id)),
        ),
      );
      const edgeRows = visibleEdges.map((e) => {
        const source = nodeMap.get(e.source),
          target = nodeMap.get(e.target);
        const ports = uniq((e.ports || []).map(portText));
        return el(
          "tr",
          { "aria-selected": String("edge:" + e.id === selected) },
          el("td", {
            class: "c-name",
            text: M.shortLabel(source) + " → " + M.shortLabel(target),
          }),
          el("td", { class: "c-addr", text: plural(e.flow_count, "flow", "flows") }),
          el("td", {
            class: "c-role",
            text: ports.slice(0, 3).join(" · ") + (ports.length > 3 ? " +" + (ports.length - 3) : ""),
          }),
          el("td", {
            class: "c-cov",
            text:
              e.verdict === "blocked"
                ? "Blocked"
                : e.verdict === "anomalous"
                  ? "Anomalous"
                  : "Clean",
          }),
          el("td", { class: "c-act" }, evidenceButton("edge:" + e.id)),
        );
      });
      list.append(
        table("Hosts and groups", ["Name", "Address", "Role", "Agent", ""], nodeRows),
        table("Links", ["From → to", "Flows", "Ports", "Status", ""], edgeRows),
      );
      const hiddenRows =
        Math.max(0, projection.nodes.length - listRows) +
        Math.max(0, projection.edges.length - listRows);
      if (hiddenRows)
        list.append(
          el(
            "div",
            { class: "tg-more" },
            el("span", { text: plural(hiddenRows, "more row", "more rows") + " not shown" }),
            button("Show more", () => {
              listRows += LIST_ROWS;
              renderList();
            }),
          ),
        );
      list.scrollTop = scrollTop;
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

    /* ---- navigation ---- */
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
      listRows = LIST_ROWS;
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
      listRows = LIST_ROWS;
      undo.disabled = true;
      lastStructure = "";
      first = false;
      hideTooltip();
      const vp = state.viewport;
      renderGraph(true);
      if (vp) {
        cy.zoom(vp.zoom);
        cy.pan(vp.pan);
      }
      markDirty();
    }
    function drill(id) {
      const n = nodeMap.get(id);
      if (!n) {
        const e = projection?.edges.find((e) => "edge:" + e.id === id);
        if (e) {
          const source = nodeMap.get(e.source);
          const target = nodeMap.get(e.target);
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
    function clearSelection() {
      selected = "";
      cy.elements().unselect();
      inspect();
    }

    /* ---- selection panel ---- */
    function syncSelectionActions() {
      if (!pinBtn) return;
      const any = selectedLeaves().length > 0;
      pinBtn.disabled = unpinBtn.disabled = arrangeBtn.disabled = !any;
    }
    const badge = (text, tone) =>
      el("span", { class: "tg-badge", "data-tone": tone || "", text });
    const facts = (rows) =>
      el(
        "dl",
        { class: "tg-facts" },
        rows
          .filter(([, v]) => v)
          .flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]),
      );
    function peersOf(n) {
      const id = n.host_id || n.id;
      const merged = new Map();
      (adjacency.get(id) || []).forEach((e) => {
        const out = e.source === id,
          other = out ? e.target : e.source;
        const m = merged.get(other) || { other, flows: 0, out: false, in: false };
        m.flows += e.flow_count || 0;
        if (out) m.out = true;
        else m.in = true;
        merged.set(other, m);
      });
      return [...merged.values()].sort((a, b) => b.flows - a.flows);
    }
    function trafficFilter(edge) {
      const s = nodeMap.get(edge.source),
        t = nodeMap.get(edge.target);
      if (!s || !t) return null;
      if (s.type === "process")
        return { process: s.process, endpoint_id: s.endpoint_id, dst_ip: t.ip || "" };
      if (t.type === "process")
        return { process: t.process, endpoint_id: t.endpoint_id, src_ip: s.ip || "" };
      if (s.ip && t.ip) return { src_ip: s.ip, dst_ip: t.ip };
      return null;
    }
    function inspect() {
      const keepFocus = context.contains(document.activeElement)
        ? document.activeElement.textContent
        : null;
      buildContext();
      if (keepFocus)
        [...context.querySelectorAll("button")]
          .find((b) => b.textContent === keepFocus)
          ?.focus({ preventScroll: true });
    }
    function buildContext() {
      context.replaceChildren();
      pinBtn = unpinBtn = arrangeBtn = null;
      selection.node = false;
      if (cy && projection) highlight(hoverID);
      const n = nodeMap.get(selected);
      const edge = projection?.edges.find((e) => "edge:" + e.id === selected);
      context.dataset.open = n || edge ? "true" : "false";
      if (!n && !edge) return;
      const head = el("div", { class: "tg-ctx-head" });
      const body = [];
      const actions = el("div", { class: "tg-row" });
      if (n) {
        selection.node = true;
        head.append(
          el("strong", { text: M.shortLabel(n) }),
          el(
            "span",
            { class: "tg-badges" },
            ...(n.is_region || n.is_group
              ? [badge(n.is_region ? "Region" : "Group")]
              : n.type === "process"
                ? [badge("Process")]
                : n.type === "domain"
                  ? [badge("Domain")]
                  : n.type === "traffic"
                    ? []
                    : [
                        M.coverage(n) === "managed"
                          ? badge("Agent installed", "ok")
                          : badge("No agent", "warn"),
                        n.risk && n.risk !== "CLEAN" && n.risk !== "LOW"
                          ? badge(n.risk, "crit")
                          : null,
                        n.is_isolated ? badge("Isolated", "crit") : null,
                        n.quiet ? badge("Quiet") : null,
                      ]),
          ),
        );
        body.push(
          facts(
            n.is_region || n.is_group
              ? [
                  ["Contains", plural(n.count, "address", "addresses")],
                  ["About", n.description],
                ]
              : [
                  ["Address", n.ip],
                  ["Role", n.role && !/^unknown$/i.test(n.role) ? n.role : ""],
                  ["System", n.os && !/^unknown$/i.test(n.os) ? n.os : ""],
                  ["Scope", n.address_scope],
                  ["Evidence", n.evidence?.length ? n.evidence.join(", ") : ""],
                  [
                    "Reported by",
                    n.type === "process"
                      ? reporterLabels.get(n.endpoint_id) || n.endpoint_id
                      : "",
                  ],
                  ["About", n.description],
                  [
                    "Traffic",
                    n.quiet
                      ? "None observed in this window"
                      : ["process", "domain", "traffic"].includes(n.type)
                        ? ""
                        : "Observed in this window",
                  ],
                ],
          ),
        );
        if (n.type !== "traffic")
          actions.append(
            button("Explore", () => drill(selected), "Double-click an item to explore it", "btn-primary"),
          );
        if (n.asset_id && n.type !== "process")
          actions.append(button("Open asset", () => api.onAsset(n)));
        if (n.type === "process")
          actions.append(
            button("Traffic records", () =>
              api.onTraffic({ process: n.process, endpoint_id: n.endpoint_id }),
            ),
          );
        else if (n.ip)
          actions.append(
            button("Outgoing flows", () => api.onTraffic({ src_ip: n.ip })),
            button("Incoming flows", () => api.onTraffic({ dst_ip: n.ip })),
          );
        if (n.is_group && state.group === "network") {
          const choice = select(
            "Region",
            [
              ["", "Automatic"],
              ...Object.entries(M.regionDefinitions).map(([k, v]) => [k, v.label]),
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
          body.push(choice);
        }
        const peers =
          !n.is_group && !n.is_region && ["managed", "unmanaged", "cloud", "threat", "gateway"].includes(n.type)
            ? peersOf(n)
            : [];
        if (peers.length) {
          body.push(
            el(
              "div",
              { class: "tg-peers" },
              el("h3", { text: "Busiest links" }),
              ...peers.slice(0, 5).map((p) => {
                const other = rawNodes.get(p.other);
                const name = other ? M.shortLabel(other) : p.other;
                return el(
                  "button",
                  {
                    type: "button",
                    class: "tg-peer",
                    title: "Explore this pair",
                    onclick: () =>
                      navigate(
                        { kind: "host", id: n.host_id || n.id, peer: p.other },
                        M.shortLabel(n) + " ↔ " + name,
                      ),
                  },
                  el("span", { text: (p.out && p.in ? "↔ " : p.out ? "→ " : "← ") + name }),
                  el("b", { text: plural(p.flows, "flow", "flows") }),
                );
              }),
              peers.length > 5
                ? el("small", { text: "+" + (peers.length - 5) + " more" })
                : null,
            ),
          );
        }
        pinBtn = button("Pin", () => {
          remember();
          const ids = selectedLeaves().map((x) => x.id());
          state.pins = [...new Set([...state.pins, ...ids])];
          updatePins();
          markDirty();
        }, "Keep the selected hosts where they are");
        unpinBtn = button("Unpin", () => {
          remember();
          const ids = new Set(selectedLeaves().map((x) => x.id()));
          state.pins = state.pins.filter((id) => !ids.has(id));
          updatePins();
          markDirty();
        });
        arrangeBtn = button("Arrange selection", () => arrange(true), "Lay out only the selected hosts");
        if (n.type !== "traffic")
          body.push(el("div", { class: "tg-row tg-layout" }, pinBtn, unpinBtn, arrangeBtn));
        syncSelectionActions();
      } else {
        const source = nodeMap.get(edge.source),
          target = nodeMap.get(edge.target);
        head.append(
          el("strong", {
            text: M.shortLabel(source) + " → " + M.shortLabel(target),
          }),
          el(
            "span",
            { class: "tg-badges" },
            edge.verdict === "blocked"
              ? badge("Blocked", "crit")
              : edge.verdict === "anomalous"
                ? badge("Anomalous", "warn")
                : badge("Clean"),
          ),
        );
        const ports = new Map();
        (edge.ports || []).forEach((p) => {
          const k = portText(p);
          ports.set(k, (ports.get(k) || 0) + (p.flow_count || 0));
        });
        const portList = [...ports.entries()].sort((a, b) => b[1] - a[1]);
        body.push(
          facts([
            ["Flows", num(edge.flow_count)],
            ["Volume", volume(edge)],
            [
              "Ports",
              portList
                .slice(0, 8)
                .map(([k, c]) => (c ? k + " (" + num(c) + ")" : k))
                .join(" · ") + (portList.length > 8 ? " +" + (portList.length - 8) : ""),
            ],
            ...relationLines(edge, 4).map((l) => {
              const i = l.indexOf(": ");
              return [l.slice(0, i), l.slice(i + 2)];
            }),
          ]),
        );
        actions.append(
          button("Explore", () => drill(selected), "Double-click an item to explore it", "btn-primary"),
        );
        const filter = trafficFilter(edge);
        if (filter)
          actions.append(button("Traffic records", () => api.onTraffic(filter)));
      }
      context.append(
        head,
        ...body,
        actions.children.length ? actions : null,
        button("Close", clearSelection, "Clear selection", "tg-close"),
      );
      // On a phone the panel takes room from the canvas; keep the selection in view.
      if (canvas.clientWidth < 640 && n)
        setTimeout(() => {
          cy.resize();
          const node = cy.getElementById(n.id);
          if (node.length && !state.list) cy.center(node);
        }, 60);
    }

    /* ---- saved views ---- */
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
          removeView.hidden = !currentView || api.role === "auditor";
        })
        .catch((e) => {
          say("Saved views unavailable: " + e.message);
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
        detail: v.state.detail || "auto",
      };
      state.expanded = state.expanded || {};
      state.positions = state.positions || {};
      state.pins = state.pins || [];
      syncControls();
      setMode(state.mode);
      lastStructure = "";
      first = false;
      selected = "";
      const vp = state.viewport;
      renderGraph(true);
      restorePositions();
      updatePins();
      if (vp) {
        cy.zoom(vp.zoom);
        cy.pan(vp.pan);
      }
      applyListMode();
      api.onWindow(state.window);
      markClean();
      removeView.hidden = api.role === "auditor";
      views_.open = false;
    }
    function loadView(id) {
      const v = views.find((v) => v.id === id);
      if (!v) return;
      if (dirty) {
        confirmDialog("Discard unsaved layout changes?", () => applyView(v), () => {
          saved.querySelector("select").value = currentView ? currentView.id : "";
        });
      } else applyView(v);
    }
    function confirmDialog(title, done, cancelled) {
      const d = el("dialog", { class: "tg-dialog" }, el("h2", { text: title }));
      const row = el("div", { class: "tg-row" });
      row.append(
        button("Keep editing", () => {
          d.close();
          d.remove();
          if (cancelled) cancelled();
        }),
        button("Continue", () => {
          d.close();
          d.remove();
          done();
        }, "", "btn-primary"),
      );
      d.append(row);
      d.addEventListener("cancel", () => {
        d.remove();
        if (cancelled) cancelled();
      });
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
          text: "Keeps filters, time window, positions, pins and zoom for your account.",
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
      }, "", "btn-primary");
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          go.click();
        }
      });
      d.addEventListener("cancel", () => d.remove());
      d.append(
        el(
          "div",
          { class: "tg-row" },
          button("Cancel", () => {
            d.close();
            d.remove();
          }),
          go,
        ),
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
          markClean();
          removeView.hidden = false;
          say("Personal view saved.");
          refreshViews();
        })
        .catch((e) => {
          saveError =
            "View not saved: " +
            e.message +
            ". Your layout is still here; use Save as to keep a separate copy.";
          renderNotice();
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
            saveError = e.message;
            renderNotice();
          }),
      );
    }

    /* ---- data ---- */
    function update(next, error) {
      if (destroyed) return;
      if (error) {
        loadError = error;
        renderEmpty();
        renderNotice();
        return;
      }
      loadError = "";
      if (!next) return;
      if (dragging) {
        pendingData = next;
        return;
      }
      // The hub serves one snapshot until it expires; an unchanged snapshot
      // needs no repaint, so a refresh never disturbs layout or hover.
      const unchanged =
        loaded &&
        !api.draft &&
        next.to &&
        next.to === data.to &&
        next.from === data.from;
      if (unchanged) {
        renderNotice();
        return;
      }
      loaded = true;
      data = next;
      reporterLabels = new Map(
        (data.nodes || [])
          .filter((n) => n.endpoint_id)
          .map((n) => [n.endpoint_id, n.label || n.ip]),
      );
      rawNodes = new Map((data.nodes || []).map((n) => [n.id, n]));
      adjacency = new Map();
      (data.edges || []).forEach((e) => {
        for (const id of [e.source, e.target]) {
          if (!adjacency.has(id)) adjacency.set(id, []);
          adjacency.get(id).push(e);
        }
      });
      const restoreDraft = api.draft;
      const vp = restoreDraft && state.viewport;
      renderGraph(!!restoreDraft);
      if (vp) {
        cy.zoom(vp.zoom);
        cy.pan(vp.pan);
      }
      api.draft = null;
    }
    renderEmpty();
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
        clearTimeout(noticeTimer);
        hideTooltip();
        document.removeEventListener("keydown", escapeKey);
        document.removeEventListener("click", closeViews);
        themeWatch.disconnect();
        observer.disconnect();
        worker.terminate();
        cy.destroy();
        root.remove();
      },
    };
  }
  window.OminullTopology = { mount };
})();
