/* Traffic: who talked to whom in the chosen window, which of it needs a look,
   and where to go next. app.js loads the data (overview and conversations) and
   calls update(); this module owns its DOM so a poll never rebuilds the list
   under the operator's focus. Styles: traffic.css plus Topology's chips,
   fields, badges and facts. */
(function () {
  "use strict";
  // A window whose newest flow is older than this reads as stale. Overridable
  // default, not a detection threshold.
  const STALE_MINUTES = 15;
  const WINDOWS = [
    ["15m", "Last 15 minutes"],
    ["1h", "Last hour"],
    ["6h", "Last 6 hours"],
    ["24h", "Last 24 hours"],
    ["7d", "Last 7 days"],
    ["all", "Last 30 days"],
  ];
  const PAGE = 300;
  const MAX_ROWS = 1000; // storage.MaxConversations
  const FILTER_LABELS = {
    src_ip: "Host address",
    dst_ip: "Peer",
    process: "Program",
    domain: "Name",
    country: "Country",
    protocol: "Protocol",
    port: "Port",
    direction: "Direction",
    action: "Action",
    hash: "Program hash",
    user: "User",
    attribution: "Attribution",
  };

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
      .filter((c) => c !== null && c !== undefined && c !== false)
      .forEach((c) => n.append(c));
    return n;
  }
  const SVG = "http://www.w3.org/2000/svg";
  function svg(tag, attrs, ...children) {
    const n = document.createElementNS(SVG, tag);
    Object.entries(attrs || {}).forEach(([k, v]) => v !== undefined && v !== null && n.setAttribute(k, v));
    children.filter(Boolean).forEach((c) => n.append(c));
    return n;
  }
  function icon(id, cls) {
    const s = svg("svg", { class: "ic ic-s" + (cls ? " " + cls : ""), "aria-hidden": "true" });
    const use = document.createElementNS(SVG, "use");
    use.setAttribute("href", "#" + id);
    s.append(use);
    return s;
  }
  const num = (n) => (Number(n) || 0).toLocaleString();
  function bytes(n) {
    n = Number(n) || 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < 4) {
      n /= 1024;
      i++;
    }
    return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : 1)) + " " + u[i];
  }
  const pad = (n) => String(n).padStart(2, "0");
  const when = (v) => {
    const d = v ? new Date(v) : null;
    return d && !isNaN(d.getTime()) ? d : null;
  };
  function ago(d) {
    if (!d) return "";
    const m = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
    if (m < 1) return "just now";
    if (m < 90) return m + " min ago";
    const h = Math.round(m / 60);
    if (h < 48) return h + " h ago";
    return Math.round(h / 24) + " days ago";
  }
  function clock(d, long) {
    if (!d) return "—";
    const now = new Date();
    const hm = pad(d.getHours()) + ":" + pad(d.getMinutes());
    if (!long && d.toDateString() === now.toDateString()) return hm;
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + hm;
  }
  function timeEl(v, long) {
    const d = when(v);
    if (!d) return el("span", { class: "tf-dim", text: "—" });
    return el("time", { datetime: d.toISOString(), title: d.toString() + " — " + ago(d), text: clock(d, long) });
  }
  // Native replaceChildren turns null into the text "null".
  const put = (node, ...kids) => node.replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
  const plural = (n, one, many) => num(n) + " " + (n === 1 ? one : many);
  const keyOf = (c) => [c.endpoint_id, c.process_path, c.direction, c.peer_ip, c.port, c.protocol].join("|");
  const hostName = (c) => c.hostname || c.endpoint_id || "—";
  const peerLabel = (c) => c.peer_name || c.peer_host || c.peer_ip;

  /* Marks: what makes a conversation worth a look, as icons with the reason
     in the tooltip and in the accessible name. */
  function marks(c, newKnown) {
    const out = [];
    const f = c.findings;
    if (f) {
      const open = f.open > 0;
      const tip =
        (open ? "Open finding: " : f.held_reason ? "Recorded finding: " : "Handled finding: ") +
        f.title +
        " (" + (f.worst || "").toLowerCase() + ")" +
        (f.count > 1 ? ", " + plural(f.count, "finding", "findings") + " in this window" : "");
      out.push({ id: "i-alert", tone: open ? "crit" : "warn", tip, kind: "finding" });
    }
    if (c.blocked > 0) out.push({ id: "g-quarantine", tone: "crit", tip: plural(c.blocked, "flow", "flows") + " blocked", kind: "blocked" });
    if (c.new && newKnown)
      out.push({ id: "i-plus", tone: "info", tip: "New: " + c.process + " on " + hostName(c) + " first reached this peer in this window", kind: "new" });
    return out;
  }
  function markIcons(c, newKnown) {
    const m = marks(c, newKnown);
    const wrap = el("span", { class: "tf-marks" });
    if (!m.length) {
      wrap.append(el("span", { class: "tf-sr", text: "Nothing flagged" }));
      return wrap;
    }
    m.forEach((x) => wrap.append(el("span", { class: "tf-mark", "data-tone": x.tone, "data-kind": x.kind, title: x.tip, role: "img", "aria-label": x.tip }, icon(x.id))));
    return wrap;
  }
  function dirIcon(c) {
    const tip = c.direction === "in" ? "Inbound: the peer connected to " + hostName(c) : "Outbound: " + hostName(c) + " connected to the peer";
    return el("span", { class: "tf-dir", "data-dir": c.direction, title: tip, role: "img", "aria-label": tip, text: c.direction === "in" ? "←" : "→" });
  }
  function volume(c) {
    const total = (Number(c.bytes_in) || 0) + (Number(c.bytes_out) || 0);
    if (!c.measured_flows) return el("span", { class: "tf-dim", title: "No byte counter for these flows: the volume is unknown, not zero", text: "—" });
    const partial = c.measured_flows < c.flows;
    return el("span", {
      title: bytes(c.bytes_in) + " in · " + bytes(c.bytes_out) + " out" + (partial ? " · byte counts for " + num(c.measured_flows) + " of " + num(c.flows) + " flows" : ""),
      text: bytes(total) + (partial ? "+" : ""),
    });
  }

  function mount(root, api) {
    const filter = () => api.filter() || {};
    let data = { overview: null, conversations: null, error: "", loading: true };
    let selected = null; // the conversation object shown in the panel
    let selectedKey = "";
    let flowsReq = 0;
    let lastFocus = null;

    /* ---- top bar ---- */
    const search = el("input", {
      type: "search",
      class: "tg-search tf-search",
      placeholder: "Host, program, peer, name or port",
      "aria-label": "Search conversations",
    });
    search.value = filter().q || "";
    let searchTimer;
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => api.onFilter({ q: search.value.trim(), limit: 0 }), 250);
    });
    function field(label, values, onChange, cls) {
      const s = el("select", { "aria-label": label });
      values.forEach(([v, t]) => s.append(el("option", { value: v, text: t })));
      s.addEventListener("change", () => onChange(s.value));
      return { node: el("label", { class: "tg-field" + (cls ? " " + cls : "") }, el("span", { text: label }), s), select: s };
    }
    const hostField = field("Host", [["", "All hosts"]], (v) => api.onFilter({ endpoint_id: v, limit: 0 }), "tf-host");
    const windowField = field("Window", WINDOWS, (v) => api.onFilter({ range: v, limit: 0 }));
    const sortField = field(
      "Order",
      [
        ["look", "Needs a look first"],
        ["volume", "Most data"],
        ["recent", "Most recent"],
        ["flows", "Most flows"],
      ],
      (v) => api.onFilter({ sort: v === "look" ? "" : v, limit: 0 }),
    );
    const filterToggle = el("button", {
      type: "button",
      class: "btn tg-button tf-filter-toggle",
      "aria-expanded": "false",
      title: "Show filters",
      onclick: () => {
        const open = ws.dataset.controls !== "open";
        ws.dataset.controls = open ? "open" : "closed";
        filterToggle.setAttribute("aria-expanded", String(open));
      },
    }, icon("i-tag"), el("span", { text: "Filters" }), el("span", { class: "tf-toggle-n" }));
    const fresh = el("span", { class: "tf-fresh", role: "img" });
    const bar = el("div", { class: "tf-bar" }, search, filterToggle, hostField.node, windowField.node, el("span", { class: "tg-fill" }), fresh);

    /* ---- filter chips: each is the filter and its count ---- */
    function chip(label, iconId, onClick, title) {
      const count = el("b");
      const b = el("button", { type: "button", class: "tg-chip", title, onclick: onClick }, icon(iconId), el("span", { text: label }), count);
      return {
        node: b,
        set(n, on, tone, disabledTip) {
          count.textContent = n === null ? "" : num(n);
          b.setAttribute("aria-pressed", String(!!on));
          b.dataset.tone = n && tone ? tone : "";
          const off = (n === 0 && !on) || !!disabledTip;
          b.setAttribute("aria-disabled", String(off));
          b.title = disabledTip || title;
        },
      };
    }
    const toggleMark = (m) => () => {
      const f = filter();
      if (chips[m].node.getAttribute("aria-disabled") === "true" && f.mark !== m) return;
      api.onFilter({ mark: f.mark === m ? "" : m, limit: 0 });
    };
    const toggleDir = (d) => () => {
      const f = filter();
      if (chips[d].node.getAttribute("aria-disabled") === "true" && f.dir !== d) return;
      api.onFilter({ dir: f.dir === d ? "" : d, limit: 0 });
    };
    const chips = {
      flagged: chip("Flagged", "i-alert", toggleMark("flagged"), "Conversations with a finding in this window"),
      new: chip("New", "i-plus", toggleMark("new"), "A program first reached this peer from this host in this window"),
      blocked: chip("Blocked", "g-quarantine", toggleMark("blocked"), "Conversations with blocked flows"),
      out: chip("Outbound", "i-arrow", toggleDir("out"), "This host opened the connection"),
      in: chip("Inbound", "i-arrow", toggleDir("in"), "The peer connected to this host"),
    };
    chips.in.node.classList.add("tf-chip-in");
    const extra = el("div", { class: "tg-set tf-extra", role: "group", "aria-label": "Other filters" });
    const shown = el("span", { class: "tf-stat tf-shown", "aria-live": "polite", title: "Program-to-peer conversations matching the filters" });
    const clearBtn = el("button", { type: "button", class: "btn tg-button", text: "Clear filters", onclick: () => {
      search.value = "";
      api.onFilter({ clear: true });
    } });
    const filters = el(
      "div",
      { class: "tf-filters", role: "group", "aria-label": "Filters" },
      el("div", { class: "tg-set" }, chips.flagged.node, chips.new.node, chips.blocked.node),
      el("span", { class: "tg-sep" }),
      el("div", { class: "tg-set" }, chips.out.node, chips.in.node),
      extra,
      el("span", { class: "tg-fill" }),
      sortField.node,
      clearBtn,
    );

    /* ---- summary and timeline ---- */
    const summary = el("div", { class: "tf-summary" });
    const timeline = el("div", { class: "tf-timeline" });

    /* ---- list and panel ---- */
    const tbody = el("tbody");
    const table = el(
      "table",
      { class: "tg-table tf-table" },
      el("caption", { class: "tf-sr", text: "Conversations in this window, most in need of a look first" }),
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", { scope: "col", class: "c-mark" }, el("span", { class: "tf-sr", text: "Marks" })),
          el("th", { scope: "col", text: "Host · program" }),
          el("th", { scope: "col", class: "c-dir" }, el("span", { class: "tf-sr", text: "Direction" })),
          el("th", { scope: "col", text: "Peer" }),
          el("th", { scope: "col", class: "c-port", text: "Port" }),
          el("th", { scope: "col", class: "c-num c-flows", text: "Flows" }),
          el("th", { scope: "col", class: "c-num", text: "Data" }),
          el("th", { scope: "col", class: "c-time", text: "Last" }),
        ),
      ),
      tbody,
    );
    const listState = el("div", { class: "tf-state" });
    const more = el("div", { class: "tg-more", hidden: "" });
    const list = el("div", { class: "tf-list" }, table, listState, more);
    const panel = el("aside", { class: "tf-panel", "aria-label": "Conversation details", tabindex: "-1" });
    const stage = el("div", { class: "tf-stage" }, list, panel);

    const ws = el("div", { class: "tf-workspace", "data-controls": "closed" }, bar, filters, summary, timeline, stage);
    root.append(ws);

    /* Escape closes the details from anywhere on the page, unless a sheet or
       menu above the page has it. */
    function onKey(e) {
      if (e.key !== "Escape" || !selected) return;
      if (document.querySelector(".sheet, .route, .palette, .ctx-menu, .drawer")) return;
      e.preventDefault();
      closePanel();
    }
    // Capture: the console's own Escape handler removes a sheet or host view
    // first, and this must still see it open.
    document.addEventListener("keydown", onKey, true);

    /* Arrow keys move between rows; Enter or Space on a row's button opens it. */
    tbody.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const btns = Array.from(tbody.querySelectorAll(".tf-open"));
      const i = btns.indexOf(document.activeElement);
      if (i < 0) return;
      e.preventDefault();
      const next = btns[Math.max(0, Math.min(btns.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      next.focus();
    });

    function syncControls() {
      const f = filter();
      if (document.activeElement !== search && search.value !== (f.q || "")) search.value = f.q || "";
      windowField.select.value = f.range || "1h";
      const hosts = api.hosts();
      const want = [["", "All hosts"]].concat(hosts.map((h) => [h.id, h.name || h.id]));
      if (f.endpoint_id && !hosts.some((h) => h.id === f.endpoint_id)) want.push([f.endpoint_id, f.endpoint_id]);
      const sig = want.map((w) => w.join("=")).join("|");
      if (hostField.select.dataset.sig !== sig) {
        hostField.select.replaceChildren(...want.map(([v, t]) => el("option", { value: v, text: t })));
        hostField.select.dataset.sig = sig;
      }
      hostField.select.value = f.endpoint_id || "";
      sortField.select.value = f.sort || "look";
      put(extra,
        ...Object.keys(FILTER_LABELS)
          .filter((k) => f[k])
          .map((k) => {
            const v = k === "hash" ? String(f[k]).slice(0, 12) + "…" : String(f[k]);
            return el(
              "button",
              { type: "button", class: "tg-chip tf-chip-x", "aria-pressed": "true", title: "Remove filter " + FILTER_LABELS[k] + " " + f[k], onclick: () => api.onFilter({ [k]: "", limit: 0 }) },
              el("span", { text: FILTER_LABELS[k] + " " + v }),
              icon("i-close"),
            );
          }),
      );
      if (f.measured_only)
        extra.append(el("button", { type: "button", class: "tg-chip tf-chip-x", "aria-pressed": "true", "aria-label": "Remove filter: flows with byte counts only", title: "Remove this filter", onclick: () => api.onFilter({ measured_only: false, limit: 0 }) }, el("span", { text: "With byte counts" }), icon("i-close")));
      const active = [f.q, f.mark, f.dir, f.endpoint_id].filter(Boolean).length + extra.childElementCount;
      clearBtn.hidden = !active;
      filterToggle.querySelector(".tf-toggle-n").textContent = active ? String(active) : "";
      filterToggle.setAttribute("aria-label", active ? "Filters, " + active + " active" : "Filters");
    }

    function renderSummary() {
      const ov = data.overview || {};
      const cv = data.conversations;
      summary.replaceChildren();
      if (!data.overview && !cv) return;
      const t = ov.totals || {};
      const item = (iconId, text, tip, tone) =>
        el("span", { class: "tf-stat", "data-tone": tone || "", title: tip }, iconId ? icon(iconId) : null, el("span", { text }), el("span", { class: "tf-sr", text: " — " + tip }));
      const f = filter();
      const narrowed = !!(cv && (f.q || f.mark || f.dir));
      if (narrowed) {
        summary.append(
          item(null, "↓ " + bytes(cv.matching_bytes_in), "Received by the conversations shown (flows with a byte counter)"),
          item(null, "↑ " + bytes(cv.matching_bytes_out), "Sent by the conversations shown (flows with a byte counter)"),
          item(null, plural(Number(cv.matching_flows) || 0, "flow", "flows"), "Flows in the conversations shown"),
        );
      } else if (data.overview) {
        summary.append(
          item(null, "↓ " + bytes(t.bytes_in), "Received in this window (flows with a byte counter)"),
          item(null, "↑ " + bytes(t.bytes_out), "Sent in this window (flows with a byte counter)"),
          item(null, plural(Number(ov.total_flows) || 0, "flow", "flows"), "Flows reported by agents and the router in this window"),
        );
        const cov = Number(ov.measured_flow_coverage) || 0;
        if (ov.total_flows && cov < 0.995) {
          const pct = Math.round(cov * 100);
          summary.append(item("g-watch", (pct === 0 ? "<1" : pct) + "% with byte counts", "Only " + (pct === 0 ? "under 1" : pct) + "% of flows carry a byte counter; the volume of the rest is unknown, not zero", "warn"));
        }
      }
      if (cv) summary.append(shown);
      /* The rail counts every open finding; say when some are not in this list. */
      const outside = cv ? api.openAlertCount() - ((cv.counts && cv.counts.open_findings) || 0) : 0;
      if (outside > 0)
        summary.append(el("button", { type: "button", class: "tf-link tf-stat tf-outside", title: "Open findings this list doesn't show: older than this window, filtered out, or not about a conversation. Opens Alerts", onclick: () => api.showAlerts() }, icon("i-alert"), el("span", { text: plural(outside, "open finding", "open findings") + " outside this view" })));
      const ws0 = when((cv || ov).window_start),
        we = when((cv || ov).window_end),
        rf = when((cv || ov).retained_from);
      if (ws0 && we && rf && rf > ws0) {
        const tip = "The hub keeps nothing before " + clock(rf, true) + ": the start of this window is missing, not quiet";
        summary.append(item("g-unknown", "From " + clock(rf, true), tip, "warn"));
      }
    }

    function renderFresh() {
      const cv = data.conversations;
      const latest = cv && when(cv.latest_flow);
      fresh.replaceChildren();
      let tone = "ok",
        tip,
        id = "g-online";
      if (data.error && (data.overview || cv)) {
        tone = "crit";
        id = "g-offline";
        tip = "Couldn't refresh (" + data.error + "). Showing what loaded at " + clock(when(cv && cv.as_of), false);
      } else if (!cv) {
        tone = "";
        id = "g-unknown";
        tip = "Loading";
      } else if (!latest) {
        tone = "";
        id = "g-unknown";
        tip = "No flows in this window";
      } else if (Date.now() - latest.getTime() > STALE_MINUTES * 60000) {
        tone = "warn";
        id = "g-watch";
        tip = "Newest flow " + ago(latest) + " (" + clock(latest, true) + "): nothing has reported since";
      } else {
        tip = "Newest flow " + ago(latest);
      }
      fresh.dataset.tone = tone;
      fresh.title = tip;
      fresh.setAttribute("aria-label", tip);
      fresh.append(icon(id));
    }

    function renderTimeline() {
      const ov = data.overview;
      const trends = (ov && Array.isArray(ov.trends) && ov.trends) || [];
      timeline.replaceChildren();
      if (trends.length < 2) return;
      const useBytes = trends.some((p) => (Number(p.bytes_in) || 0) + (Number(p.bytes_out) || 0) > 0);
      const val = (p) => (useBytes ? (Number(p.bytes_in) || 0) + (Number(p.bytes_out) || 0) : Number(p.flows) || 0);
      const max = Math.max(1, ...trends.map(val));
      const W = 1000,
        H = 48,
        n = trends.length,
        slot = W / n;
      const s = svg("svg", { class: "tf-chart", viewBox: "0 0 " + W + " " + (H + 8), preserveAspectRatio: "none", role: "img" });
      const ws0 = when(ov.window_start),
        we = when(ov.window_end),
        rf = when(ov.retained_from);
      if (ws0 && we && rf && rf > ws0 && we > ws0) {
        const x = Math.min(W, ((Math.min(rf, we) - ws0) / (we - ws0)) * W);
        s.append(svg("rect", { class: "tf-uncovered", x: 0, y: 0, width: x, height: H }, svg("title", {}, document.createTextNode("No data kept before " + clock(rf, true)))));
      }
      let peak = trends[0],
        blocks = 0,
        flagged = 0;
      trends.forEach((p, i) => {
        const v = val(p);
        if (v > val(peak)) peak = p;
        blocks += Number(p.blocks) || 0;
        flagged += Number(p.anomalies) || 0;
        const hgt = v ? Math.max(1.5, (v / max) * H) : 0;
        const d = when(p.timestamp);
        const tip = clock(d, true) + " — " + (useBytes ? bytes(v) + ", " : "") + plural(Number(p.flows) || 0, "flow", "flows") + (p.blocks ? ", " + plural(p.blocks, "blocked", "blocked") : "") + (p.anomalies ? ", " + plural(p.anomalies, "finding", "findings") : "");
        const g = svg("g", {}, svg("title", {}, document.createTextNode(tip)));
        g.append(svg("rect", { class: "tf-hit", x: i * slot, y: 0, width: slot, height: H + 8 }));
        if (hgt) g.append(svg("rect", { class: "tf-bar-v", x: i * slot + slot * 0.12, y: H - hgt, width: slot * 0.76, height: hgt }));
        if (p.blocks) g.append(svg("rect", { class: "tf-tick-block", x: i * slot + slot * 0.12, y: H + 2, width: slot * 0.76, height: 5 }));
        if (p.anomalies) g.append(svg("rect", { class: "tf-tick-finding", x: i * slot + slot * 0.12, y: H + 2, width: slot * 0.76, height: 5 }));
        s.append(g);
      });
      s.append(svg("line", { class: "tf-axis", x1: 0, y1: H + 0.5, x2: W, y2: H + 0.5 }));
      s.setAttribute(
        "aria-label",
        (useBytes ? "Data" : "Flows") + " over the window, peak " + (useBytes ? bytes(val(peak)) : num(val(peak))) + " at " + clock(when(peak.timestamp), true) + (blocks ? ", " + plural(blocks, "blocked flow", "blocked flows") : "") + (flagged ? ", " + plural(flagged, "finding", "findings") : ""),
      );
      const first = when(trends[0].timestamp),
        last = when(trends[n - 1].timestamp);
      timeline.append(
        s,
        el("div", { class: "tf-ticks", "aria-hidden": "true" }, el("span", { text: clock(first, n > 100 || (last - first) > 86400000) }), el("span", { text: clock(last, (last - first) > 86400000) })),
      );
    }

    function renderList() {
      const cv = data.conversations;
      const f = filter();
      const focusedKey = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.key : "";
      tbody.replaceChildren();
      listState.replaceChildren();
      more.hidden = true;
      if (!cv) {
        table.hidden = true;
        if (data.error) {
          listState.append(
            el("p", { role: "alert", class: "tf-error", text: "Couldn't load traffic: " + data.error }),
            el("button", { type: "button", class: "btn tg-button", text: "Retry", onclick: () => api.retry() }),
          );
        } else listState.append(el("p", { role: "status", class: "tf-empty", text: "Loading traffic…" }));
        return;
      }
      const rows = cv.conversations || [];
      table.hidden = !rows.length;
      const c = cv.counts || {};
      chips.flagged.set(c.flagged || 0, f.mark === "flagged", c.open ? "crit" : "warn");
      chips.new.set(cv.new_known ? c.new || 0 : null, f.mark === "new", "info", cv.new_known ? "" : "The hub's history starts " + clock(when(cv.profiles_from), true) + ", so it can't yet tell which peers are new in this window");
      chips.blocked.set(c.blocked || 0, f.mark === "blocked", "crit");
      chips.out.set(c.out || 0, f.dir === "out");
      chips.in.set(c.in || 0, f.dir === "in");
      shown.textContent = (cv.matching > rows.length ? num(rows.length) + " of " : "") + plural(cv.matching || 0, "conversation", "conversations");
      if (!rows.length) {
        const filtered = f.q || f.mark || f.dir || f.endpoint_id || extra.childElementCount;
        if (filtered) {
          listState.append(
            el("p", { role: "status", class: "tf-empty", text: "Nothing in this window matches these filters." }),
            el("button", { type: "button", class: "btn tg-button", text: "Clear filters", onclick: () => {
              search.value = "";
              api.onFilter({ clear: true });
            } }),
          );
        } else {
          const rf = when(cv.retained_from);
          const we = when(cv.window_end);
          listState.append(
            el("p", {
              role: "status",
              class: "tf-empty",
              text: !rf ? "The hub holds no flows yet." : rf > we ? "The hub holds nothing this recent." : "No flows were reported in this window.",
            }),
          );
          const wider = WINDOWS.findIndex((w) => w[0] === (f.range || "1h"));
          if (wider >= 0 && wider < WINDOWS.length - 1)
            listState.append(el("button", { type: "button", class: "btn tg-button", text: "Show " + WINDOWS[wider + 1][1].toLowerCase(), onclick: () => api.onFilter({ range: WINDOWS[wider + 1][0] }) }));
        }
        return;
      }
      rows.forEach((conv) => {
        const k = keyOf(conv);
        const open = el(
          "button",
          { type: "button", class: "tf-open", "data-key": k, "aria-expanded": String(k === selectedKey), "aria-controls": "tf-panel", title: conv.process_path || conv.process, onclick: () => openPanel(conv, open) },
          el("strong", { text: hostName(conv) }),
          el("span", { class: "tf-dot", "aria-hidden": "true", text: " · " }),
          el("span", { text: conv.process }),
        );
        const peer = el(
          "span",
          { class: "tf-peer" },
          el("span", { class: "tf-peer-main", text: peerLabel(conv) }),
          peerLabel(conv) !== conv.peer_ip || conv.country
            ? el("small", { text: [peerLabel(conv) !== conv.peer_ip ? conv.peer_ip : "", conv.country].filter(Boolean).join(" · ") })
            : null,
        );
        const tr = el(
          "tr",
          { "aria-selected": String(k === selectedKey), "data-tone": conv.findings && conv.findings.open ? "crit" : "" },
          el("td", { class: "c-mark" }, markIcons(conv, cv.new_known)),
          el("td", { class: "c-who" }, open),
          el("td", { class: "c-dir" }, dirIcon(conv)),
          el("td", { class: "c-peer" }, peer),
          el("td", { class: "c-port", text: conv.port + "/" + conv.protocol }),
          el("td", { class: "c-num c-flows", text: num(conv.flows) }),
          el("td", { class: "c-num" }, volume(conv)),
          el("td", { class: "c-time" }, timeEl(conv.last_seen)),
        );
        tr.addEventListener("click", (e) => {
          if (e.target.closest("button, a")) return;
          openPanel(conv, open);
        });
        tbody.append(tr);
        if (focusedKey && focusedKey === k) open.focus();
      });
      if (cv.truncated) {
        more.hidden = false;
        put(more,
          el("span", { text: plural(cv.matching - rows.length, "more conversation", "more conversations") + " not shown" + (rows.length >= MAX_ROWS ? ": search or filter to reach them" : "") }),
          rows.length < MAX_ROWS ? el("button", { type: "button", class: "btn tg-button", text: "Show more", onclick: () => api.onFilter({ limit: rows.length + PAGE }) }) : null,
        );
      }
    }

    function openPanel(conv, opener) {
      lastFocus = opener || document.activeElement;
      selected = conv;
      selectedKey = keyOf(conv);
      tbody.querySelectorAll("tr").forEach((tr) => {
        const b = tr.querySelector(".tf-open");
        const on = !!b && b.dataset.key === selectedKey;
        tr.setAttribute("aria-selected", String(on));
        if (b) b.setAttribute("aria-expanded", String(on));
      });
      renderPanel();
      ws.dataset.panel = "open";
      panel.focus({ preventScroll: true });
    }
    function closePanel() {
      // A poll may have rebuilt the row since it opened the panel.
      const row = Array.from(tbody.querySelectorAll(".tf-open")).find((b) => b.dataset.key === selectedKey);
      if (row) lastFocus = row;
      selected = null;
      selectedKey = "";
      ws.dataset.panel = "";
      panel.replaceChildren();
      tbody.querySelectorAll("tr").forEach((tr) => {
        tr.setAttribute("aria-selected", "false");
        const b = tr.querySelector(".tf-open");
        if (b) b.setAttribute("aria-expanded", "false");
      });
      const back = lastFocus && lastFocus.isConnected ? lastFocus : tbody.querySelector(".tf-open[data-key]");
      if (back) back.focus();
      lastFocus = null;
    }

    function renderPanel(keepFlows) {
      const c = selected;
      if (!c) return;
      const oldFlows = keepFlows ? panel.querySelector(".tf-flows") : null;
      const cv = data.conversations || {};
      const f = c.findings;
      const facts = el("dl", { class: "tg-facts tf-facts" });
      const fact = (k, ...v) => facts.append(el("dt", { text: k }), el("dd", {}, ...v));
      fact("Host", el("button", { type: "button", class: "tf-link", text: hostName(c), title: "Open this host", onclick: () => api.openHost(c.endpoint_id) }));
      fact("Program", el("span", { class: "tf-mono", text: c.process_path || c.process }));
      fact(
        "Peer",
        c.peer_endpoint
          ? el("button", { type: "button", class: "tf-link", text: c.peer_host || c.peer_endpoint, title: "Open this host", onclick: () => api.openHost(c.peer_endpoint) })
          : el("span", { text: c.peer_name || c.peer_host || c.peer_ip }),
        (c.peer_endpoint || c.peer_name || c.peer_host) || c.country
          ? el("span", { class: "tf-mono tf-dim", text: " " + [c.peer_endpoint || c.peer_name || c.peer_host ? c.peer_ip : "", c.country].filter(Boolean).join(" · ") })
          : null,
      );
      fact("Service", el("span", { text: c.port + "/" + c.protocol + " · " + (c.direction === "in" ? "peer connected in" : "host connected out") }));
      fact("Flows", el("span", { text: num(c.flows) + (c.blocked ? " · " + num(c.blocked) + " blocked" : "") }));
      fact("Data", c.measured_flows ? el("span", { text: bytes(c.bytes_in) + " in · " + bytes(c.bytes_out) + " out" + (c.measured_flows < c.flows ? " (counted for " + num(c.measured_flows) + " of " + num(c.flows) + " flows)" : "") }) : el("span", { class: "tf-dim", text: "Unknown: no byte counter" }));
      fact("Seen", timeEl(c.first_seen, true), el("span", { text: " – " }), timeEl(c.last_seen, true));
      const ks = when(c.known_since);
      fact(
        "Known since",
        ks ? timeEl(c.known_since, true) : el("span", { class: "tf-dim", text: "No history kept for this peer" }),
        c.new && cv.new_known ? el("span", { class: "tg-badge", "data-tone": "info", title: "First reached in this window", text: "new" }) : null,
      );

      const head = el(
        "div",
        { class: "tf-panel-head" },
        el("strong", { id: "tf-panel-title", text: c.process + " " + (c.direction === "in" ? "←" : "→") + " " + peerLabel(c) + ":" + c.port }),
        el("span", { class: "tf-dim", text: hostName(c) }),
        markIcons(c, cv.new_known),
      );
      const close = el("button", { type: "button", class: "btn tg-button tg-close", title: "Close (Esc)", "aria-label": "Close details", onclick: closePanel }, icon("i-close"));

      const findingBox = f
        ? el(
            "section",
            { class: "tf-finding", "data-tone": f.open ? "crit" : "warn", "aria-label": "Findings" },
            el("div", { class: "tf-finding-title" }, icon("i-alert"), el("strong", { text: f.title }), el("span", { class: "tg-badge", "data-tone": f.open ? "crit" : "warn", title: f.open ? "Open: not yet acknowledged" : f.held_reason ? "Recorded, not paged" : "Acknowledged", text: (f.worst || "").toLowerCase() })),
            f.count > 1 ? el("span", { class: "tf-dim", text: plural(f.count, "finding", "findings") + " about this conversation in the window" }) : null,
            el("button", { type: "button", class: "btn tg-button btn-primary", text: f.count > 1 ? "Open findings" : "Open finding", onclick: () => api.openFindings(c) }),
          )
        : null;

      const actions = el(
        "div",
        { class: "tf-actions" },
        el("button", { type: "button", class: "btn tg-button", onclick: () => api.openHost(c.endpoint_id) }, icon("i-external"), el("span", { text: "Open host" })),
        el("button", { type: "button", class: "btn tg-button", onclick: () => api.showTopology(c) }, icon("i-topology"), el("span", { text: "Show in Topology" })),
        el("button", { type: "button", class: "btn tg-button", onclick: () => api.onFilter({ dst_ip: c.peer_ip, limit: 0 }) }, icon("i-search"), el("span", { text: "All traffic with " + c.peer_ip })),
        el("button", { type: "button", class: "btn tg-button", onclick: () => api.copy(c.peer_ip) }, icon("i-copy"), el("span", { text: "Copy peer address" })),
      );

      const flowsBox = oldFlows || el("section", { class: "tf-flows", "aria-label": "Recent flows" }, el("h3", { text: "Recent flows" }), el("p", { class: "tf-dim", role: "status", text: "Loading…" }));
      put(panel, close, head, findingBox, facts, actions, flowsBox);
      panel.id = "tf-panel";
      panel.setAttribute("aria-labelledby", "tf-panel-title");
      if (!oldFlows) loadFlows(c, flowsBox);
    }

    function loadFlows(c, box) {
      const id = ++flowsReq;
      const f = filter();
      const qs = new URLSearchParams({ range: f.range || "1h", endpoint_id: c.endpoint_id, dst_ip: c.peer_ip, port: String(c.port), protocol: String(c.proto), limit: "8" });
      if (c.process_path) qs.set("process", c.process_path);
      api
        .request("/api/v1/traffic/flows?" + qs.toString())
        .then((d) => {
          if (id !== flowsReq || !box.isConnected) return;
          const flows = (d && d.flows) || [];
          const items = flows.map((fl) =>
            el(
              "li",
              {},
              el(
                "button",
                { type: "button", class: "tg-peer tf-flow", title: "Open this flow's process, command line and lineage", onclick: () => api.openFlow(fl) },
                fl.action === "BLOCK" ? el("span", { class: "tf-mark", "data-tone": "crit", role: "img", "aria-label": "Blocked", title: "Blocked" }, icon("g-quarantine")) : null,
                timeEl(fl.timestamp, true),
                el("span", { class: "tf-mono", text: fl.src_ip + ":" + fl.src_port + " → " + fl.dst_ip + ":" + fl.dst_port }),
                el("b", { text: (Number(fl.bytes_in) || 0) + (Number(fl.bytes_out) || 0) ? bytes((Number(fl.bytes_in) || 0) + (Number(fl.bytes_out) || 0)) : "—" }),
              ),
            ),
          );
          put(box,
            el("h3", { text: "Recent flows" }),
            items.length ? el("ul", { class: "tf-flow-list" }, items) : el("p", { class: "tf-dim", text: "None kept for this window." }),
            d && d.total > flows.length ? el("p", { class: "tf-dim", text: "Newest " + flows.length + " of " + num(d.total) }) : null,
          );
        })
        .catch((e) => {
          if (id !== flowsReq || !box.isConnected) return;
          put(box, el("h3", { text: "Recent flows" }), el("p", { role: "alert", class: "tf-error", text: "Couldn't load flows: " + ((e && e.message) || "request failed") }), el("button", { type: "button", class: "btn tg-button", text: "Retry", onclick: () => loadFlows(c, box) }));
        });
    }

    function update(next) {
      const prevKey = selectedKey;
      data = next;
      syncControls();
      renderFresh();
      renderSummary();
      renderTimeline();
      renderList();
      /* Keep the panel on its conversation across polls; refresh its numbers
         when the row is still listed, keep the last copy when it is not. */
      if (prevKey && selected) {
        const cur = ((data.conversations && data.conversations.conversations) || []).find((x) => keyOf(x) === prevKey);
        const sig = (x) => JSON.stringify([x.flows, x.bytes_in, x.bytes_out, x.blocked, x.last_seen, x.findings, x.new]);
        if (cur && sig(cur) !== sig(selected) && !panel.contains(document.activeElement)) {
          selected = cur;
          renderPanel(true);
        }
      }
    }

    syncControls();
    renderList();
    return {
      update,
      destroy() {
        document.removeEventListener("keydown", onKey, true);
        clearTimeout(searchTimer);
        ws.remove();
      },
    };
  }

  window.OminullTraffic = { mount };
})();
