/* Ominull console.
 *
 * Invariants this file exists to hold:
 *   - No inline style attributes. Anything data-driven is SVG geometry, a
 *     data-* attribute the stylesheet selects on, or a custom property set
 *     through the CSSOM (`vars`). A `style=` here would be a colour the theme
 *     switcher cannot reach - and `style-src` is `'self'`, so the browser
 *     refuses it silently and the value simply never applies. This held until
 *     the slice era put 54 of them back; they are gone again and the CSP is
 *     what keeps them out.
 *   - Hue means state. Chrome uses only the neutral ink tokens and --brand;
 *     --ok/--warn/--crit/--info are reserved for asset state.
 *   - Rows sort on stable identity, never last_seen_at, so an isolate click
 *     cannot land on a host that reshuffled under the cursor.
 *   - Selection, cursor and expansion live in state, not in the DOM, so a
 *     five-second refresh preserves all three.
 */
(function () {
  "use strict";

  var CFG = window.OMINULL || {};
  var API_KEY = CFG.key || "";
  var HUB_VERSION = CFG.version || "";
  /* Who the hub rendered this document for. The key is only embedded when the
     operator unlocked the console with it; signing in through Cloudflare Access
     leaves it empty and the session cookie carries the role instead. */
  var OPERATOR = CFG.operator || "";
  var ROLE = CFG.role || "admin";
  var IS_ADMIN = ROLE === "admin";
  var READ_ONLY = ROLE === "auditor";

  var THEMES = ["graphite", "bunker", "ash", "phosphor"];
  var THEME_NAMES = {
    graphite: "Graphite",
    bunker: "Bunker",
    ash: "Ash",
    phosphor: "Phosphor"
  };
  var DEFAULT_THEME = "ash";

  var SECTIONS = [
    { id: "assets", label: "Assets" },
    { id: "topology", label: "Topology" },
    { id: "traffic", label: "Traffic" },
    { id: "policy", label: "Policy" },
    { id: "alerts", label: "Alerts" },
    { id: "response", label: "Response" },
    { id: "forensics", label: "Forensics" },
    { id: "audit", label: "Audit" }
  ];

  /* Managing who can sign in is an administrator's section. It is appended
     rather than declared inline so the command palette and the rail agree about
     what exists without either of them testing the role again. */
  if (IS_ADMIN) SECTIONS.push({ id: "access", label: "Access" });

  var IS_MAC = /mac|iphone|ipad/i.test(navigator.userAgent);
  var MOD_LABEL = IS_MAC ? "\u2318K" : "Ctrl K";

  /* ------------------------------------------------------------------ dom */

  /* Matches the hub's page size for /api/v1/anomalies. A full page means "this
     many or more", never "exactly this many". */
  var ANOMALY_PAGE = 100;
  /* The hub answers GET /api/v1/events with at most this many rows. */
  var EVENT_PAGE = 100;
  /* And GET /api/v1/threat-intel/iocs with at most this many. */
  var IOC_PAGE = 200;

  /* Renders a page-limited length honestly: "100+" when the page came back
     full, because the real total is not knowable from it. */
  function capped(n, page) { return n >= page ? String(page) + "+" : String(n); }

  function h(tag, props) {
    var el = document.createElement(tag);
    if (props) {
      for (var k in props) {
        if (!Object.prototype.hasOwnProperty.call(props, k)) continue;
        var v = props[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === "text") el.textContent = String(v);
        else if (k === "cls") el.className = v;
        else if (k === "vars") {
          /* style-src is 'self' with no unsafe-inline, so a style attribute is
             refused by the browser and the value silently never applies. Custom
             properties set through the CSSOM are not an inline style. */
          for (var cp in v) el.style.setProperty(cp, v[cp]);
        }
        else if (k === "on") {
          for (var ev in v) el.addEventListener(ev, v[ev]);
        } else if (v === true) el.setAttribute(k, "");
        else el.setAttribute(k, String(v));
      }
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x) el.appendChild(x); });
      else if (typeof c === "string" || typeof c === "number") el.appendChild(document.createTextNode(String(c)));
      else el.appendChild(c);
    }
    return el;
  }

  var SVG_NS = "http://www.w3.org/2000/svg";

  function s(tag, attrs) {
    var el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === "text") { el.textContent = String(v); continue; }
        if (k === "on") { for (var ev in v) el.addEventListener(ev, v[ev]); continue; }
        el.setAttribute(k, String(v));
      }
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (!c) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x) el.appendChild(x); });
      else el.appendChild(c);
    }
    return el;
  }

  function icon(id, small) {
    var svg = s("svg", { "class": small ? "ic ic-s" : "ic", "aria-hidden": "true" });
    var use = document.createElementNS(SVG_NS, "use");
    use.setAttribute("href", "#" + id);
    svg.appendChild(use);
    return svg;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  /* Overlay geometry is the one thing the stylesheet cannot know: a context
     menu opens where the pointer is. It travels as custom properties the
     stylesheet reads, so no appearance value is ever written inline. */
  function placeOverlay(el, x, y) {
    el.style.setProperty("--x", Math.round(Math.max(8, x)) + "px");
    el.style.setProperty("--y", Math.round(Math.max(8, y)) + "px");
  }

  function $(id) { return document.getElementById(id); }

  /* ------------------------------------------------------------- storage */

  function readStore(key, fallback) {
    try {
      var v = localStorage.getItem(key);
      return v === null ? fallback : v;
    } catch (e) {
      return fallback;
    }
  }

  function writeStore(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      /* Storage is a convenience here; the console must work without it. */
    }
  }

  /* ----------------------------------------------------------- addressing

     Everything the console showed lived in a closure variable and nowhere
     else: Back left the console entirely, reload dropped you on Assets with
     no filter, and there was no way to send a colleague the view you were
     looking at. Section, query, filters and the open row are in the URL now,
     and the same four are remembered across a reload so a refresh does not
     undo a filter you spent a minute building.

     The URL is a hash. A path would need the hub to serve index.html for
     arbitrary routes, and it serves exactly the files it embeds. */

  var URL_KEYS = ["q", "f", "row", "route"];
  var suppressHistory = false;

  function currentURLState() {
    var f = Object.keys(state.filters || {}).filter(function (k) { return state.filters[k]; });
    return {
      section: state.section,
      q: state.query || "",
      f: f.sort().join(","),
      row: state.expandedKey || "",
      route: state.routeKey || ""
    };
  }

  function encodeURLState(u) {
    var parts = [];
    URL_KEYS.forEach(function (k) {
      if (u[k]) parts.push(k + "=" + encodeURIComponent(u[k]));
    });
    return "#/" + (u.section || "assets") + (parts.length ? "?" + parts.join("&") : "");
  }

  function decodeURLState(hash) {
    var m = /^#\/([a-z-]+)(?:\?(.*))?$/.exec(hash || "");
    if (!m) return null;
    var out = { section: m[1], q: "", f: "", row: "", route: "" };
    (m[2] || "").split("&").forEach(function (pair) {
      if (!pair) return;
      var i = pair.indexOf("=");
      var k = i < 0 ? pair : pair.slice(0, i);
      if (URL_KEYS.indexOf(k) < 0) return;
      try { out[k] = decodeURIComponent(i < 0 ? "" : pair.slice(i + 1)); } catch (e) { out[k] = ""; }
    });
    return out;
  }

  /* push for a navigation the operator should be able to walk back out of,
     replace for a keystroke in the filter box - one entry per typed character
     would make Back useless. */
  function syncURL(push) {
    if (suppressHistory) return;
    var u = currentURLState();
    var href = encodeURLState(u);
    try {
      if (push && location.hash !== href) history.pushState(u, "", href);
      else history.replaceState(u, "", href);
    } catch (e) { /* addressing is a convenience; never break the view for it */ }
    persistView(u);
  }

  function persistView(u) {
    writeStore("ominull.view", JSON.stringify({
      section: u.section, q: u.q, f: u.f, sort: state.assetSort
    }));
  }

  function restoreView() {
    var u = decodeURLState(location.hash);
    if (!u) {
      /* No address to honour, so fall back to what this operator was last
         looking at. A deliberate link always wins over the remembered view. */
      try {
        var saved = JSON.parse(readStore("ominull.view", "null"));
        if (saved && saved.section) u = { section: saved.section, q: saved.q || "", f: saved.f || "", row: "", route: "" };
        if (saved && saved.sort && typeof saved.sort.col === "number") state.assetSort = saved.sort;
      } catch (e) { u = null; }
    }
    if (u) applyURLState(u);
  }

  function applyURLState(u) {
    if (!u) return;
    var section = u.section === "discovery" ? "assets" : u.section;
    if (SECTIONS.some(function (sec) { return sec.id === section; })) state.section = section;
    state.query = u.q || "";
    state.filters = {};
    (u.f || "").split(",").forEach(function (k) {
      if (k && FILTERS[k]) state.filters[k] = true;
    });
    state.expandedKey = u.row || "";
    if (u.route) {
      state.routeKey = u.route;
    } else {
      closeRoute();
    }
  }

  /* --------------------------------------------------------------- utils */

  function pad(n, w) {
    var t = String(n);
    while (t.length < w) t = "0" + t;
    return t;
  }

  /* Zero-pads dotted-quads so 10.0.4.9 sorts before 10.0.4.20. Anything that is
     not an IPv4 literal sorts after every address, by its own text. */
  function addressSortKey(ip) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || ""));
    if (!m) return "9|" + String(ip || "");
    return "1|" + pad(m[1], 3) + pad(m[2], 3) + pad(m[3], 3) + pad(m[4], 3);
  }

  function parseTime(v) {
    if (!v) return null;
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  }

  /* A span of time in the largest unit that keeps it readable. "24 of 60
     minutes" and "6 of 7 days" both have to come out of the same call, so the
     chart's coverage line reads correctly on a 15m window and a 30d one. */
  function spanText(ms) {
    var mins = Math.max(0, Math.round(ms / 60000));
    if (mins < 180) return mins + (mins === 1 ? " minute" : " minutes");
    var hrs = Math.round(mins / 60);
    if (hrs < 72) return hrs + (hrs === 1 ? " hour" : " hours");
    var days = Math.round(hrs / 24);
    return days + (days === 1 ? " day" : " days");
  }

  function ago(date) {
    if (!date) return "\u2014";
    var secs = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (secs < 60) return secs + "s";
    var mins = Math.floor(secs / 60);
    if (mins < 60) return mins + "m " + pad(secs % 60, 2) + "s";
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h " + pad(mins % 60, 2) + "m";
    return Math.floor(hrs / 24) + "d " + pad(hrs % 24, 2) + "h";
  }

  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  /* "4m 12s ago" is the wrong headline for a last-seen column. A host that hung
     at 02:14 reads as a number that keeps climbing, and the one fact worth
     having - when it stopped - is the one the console threw away. So the
     absolute local time leads and the age moves to the tooltip. */
  function stampText(date) {
    if (!date) return "\u2014";
    var now = new Date();
    var hhmm = pad(date.getHours(), 2) + ":" + pad(date.getMinutes(), 2);
    if (date.getFullYear() !== now.getFullYear()) {
      return date.getFullYear() + "-" + pad(date.getMonth() + 1, 2) + "-" + pad(date.getDate(), 2) + " " + hhmm;
    }
    if (date.getDate() === now.getDate() && date.getMonth() === now.getMonth()) {
      return hhmm + ":" + pad(date.getSeconds(), 2);
    }
    return MONTHS[date.getMonth()] + " " + pad(date.getDate(), 2) + " " + hhmm;
  }

  function stampTitle(date) {
    if (!date) return "No timestamp recorded";
    return date.toString() + " \u2014 " + ago(date) + " ago";
  }

  /* A <time> so the machine-readable instant travels with the text, and so a
     copy-paste out of the console lands somewhere with a timezone on it. */
  function stamp(date, extraCls) {
    if (!date) return h("span", { cls: "ago" + (extraCls ? " " + extraCls : ""), text: "\u2014" });
    return h("time", {
      cls: "stamp" + (extraCls ? " " + extraCls : ""),
      datetime: date.toISOString(),
      title: stampTitle(date),
      text: stampText(date)
    });
  }

  function bytes(n) {
    n = Number(n) || 0;
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
  }

  function versionTriple(v) {
    var out = [0, 0, 0];
    var parts = String(v || "").replace(/^v/, "").split(".");
    for (var i = 0; i < 3 && i < parts.length; i++) out[i] = parseInt(parts[i], 10) || 0;
    return out;
  }

  function versionLess(a, b) {
    var x = versionTriple(a), y = versionTriple(b);
    for (var i = 0; i < 3; i++) {
      if (x[i] !== y[i]) return x[i] < y[i];
    }
    return false;
  }

  function shortVersion(v) {
    var m = /^v?(\d+\.\d+\.\d+)/.exec(String(v || ""));
    return m ? m[1] : (v || "\u2014");
  }

  /* Collector label from the compatibility version an agent reports. */
  function engineOf(v) {
    var m = /\(([^)]+)\)/.exec(String(v || ""));
    return m ? m[1] : "";
  }

  function osFamily(os) {
    var l = String(os || "").toLowerCase();
    if (l.indexOf("windows") >= 0) return "windows";
    if (l.indexOf("linux") >= 0 || l.indexOf("debian") >= 0 || l.indexOf("ubuntu") >= 0) return "linux";
    return "";
  }

  /* --------------------------------------------------------------- state */

  var state = {
    section: "assets",
    theme: DEFAULT_THEME,
    demo: false,
    loading: true,
    lastError: "",

    hierarchy: [],
    endpoints: [],
    assetGraph: [],
    scanAssets: [],
    locations: [],
    coverage: null,
    anomalies: [],
    // True when the last fetch came back a full page, so the count on the
    // badge is a floor rather than a total.
    anomaliesCapped: false,
    updateStatus: null,
    meshPeers: [],
    exclusions: [],
    iocs: [],
    baselinePolicies: [],
    tuning: null,
    baselineServices: [],
    // Keyed by endpoint id. Resolved on demand rather than for the whole fleet:
    // it is a per-host answer and only one host is ever on screen.
    baselineByEndpoint: {},
    audit: [],
    responseAuthStatus: null,
    responseJobs: [],
    responseSession: null,
    terminalSessions: [],
    scripts: [],
    scriptSchedules: [],
    evidenceBundles: [],
    vulnerabilities: [],
    operators: [],
    operatorRoles: ["admin", "analyst", "auditor"],
    you: "",
    events: [],
    analytics: null,
    trafficOverview: null,
    trafficFlows: null,
    trafficFilter: { range: "1h", endpoint_id: "", src_ip: "", dst_ip: "", process: "", domain: "", country: "", protocol: "", port: "", direction: "", action: "", measured_only: false, cursor: "" },
    selectedFlow: null,
    dnsStatus: null,
    dnsEvents: [],
    dnsPolicy: [],
    terminalAvailable: false,
    /* The hub runs 24 checks with remediation text and the console never asked
       for them once. They are not on the 5s poll: each run has an 8 second
       timeout and touches the network, so it is fetched when the section is
       first shown and whenever the operator asks again. */
    diagnostics: null,
    diagnosticsAt: 0,
    diagnosticsError: "",
    diagnosticsRunning: false,
    viewStale: false,
    pointerDragging: false,
    topology: null,
    topoWindow: "24h",
    /* The graph is reduced before it is drawn; these decide how. */
    topoScope: "groups",
    topoGroupBy: "subnet",
    topoFocus: "notable",
    topoDrill: "",
    /* Until the operator touches a control, the scope follows the size of the
       graph: a small estate is drawn host by host, because collapsing twelve
       machines into three boxes hides more than it clarifies. */
    topoAuto: true,

    assets: [],
    assetByKey: {},

    filters: {},
    query: "",
    selected: {},
    cursorKey: "",
    expandedKey: "",
    collapsedGroups: {},
    routeKey: "",

    /* Which Assets column the operator sorted on, {col, dir}, or null for the
       stable address order. "Who is oldest on agent version" and "who was seen
       least recently" are two of the questions this table exists to answer and
       neither was reachable. */
    assetSort: null,

    topoSelected: "",
    topoEdgeSelected: "",
    statHistory: {},
    scanJob: null,
    // The running scan's own answer about itself. Polled while it runs; the
    // console used to hold the id and never ask the hub what became of it.
    scanStatus: null,
    scanPoll: null,

    alertsFilter: { page: 1, limit: 50, severity: "", type: "", endpoint_id: "", unacknowledged_only: true, search: "", held: false },
    alertsData: null,
    selectedAlerts: {},
    expandedAlertId: "",
    unackAlertsTotal: 0,
    lastClickedAssetIndex: -1,

    // Phase 7: Software Inventory & Vulnerability Correlation
    softwareByEndpoint: {},
    /* The hub has kept a rolling communication profile per endpoint since the
       first release and the console never read it, so "what does this host
       normally talk to" could only be answered by scrolling raw flows. */
    profilesByEndpoint: {},
    /* One bearer credential per enrolled machine. Admin-only, listed without
       the secret - the hub returns the credential string exactly once, at
       issue. */
    deviceCredentials: [],
    activeSnapshot: null,
    vulnFilterStatus: "",
    softwareSearchQuery: ""
  };

  function selectedKeys() {
    return Object.keys(state.selected).filter(function (k) { return state.selected[k]; });
  }

  /* ----------------------------------------------------------------- api */

  function apiURL(path) {
    return path;
  }

  function request(path, method, body) {
    if (state.demo) return demoResponse(path, method, body);
    /* An empty X-API-Key is a failed credential as far as the hub is concerned,
       and failed credentials are throttled by source address. When there is no
       key the session cookie is the credential, so send nothing rather than
       something wrong. */
    var headers = { "Content-Type": "application/json" };
    if (API_KEY) headers["X-API-Key"] = API_KEY;
    var opts = {
      method: method || "GET",
      headers: headers,
      credentials: "same-origin"
    };
    if (body) opts.body = JSON.stringify(body);
    return fetch(apiURL(path), opts).then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) {
          /* The hub answers a refusal as {"error": "..."} written for a person
             to read. Pasting the raw body into a toast showed them the JSON
             around their own answer. */
          var parsed = null;
          var msg = "";
          try { parsed = JSON.parse(t); msg = (parsed || {}).error || ""; } catch (e) { msg = ""; }
          if (!msg) msg = (t || "").slice(0, 200);
          var err = new Error(msg || "HTTP " + res.status);
          /* The isolation gate refuses with the whole picture in the body -
             what is uncovered, what would still be permitted. A caller that
             only sees the sentence cannot offer the operator the choice. */
          err.status = res.status;
          err.body = parsed;
          throw err;
        });
      }
      var ct = res.headers.get("content-type") || "";
      if (ct.indexOf("application/json") < 0) return res.text();
      return res.json();
    });
  }

  function arrayOf(v) {
    return Array.isArray(v) ? v : [];
  }

  /* ------------------------------------------------------- demo fixtures */

  /* Demo mode seeds a synthetic fleet so the console can be exercised and
     screenshotted without a live hub. Addresses are 10.0.4.x / 172.16.x by
     repo convention. */
  /* Mirrors the shipped catalogue in hub/pkg/storage/baseline.go. Demo mode has
     no hub to ask, and an editor with an empty service list is not a demo of
     anything. */
  var DEMO_BASELINE_SERVICES = [
    { service: "dns", label: "DNS", protocol: "udp", ports: [53], why: "Name resolution." },
    { service: "dhcp", label: "DHCP", protocol: "udp", ports: [67, 547], broadcast: ["255.255.255.255", "ff02::1:2"], why: "Lease renewal." },
    { service: "ntp", label: "NTP", protocol: "udp", ports: [123], why: "Clock synchronisation." },
    { service: "custom", label: "Custom", protocol: "", ports: null, why: "Anything else this network needs." }
  ];

  var DEMO_BASELINE_POLICIES = [
    {
      id: "bp-corp-resolvers", name: "Corporate resolvers", scope: "global", scope_value: "", enabled: true,
      rules: [
        { id: "br-1", policy_id: "bp-corp-resolvers", service: "dns", destination: "10.0.4.10" },
        { id: "br-2", policy_id: "bp-corp-resolvers", service: "dns", destination: "10.0.4.11" },
        { id: "br-3", policy_id: "bp-corp-resolvers", service: "dhcp", destination: "10.0.4.1" }
      ]
    },
    {
      id: "bp-cloud", name: "AWS production VPC", scope: "location", scope_value: "loc-cloud", enabled: true,
      rules: [
        { id: "br-4", policy_id: "bp-cloud", service: "dns", destination: "172.16.0.2" },
        { id: "br-5", policy_id: "bp-cloud", service: "ntp", destination: "169.254.169.123" }
      ]
    }
  ];

  function demoData() {
    var now = new Date().toISOString();
    var mins = function (m) { return new Date(Date.now() - m * 60000).toISOString(); };

    var endpoints = [
      { id: "win11-corp-exec", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "corp-win11-exec", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.15", mac: "00:1A:2B:3C:4D:5E", role_tag: "workstation", installed_software: "Ominull Windows user-mode WFP agent", driver_version: "1.1.0 (windows-user-wfp)", status: "online", is_isolated: true, last_seen_at: now, created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-dmz-web-01", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "dmz-web-01", os: "Debian 12 Bookworm (x86_64)", ip: "10.0.4.20", mac: "00:50:56:A1:B2:C3", role_tag: "web-server", installed_software: "Ominull Linux socket agent, Nginx 1.26", driver_version: "1.1.0 (linux-socket-v1)", status: "online", is_isolated: false, last_seen_at: mins(0.2), created_at: "2026-08-20T10:00:00Z" },
      { id: "win11-fin-11", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "corp-win11-fin", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.31", mac: "00:1A:2B:99:88:77", role_tag: "workstation", installed_software: "Ominull Windows user-mode WFP agent", driver_version: "1.0.0 (windows-user-wfp)", status: "offline", is_isolated: false, last_seen_at: mins(134), created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-prod-db-01", tenant_id: "corp-default", location_id: "loc-cloud", location_name: "AWS Production VPC", hostname: "prod-db-01", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.4", mac: "02:42:AC:11:00:02", role_tag: "db-server", installed_software: "Ominull Linux socket agent, PostgreSQL 16", driver_version: "1.0.0 (linux-socket-v1)", status: "online", is_isolated: false, last_seen_at: mins(0.05), created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-prod-api-02", tenant_id: "corp-default", location_id: "loc-cloud", location_name: "AWS Production VPC", hostname: "prod-api-02", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.9", mac: "02:42:AC:11:00:09", role_tag: "app-server", installed_software: "Ominull Linux socket agent", driver_version: "1.1.0 (linux-socket-v1)", status: "online", is_isolated: false, last_seen_at: mins(0.15), created_at: "2026-08-21T10:00:00Z" },
      { id: "win11-branch-kiosk", tenant_id: "harbour-health", location_id: "loc-branch", location_name: "Branch Clinic", hostname: "branch-kiosk-19", os: "Windows 11 IoT Enterprise (x86_64)", ip: "10.0.4.44", mac: "00:1A:2B:44:44:44", role_tag: "kiosk", installed_software: "Ominull Windows user-mode WFP agent", driver_version: "1.1.0 (windows-user-wfp)", status: "online", is_isolated: false, last_seen_at: mins(0.3), created_at: "2026-08-22T10:00:00Z" },
      { id: "linux-branch-nvr", tenant_id: "harbour-health", location_id: "loc-branch", location_name: "Branch Clinic", hostname: "branch-nvr-01", os: "Debian 12 Bookworm (aarch64)", ip: "10.0.4.46", mac: "00:50:56:46:46:46", role_tag: "recorder", installed_software: "Ominull Linux socket agent", driver_version: "1.0.0 (linux-socket-v1)", status: "online", is_isolated: false, last_seen_at: mins(0.4), created_at: "2026-08-22T10:00:00Z" }
    ];

    var locations = [
      { id: "loc-hq", tenant_id: "corp-default", name: "Corporate HQ LAN", city: "Denver", country: "US", subnet_cidr: "10.0.4.0/24" },
      { id: "loc-cloud", tenant_id: "corp-default", name: "AWS Production VPC", city: "us-east-1", country: "US", subnet_cidr: "172.16.0.0/16" },
      { id: "loc-branch", tenant_id: "harbour-health", name: "Branch Clinic", city: "Portland", country: "US", subnet_cidr: "10.0.4.0/24" }
    ];
    var tenants = [
      { id: "corp-default", name: "Acme CyberOps Enterprise" },
      { id: "harbour-health", name: "Harbourline Health" }
    ];

    var hierarchy = tenants.map(function (t) {
      var locs = locations.filter(function (l) { return l.tenant_id === t.id; }).map(function (l) {
        var eps = endpoints.filter(function (e) { return e.location_id === l.id; });
        return {
          location: l,
          endpoints: eps,
          total_endpoints: eps.length,
          isolated_count: eps.filter(function (e) { return e.is_isolated; }).length
        };
      });
      var all = endpoints.filter(function (e) { return e.tenant_id === t.id; });
      return {
        tenant: t,
        locations: locs,
        total_endpoints: all.length,
        isolated_count: all.filter(function (e) { return e.is_isolated; }).length
      };
    });

    var scan = [
      { ip: "10.0.4.1", mac: "00:00:0C:9F:F0:01", vendor: "Cisco Systems", hostname: "core-gateway", os_guess: "Cisco IOS-XE Gateway", category: "Router / Firewall", confidence: 0.95, ttl: 255, app_delta_ms: 0.8, is_managed: false, agent_endpoint_id: "", risk_score: "LOW", weakpoints: [], identity_method: "signature", identity_why: ["OUI 00:00:0C is listed for Cisco Catalyst / IOS Core Switch", "measured TTL 255 is consistent with an initial 255", "open ports 22, 443 are expected for Cisco Catalyst / IOS Core Switch"], last_seen: mins(2), open_ports: [{ port: 22, protocol: "tcp", service: "ssh", risk_level: "LOW" }, { port: 443, protocol: "tcp", service: "https", risk_level: "LOW" }] },
      { ip: "10.0.4.10", mac: "00:1A:2B:0A:0A:0A", vendor: "Dell Inc.", hostname: "", os_guess: "Windows Server", category: "Server", confidence: 0.71, ttl: 128, app_delta_ms: 1.0, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["RDP reachable from three subnets"], identity_method: "netbios", identity_why: ["NBSTAT: DC01<00> DC01<20> CORP<00> group"], last_seen: mins(0.2), open_ports: [{ port: 53, protocol: "tcp", service: "dns", risk_level: "LOW" }, { port: 88, protocol: "tcp", service: "kerberos", risk_level: "LOW" }, { port: 135, protocol: "tcp", service: "rpc", risk_level: "LOW" }, { port: 389, protocol: "tcp", service: "ldap", risk_level: "LOW" }, { port: 445, protocol: "tcp", service: "smb", risk_level: "HIGH" }, { port: 636, protocol: "tcp", service: "ldaps", risk_level: "LOW" }, { port: 3389, protocol: "tcp", service: "rdp", risk_level: "HIGH" }] },
      { ip: "10.0.4.15", mac: "00:1A:2B:3C:4D:5E", vendor: "Dell Inc.", hostname: "corp-win11-exec", os_guess: "Windows 11 Enterprise (x86_64)", category: "Workstation", confidence: 0.98, ttl: 128, app_delta_ms: 1.1, is_managed: true, agent_endpoint_id: "win11-corp-exec", risk_score: "LOW", weakpoints: [], identity_method: "agent", identity_why: ["reported by the agent installed on this host"], last_seen: mins(1), open_ports: [{ port: 135, protocol: "tcp", service: "epmap", risk_level: "LOW" }, { port: 445, protocol: "tcp", service: "microsoft-ds", risk_level: "LOW" }] },
      { ip: "10.0.4.20", mac: "00:50:56:A1:B2:C3", vendor: "VMware, Inc.", hostname: "dmz-web-01", os_guess: "Linux (generic)", category: "Server", confidence: 0.62, ttl: 64, app_delta_ms: 1.2, is_managed: true, agent_endpoint_id: "linux-dmz-web-01", risk_score: "LOW", weakpoints: [], identity_method: "ssh-banner", identity_why: ["SSH-2.0-OpenSSH_9.6", "the banner names no distribution, so the release is not known"], last_seen: mins(1), open_ports: [{ port: 80, protocol: "tcp", service: "http", risk_level: "MEDIUM" }, { port: 443, protocol: "tcp", service: "https", risk_level: "LOW" }] },
      { ip: "10.0.4.55", mac: "00:11:32:44:55:66", vendor: "Synology Inc.", hostname: "unmanaged-nas", os_guess: "Synology DiskStation DSM 7.2", category: "Storage / NAS", confidence: 0.92, ttl: 64, app_delta_ms: 1.4, is_managed: false, agent_endpoint_id: "", risk_score: "HIGH", weakpoints: ["Unencrypted HTTP administrative console (port 5000)", "SMBv1 legacy dialect enabled"], identity_method: "http-server", identity_why: ["Server: Synology DiskStation 7.2"], last_seen: mins(3), open_ports: [{ port: 445, protocol: "tcp", service: "smb", risk_level: "HIGH" }, { port: 5000, protocol: "tcp", service: "http", risk_level: "HIGH" }, { port: 5001, protocol: "tcp", service: "https", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.71", mac: "00:1B:A9:71:71:71", vendor: "Brother Industries", hostname: "", os_guess: "Embedded print controller", category: "Printer", confidence: 0.44, ttl: 64, app_delta_ms: 2.6, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["Unauthenticated raw print queue on 9100"], identity_method: "mdns-services", identity_why: ["mDNS services: _ipp _pdl-datastream", "mDNS name: brother-mfc.local"], last_seen: mins(4), open_ports: [{ port: 631, protocol: "tcp", service: "ipp", risk_level: "LOW" }, { port: 9100, protocol: "tcp", service: "jetdirect", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.99", mac: "B8:27:EB:12:34:56", vendor: "Raspberry Pi Foundation", hostname: "rogue-dev-kali", os_guess: "Kali Linux Rolling (ARM64)", category: "Shadow IT / Pentest", confidence: 0.89, ttl: 64, app_delta_ms: 2.1, is_managed: false, agent_endpoint_id: "", risk_score: "CRITICAL", weakpoints: ["Unauthorized Metasploit payload listener on port 4444", "Unmanaged shadow IT device"], identity_method: "ssh-banner", identity_why: ["SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"], last_seen: mins(0.5), open_ports: [{ port: 22, protocol: "tcp", service: "ssh", risk_level: "MEDIUM" }, { port: 4444, protocol: "tcp", service: "metasploit", risk_level: "CRITICAL" }] },
      { ip: "10.0.4.120", mac: "50:02:91:AA:BB:CC", vendor: "Samsung Electronics", hostname: "lobby-display", os_guess: "Samsung Tizen Smart Display", category: "IoT / Display", confidence: 0.88, ttl: 64, app_delta_ms: 1.9, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["Unauthenticated smart-display remote API on LAN"], identity_method: "ssdp", identity_why: ["SSDP SERVER: Linux/4.1 UPnP/1.0 Samsung/1.0"], last_seen: mins(9), open_ports: [{ port: 8001, protocol: "tcp", service: "smarttv-api", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.201", mac: "", vendor: "", hostname: "", os_guess: "", category: "", confidence: 0.12, ttl: 0, app_delta_ms: 0, is_managed: false, agent_endpoint_id: "", risk_score: "LOW", weakpoints: [], identity_method: "", identity_why: ["nothing on this host answered any probe"], last_seen: mins(62), open_ports: [] }
    ];

    var anomalies = [
      { id: "alert-ioc-01", tenant_id: "corp-default", location_id: "loc-hq", endpoint_id: "win11-corp-exec", hostname: "corp-win11-exec", anomaly_type: "THREAT_INTEL_MATCH", severity: "CRITICAL", title: "Threat-intel destination blocked", description: "powershell.exe attempted a connection to an active threat-intel destination.", details: "Destination 198.51.100.22:443 matched the active IOC catalogue.", process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", dst_ip: "198.51.100.22", dst_port: 443, timestamp: mins(4), acknowledged: false },
      { id: "alert-offhours-02", tenant_id: "corp-default", location_id: "loc-hq", endpoint_id: "win11-corp-exec", hostname: "corp-win11-exec", anomaly_type: "NOVEL_PROCESS_EGRESS", severity: "HIGH", title: "Off-hours interactive shell egress", description: "Interactive shell opened an external session at 02:14 UTC.", details: "explorer.exe -> powershell.exe -> 198.51.100.22:8443", process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", dst_ip: "198.51.100.22", dst_port: 8443, timestamp: mins(38), acknowledged: false },
      { id: "alert-bandwidth-04", tenant_id: "corp-default", location_id: "loc-cloud", endpoint_id: "linux-prod-db-01", hostname: "prod-db-01", anomaly_type: "BANDWIDTH_SPIKE", severity: "MEDIUM", title: "Egress volume 14x baseline", description: "Sustained outbound transfer well above the learned diurnal baseline.", details: "4.2 GB out in 20m vs 300 MB baseline", process_path: "/usr/lib/postgresql/16/bin/postgres", dst_ip: "203.0.113.51", dst_port: 5432, timestamp: mins(96), acknowledged: false }
    ];

    var talkers = [
      { process: "C:\\Windows\\System32\\svchost.exe", flow_count: 18422, bytes_in: 920000000, bytes_out: 210000000, total_bytes: 1130000000 },
      { process: "/usr/sbin/nginx", flow_count: 12408, bytes_in: 180000000, bytes_out: 1420000000, total_bytes: 1600000000 },
      { process: "/usr/lib/postgresql/16/bin/postgres", flow_count: 6120, bytes_in: 88000000, bytes_out: 4200000000, total_bytes: 4288000000 },
      { process: "powershell.exe", flow_count: 942, bytes_in: 4100000, bytes_out: 19400000, total_bytes: 23500000 },
      { process: "/usr/bin/nmap", flow_count: 618, bytes_in: 210000, bytes_out: 480000, total_bytes: 690000 }
    ];

    var timeline = [];
    for (var i = 23; i >= 0; i--) {
      var base = 40 + Math.round(38 * Math.sin((23 - i) / 3.4));
      timeline.push({
        timestamp: new Date(Date.now() - i * 3600000).toISOString(),
        bytes_in: (base + 22) * 4200000,
        bytes_out: (base + 9) * 3100000,
        blocks: Math.max(0, 12 - Math.abs(12 - (23 - i)))
      });
    }

    /* Nodes come from the asset graph, so every one carries its evidence and
       its role. Two of them are quiet: known assets that said nothing inside
       the window, drawn dimmed rather than dropped. */
    var topoNodes = endpoints.map(function (e) {
      return {
        id: e.ip, label: e.hostname, type: "managed", ip: e.ip, os: e.os,
        role: e.role_tag, risk: e.is_isolated ? "CRITICAL" : "CLEAN",
        is_isolated: e.is_isolated, group: e.location_name,
        evidence: ["agent", "scan"], confidence: 1.0, quiet: e.status !== "online"
      };
    });
    topoNodes.push({ id: "10.0.4.1", label: "core-gateway", type: "gateway", ip: "10.0.4.1", os: "Cisco IOS-XE Gateway", role: "Router / Firewall", risk: "LOW", is_isolated: false, group: "Corporate HQ LAN", evidence: ["scan"], quiet: false });
    topoNodes.push({ id: "10.0.4.10", label: "10.0.4.10", type: "unmanaged", ip: "10.0.4.10", os: "Windows Server", role: "Server", risk: "MEDIUM", is_isolated: false, group: "Server", evidence: ["scan"], confidence: 0.71, quiet: false });
    topoNodes.push({ id: "10.0.4.12", label: "10.0.4.12", type: "unmanaged", ip: "10.0.4.12", os: "", role: "unknown", risk: "MEDIUM", is_isolated: false, group: "Seen in traffic only", evidence: [], quiet: false });
    topoNodes.push({ id: "10.0.4.55", label: "unmanaged-nas", type: "unmanaged", ip: "10.0.4.55", os: "Synology DiskStation DSM 7.2", role: "Storage / NAS", risk: "HIGH", is_isolated: false, group: "Storage / NAS", evidence: ["scan"], confidence: 0.92, quiet: false });
    topoNodes.push({ id: "10.0.4.71", label: "10.0.4.71", type: "unmanaged", ip: "10.0.4.71", os: "Embedded print controller", role: "Printer", risk: "MEDIUM", is_isolated: false, group: "Printer", evidence: ["scan"], confidence: 0.44, quiet: true });
    topoNodes.push({ id: "10.0.4.99", label: "rogue-dev-kali", type: "unmanaged", ip: "10.0.4.99", os: "Kali Linux Rolling (ARM64)", role: "Shadow IT / Pentest", risk: "CRITICAL", is_isolated: false, group: "Shadow IT / Pentest", evidence: ["scan"], quiet: false });
    topoNodes.push({ id: "10.0.4.120", label: "lobby-display", type: "unmanaged", ip: "10.0.4.120", os: "Samsung Tizen Smart Display", role: "IoT / Display", risk: "MEDIUM", is_isolated: false, group: "IoT / Display", evidence: ["scan"], quiet: true });
    topoNodes.push({ id: "198.51.100.22", label: "198.51.100.22", type: "threat", ip: "198.51.100.22", os: "", role: "unknown", risk: "CRITICAL", is_isolated: false, group: "Blocked destination", evidence: [], quiet: false });

    /* The demo asset graph is generated from the same scan and agent fixtures
       the live hub merges. Flow-only addresses remain topology nodes without
       being promoted into an asset identity. */
    function demoClaim(field, source, value, confidence, rationale, seen) {
      return { field: field, source: source, value: value, confidence: confidence, rationale: rationale || "", observed_at: seen, winner: false };
    }

    /* Same rule as the hub: highest confidence wins per field, with agent and
       operator claims outranking scan evidence. */
    var demoMergeAsset = DEMO_REMERGE;

    function demoAssetGraph() {
      var scanByIP = {};
      var scanByEp = {};
      scan.forEach(function (a) { scanByIP[a.ip] = a; if (a.agent_endpoint_id) scanByEp[a.agent_endpoint_id] = a; });

      var out = [];
      var used = {};

      endpoints.forEach(function (ep) {
        var sc = scanByEp[ep.id] || scanByIP[ep.ip] || null;
        if (sc) used[sc.ip] = true;
        var claims = [
          demoClaim("hostname", "agent", ep.hostname, 1.0, "", ep.last_seen_at),
          demoClaim("os", "agent", ep.os, 1.0, "", ep.last_seen_at),
          demoClaim("role", "agent", ep.role_tag, 1.0, "operator-assigned role tag on the agent", ep.last_seen_at)
        ];
        if (sc) {
          claims.push(demoClaim("os", "scan", sc.os_guess, sc.confidence, "TTL and application-delta fingerprint", sc.last_seen));
          claims.push(demoClaim("vendor", "scan", sc.vendor, 0.9, "OUI lookup on the hardware address", sc.last_seen));
          claims.push(demoClaim("category", "scan", sc.category, sc.confidence, "device signature match on open ports and banners", sc.last_seen));
          claims.push(demoClaim("risk", "scan", sc.risk_score, sc.confidence, "exposure assessment of open ports", sc.last_seen));
        }
        out.push(demoMergeAsset({
          id: "asset-mac-" + (ep.mac || ep.id).replace(/:/g, "").toLowerCase(),
          identity_kind: ep.mac ? "mac" : "ip", identity_value: ep.mac || ep.ip,
          agent_endpoint_id: ep.id, tenant_id: ep.tenant_id, location_id: ep.location_id,
          ip: ep.ip, mac: ep.mac || (sc ? sc.mac : ""), subnet: "",
          first_seen_at: ep.created_at, last_seen_at: ep.last_seen_at,
          ports: sc ? sc.open_ports : [], claims: claims
        }));
      });

      scan.forEach(function (sc) {
        if (used[sc.ip]) return;
        out.push(demoMergeAsset({
          id: "asset-mac-" + (sc.mac || sc.ip).replace(/[:.]/g, "").toLowerCase(),
          identity_kind: sc.mac ? "mac" : "ip", identity_value: sc.mac || sc.ip,
          agent_endpoint_id: "", tenant_id: "default", location_id: "",
          ip: sc.ip, mac: sc.mac, subnet: "10.0.4.0/24",
          first_seen_at: sc.last_seen, last_seen_at: sc.last_seen,
          ports: sc.open_ports,
          claims: [
            demoClaim("hostname", "scan", sc.hostname, sc.confidence, "reverse lookup during probe", sc.last_seen),
            demoClaim("os", "scan", sc.os_guess, sc.confidence, "TTL and application-delta fingerprint", sc.last_seen),
            demoClaim("vendor", "scan", sc.vendor, 0.9, "OUI lookup on the hardware address", sc.last_seen),
            demoClaim("category", "scan", sc.category, sc.confidence, "device signature match on open ports and banners", sc.last_seen),
            demoClaim("risk", "scan", sc.risk_score, sc.confidence, "exposure assessment of open ports", sc.last_seen)
          ].filter(function (c) { return c.value; })
        }));
      });

      return out;
    }

    var topoEdges = [
      { id: "e1", source: "10.0.4.15", target: "10.0.4.10", protocol: "tcp", port: 389, flow_count: 2140, total_bytes: 42000000, verdict: "clean", last_seen: now },
      { id: "e3", source: "10.0.4.20", target: "10.0.4.1", protocol: "tcp", port: 443, flow_count: 18200, total_bytes: 1420000000, verdict: "clean", last_seen: now },
      { id: "e4", source: "10.0.4.44", target: "10.0.4.10", protocol: "tcp", port: 445, flow_count: 640, total_bytes: 8100000, verdict: "clean", last_seen: now },
      { id: "e5", source: "10.0.4.46", target: "10.0.4.55", protocol: "tcp", port: 445, flow_count: 3120, total_bytes: 620000000, verdict: "clean", last_seen: now },
      { id: "e6", source: "10.0.4.15", target: "198.51.100.22", protocol: "tcp", port: 443, flow_count: 142, total_bytes: 810000, verdict: "blocked", last_seen: now },
      { id: "e8", source: "172.16.10.4", target: "172.16.10.9", protocol: "tcp", port: 5432, flow_count: 9400, total_bytes: 2100000000, verdict: "clean", last_seen: now },
      { id: "e9", source: "10.0.4.31", target: "10.0.4.10", protocol: "tcp", port: 135, flow_count: 220, total_bytes: 2400000, verdict: "clean", last_seen: now },
      { id: "e10", source: "172.16.10.9", target: "10.0.4.1", protocol: "tcp", port: 443, flow_count: 5100, total_bytes: 310000000, verdict: "clean", last_seen: now },
      { id: "e11", source: "10.0.4.15", target: "10.0.4.12", protocol: "tcp", port: 88, flow_count: 1480, total_bytes: 9200000, verdict: "clean", last_seen: now },
      { id: "e12", source: "10.0.4.31", target: "10.0.4.12", protocol: "tcp", port: 389, flow_count: 910, total_bytes: 5400000, verdict: "clean", last_seen: now },
      { id: "e13", source: "10.0.4.44", target: "10.0.4.12", protocol: "tcp", port: 135, flow_count: 320, total_bytes: 1900000, verdict: "clean", last_seen: now }
    ];

    /* The hub aggregates edges to the asset pair and hands the port breakdown
       over with them, so the demo carries the same shape. */
    topoEdges.forEach(function (e) {
      /* The demo stands for a fleet whose collectors can read a byte counter,
         so every flow in it is a measured one. A live hub reports how many
         actually were, and the console says so where it prints a volume. */
      e.measured_flows = e.flow_count;
      e.ports = [{ port: e.port, protocol: (e.protocol || "tcp").toUpperCase(), flow_count: e.flow_count, total_bytes: e.total_bytes, measured_flows: e.flow_count, verdict: e.verdict }];
    });
    topoEdges[0].ports.push({ port: 445, protocol: "TCP", flow_count: 610, total_bytes: 7400000, measured_flows: 610, verdict: "clean" });
    topoEdges[0].ports.push({ port: 135, protocol: "TCP", flow_count: 240, total_bytes: 1100000, measured_flows: 240, verdict: "clean" });
    topoEdges[0].ports.push({ port: 88, protocol: "TCP", flow_count: 1290, total_bytes: 6800000, measured_flows: 1290, verdict: "clean" });

    return {
      "/api/v1/hierarchy": hierarchy,
      "/api/v1/endpoints": endpoints,
      "/api/v1/baseline/catalogue": { services: DEMO_BASELINE_SERVICES },
      "/api/v1/baseline/policies": { policies: DEMO_BASELINE_POLICIES, services: DEMO_BASELINE_SERVICES },
      "/api/v1/assets": demoAssetGraph(),
      "/api/v1/scanner/results": scan,
      "/api/v1/scanner/coverage": {
        total_discovered: scan.length, total_managed: endpoints.length, total_unmanaged: scan.length - endpoints.length,
        coverage_percent: Math.round((endpoints.length / scan.length) * 1000) / 10, critical_risks: 1, high_risks: 1
      },
      "/api/v1/anomalies": anomalies,
      "/api/v1/agents/update-status": {
        latest_version: "1.1.0",
        outdated: [
          { endpoint_id: "linux-prod-db-01", hostname: "prod-db-01", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.4", driver_version: "1.0.0 (linux-socket-v1)" },
          { endpoint_id: "win11-fin-11", hostname: "corp-win11-fin", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.31", driver_version: "1.0.0 (windows-user-wfp)" },
          { endpoint_id: "linux-branch-nvr", hostname: "branch-nvr-01", os: "Debian 12 Bookworm (aarch64)", ip: "10.0.4.46", driver_version: "1.0.0 (linux-socket-v1)" }
        ],
        pending: []
      },
      /* Demo mode has to reach the self-service screen too, or the only way to
         see what a window looks like is to open a real one on a real network. */
      "/api/v1/enrolment/windows": {
        portal_url: "http://10.0.0.58:9999/install",
        suggested_cidrs: ["10.0.4.0/24"],
        enrollment_ttl: "30m0s",
        windows: [
          { id: "win-demo01", label: "Branch Clinic rollout", cidrs: ["10.0.4.0/24"], state: "open", used: 6, max_uses: 40, has_passcode: true, expires_at: new Date(Date.now() + 5 * 3600000).toISOString() },
          { id: "win-demo02", label: "Server room", cidrs: ["10.0.2.0/24"], state: "spent", used: 4, max_uses: 4, has_passcode: false, expires_at: new Date(Date.now() + 2 * 3600000).toISOString() },
          { id: "win-demo03", label: "Tuesday laptops", cidrs: ["10.0.9.0/24"], state: "expired", used: 11, max_uses: 0, has_passcode: false, expires_at: new Date(Date.now() - 26 * 3600000).toISOString() }
        ]
      },
      "/api/v1/mesh/quarantined": [
        { id: "mq-01", target_ip: "10.0.4.99", target_mac: "B8:27:EB:12:34:56", subnet: "10.0.4.0/24", reason: "Metasploit listener on 4444", active: true, created_at: mins(22) }
      ],
      "/api/v1/exclusions": [
        { id: "ex-01", tenant_id: "corp-default", scope: "global", scope_value: "", name: "Directory service authentication", process_path: "", dst_ip_range: "10.0.4.10/32", port: 88, protocol: "tcp", reason: "Kerberos to the site directory server", active: true, created_at: "2026-08-20T10:00:00Z" },
        { id: "ex-02", tenant_id: "corp-default", scope: "location", scope_value: "loc-cloud", name: "Database replication", process_path: "/usr/lib/postgresql/16/bin/postgres", dst_ip_range: "172.16.10.0/24", port: 5432, protocol: "tcp", reason: "Intra-VPC replication", active: true, created_at: "2026-08-21T10:00:00Z" }
      ],
      "/api/v1/threatintel/iocs": [
        { id: "ioc-01", value: "185.220.101.5", type: "ipv4", source: "feodo", threat_type: "c2", confidence: 90, active: true, created_at: mins(180), last_seen_at: mins(12) },
        { id: "ioc-02", value: "194.26.29.114", type: "ipv4", source: "emerging_threats", threat_type: "c2", confidence: 85, active: true, created_at: mins(240), last_seen_at: mins(40) },
        { id: "ioc-03", value: "xj829vbnpqlmz019.xyz", type: "domain", source: "custom", threat_type: "c2", confidence: 95, active: true, created_at: mins(6), last_seen_at: mins(4) },
        { id: "ioc-04", value: "198.51.100.0/24", type: "cidr", source: "emerging_threats", threat_type: "scanner", confidence: 70, active: true, created_at: mins(600), last_seen_at: mins(90) }
      ],
      "/api/v1/audit/logs": [
        { id: "a-1", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "ISOLATE_HOST", resource: "win11-corp-exec", details: "Auto-isolated by detector: active threat-intel destination", ip_address: "10.0.4.58", timestamp: mins(4) },
        { id: "a-2", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "MESH_QUARANTINE", resource: "10.0.4.99", details: "Metasploit listener on 4444", ip_address: "10.0.4.58", timestamp: mins(22) },
        { id: "a-3", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "SYNC_TI", resource: "threatintel", details: "4 indicators refreshed from 3 feeds", ip_address: "10.0.4.58", timestamp: mins(60) },
      ],
      "/api/v1/events": [
        { id: 9001, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(4), layer: "ALE_AUTH_CONNECT", action: "BLOCK", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "198.51.100.22", src_port: 52140, dst_port: 443, bytes_in: 0, bytes_out: 1240, country: "NL", process_path: "powershell.exe", process_id: 4812, domain: "xj829vbnpqlmz019.xyz" },
        { id: 9003, tenant_id: "corp-default", endpoint_id: "linux-dmz-web-01", timestamp: mins(2), layer: "linux-socket-v1", action: "PERMIT", direction: "INBOUND", protocol: 6, src_ip: "203.0.113.9", dst_ip: "10.0.4.20", src_port: 44120, dst_port: 443, bytes_in: 8400, bytes_out: 142000, country: "DE", process_path: "/usr/sbin/nginx", process_id: 1220 },
        { id: 9004, tenant_id: "corp-default", endpoint_id: "linux-prod-db-01", timestamp: mins(96), layer: "linux-socket-v1", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "172.16.10.4", dst_ip: "203.0.113.51", src_port: 40122, dst_port: 5432, bytes_in: 210000, bytes_out: 4200000000, country: "US", process_path: "/usr/lib/postgresql/16/bin/postgres", process_id: 780 },
        /* Several retained endpoints reach the same internal services; the
           topology shows that traffic without assigning an identity. */
        { id: 9005, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.10", src_port: 49812, dst_port: 389, bytes_in: 21400, bytes_out: 9200, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9006, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1.2), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.10", src_port: 49813, dst_port: 88, bytes_in: 4100, bytes_out: 2600, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9007, tenant_id: "corp-default", endpoint_id: "win11-branch-kiosk", timestamp: mins(2), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.44", dst_ip: "10.0.4.10", src_port: 51002, dst_port: 445, bytes_in: 812000, bytes_out: 44000, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 1044 },
        { id: 9008, tenant_id: "corp-default", endpoint_id: "win11-fin-11", timestamp: mins(140), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.31", dst_ip: "10.0.4.10", src_port: 50221, dst_port: 135, bytes_in: 9400, bytes_out: 3100, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 998 },
        { id: 9010, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.12", src_port: 49901, dst_port: 88, bytes_in: 8400, bytes_out: 3100, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9011, tenant_id: "corp-default", endpoint_id: "win11-fin-11", timestamp: mins(2.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.31", dst_ip: "10.0.4.12", src_port: 50120, dst_port: 389, bytes_in: 6200, bytes_out: 2400, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 704 },
        { id: 9012, tenant_id: "corp-default", endpoint_id: "win11-branch-kiosk", timestamp: mins(4.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.44", dst_ip: "10.0.4.12", src_port: 51002, dst_port: 135, bytes_in: 3100, bytes_out: 1400, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 988 }
      ],
      "/api/v1/analytics/summary": {
        total_bytes_in: 3120000000, total_bytes_out: 7480000000, total_events: 48210,
        /* The demo stands for a fleet whose collectors can read a byte
           counter, so every flow in it is a measured one. */
        measured_flow_count: 48210,
        total_blocks: 318, total_permits: 47892,
        countries: { US: 31200, DE: 4210, NL: 980, SG: 640, GB: 410 },
        top_processes: {},
        severity_counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 0 },
        enforcement_counts: { "Windows user-mode WFP": 3, "Linux socket collector": 4 },
        bandwidth_timeline: timeline,
        diurnal_baseline: {}, diurnal_live: {},
        top_talkers: talkers,
        geo_stats: [
          { country: "US", country_name: "United States", flow_count: 31200, total_bytes: 6100000000, threat_count: 2 },
          { country: "DE", country_name: "Germany", flow_count: 4210, total_bytes: 820000000, threat_count: 0 },
          { country: "NL", country_name: "Netherlands", flow_count: 980, total_bytes: 41000000, threat_count: 1 },
          { country: "SG", country_name: "Singapore", flow_count: 640, total_bytes: 22000000, threat_count: 0 },
          { country: "GB", country_name: "United Kingdom", flow_count: 410, total_bytes: 18000000, threat_count: 0 }
        ]
      },
      "/api/v1/topology/graph": {
        nodes: topoNodes, edges: topoEdges,
        metrics: {
          total_nodes: topoNodes.length, total_edges: topoEdges.length,
          anomalous_edge_count: 2, managed_nodes_count: endpoints.length,
          unmanaged_nodes_count: topoNodes.length - endpoints.length,
          quiet_nodes_count: topoNodes.filter(function (n) { return n.quiet; }).length,
          total_flow_count: topoEdges.reduce(function (t, e) { return t + e.flow_count; }, 0),
          measured_flow_count: topoEdges.reduce(function (t, e) { return t + e.measured_flows; }, 0),
          window_label: "24h"
        }
      },
    };
  }

  var DEMO_CACHE = null;

  /* The same merge rule the hub applies, so a demo correction visibly wins
     the field the way a live one would. */
  function DEMO_REMERGE(a) {
    var rank = { operator: 3, agent: 2, scan: 1 };
    var best = {};
    arrayOf(a.claims).forEach(function (c) {
      c.winner = false;
      var b = best[c.field];
      if (!b || rank[c.source] > rank[b.source] ||
        (rank[c.source] === rank[b.source] && c.confidence > b.confidence)) best[c.field] = c;
    });
    a.hostname = ""; a.os = ""; a.vendor = ""; a.category = ""; a.role = "";
    a.risk_score = ""; a.role_confidence = 0; a.rationale = "";
    Object.keys(best).forEach(function (f) {
      var c = best[f];
      c.winner = true;
      if (f === "hostname") a.hostname = c.value;
      else if (f === "os") a.os = c.value;
      else if (f === "vendor") a.vendor = c.value;
      else if (f === "category") a.category = c.value;
      else if (f === "risk") a.risk_score = c.value;
      else if (f === "role") { a.role = c.value; a.role_confidence = c.confidence; a.rationale = c.rationale; }
    });
    return a;
  }

  function demoResponse(path, method, body) {
    if (!DEMO_CACHE) DEMO_CACHE = demoData();
    var base = path.split("?")[0];

    return new Promise(function (resolve) {
      setTimeout(function () {
        if (method && method !== "GET") {
          resolve(demoMutate(base, body));
          return;
        }
        if (base === "/api/v1/baseline/endpoint") {
          resolve(demoBaselineFor(path));
          return;
        }
        if (base === "/api/v1/detection/tuning") { resolve(demoTuning()); return; }
        /* Learning mode reads answer empty in the demo console: the section
           renders and explains itself rather than throwing on a hub that is
           not there. */
        if (base === "/api/v1/learning/windows") { resolve({ windows: [] }); return; }
        if (base === "/api/v1/learning/proposals") { resolve({ window: "demo-window", proposals: [] }); return; }
        if (base === "/api/v1/scanner/status") { resolve(demoScanStatus(path)); return; }
        var hit = DEMO_CACHE[base];
        if (hit !== undefined) {
          resolve(hit);
          return;
        }
        resolve(base.indexOf("/coverage") >= 0 || base.indexOf("/summary") >= 0 ? {} : []);
      }, 40);
    });
  }

  /* A sweep takes minutes on real hardware, so demo mode runs it on a clock:
     the progress bar fills and the failure path is reachable without a host to
     fail against. */
  var DEMO_JOBS = {};

  /* Demo mode ships one changed threshold, so the "differs from the shipped
     values" line and the restore button are both reachable. */
  var DEMO_TUNING = { beacon_score_threshold: 0.88, warmup_hours: 48 };

  function demoTuning() {
    var defaults = {
      off_hours_start: 22, off_hours_end: 5, off_hours_zone: "Local", off_hours_enabled: true,
      beacon_enabled: true, beacon_min_samples: 12, beacon_min_span_minutes: 10,
      beacon_min_interval_seconds: 5, beacon_max_interval_seconds: 3600,
      beacon_score_threshold: 0.8, beacon_cooldown_minutes: 30,
      first_seen_enabled: true, first_seen_cooldown_minutes: 30,
      bandwidth_enabled: true, bandwidth_cooldown_minutes: 5,
      warmup_hours: 24,
      quiet_processes: ["svchost.exe", "systemd-timesyncd", "ominull-agent"],
      quiet_orgs: ["cloudflare", "microsoft"]
    };
    var t = {};
    Object.keys(defaults).forEach(function (k) { t[k] = defaults[k]; });
    if (DEMO_TUNING) {
      Object.keys(DEMO_TUNING).forEach(function (k) { t[k] = DEMO_TUNING[k]; });
      t.updated_by = "demo@example.invalid";
      t.updated_at = new Date().toISOString();
    }
    return {
      tuning: t, defaults: defaults,
      zone: "Local", window: pad(t.off_hours_start, 2) + ":00-" + pad(t.off_hours_end, 2) + ":00 Local",
      now: pad(new Date().getHours(), 2) + ":" + pad(new Date().getMinutes(), 2)
    };
  }

  function demoScanStatus(path) {
    var id = new URLSearchParams(path.split("?")[1] || "").get("id") || "";
    var job = DEMO_JOBS[id];
    if (!job) return { id: id, status: "failed", subnet: "", progress: 0 };
    var age = (Date.now() - job.started) / 1000;
    var pct = Math.min(100, Math.round((age / 12) * 100));
    return {
      id: id, subnet: job.subnet, profile: job.profile,
      status: pct >= 100 ? "completed" : "running",
      progress: pct,
      total_hosts: 254,
      found_count: Math.round((pct / 100) * 9),
      start_time: new Date(job.started).toISOString(),
      end_time: pct >= 100 ? new Date(job.started + 12000).toISOString() : ""
    };
  }

  /* One demo host reports a resolver nothing covers, so the refusal path and the
     override are both reachable without a live fleet. */
  function demoBaselineFor(path) {
    var id = new URLSearchParams(path.split("?")[1] || "").get("endpoint_id") || "";
    var cloud = id.indexOf("prod-") >= 0;
    /* Read from the live fixture, not the seed, so a policy saved from the
       editor visibly closes the gap the isolate sheet complained about. */
    var held = ((DEMO_CACHE || {})["/api/v1/baseline/policies"] || {}).policies || DEMO_BASELINE_POLICIES;
    var applied = held.filter(function (pl) {
      if (pl.enabled === false) return false;
      if (pl.scope === "global") return true;
      if (pl.scope === "endpoint") return pl.scope_value === id;
      if (pl.scope === "location") return pl.scope_value === (cloud ? "loc-cloud" : "loc-hq");
      return false;
    });
    var rules = [];
    applied.forEach(function (pl) { rules = rules.concat(arrayOf(pl.rules)); });
    var wire = [];
    rules.forEach(function (r) {
      var sp = null;
      DEMO_BASELINE_SERVICES.forEach(function (x) { if (x.service === r.service) sp = x; });
      if (!sp) return;
      arrayOf(sp.ports).forEach(function (pt) {
        if (sp.service === "dhcp" && ((r.destination.indexOf(":") >= 0) !== (pt === 547))) return;
        wire.push({ service: r.service, destination: r.destination, protocol: sp.protocol, port: pt });
      });
    });
    var observed = cloud
      ? [{ service: "dns", destination: "172.16.0.2", source: "resolv.conf" },
         { service: "dns", destination: "1.1.1.1", source: "resolv.conf" },
         { service: "ntp", destination: "169.254.169.123", source: "timesyncd" }]
      : [{ service: "dns", destination: "10.0.4.10", source: "resolv.conf" },
         { service: "dhcp", destination: "10.0.4.1", source: "dhcp lease" }];
    var covered = {};
    rules.forEach(function (r) { covered[r.service + "|" + r.destination] = true; });
    var uncovered = observed.filter(function (o) { return !covered[o.service + "|" + o.destination]; });
    return {
      resolution: {
        endpoint_id: id, rules: rules,
        policies: applied.map(function (pl) { return pl.name || pl.id; }),
        observed: observed, uncovered: uncovered,
        readiness: {
          enforcement_engine: "ok", hub_literal: "10.0.4.2", address_origin: "dhcp",
          last_applied: "clear", reported_at: new Date().toISOString()
        },
        readiness_reported: true
      },
      wire: wire,
      ready: uncovered.length === 0,
      blocker: uncovered.length
        ? "The baseline does not cover services this host is actually using: " +
          uncovered.map(function (u) { return u.service + " to " + u.destination; }).join(", ") +
          ". Isolating it would cut those off. Add them to a baseline policy, or override deliberately."
        : "",
      warning: "",
      always_permitted: [
        { what: "hub pinhole", why: "the only path by which this isolation can be lifted" },
        { what: "loopback", why: "local software talking to itself" }
      ]
    };
  }

  /* Demo writes mutate the fixture so an isolate or an acknowledge visibly
     lands, the same way it would against a live hub. */
  /* The demo installer is a real-shaped script with a demonstrably fake code,
     so the copy and download buttons can be exercised without minting a live
     enrollment profile. */
  function demoInstaller(body) {
    var plat = body.platform || "linux";
    var host = "https://hub.demo.invalid:9443";
    var spec = {
      linux: {
        file: "ominull-install.sh",
        one: "curl -fsSL '" + host + "/bootstrap.sh' | sudo bash",
        script: "#!/bin/bash\n# Ominull Linux installer (demo mode - installs nothing)\n"
          + "curl -fsSL '" + host + "/bootstrap.sh' | sudo bash\n"
      },
      windows: {
        file: "ominull-install.ps1",
        one: "iwr -UseBasicParsing '" + host + "/bootstrap.ps1' | iex",
        script: "# Ominull Windows PowerShell installer (demo mode - installs nothing)\n"
          + "$HubURL = '" + host + "'\nWrite-Host 'Demo only'\n"
      }
    }[plat] || {};
    var out = {
      platform: plat,
      filename: spec.file,
      script: spec.script,
      profile_id: "enr_demo",
      expires_in: body.kind === "deployment" ? "until revoked" : "30 minutes",
      note: "Demo mode: nothing was minted and this script will not enroll anything."
    };
    out.enrollment_code = "one-demo-code";
    if (body.one_liner) { out.one_liner = spec.one; out.one_liner_expires_in = "30 minutes"; }
    return out;
  }

  function demoMutate(base, body) {
    var eps = DEMO_CACHE["/api/v1/endpoints"];
    var setIso = function (id, on) {
      eps.forEach(function (e) { if (e.id === id) e.is_isolated = on; });
      DEMO_CACHE["/api/v1/hierarchy"] = demoRebuildHierarchy();
    };
    if (base === "/api/v1/scanner/scan") {
      var sid = "scan-" + Date.now();
      DEMO_JOBS[sid] = { started: Date.now(), subnet: (body && body.subnet) || "10.0.4.0/24", profile: (body && body.profile) || "standard" };
      return { scan_id: sid, status: "started" };
    }
    if (base === "/api/v1/enrolment/script") return demoInstaller(body || {});
    if (base === "/api/v1/detection/tuning") {
      if (body) DEMO_TUNING = body;
      else DEMO_TUNING = null;
      return demoTuning();
    }
    if (base === "/api/v1/endpoints/isolate") { setIso(body && body.endpoint_id, true); return { status: "isolated" }; }
    if (base === "/api/v1/endpoints/unisolate") { setIso(body && body.endpoint_id, false); return { status: "released" }; }
    if (base === "/api/v1/endpoints/isolate-bulk") { arrayOf(body && body.endpoint_ids).forEach(function (id) { setIso(id, true); }); return { status: "isolated" }; }
    if (base === "/api/v1/endpoints/unisolate-bulk") { arrayOf(body && body.endpoint_ids).forEach(function (id) { setIso(id, false); }); return { status: "released" }; }
    if (base === "/api/v1/detection/tuning/suppress") {
      var silenced = (DEMO_CACHE["/api/v1/anomalies"] || []).filter(function (a) { return a.id === (body && body.id); })[0];
      DEMO_CACHE["/api/v1/anomalies"] = DEMO_CACHE["/api/v1/anomalies"].filter(function (a) { return a.id !== (body && body.id); });
      var demoProc = silenced && silenced.process_path
        ? silenced.process_path.split("\\").pop().split("/").pop().toLowerCase()
        : "process";
      return { pair: demoProc + "@example", added: true, acknowledged: body && body.id };
    }
    /* Learning mode in the demo console. The windows list answers empty and
       the write paths answer plausibly, so the section renders and explains
       itself rather than throwing on a hub that is not there. */
    if (base === "/api/v1/learning/windows") {
      return { window: { id: "demo-window", scope_type: (body && body.scope_type) || "endpoint", scope_label: "demo", status: "active", ends_at: new Date(Date.now() + 7 * 86400000).toISOString(), note: (body && body.note) || "" }, open: true };
    }
    if (base === "/api/v1/learning/windows/close") { return { id: body && body.id, status: "completed" }; }
    if (base === "/api/v1/learning/proposals/apply") { return { applied: arrayOf(body && body.ids), skipped: {} }; }
    if (base === "/api/v1/anomalies/acknowledge") {
      DEMO_CACHE["/api/v1/anomalies"] = DEMO_CACHE["/api/v1/anomalies"].filter(function (a) { return a.id !== (body && body.id); });
      return { status: "acknowledged" };
    }
    if (base === "/api/v1/mesh/quarantine") {
      DEMO_CACHE["/api/v1/mesh/quarantined"].push({
        id: "mq-" + Date.now(), target_ip: body && body.target_ip, target_mac: "", subnet: "10.0.4.0/24",
        reason: (body && body.reason) || "Operator action", active: true, created_at: new Date().toISOString()
      });
      return { status: "quarantined" };
    }
    if (base === "/api/v1/mesh/unquarantine") {
      DEMO_CACHE["/api/v1/mesh/quarantined"] = DEMO_CACHE["/api/v1/mesh/quarantined"].filter(function (p) { return p.target_ip !== (body && body.target_ip); });
      return { status: "unquarantined" };
    }
    if (base === "/api/v1/assets/correct") {
      var target = DEMO_CACHE["/api/v1/assets"].filter(function (a) {
        return a.id === (body && body.asset_id) || (body && body.ip && a.ip === body.ip);
      })[0];
      if (target) {
        target.claims = target.claims.filter(function (c) {
          return !(c.source === "operator" && c.field === body.field);
        });
        if (!body.withdraw) {
          target.claims.push({
            field: body.field, source: "operator", value: body.value, confidence: 1.0,
            rationale: body.reason || "operator correction",
            observed_at: new Date().toISOString(), winner: false
          });
        }
        DEMO_REMERGE(target);
      }
      return target || { status: "ok" };
    }
    if (base === "/api/v1/baseline/policies") {
      var saved = DEMO_CACHE["/api/v1/baseline/policies"];
      var incoming = body || {};
      if (!incoming.id) incoming.id = "bp-" + Date.now();
      saved.policies = saved.policies.filter(function (pl) { return pl.id !== incoming.id; }).concat([incoming]);
      return { status: "saved", policy: incoming };
    }
    if (base === "/api/v1/baseline/policies/delete") {
      var held = DEMO_CACHE["/api/v1/baseline/policies"];
      held.policies = held.policies.filter(function (pl) { return pl.id !== (body && body.id); });
      return { status: "deleted" };
    }
    if (base === "/api/v1/baseline/propose") {
      var info = demoBaselineFor("/api/v1/baseline/endpoint?endpoint_id=" + encodeURIComponent((body && body.endpoint_id) || ""));
      return {
        endpoint_id: body && body.endpoint_id,
        rules: arrayOf(info.resolution.observed).map(function (o) { return { service: o.service, destination: o.destination }; }),
        observed: info.resolution.observed,
        suggested_name: "Baseline for " + (body && body.endpoint_id)
      };
    }
    if (base === "/api/v1/scanner/scan") return { scan_id: "scan-demo", status: "running" };
    if (base === "/api/v1/agents/update") {
      return { desired_version: "1.1.0", scheduled: [
        { endpoint_id: "linux-prod-db-01", hostname: "prod-db-01", from: "1.0.0", to: "1.1.0" },
        { endpoint_id: "win11-fin-11", hostname: "corp-win11-fin", from: "1.0.0", to: "1.1.0" }
      ], unsupported: [] };
    }
    return { status: "ok" };
  }

  function demoRebuildHierarchy() {
    var eps = DEMO_CACHE["/api/v1/endpoints"];
    return DEMO_CACHE["/api/v1/hierarchy"].map(function (c) {
      var locs = c.locations.map(function (l) {
        var mine = eps.filter(function (e) { return e.location_id === l.location.id; });
        return { location: l.location, endpoints: mine, total_endpoints: mine.length, isolated_count: mine.filter(function (e) { return e.is_isolated; }).length };
      });
      var all = eps.filter(function (e) { return e.tenant_id === c.tenant.id; });
      return { tenant: c.tenant, locations: locs, total_endpoints: all.length, isolated_count: all.filter(function (e) { return e.is_isolated; }).length };
    });
  }

  /* ---------------------------------------------------------------- toast */

  function toast(message, tone) {
    var box = $("toasts");
    var node = h("div", { cls: "toast", "data-tone": tone || "" }, message);
    box.appendChild(node);
    setTimeout(function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    }, tone === "crit" ? 8000 : 4500);
  }

  /* ---------------------------------------------------------------- theme */

  function applyTheme(name, persist) {
    if (THEMES.indexOf(name) < 0) name = DEFAULT_THEME;
    state.theme = name;
    document.documentElement.setAttribute("data-theme", name);
    if (persist) writeStore("ominull.theme", name);

    /* A live terminal recolours with everything else. The data-theme attribute
       is already on <html> at this point, so the tokens read here are the new
       theme's. */
    if (liveTerminal) {
      try { liveTerminal.options.theme = terminalTheme(); } catch (e) {}
    }
  }

  /* xterm cannot read CSS custom properties, so its palette has to be handed
     to it as literal colours. It was a hardcoded GitHub-dark set maintained in
     two places that had to be kept in sync by hand - here and 25 !important
     rules in app.css - and it ignored all four of the console's themes, so a
     Phosphor operator got a blue-black rectangle in the middle of a green
     console. These read the real tokens off the document, so there is one
     source of truth and a theme switch can re-derive them.

     ANSI 0-15 are not tokens and should not be: the console's own palette is
     four hues reserved for asset state, while a shell needs sixteen
     distinguishable colours for other people's programs. They are derived
     from the console's semantic tokens where one exists and are fixed,
     theme-independent values otherwise. */
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    v = (v || "").trim();
    return v || fallback;
  }

  /* xterm's palette. Every colour comes from a --term-* token in app.css, so
   * the emulator, the .terminal-container fallback rules and the four themes
   * are one definition instead of three that drifted. applyTheme re-derives
   * this for a live terminal, so switching theme with a shell open recolours
   * it in place rather than leaving a blue-black rectangle behind. */
  function terminalTheme() {
    function ansi(n, fallback) { return cssVar("--term-ansi-" + n, fallback); }
    var bg = cssVar("--term-bg", "#14161A");
    var fg = cssVar("--term-fg", "#DADDE3");
    return {
      background: bg,
      foreground: fg,
      cursor: cssVar("--brand", "#8FA9E8"),
      cursorAccent: bg,
      selectionBackground: cssVar("--raised", "#22262E"),
      black: ansi(0, "#2C313A"),
      red: ansi(1, "#CD7670"),
      green: ansi(2, "#73B87D"),
      yellow: ansi(3, "#E6BE6D"),
      blue: ansi(4, "#689BDB"),
      magenta: ansi(5, "#BC8CFF"),
      cyan: ansi(6, "#39C5CF"),
      white: ansi(7, "#949BA8"),
      brightBlack: ansi(8, "#878E9B"),
      brightRed: ansi(9, "#D35A55"),
      brightGreen: ansi(10, "#8FD48F"),
      brightYellow: ansi(11, "#F0CE84"),
      brightBlue: ansi(12, "#8FA9E8"),
      brightMagenta: ansi(13, "#D2A8FF"),
      brightCyan: ansi(14, "#6FDDE4"),
      brightWhite: ansi(15, "#DADDE3")
    };
  }

  /* The live terminal, if one is open. applyTheme re-colours it in place. */
  var liveTerminal = null;

  /* ------------------------------------------------------- asset merging */

  var STATE_ONLINE = { tone: "ok", glyph: "g-online", word: "Online" };
  var STATE_OFFLINE = { tone: "idle", glyph: "g-offline", word: "Offline" };
  var STATE_QUARANTINED = { tone: "crit", glyph: "g-quarantine", word: "Quarantined" };
  var STATE_NOAGENT = { tone: "warn", glyph: "g-watch", word: "No agent" };
  var STATE_SILENT = { tone: "idle", glyph: "g-unknown", word: "Silent" };

  function endpointOnline(ep) {
    if (ep.status === "online") return true;
    var t = parseTime(ep.last_seen_at);
    return !!t && (Date.now() - t.getTime()) < 30000;
  }

  /* The asset row an endpoint id belongs to.

     Asset ids are `asset-<kind>-<safe>` with kind in {mac, ip} - identity keys
     on the hardware address so a host keeps one row across a DHCP lease change
     (storage/assets.go). Three call sites indexed `state.assetByKey` by the
     endpoint id directly, or by a hand-built "asset-ep-<id>" that is not a
     shape the hub ever emits, so they always missed: the Alerts page's
     "Isolate Endpoint" - the primary containment action there - could only
     ever answer "Asset mapping not found". There is no index by endpoint id,
     so this walks; the map is one row per host and the walk is bounded by the
     fleet, not by traffic. */
  function assetForEndpoint(epId) {
    if (!epId) return null;
    for (var k in state.assetByKey) {
      if (!Object.prototype.hasOwnProperty.call(state.assetByKey, k)) continue;
      var a = state.assetByKey[k];
      if (a && a.endpoint && a.endpoint.id === epId) return a;
    }
    return null;
  }

  /* Same question asked from an alert, which may carry a hostname and no id. */
  function assetForAlert(a) {
    if (!a) return null;
    var found = assetForEndpoint(a.endpoint_id);
    if (found) return found;
    if (!a.hostname) return null;
    for (var k in state.assetByKey) {
      if (!Object.prototype.hasOwnProperty.call(state.assetByKey, k)) continue;
      var asset = state.assetByKey[k];
      if (asset && asset.name && asset.name === a.hostname) return asset;
    }
    return null;
  }

  /* One row per host, from the server's asset graph.

     Pass 1 merged endpoints and scan results here in the browser, which meant
     the console's idea of a host and the hub's idea of a host could differ.
     The merge now happens once, in the store, against a persisted assets
     table; this function only decorates the result with the things that are
     genuinely presentational - the client and location names, the live agent
     status, and the mesh state. */
  function bestClaim(asset, field, source) {
    var found = null;
    arrayOf(asset.claims).forEach(function (c) {
      if (c.field !== field || (source && c.source !== source)) return;
      if (!found || (c.confidence || 0) > (found.confidence || 0)) found = c;
    });
    return found;
  }

  function claimGrade(claim) {
    if (!claim) return false;
    return (claim.confidence || 0) >= 0.6 ? "full" : "partial";
  }

  function evidenceOf(a) {
    var scanClaim = null;
    arrayOf(a.claims).forEach(function (c) {
      if (c.source === "scan" && (!scanClaim || (c.confidence || 0) > (scanClaim.confidence || 0))) scanClaim = c;
    });
    return {
      agent: !!a.agent_endpoint_id,
      scan: claimGrade(scanClaim),
      operator: !!bestClaim(a, "role", "operator") || !!bestClaim(a, "category", "operator")
    };
  }

  function buildAssets() {
    var epById = {};
    arrayOf(state.endpoints).forEach(function (ep) { epById[ep.id] = ep; });

    var scanByIP = {};
    arrayOf(state.scanAssets).forEach(function (a) { if (a.ip) scanByIP[a.ip] = a; });

    var locationOf = {};
    var tenantOf = {};
    arrayOf(state.hierarchy).forEach(function (c) {
      arrayOf(c.locations).forEach(function (l) {
        locationOf[l.location.id] = l.location;
        tenantOf[l.location.id] = c.tenant;
      });
    });

    var meshByIP = {};
    arrayOf(state.meshPeers).forEach(function (p) {
      if (p.active !== false) meshByIP[p.target_ip] = p;
    });

    var latest = (state.updateStatus && state.updateStatus.latest_version) || "";
    var graph = arrayOf(state.assetGraph);
    if (!graph.length) graph = legacyAssetGraph();

    var rows = graph.map(function (a) {
      var ep = a.agent_endpoint_id ? epById[a.agent_endpoint_id] : null;
      var loc = ep ? locationOf[ep.location_id] : null;
      var ten = ep ? tenantOf[ep.location_id] : null;
      var ev = evidenceOf(a);

      var seen = parseTime(a.last_seen_at);
      var online = ep ? endpointOnline(ep) : false;
      var quiet = !seen || (Date.now() - seen.getTime()) > 3600000;

      var st;
      if (ep) st = ep.is_isolated ? STATE_QUARANTINED : (online ? STATE_ONLINE : STATE_OFFLINE);
      else st = quiet ? STATE_SILENT : STATE_NOAGENT;

      var roleClaim = bestClaim(a, "role");
      var identityBits = [];
      if (a.os && a.os.toLowerCase() !== "discovered" && a.os.toLowerCase() !== "unidentified") {
        identityBits.push(a.os);
      }
      var descriptor = a.category || a.role;
      if (descriptor && descriptor.toLowerCase() !== "discovered" && descriptor.toLowerCase() !== "unclassified" && identityBits.indexOf(descriptor) === -1) {
        identityBits.push(descriptor);
      }
      if (!identityBits.length) {
        identityBits.push(ep ? "Managed Host" : "Unmanaged Host");
      }

      return {
        key: a.id,
        assetId: a.id,
        name: a.hostname || a.ip || a.id,
        ip: a.ip || "",
        mac: a.mac || "",
        vendor: a.vendor || "",
        identity: identityBits.join(" \u00b7 "),
        tenantId: a.tenant_id || "",
        tenantName: ten ? ten.name : (ep ? (ep.tenant_id || "Unassigned") : "Unassigned"),
        locationId: a.location_id || "",
        locationName: ep ? (ep.location_name || (loc ? loc.name : "Unassigned"))
          : "Unassigned Devices",
        subnet: a.subnet || (loc ? loc.subnet_cidr : ""),
        evidence: ev,
        endpoint: ep,
        scan: scanByIP[a.ip] || null,
        claims: arrayOf(a.claims),
        role: a.role || "",
        roleConf: Number(a.role_confidence) || 0,
        rationale: a.rationale || "",
        roleSource: roleClaim ? roleClaim.source : "",
        state: st,
        online: online,
        isolated: !!(ep && ep.is_isolated),
        meshed: !!meshByIP[a.ip],
        stale: !!(ep && latest && versionLess(ep.driver_version, latest)),
        ports: arrayOf(a.ports),
        risk: a.risk_score || "",
        lastSeen: ep ? (parseTime(ep.last_seen_at) || seen) : seen
      };
    });

    rows.forEach(function (r) {
      r.sortKey = addressSortKey(r.ip) + "|" + r.key;
      r.riskyPorts = r.ports.filter(function (p) {
        return p.risk_level === "HIGH" || p.risk_level === "CRITICAL";
      }).length;
      r.groupKey = r.tenantName + " \u203a " + r.locationName;
      r.searchText = [r.name, r.ip, r.mac, r.identity, r.role, r.tenantName, r.locationName, r.key]
        .join(" ").toLowerCase();
    });

    /* Stable identity ordering. last_seen_at is deliberately not consulted:
       rows that reshuffle under the cursor make an isolate click hit the wrong
       host, and that has already cost this project time once. */
    rows.sort(function (a, b) {
      if (a.groupKey !== b.groupKey) return a.groupKey < b.groupKey ? -1 : 1;
      return a.sortKey < b.sortKey ? -1 : (a.sortKey > b.sortKey ? 1 : 0);
    });

    state.assets = rows;
    state.assetByKey = {};
    rows.forEach(function (r) { state.assetByKey[r.key] = r; });
  }

  /* A hub older than this console has no /api/v1/assets. Rather than render
     an empty fleet during a rolling upgrade, synthesise the same shape from
     the two sources Pass 1 used. */
  function legacyAssetGraph() {
    var out = [];
    var used = {};
    var scanByIP = {};
    var scanByEndpoint = {};
    arrayOf(state.scanAssets).forEach(function (a) {
      if (a.ip) scanByIP[a.ip] = a;
      if (a.agent_endpoint_id) scanByEndpoint[a.agent_endpoint_id] = a;
    });

    arrayOf(state.endpoints).forEach(function (ep) {
      var sc = scanByEndpoint[ep.id] || scanByIP[ep.ip] || null;
      if (sc) used[sc.ip] = true;
      var claims = [{ field: "os", source: "agent", value: ep.os || "", confidence: 1, winner: true }];
      if (sc && sc.os_guess) claims.push({ field: "os", source: "scan", value: sc.os_guess, confidence: Number(sc.confidence) || 0, winner: false });
      out.push({
        id: ep.id, agent_endpoint_id: ep.id, ip: ep.ip || "", mac: ep.mac || "",
        hostname: ep.hostname, os: ep.os, vendor: sc ? sc.vendor : "", category: ep.role_tag,
        role: ep.role_tag, risk_score: sc ? sc.risk_score : "", tenant_id: ep.tenant_id,
        location_id: ep.location_id, last_seen_at: ep.last_seen_at,
        ports: sc ? arrayOf(sc.open_ports) : [], claims: claims
      });
    });

    arrayOf(state.scanAssets).forEach(function (a) {
      if (used[a.ip]) return;
      out.push({
        id: "ip:" + a.ip, agent_endpoint_id: "", ip: a.ip, mac: a.mac || "",
        hostname: a.hostname, os: a.os_guess, vendor: a.vendor, category: a.category,
        role: "", risk_score: a.risk_score, tenant_id: "", location_id: "",
        last_seen_at: a.last_seen, ports: arrayOf(a.open_ports),
        claims: [{ field: "os", source: "scan", value: a.os_guess || "", confidence: Number(a.confidence) || 0, winner: true }]
      });
    });
    return out;
  }

  /* -------------------------------------------------------------- filters */

  var FILTERS = {
    agented: { label: "Agented", test: function (a) { return a.evidence.agent; } },
    noagent: { label: "No agent", test: function (a) { return !a.evidence.agent; } },
    quarantined: { label: "Quarantined", test: function (a) { return a.isolated || a.meshed; } },
    outdated: { label: "Agent outdated", test: function (a) { return a.stale; } },
    risky: { label: "Risky ports", test: function (a) { return a.riskyPorts > 0; } },
    keyonly: { label: "Key only, no cert", test: function (a) { return a.evidence.agent && !(a.endpoint && a.endpoint.cert_cn); } },
    offline: { label: "Offline", test: function (a) { return a.evidence.agent && !a.online; } }
  };

  function activeFilters() {
    return Object.keys(state.filters).filter(function (k) { return state.filters[k]; });
  }

  function visibleAssets() {
    var active = activeFilters();
    var q = state.query.trim().toLowerCase();
    return state.assets.filter(function (a) {
      for (var i = 0; i < active.length; i++) {
        var f = FILTERS[active[i]];
        if (f && !f.test(a)) return false;
      }
      if (q && a.searchText.indexOf(q) < 0) return false;
      return true;
    });
  }

  /* ---------------------------------------------------------------- stats */

  function assetStats() {
    var a = state.assets;
    var count = function (fn) { return a.filter(fn).length; };
    return {
      total: a.length,
      agented: count(function (x) { return x.evidence.agent; }),
      noagent: count(function (x) { return !x.evidence.agent; }),
      quarantined: count(function (x) { return x.isolated || x.meshed; }),
      outdated: count(function (x) { return x.stale; }),
      risky: count(function (x) { return x.riskyPorts > 0; }),
      offline: count(function (x) { return x.evidence.agent && !x.online; }),
      /* A new agent can report with its unique device credential before direct
         native mTLS is enabled. This is the number still missing the extra
         certificate proof before --client-certs required is safe. */
      /* Named to match the filter id and the tile id. It was `keyOnly` while
         both of those are `keyonly`, so `sparkline(state.statHistory[t.id])`
         looked up a key nothing ever wrote and this one tile had no trend. */
      keyonly: count(function (x) { return x.evidence.agent && !(x.endpoint && x.endpoint.cert_cn); })
    };
  }

  /* Keeps a short rolling history per stat so the tile sparkline shows real
     movement rather than a decorative shape. */
  function pushHistory(stats) {
    Object.keys(stats).forEach(function (k) {
      var series = state.statHistory[k] || (state.statHistory[k] = []);
      series.push(stats[k]);
      if (series.length > 12) series.shift();
    });
  }

  /* Scaled to the series' own range, not to zero: a stat that has not moved
     draws a flat low line instead of six full-height bars shouting at an
     operator about nothing happening. */
  function sparkline(values) {
    if (!values || values.length < 2) return null;
    var max = Math.max.apply(null, values);
    var min = Math.min.apply(null, values);
    var span = max - min;
    var n = values.length;
    var svg = s("svg", { "class": "spark", viewBox: "0 0 " + (n * 3) + " 12", preserveAspectRatio: "none", "aria-hidden": "true" });
    values.forEach(function (v, i) {
      var hgt = span > 0 ? Math.max(1, Math.round(2 + ((v - min) / span) * 10)) : 2;
      svg.appendChild(s("rect", {
        "class": i === n - 1 ? "bar-last" : "bar",
        x: i * 3, y: 12 - hgt, width: 2, height: hgt, rx: 0.5
      }));
    });
    return svg;
  }

  function renderStrip() {
    var strip = $("strip");
    clear(strip);

    if (state.section !== "assets") {
      sectionSummary().forEach(function (t) {
        /* Tiles were built for counts. An email address in one ran past its own
           box and into the tile beside it, clipped mid-character. The length
           goes on the element and the stylesheet decides what to do with it -
           a style attribute here would be a size the theme cannot reach. */
        var text = String(t.value);
        strip.appendChild(h("div", {
          cls: "tile", "data-static": "true", "data-tone": t.tone || "",
          "data-len": text.length > 12 ? "long" : "", title: text
        },
          h("div", { cls: "v", text: text }),
          h("div", { cls: "l", text: t.label })));
      });
      return;
    }

    var stats = assetStats();
    var tiles = [
      { id: "", label: "Assets known", value: stats.total, tone: "" },
      { id: "agented", label: "Agented", value: stats.agented, tone: "" },
      { id: "noagent", label: "No agent", value: stats.noagent, tone: stats.noagent ? "warn" : "" },
      { id: "quarantined", label: "Quarantined", value: stats.quarantined, tone: stats.quarantined ? "crit" : "" },
      { id: "outdated", label: "Agent outdated", value: stats.outdated, tone: stats.outdated ? "warn" : "" },
      { id: "keyonly", label: "Key only, no cert", value: stats.keyonly, tone: stats.keyonly ? "warn" : "" },
      { id: "risky", label: "Risky ports", value: stats.risky, tone: stats.risky ? "warn" : "" }
    ];

    tiles.forEach(function (t) {
      var pressed = t.id ? !!state.filters[t.id] : activeFilters().length === 0;
      var tile = h("button", {
        cls: "tile", type: "button", "data-tone": t.tone,
        "aria-pressed": pressed ? "true" : "false",
        title: t.id ? "Filter to " + t.label.toLowerCase() : "Clear filters",
        on: {
          click: function () {
            if (!t.id) state.filters = {};
            else state.filters[t.id] = !state.filters[t.id];
            state.cursorKey = "";
            syncURL(true);
            render();
          }
        }
      },
        h("div", { cls: "v", text: String(t.value) }),
        h("div", { cls: "l", text: t.label }));
      var spark = sparkline(state.statHistory[t.id || "total"]);
      if (spark) tile.appendChild(spark);
      strip.appendChild(tile);
    });
  }

  /* Prefers a location's declared CIDR, falls back to a /24 around a managed
     endpoint's address, and only then to the demo subnet. */
  function suggestedSubnet() {
    var locs = arrayOf(state.locations);
    for (var i = 0; i < locs.length; i++) {
      if (locs[i] && locs[i].subnet_cidr) return locs[i].subnet_cidr;
    }
    for (var j = 0; j < state.assets.length; j++) {
      var ip = state.assets[j].ip || "";
      var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(ip);
      if (m) return m[1] + "." + m[2] + "." + m[3] + ".0/24";
    }
    return "10.0.4.0/24";
  }

  function sectionSummary() {
    var stats = assetStats();
    if (state.section === "discovery") {
      var cov = state.coverage || {};
      var covered = (cov.total_discovered !== undefined ? cov.total_discovered : state.scanAssets.length) > 0;
      return [
        /* Every figure here is scoped to the sweep. Before one has run they are
           undefined rather than zero, and an em dash says so - "0 managed"
           beside an Assets view reporting four is just wrong. */
        { label: "Discovered", value: String(covered ? cov.total_discovered : 0) },
        { label: "Managed", value: covered ? String(cov.total_managed || 0) : "\u2014" },
        { label: "Unmanaged", value: covered ? String(cov.total_unmanaged || 0) : "\u2014", tone: "warn" },
        { label: "Coverage", value: covered ? pct(cov.coverage_percent) : "\u2014" },
        { label: "Critical risks", value: String(cov.critical_risks || 0), tone: cov.critical_risks ? "crit" : "" }
      ];
    }
    if (state.section === "topology") {
      var m = (state.topology && state.topology.metrics) || {};
      return [
        { label: "Nodes", value: String(m.total_nodes || 0) },
        { label: "Edges", value: String(m.total_edges || 0) },
        { label: "Managed", value: String(m.managed_nodes_count || 0) },
        { label: "Unmanaged", value: String(m.unmanaged_nodes_count || 0), tone: "warn" },
        { label: "Quiet in window", value: String(m.quiet_nodes_count || 0) },
        { label: "Anomalous edges", value: String(m.anomalous_edge_count || 0), tone: m.anomalous_edge_count ? "warn" : "" },
        { label: "Blocked edges", value: String(m.blocked_edge_count || 0), tone: m.blocked_edge_count ? "warn" : "" },
        /* Volume is only as real as the share of flows that carried a byte
           count. Reporting it beside the graph keeps every figure on the page
           readable as what it is. */
        measuredStat(m)
      ];
    }
    if (state.section === "traffic") {
      var ov = state.trafficOverview || {};
      var tot = ov.totals || {};
      var totalFlows = ov.total_flows || tot.flow_count || 0;
      var measuredFlows = ov.measured_flows || 0;
      var permits = totalFlows - (tot.block_count || 0);
      if (permits < 0) permits = 0;
      return [
        { label: "Events", value: String(totalFlows) },
        { label: "Blocked", value: String(tot.block_count || 0), tone: tot.block_count ? "crit" : "" },
        { label: "Permitted", value: String(permits) },
        { label: "Bytes in", value: bytes(tot.bytes_in) },
        { label: "Bytes out", value: bytes(tot.bytes_out) },
        measuredStat({ total_flow_count: totalFlows, measured_flow_count: measuredFlows })
      ];
    }
    if (state.section === "policy") {
      return [
        { label: "Baseline policies", value: String(state.baselinePolicies.length) },
        { label: "Baseline services", value: String(state.baselineServices.length) },
        { label: "Exclusions", value: String(state.exclusions.length) },
        /* The hub returns at most IOC_PAGE indicators; the tile said 200 whether
           the feeds held 200 or 200,000. */
        { label: "Indicators", value: capped(state.iocs.length, IOC_PAGE) },
        { label: "Mesh quarantined", value: String(state.meshPeers.length), tone: state.meshPeers.length ? "crit" : "" },
        { label: "Isolated hosts", value: String(stats.quarantined), tone: stats.quarantined ? "crit" : "" }
      ];
    }
    if (state.section === "access") {
      var admins = state.operators.filter(function (o) { return o.role === "admin"; }).length;
      return [
        { label: "Operators", value: String(state.operators.length) },
        { label: "Administrators", value: String(admins), tone: admins === 1 ? "warn" : "" },
        { label: "Analysts", value: String(state.operators.filter(function (o) { return o.role === "analyst"; }).length) },
        { label: "Auditors", value: String(state.operators.filter(function (o) { return o.role === "auditor"; }).length) },
        { label: "Signed in as", value: state.you || OPERATOR || "admin key" },
        { label: "Assets known", value: String(stats.total) }
      ];
    }
    if (state.section === "audit") {
      return [
        { label: "Audit entries", value: String(state.audit.length) },
        /* These two are pages, not totals - the hub returns at most EVENT_PAGE
           events and ANOMALY_PAGE alerts. Rendering the page size as a count
           made a busy fleet and a quiet one read identically at 100. */
        { label: "Recent events", value: capped(state.events.length, EVENT_PAGE) },
        { label: "Open alerts", value: capped(state.anomalies.length, ANOMALY_PAGE), tone: state.anomalies.length ? "warn" : "" },
        /* Blocked flows comes from the analytics summary, which counts them
           all; counting BLOCKs inside the page would have reported at most the
           page size no matter how many there were. */
        { label: "Blocked flows", value: String((state.analytics && state.analytics.total_blocks) || 0), tone: (state.analytics && state.analytics.total_blocks) ? "crit" : "" },
        { label: "Assets known", value: String(stats.total) },
        { label: "Agented", value: String(stats.agented) }
      ];
    }
    return [];
  }

  /* --------------------------------------------------------- context menu */

  var ctxMenu = null;

  function closeCtx() {
    var opener = ctxMenu && ctxMenu._opener;
    if (ctxMenu && ctxMenu._keys) document.removeEventListener("keydown", ctxMenu._keys, true);
    if (ctxMenu && ctxMenu.parentNode) ctxMenu.parentNode.removeChild(ctxMenu);
    ctxMenu = null;
    Array.prototype.forEach.call(document.querySelectorAll('.menu-btn[aria-expanded="true"]'), function (b) {
      b.setAttribute("aria-expanded", "false");
    });
    restoreFocus(opener);
  }

  /* role="menu" promises arrow-key navigation; this one had none, no initial
     focus, no trap and no way to open it from the keyboard at all - every
     per-host action in the console was mouse-only. */
  function wireMenuKeys(menu) {
    var items = function () {
      return Array.prototype.filter.call(menu.querySelectorAll('[role="menuitem"]'), function (b) { return !b.disabled; });
    };
    menu._keys = function (e) {
      var list = items();
      if (!list.length) return;
      var at = list.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); list[(at + 1 + list.length) % list.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); list[(at - 1 + list.length) % list.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); list[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); list[list.length - 1].focus(); }
      else if (e.key === "Tab") { e.preventDefault(); }
      else if (e.key === "Escape") { e.preventDefault(); closeCtx(); }
    };
    document.addEventListener("keydown", menu._keys, true);
    var first = items()[0];
    if (first) { try { first.focus(); } catch (e) {} }
  }

  function menuItem(label, iconId, shortcut, fn, opts) {
    opts = opts || {};
    var btn = h("button", {
      type: "button", role: "menuitem",
      "data-danger": opts.danger ? "true" : null,
      disabled: opts.disabled ? true : null,
      on: {
        click: function () {
          closeCtx();
          if (!opts.disabled) fn();
        }
      }
    }, icon(iconId), h("span", { text: label }));
    if (shortcut) btn.appendChild(h("kbd", { text: shortcut }));
    if (opts.disabled && opts.why) btn.setAttribute("title", opts.why);
    return btn;
  }

  /* Actions live in a contextual menu on the left side of the row */
  function openAssetMenu(asset, x, y, anchorBtn) {
    closeCtx();
    var agent = asset.evidence.agent;
    var menu = h("div", { cls: "ctx", role: "menu" });
    var targetVer = HUB_VERSION || "1.8.1";

    if (agent && asset.endpoint) {
      // ----------------- Agent-managed host menu
      var isOutdated = asset.endpoint.driver_version !== targetVer;
      menu.appendChild(h("div", { cls: "lbl", text: "Managed Host (" + (asset.name || asset.ip) + ")" }));
      menu.appendChild(menuItem("Open full view", "i-external", "\u21b5", function () { openRoute(asset.key); }));
      /* Topology nodes are keyed by address; this set the asset id, which
         matches no node, so a managed host silently opened Topology with
         nothing selected. The unmanaged branch below always had it right. */
      menu.appendChild(menuItem("Show in topology", "i-topology", "g t", function () {
        state.topoSelected = asset.ip;
        go("topology");
      }));
      menu.appendChild(menuItem("Copy IP address", "i-copy", "y", function () { copyAddress(asset); }));

      menu.appendChild(h("div", { cls: "sep" }));
      menu.appendChild(h("div", { cls: "lbl", text: "Agent Operations" }));
      menu.appendChild(menuItem("Upgrade agent to v" + targetVer, "i-refresh", null, function () {
        request("/api/v1/agents/update", "POST", { endpoint_ids: [asset.endpoint.id], version: targetVer })
          .then(function () { toast("Upgrade to v" + targetVer + " queued for " + asset.name, "ok"); refresh(); })
          .catch(function (e) { toast("Upgrade failed: " + e.message, "crit"); });
      }, { disabled: !IS_ADMIN, why: isOutdated ? "Queue upgrade to v" + targetVer : "Already running latest v" + targetVer }));

      menu.appendChild(menuItem("Rescan this host", "i-refresh", "r", function () { rescan(asset); }));

      menu.appendChild(h("div", { cls: "sep" }));
      menu.appendChild(h("div", { cls: "lbl", text: "Containment" }));
      if (asset.isolated) {
        menu.appendChild(menuItem("Release host", "i-unlock", null, function () { setIsolation(asset, false); }));
      } else {
        menu.appendChild(menuItem("Isolate host", "i-lock", "i", function () { setIsolation(asset, true); }, { danger: true }));
      }

      if (asset.meshed) {
        menu.appendChild(menuItem("Release from peer mesh", "i-unlock", null, function () { setMesh(asset, false); }));
      } else {
        menu.appendChild(menuItem("Quarantine via peer mesh", "i-lock", null, function () { setMesh(asset, true); }, { danger: true }));
      }

      menu.appendChild(h("div", { cls: "sep" }));
      menu.appendChild(h("div", { cls: "lbl", text: "Response & Forensics" }));
      /* The icon was i-unlock, which this same menu uses for "Release host" -
         two unrelated actions with one glyph. i-terminal is its own symbol
         now (index.html). */
      var liveShell = liveTerminalFor(asset.endpoint);
      if (liveShell) {
        var elapsed = parseTime(liveShell.started_at || liveShell.created_at);
        var elapsedLabel = elapsed ? " \u00b7 " + ago(elapsed) : "";
        menu.appendChild(menuItem(
          "Reattach Terminal (" + (liveShell.program || "shell") + elapsedLabel + ")",
          "i-terminal", null, function () { reattachTerminal(liveShell); }));
        menu.appendChild(menuItem("Terminate Active Terminal", "i-close", null, function () {
          terminateTerminalSession(liveShell, asset.name || asset.ip);
        }, { danger: true }));
      } else {
        menu.appendChild(menuItem("Launch Terminal Shell\u2026", "i-terminal", null, function () {
          launchTerminalShell(asset);
        }));
      }
      menu.appendChild(menuItem("Collect Forensics\u2026", "i-search", null, function () {
        launchForensicsSheet(asset);
      }));
    } else {
      // ----------------- Unassigned / Discovered asset menu
      menu.appendChild(h("div", { cls: "lbl", text: "Unmanaged Asset (" + (asset.ip || asset.name) + ")" }));
      menu.appendChild(menuItem("Install Ominull agent", "i-download", "d", function () { installAgent(asset); }));
      menu.appendChild(menuItem("Show in topology", "i-topology", "g t", function () {
        state.topoSelected = asset.ip;
        go("topology");
      }));
      menu.appendChild(menuItem("Copy IP address", "i-copy", "y", function () { copyAddress(asset); }));

      menu.appendChild(h("div", { cls: "sep" }));
      menu.appendChild(h("div", { cls: "lbl", text: "Discovery" }));
      menu.appendChild(menuItem("Rescan this host", "i-refresh", "r", function () { rescan(asset); }));
      menu.appendChild(menuItem("Correct fingerprint\u2026", "i-tag", null, function () { correctFingerprint(asset); },
        { disabled: !asset.scan, why: "Needs a scan result to correct" }));

      menu.appendChild(h("div", { cls: "sep" }));
      menu.appendChild(h("div", { cls: "lbl", text: "Containment" }));
      if (asset.meshed) {
        menu.appendChild(menuItem("Release from peer mesh", "i-unlock", null, function () { setMesh(asset, false); }));
      } else {
        menu.appendChild(menuItem("Quarantine via peer mesh", "i-lock", null, function () { setMesh(asset, true); },
          { danger: true, disabled: !asset.ip, why: "Needs an IP address" }));
      }
    }

    document.body.appendChild(menu);
    var r = menu.getBoundingClientRect();
    placeOverlay(menu, Math.max(8, Math.min(x, window.innerWidth - r.width - 8)), Math.min(y, window.innerHeight - r.height - 8));
    ctxMenu = menu;
    menu._opener = anchorBtn || document.activeElement;
    if (anchorBtn) anchorBtn.setAttribute("aria-expanded", "true");
    wireMenuKeys(menu);
  }

  /* --------------------------------------------------------------- actions */

  function copyAddress(asset) {
    var value = asset.ip || asset.name;
    var done = function () { toast("Copied " + value, "ok"); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () { toast("Could not copy \u2014 " + value); });
    } else {
      toast(value);
    }
  }

  function setIsolation(asset, on) {
    if (!asset.endpoint) { toast("No agent on " + asset.name + " \u2014 use mesh quarantine", "warn"); return; }
    /* Isolating asks first. Not for ceremony - the question "what can this host
       still reach once I cut it off" has an answer, and the moment to read it
       is before the cut, not while standing in front of the machine. Releasing
       needs no such screen: it only ever gives access back. */
    if (on) { confirmIsolate(asset); return; }
    request("/api/v1/endpoints/unisolate", "POST", { endpoint_id: asset.endpoint.id }).then(function () {
      toast("Released " + asset.name, "ok");
      refresh();
    }).catch(function (e) { toast("Release failed: " + e.message, "crit"); });
  }

  function doIsolate(asset, force) {
    var body = { endpoint_id: asset.endpoint.id, allow_ips: [] };
    if (force) body.force = true;
    request("/api/v1/endpoints/isolate", "POST", body).then(function () {
      closeSheet();
      toast("Isolated " + asset.name + (force ? " \u2014 readiness overridden" : ""), "crit");
      delete state.baselineByEndpoint[asset.endpoint.id];
      refresh();
    }).catch(function (e) { toast("Isolation failed: " + e.message, "crit"); });
  }

  function confirmIsolate(asset) {
    request("/api/v1/baseline/endpoint?endpoint_id=" + encodeURIComponent(asset.endpoint.id))
      .then(function (info) {
        state.baselineByEndpoint[asset.endpoint.id] = info || {};
        openIsolateSheet(asset, info || {});
      })
      .catch(function (e) { toast("Could not read the baseline: " + e.message, "crit"); });
  }

  function openIsolateSheet(asset, info) {
    var res = info.resolution || {};
    var uncovered = arrayOf(res.uncovered);

    var body = h("div", { cls: "stack" },
      h("p", { cls: "why" },
        h("b", { text: asset.name }),
        document.createTextNode(" keeps only what is listed here. Every other flow, in both directions, stops.")),
      simpleTable(["Permitted", "Destination", "Wire"], wireRows(info.wire, info.always_permitted)),
      uncovered.length
        ? h("div", {},
            h("p", { cls: "note note-crit", role: "alert", text: "This host is using services the baseline does not cover. Isolating it cuts them off." }),
            simpleTable(["Not covered", "Destination"], uncovered.map(function (u) {
              return [h("span", { text: u.service }), h("span", { cls: "ip", text: u.destination })];
            })))
        : null,
      info.blocker && !uncovered.length ? h("p", { cls: "note note-crit", role: "alert", text: info.blocker }) : null,
      info.warning ? h("p", { cls: "note note-warn", role: "alert", text: info.warning }) : null);

    var confirm = info.ready
      ? h("button", { cls: "btn btn-primary", type: "button", text: "Isolate", on: { click: function () { doIsolate(asset, false); } } })
      : h("button", { cls: "btn btn-crit", type: "button", text: "Isolate anyway", on: { click: function () { doIsolate(asset, true); } } });

    var actions = [h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } })];
    if (!info.ready && IS_ADMIN) {
      actions.push(h("button", {
        cls: "btn", type: "button", text: "Fix the baseline",
        on: { click: function () { proposeBaseline(asset); } }
      }));
    }
    actions.push(confirm);

    openSheet("Isolate " + asset.name, body, actions);
  }

  /* The one confirmation shape, taken from openIsolateSheet above: what is
     about to happen, in a sentence a person can act on, and a `btn-crit`
     confirm that is never the focused control.

     Eighteen destructive actions had six different levels of ceremony and
     almost no correlation with blast radius. Removing your own admin access
     was one unconfirmed click while deleting one baseline policy got a full
     consequence sheet; pushing an agent update to the entire fleet, bulk
     isolation, mesh quarantine and clearing a tenant's acknowledged alerts had
     none at all. Everything destructive now comes through here.

     opts:
       title         heading
       consequence   what happens, in plain language - required
       detail        the specific thing being acted on
       extra         an extra node (a list, a reason field)
       confirmLabel  the confirm button's text
       requireText   make the operator type this string first
       confirmTone   "crit" (default) or "primary" for a reversible action
       stack         keep the sheet underneath alive (a live terminal)
       onConfirm     called after the sheet closes */
  function confirmSheet(opts) {
    var typed = null;
    var confirmBtn = h("button", {
      cls: opts.confirmTone === "primary" ? "btn btn-primary" : "btn btn-crit",
      type: "button",
      text: opts.confirmLabel || "Confirm",
      on: {
        click: function () {
          if (opts.requireText && (!typed || typed.value.trim() !== opts.requireText)) return;
          closeSheet();
          if (typeof opts.onConfirm === "function") opts.onConfirm();
        }
      }
    });

    if (opts.requireText) {
      confirmBtn.disabled = true;
      typed = h("input", {
        type: "text", autocomplete: "off", spellcheck: "false",
        "aria-label": "Type " + opts.requireText + " to confirm",
        placeholder: opts.requireText
      });
      typed.addEventListener("input", function () {
        confirmBtn.disabled = typed.value.trim() !== opts.requireText;
      });
    }

    var body = h("div", { cls: "stack" },
      h("p", { cls: "note note-crit", role: "alert", text: opts.consequence }),
      opts.detail ? h("p", { cls: "why", text: opts.detail }) : null,
      opts.extra || null,
      typed ? h("div", { cls: "form-row stack-s" },
        h("span", { cls: "dim-2", text: "Type " + opts.requireText + " to confirm:" }),
        typed) : null);

    openSheet(opts.title || "Confirm", body, [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      confirmBtn
    ], opts.cls || null, {
      stack: !!opts.stack,
      guardDirty: false,
      /* Never the confirm button. openSheet's old heuristic focused the first
         `input, select, button.btn-primary` it found, which in the isolate
         sheet was the Isolate button - one Space from cutting a host off. */
      initialFocus: typed || false
    });
  }

  /* The console's replacement for window.prompt(). The native one cannot be
     styled, cannot be labelled beyond one line, blocks the whole tab, and on
     a second monitor opens where the browser feels like rather than where the
     operator is looking. */
  function promptSheet(opts) {
    var field = h("input", {
      type: "text", autocomplete: "off", spellcheck: "false",
      "aria-label": opts.label || opts.title || "Value",
      placeholder: opts.placeholder || "",
      value: opts.value == null ? "" : String(opts.value)
    });

    var submit = function () {
      var v = field.value.trim();
      if (!v) return;
      closeSheet();
      if (typeof opts.onSubmit === "function") opts.onSubmit(v);
    };
    field.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); submit(); }
    });

    var body = h("div", { cls: "stack" },
      opts.detail ? h("p", { cls: "why", text: opts.detail }) : null,
      h("label", { cls: "field" },
        h("span", { text: opts.label || "Value" }),
        field));

    openSheet(opts.title || "Enter a value", body, [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      h("button", { cls: "btn btn-primary", type: "button", text: opts.submitLabel || "Save", on: { click: submit } })
    ], opts.cls || null, { stack: !!opts.stack, guardDirty: false, initialFocus: field });
  }

  function setMesh(asset, on) {
    if (!asset.ip) { toast("No address for " + asset.name, "warn"); return; }
    /* Mesh quarantine is enforced upstream of the host, so unlike endpoint
       isolation the host itself cannot undo it and cannot tell you it is
       happening - it simply stops reaching the network. It fired straight off
       a menu click with no confirmation at all. */
    if (on) {
      confirmSheet({
        title: "Mesh-quarantine " + (asset.name || asset.ip),
        consequence: asset.ip + " is cut off at the mesh, not on the host. Everything it serves stops answering, and because the block is upstream the machine itself has no way to report or lift it.",
        detail: (asset.mac ? asset.mac + " \u00b7 " : "") + (asset.subnet || "no subnet recorded"),
        confirmLabel: "Quarantine at the mesh",
        onConfirm: function () { sendMesh(asset, true); }
      });
      return;
    }
    sendMesh(asset, false);
  }

  function sendMesh(asset, on) {
    var path = on ? "/api/v1/mesh/quarantine" : "/api/v1/mesh/unquarantine";
    var body = { target_ip: asset.ip };
    if (on) {
      body.target_mac = asset.mac || "";
      body.subnet = asset.subnet || "";
      body.reason = "Operator action from the console";
    }
    request(path, "POST", body).then(function () {
      toast((on ? "Mesh-quarantined " : "Released from mesh: ") + asset.ip, on ? "crit" : "ok");
      refresh();
    }).catch(function (e) { toast("Mesh action failed: " + e.message, "crit"); });
  }

  function rescan(asset) {
    if (!asset.ip) { toast("No address to rescan", "warn"); return; }
    request("/api/v1/scanner/scan", "POST", { subnet: asset.ip + "/32", profile: "standard" })
      .then(function (res) {
        toast("Rescanning " + asset.ip + (res && res.scan_id ? " (" + res.scan_id + ")" : ""), "ok");
        setTimeout(refresh, 2500);
      })
      .catch(function (e) { toast("Rescan failed: " + e.message, "crit"); });
  }

  function correctFingerprint(asset) {
    promptSheet({
      title: "Correct fingerprint",
      label: "Actual device",
      detail: "Teaches the scanner's signature database. " + asset.ip +
        " is currently identified as " + ((asset.scan && asset.scan.os_guess) || "unknown") + ".",
      placeholder: "e.g. Ubiquiti UniFi AP",
      value: asset.scan ? asset.scan.os_guess : "",
      submitLabel: "Train signature",
      onSubmit: function (actual) {
        request("/api/v1/scanner/feedback", "POST", {
          ip: asset.ip, actual_device: actual,
          vendor: asset.scan ? asset.scan.vendor : "",
          category: asset.scan ? asset.scan.category : ""
        }).then(function () {
          toast("Signature trained for " + asset.ip, "ok");
          refresh();
        }).catch(function (e) { toast("Training failed: " + e.message, "crit"); });
      }
    });
  }

  function installAgent(asset) {
    if (asset.evidence.agent) { toast(asset.name + " already runs an agent", "warn"); return; }
    var guessed = osFamily(asset.scan ? asset.scan.os_guess : "");
    if (guessed && guessed !== "linux" && guessed !== "windows") {
      toast("Only Linux and Windows agents are supported", "warn");
      return;
    }
    var platform = guessed === "windows" ? "windows" : "linux";
    openInstallerSheet({ platform: platform });
  }

  function bulkIsolate(on) {
    var keys = selectedKeys();
    var assets = keys.map(function (k) { return state.assetByKey[k]; })
      .filter(function (a) { return a && a.endpoint; });
    var ids = assets.map(function (a) { return a.endpoint.id; });
    if (!ids.length) { toast("Select agented hosts first", "warn"); return; }

    /* Isolating one host asks first. Isolating forty from the toolbar did not
       - the single most consequential control in the console was the one with
       no confirmation. The names are listed because "40 hosts" is not enough
       information to notice that the selection is wrong. */
    if (on) {
      var names = assets.map(function (a) { return a.name || a.ip || a.endpoint.id; });
      confirmSheet({
        title: "Isolate " + ids.length + " host" + (ids.length === 1 ? "" : "s"),
        consequence: "Each host keeps only its link to this hub. Every other inbound and outbound flow is dropped at the agent - sessions, shares, backups, anything that host serves to anyone else stops immediately.",
        detail: names.slice(0, 8).join(", ") + (names.length > 8 ? " and " + (names.length - 8) + " more" : ""),
        confirmLabel: "Isolate " + ids.length + " host" + (ids.length === 1 ? "" : "s"),
        requireText: ids.length >= 5 ? "ISOLATE" : null,
        onConfirm: function () { sendBulkIsolate(ids, true); }
      });
      return;
    }
    sendBulkIsolate(ids, false);
  }

  function sendBulkIsolate(ids, on) {
    var path = on ? "/api/v1/endpoints/isolate-bulk" : "/api/v1/endpoints/unisolate-bulk";
    var send = function (force) {
      var body = { endpoint_ids: ids };
      if (on) { body.allow_ips = []; }
      if (force) body.force = true;
      return request(path, "POST", body).then(function () {
        closeSheet();
        toast((on ? "Isolated " : "Released ") + ids.length + " host" + (ids.length === 1 ? "" : "s"), on ? "crit" : "ok");
        state.baselineByEndpoint = {};
        refresh();
      });
    };
    send(false).catch(function (e) {
      /* The gate refuses the whole batch on one unready host, and says which.
         A toast would leave the operator guessing which of forty it was. */
      if (e.status === 409 && e.body) { openBulkBlockedSheet(ids, e.body, send); return; }
      toast("Bulk action failed: " + e.message, "crit");
    });
  }

  function openBulkBlockedSheet(ids, info, send) {
    var uncovered = arrayOf(info.uncovered);
    var body = h("div", { cls: "stack" },
      h("p", { cls: "note note-crit", role: "alert", text: info.error || "One of the selected hosts is not ready to be isolated." }),
      h("p", { cls: "pending", text: "Blocked on " + (info.endpoint_id || "an endpoint") + ". Nothing has been isolated." }),
      uncovered.length
        ? simpleTable(["Not covered", "Destination"], uncovered.map(function (u) {
            return [h("span", { text: u.service }), h("span", { cls: "ip", text: u.destination })];
          }))
        : null,
      h("p", { cls: "pending", text: "Isolating anyway applies to all " + ids.length + " selected host" + (ids.length === 1 ? "" : "s") + " and is recorded as an override." }));

    openSheet("Isolation refused", body, [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-crit", type: "button", text: "Isolate anyway",
        on: {
          click: function () {
            send(true).catch(function (e2) { toast("Bulk action failed: " + e2.message, "crit"); });
          }
        }
      })
    ]);
  }

  function pushAgentUpdates() {
    /* One click queued a self-update on every agent in the fleet. An agent
       that restarts into a broken build takes its host's enforcement with it,
       and there is no console-side undo. */
    confirmSheet({
      title: "Push agent updates to the whole fleet",
      consequence: "Every enrolled agent that supports self-update downloads the bundled build and restarts. Enforcement on each host is briefly down during the restart, and an agent that fails to come back has to be recovered on the host itself.",
      detail: "Hosts on native packages are skipped and reported instead.",
      confirmLabel: "Push updates",
      onConfirm: sendAgentUpdates
    });
  }

  function sendAgentUpdates() {
    request("/api/v1/agents/update", "POST", { all: true }).then(function (res) {
      var n = arrayOf(res && res.scheduled).length;
      var u = arrayOf(res && res.unsupported).length;
      toast("Queued " + n + " self-update" + (n === 1 ? "" : "s") +
        (u ? "; " + u + " need native package enrollment" : ""), n ? "ok" : "warn");
      refresh();
    }).catch(function (e) { toast("Update push failed: " + e.message, "crit"); });
  }

  /* ---------------------------------------------------------- assets view */

  function evidenceStrip(asset) {
    var wrap = h("span", {
      cls: "ev",
      title: "Known by \u2014 agent: " + (asset.evidence.agent ? "yes" : "no") +
        ", scan: " + (asset.evidence.scan || "no")
    });
    wrap.appendChild(h("i", { "data-on": asset.evidence.agent ? "agent" : null }));
    wrap.appendChild(h("i", { "data-on": asset.evidence.scan ? "scan" : null }));
    return wrap;
  }

  function stateBadge(st) {
    return h("span", { cls: "st", "data-state": st.tone }, icon(st.glyph, true), h("span", { text: st.word }));
  }

  /* The sections built after the core were written against a `.badge` /
     `.badge-ok` vocabulary that has no rules in app.css at all, so every state
     chip in Response, Terminal, Scripts and Forensics rendered as unstyled grey
     body text - "collected" and "permission_denied" evidence looked identical.
     `.st[data-state]` is the console's one state chip: a 3px stripe plus a word,
     never colour alone. chip() builds one; setChip() is for the few places that
     reassign className on a node they already hold. Tones map straight across
     (ok/warn/crit) and the old `badge-neutral`/bare `badge` become `idle`. */
  function chip(tone, text) {
    return h("span", { cls: "st", "data-state": tone || "idle" }, h("span", { text: String(text == null ? "" : text) }));
  }

  /* A terminal session's state as a chip tone. `detached` is a running shell
     with nobody watching it - warn, not crit: nothing is broken, but it is
     holding an endpoint's one session slot and burning its 60m budget. */
  function terminalStateTone(st) {
    if (st === "active") return "ok";
    if (st === "detached") return "warn";
    if (st === "waiting" || st === "connecting") return "info";
    if (st === "failed" || st === "expired") return "crit";
    return "idle";
  }

  function setChip(el, tone, text) {
    if (!el) return el;
    el.className = "st";
    el.setAttribute("data-state", tone || "idle");
    if (text != null) el.textContent = String(text);
    return el;
  }

  function meter(fraction) {
    var svg = s("svg", { "class": "meter", viewBox: "0 0 110 3", preserveAspectRatio: "none", "aria-hidden": "true" });
    svg.appendChild(s("rect", { "class": "track", x: 0, y: 0, width: 110, height: 3, rx: 1.5 }));
    svg.appendChild(s("rect", { "class": "fill", x: 0, y: 0, width: Math.max(0, Math.min(1, fraction)) * 110, height: 3, rx: 1.5 }));
    return svg;
  }

  function claimRow(source, value, confidence, win) {
    return h("div", { cls: "claim", "data-win": win ? "true" : "false" },
      h("span", { cls: "src", text: source }),
      h("span", { cls: "val", text: value }),
      h("span", { cls: "conf", text: confidence === null ? "" : confidence.toFixed(2) }));
  }

  var FIELD_LABEL = {
    hostname: "Hostname", os: "Operating system", vendor: "Vendor",
    category: "Device class", role: "Role", risk: "Risk"
  };

  /* Every source's opinion, winner first, losers kept. An operator has to be
     able to see that the scanner said one thing and the agent another; a
     merge that silently discards the loser is a merge you cannot audit. */
  function claimsPanel(asset) {
    var wrap = h("div", { cls: "claims" });
    var byField = {};
    var order = [];
    arrayOf(asset.claims).forEach(function (c) {
      if (c.source === "inferred") return;
      if (!byField[c.field]) { byField[c.field] = []; order.push(c.field); }
      byField[c.field].push(c);
    });
    if (!order.length) {
      wrap.appendChild(claimRow("\u2014", "No identity claim yet", null, false));
      return wrap;
    }
    order.sort(function (a, b) {
      var rank = { hostname: 0, os: 1, category: 2, role: 3, vendor: 4, risk: 5 };
      return (rank[a] === undefined ? 9 : rank[a]) - (rank[b] === undefined ? 9 : rank[b]);
    });
    order.forEach(function (field) {
      wrap.appendChild(h("div", { cls: "claim-field", text: FIELD_LABEL[field] || field }));
      byField[field].forEach(function (c) {
        wrap.appendChild(claimRow(c.source, c.value, Number(c.confidence) || 0, !!c.winner));
      });
    });
    return wrap;
  }

  /* Corrections outrank every other source permanently, so they are an
     explicit act with a visible result, not a silent edit. */
  function correctAsset(asset, field, value, reason, withdraw) {
    return request("/api/v1/assets/correct", "POST", {
      asset_id: asset.assetId, ip: asset.ip, field: field,
      value: value, reason: reason, withdraw: !!withdraw
    }).then(function () {
      toast(withdraw ? "Correction withdrawn on " + asset.name
        : "Recorded: " + (FIELD_LABEL[field] || field) + " is " + value, "ok");
      refresh();
    }).catch(function (e) { toast("Correction failed: " + e.message, "crit"); });
  }

  function roleLabel(role) {
    if (!role) return "";
    return role.charAt(0).toUpperCase() + role.slice(1).replace(/-/g, " ");
  }

  function detailRow(asset, colspan) {
    var ep = asset.endpoint;
    var sc = asset.scan;

    var kv = h("dl", { cls: "kv" });
    var addKV = function (k, v, strong) {
      kv.appendChild(h("dt", { text: k }));
      kv.appendChild(h("dd", {}, strong ? h("b", { text: v }) : document.createTextNode(v)));
    };
    addKV("Address", asset.ip || "\u2014", true);
    addKV("MAC / OUI", (asset.mac || "\u2014") + (asset.vendor ? " \u00b7 " + asset.vendor : ""));
    addKV("Identity key", asset.assetId);
    addKV("Client", asset.tenantName);
    addKV("Location", asset.locationName);
    /* The scanner scores every asset and the merge records why it settled on a
       role and how sure it was. All three were computed on every refresh and
       rendered nowhere in Assets: risk surfaced only in Topology's side panel,
       and the confidence behind "Role: Printer" was invisible, so a 44% guess
       and a 99% certainty read identically. */
    if (asset.risk) addKV("Risk", asset.risk, asset.risk === "CRITICAL" || asset.risk === "HIGH");
    if (asset.role) {
      addKV("Role", asset.role + (asset.roleConf ? " \u00b7 " + Math.round(asset.roleConf * 100) + "% confidence" : ""));
    }
    if (asset.rationale) addKV("Why that role", asset.rationale);
    if (ep) {
      addKV("Endpoint id", ep.id);
      addKV("Agent", shortVersion(ep.driver_version) + (engineOf(ep.driver_version) ? " \u00b7 " + engineOf(ep.driver_version) : ""), true);
      if (ep.installed_software) addKV("Software", ep.installed_software);
    } else {
      addKV("Agent", "none \u2014 deployment candidate", true);
    }
    if (sc) {
      addKV("TTL", String(sc.ttl || "\u2014"));
      addKV("App delta", (sc.app_delta_ms || 0) + " ms");
    }

    var identityCol = h("div", {},
      h("h4", { text: "Identity \u2014 merged claims" }),
      claimsPanel(asset),
      kv,
      h("div", { cls: "detail-acts" },
        h("button", {
          cls: "mini", type: "button", text: "Open full asset view",
          on: { click: function (e) { e.stopPropagation(); openRoute(asset.key); } }
        })));

    var ports = h("div", { cls: "portlist" });
    if (asset.ports.length) {
      asset.ports.slice().sort(function (a, b) { return (a.port || 0) - (b.port || 0); }).forEach(function (p) {
        ports.appendChild(h("span", { cls: "port", "data-risk": p.risk_level || "LOW", text: p.port + (p.service ? " " + p.service : "") }));
      });
    } else {
      ports.appendChild(h("span", { cls: "dim-3", text: asset.evidence.scan ? "No open ports observed" : "Not scanned" }));
    }

    var exposureCol = h("div", {}, h("h4", { text: "Observed exposure" }), ports);
    var weak = sc ? arrayOf(sc.weakpoints) : [];
    if (weak.length) {
      var list = h("div", { cls: "why" });
      weak.forEach(function (w) { list.appendChild(h("div", { text: "\u00b7 " + w })); });
      exposureCol.appendChild(h("h4", { text: "Weak points" }));
      exposureCol.appendChild(list);
    }
    if (asset.meshed) {
      exposureCol.appendChild(h("h4", { text: "Mesh" }));
      exposureCol.appendChild(h("div", { cls: "why", text: "Peer mesh is dropping traffic to this address across the subnet." }));
    }

    var whyCol = h("div", {}, h("h4", { text: "Why we think this" }));
    if (ep && asset.evidence.scan) {
      var osScan = bestClaim({ claims: asset.claims }, "os", "scan");
      whyCol.appendChild(h("p", { cls: "why" },
        h("b", { text: "Agent and scan agree on this host." }),
        document.createTextNode(" The agent reports " + (ep.os || "an OS") + " directly; the probe independently fingerprinted " +
          ((osScan && osScan.value) || "the same host") + " at " + ((osScan ? Number(osScan.confidence) : 0) || 0).toFixed(2) + " confidence.")));
      whyCol.appendChild(h("div", { cls: "detail-acts" }, meter((osScan ? Number(osScan.confidence) : 0) || 0)));
    } else if (ep) {
      whyCol.appendChild(h("p", { cls: "why" },
        h("b", { text: "Agent ground truth only." }),
        document.createTextNode(" No scan has covered this address and no flow shape names it, so open ports and the OUI vendor are unknown. Run Discovery over " +
          (asset.subnet || "its subnet") + " to add the second source.")));
    } else if (asset.evidence.scan) {
      var osClaim = bestClaim({ claims: asset.claims }, "os", "scan");
      whyCol.appendChild(h("p", { cls: "why" },
        h("b", { text: "Probe evidence only." }),
        document.createTextNode(" " + ((osClaim && osClaim.value) || "Unidentified") + " at " +
          (((osClaim ? Number(osClaim.confidence) : 0) || 0).toFixed(2)) + " confidence" +
          (sc ? " from TTL " + (sc.ttl || "?") + ", app delta " + (sc.app_delta_ms || 0) + " ms" : "") +
          (asset.vendor ? " and the " + asset.vendor + " OUI" : "") +
          ". Nothing in the last day of traffic gives it a role.")));
      whyCol.appendChild(h("div", { cls: "detail-acts" }, meter(((osClaim ? Number(osClaim.confidence) : 0) || 0))));
    } else {
      whyCol.appendChild(h("p", { cls: "why", text: "Seen, but not yet identified by any source." }));
    }

    /* A live root shell on this host outranks all three columns and must not
       be something you scan sideways for, so it is a full-width banner above
       the grid rather than a fourth column.

       It renders for every operator role - seeing that a shell is open is
       situational awareness, not a privilege - while Reattach and Terminate
       prompt for the response unlock when clicked. */
    var td = h("td", { colspan: String(colspan) },
      h("div", { cls: "stack" }, terminalBanner(asset), h("div", { cls: "detail" }, identityCol, exposureCol, whyCol)));
    return h("tr", { cls: "exp" }, td);
  }

  function terminalBanner(asset) {
    if (!state.terminalAvailable || !asset.endpoint) return null;
    var ep = asset.endpoint;
    var host = asset.name || asset.ip || ep.id;
    var t = liveTerminalFor(ep);

    if (!t) {
      /* No session: one quiet line, not a banner. An absent shell is not news. */
      return h("div", { cls: "term-banner", "data-state": "none" },
        h("span", { cls: "dim-3", text: "No terminal session on this host." }),
        h("span", { cls: "fill" }),
        h("button", {
          cls: "mini", type: "button", text: "Launch Terminal Shell",
          on: { click: function (e) { e.stopPropagation(); launchTerminalShell(asset); } }
        }));
    }

    var isWindows = String(ep.os || "").indexOf("Windows") !== -1;
    var identity = isWindows ? "LocalSystem" : "root";
    var mine = !t.operator_id || t.operator_id === OPERATOR;
    var started = parseTime(t.started_at || t.created_at);

    var tone, word;
    if (t.state === "detached") { tone = "warn"; word = "Detached \u2014 running in background"; }
    else if (t.state === "waiting" || t.state === "connecting") { tone = "info"; word = "Waiting for agent"; }
    else if (mine) { tone = "ok"; word = "Live \u2014 attached"; }
    else { tone = "warn"; word = "Live \u2014 held by another operator"; }

    var facts = h("div", { cls: "term-banner-facts" },
      chip(tone, word),
      h("span", { cls: "ip", text: t.program || (isWindows ? "powershell.exe" : "/bin/bash") }),
      chip("idle", identity),
      h("span", { cls: "dim-2", text: t.operator_id || "unknown operator" }),
      started ? stamp(started) : null);

    var acts = h("div", { cls: "term-banner-acts" });
    /* Another operator's live session is theirs to drive; an administrator can
       still end it, because "somebody left a root shell open and went home" is
       exactly the situation this has to be able to resolve. */
    if (mine || t.state === "detached") {
      acts.appendChild(h("button", {
        cls: "btn mini", type: "button", text: "Reattach Console",
        on: { click: function (e) { e.stopPropagation(); reattachTerminal(t); } }
      }));
    }
    if (mine || IS_ADMIN) {
      acts.appendChild(h("button", {
        cls: "btn mini", type: "button", "data-danger": "true", text: "Terminate Session",
        on: { click: function (e) { e.stopPropagation(); terminateTerminalSession(t, host); } }
      }));
    }

    return h("div", { cls: "term-banner", "data-state": tone }, facts, h("span", { cls: "fill" }), acts);
  }

  /* A glyph on the collapsed row, so an open shell is visible while scanning
     the table rather than only after expanding a host. */
  function terminalRowGlyph(asset) {
    if (!state.terminalAvailable || !asset.endpoint) return null;
    var t = liveTerminalFor(asset.endpoint);
    if (!t) return null;
    var tone = t.state === "detached" ? "warn" : (t.state === "active" ? "ok" : "info");
    var label = t.state === "detached" ? "Terminal session detached and still running" : "Terminal session open";
    return h("span", {
      cls: "term-glyph", "data-state": tone,
      title: label + " \u00b7 " + (t.program || "shell"),
      "aria-label": label
    }, icon("i-terminal", true));
  }

  function assetRow(asset, colspan, index, allRows) {
    var selected = !!state.selected[asset.key];
    var isCursor = state.cursorKey === asset.key;

    var check = h("input", {
      type: "checkbox", "aria-label": "Select " + asset.name,
      on: {
        click: function (e) {
          e.stopPropagation();
          state.selected[asset.key] = e.target.checked;
          if (!e.target.checked) delete state.selected[asset.key];
          state.lastClickedAssetIndex = index;
          render();
        }
      }
    });
    check.checked = selected;

    var menuBtn = h("button", {
      cls: "menu-btn", type: "button", "aria-haspopup": "true", "aria-expanded": "false",
      "aria-label": "Actions for " + asset.name,
      title: "Actions for " + asset.name,
      on: {
        click: function (e) {
          e.stopPropagation();
          var r = e.currentTarget.getBoundingClientRect();
          openAssetMenu(asset, r.left, r.bottom + 2, e.currentTarget);
        }
      }
    }, icon("i-dots"));

    var nameCell = h("td", {}, h("span", { cls: "host", text: asset.name }), terminalRowGlyph(asset));

    var agentCell;
    if (asset.endpoint) {
      agentCell = h("span", { cls: "ver", "data-stale": asset.stale ? "true" : "false", text: shortVersion(asset.endpoint.driver_version) });
    } else {
      agentCell = h("span", { cls: "dim-3", text: "\u2014" });
    }

    var exposure = asset.ports.length
      ? h("span", { cls: "ago", text: asset.ports.length + (asset.riskyPorts ? " \u00b7 " + asset.riskyPorts + " risky" : "") })
      : h("span", { cls: "dim-3", text: asset.scan ? "0" : "\u2014" });

    var identMethod = (asset.scan && asset.scan.identity_method) || (asset.endpoint ? "agent" : "");
    var identityCell = h("td", {
      cls: "dim",
      title: identMethod
        ? "Identified from " + (IDENT_METHODS[identMethod] || identMethod) +
          (asset.scan && asset.scan.confidence ? " \u2014 " + Math.round(asset.scan.confidence * 100) + "% confidence" : "")
        : "Nothing has identified this host yet"
    }, h("span", { text: asset.identity }));
    if (asset.endpoint) {
      var cn = asset.endpoint.cert_cn || "";
      identityCell.appendChild(document.createTextNode(" "));
      identityCell.appendChild(h("span", {
        cls: "auth", "data-bound": cn ? "true" : "false",
        title: cn
          ? "Last reported under client certificate \u201c" + cn + "\u201d"
          : "Reports with its unique device credential; direct native mTLS was not seen on the last heartbeat.",
        text: cn ? "\u00b7 mTLS" : "\u00b7 device credential"
      }));
    }

    /* Cell order: select · menu · Asset · Address · Identity · Known by · State · Exposure · Agent · Last seen */
    return h("tr", {
      cls: "row",
      "data-selected": selected ? "true" : "false",
      "data-cursor": isCursor ? "true" : "false",
      "data-key": asset.key,
      on: {
        click: function (e) {
          if (e.ctrlKey || e.metaKey) {
            state.selected[asset.key] = !state.selected[asset.key];
            if (!state.selected[asset.key]) delete state.selected[asset.key];
            state.lastClickedAssetIndex = index;
            render();
          } else if (e.shiftKey && state.lastClickedAssetIndex >= 0 && allRows) {
            var start = Math.min(state.lastClickedAssetIndex, index);
            var end = Math.max(state.lastClickedAssetIndex, index);
            for (var i = start; i <= end; i++) {
              if (allRows[i]) state.selected[allRows[i].key] = true;
            }
            render();
          } else {
            state.cursorKey = asset.key;
            state.expandedKey = state.expandedKey === asset.key ? "" : asset.key;
            state.lastClickedAssetIndex = index;
            render();
          }
        },
        contextmenu: function (e) {
          e.preventDefault();
          state.cursorKey = asset.key;
          openAssetMenu(asset, e.clientX, e.clientY, null);
        }
      }
    },
      h("td", { cls: "c-sel" }, check),
      h("td", { cls: "c-menu" }, menuBtn),
      nameCell,
      h("td", {}, h("span", { cls: "ip", text: asset.ip || "\u2014" })),
      identityCell,
      h("td", {}, evidenceStrip(asset)),
      h("td", {}, stateBadge(asset.state)),
      h("td", {}, exposure),
      h("td", {}, agentCell),
      h("td", {}, stamp(asset.lastSeen)));
  }

  /* One comparable value per sortable Assets column. Numbers where the column
     is a quantity, so "12 ports" does not sort before "2 ports". */
  var ASSET_SORT = {
    2: function (r) { return (r.name || "").toLowerCase(); },
    3: function (r) { return r.sortKey; },
    4: function (r) { return (r.identity || "").toLowerCase(); },
    5: function (r) { return (r.evidence.agent ? 2 : 0) + (r.evidence.scan ? 1 : 0); },
    6: function (r) { return (r.state || "").toLowerCase(); },
    7: function (r) { return r.riskyPorts * 10000 + r.ports.length; },
    8: function (r) {
      if (!r.endpoint) return -1;
      var t = versionTriple(r.endpoint.driver_version);
      return t[0] * 1000000 + t[1] * 1000 + t[2];
    },
    9: function (r) { return r.lastSeen ? +r.lastSeen : 0; }
  };

  /* Sorting is applied inside each tenant/location group, never across them:
     the grouping is the operator's mental map of the estate and reordering it
     under a context menu is how a click lands on the wrong host. */
  function sortAssetRows(rows) {
    var st = state.assetSort;
    var pick = st && ASSET_SORT[st.col];
    if (!pick) return rows;
    var dir = st.dir === "desc" ? -1 : 1;
    return rows.slice().sort(function (a, b) {
      if (a.groupKey !== b.groupKey) return a.groupKey < b.groupKey ? -1 : 1;
      var va = pick(a), vb = pick(b);
      if (typeof va === "number" && typeof vb === "number") {
        if (va !== vb) return (va - vb) * dir;
      } else {
        var c = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
        if (c) return c * dir;
      }
      /* Ties keep the stable address order, so a re-render never shuffles
         equal rows past one another. */
      return a.sortKey < b.sortKey ? -1 : (a.sortKey > b.sortKey ? 1 : 0);
    });
  }

  function assetSortHeader(col, label, attrs) {
    var st = state.assetSort;
    var active = st && st.col === col;
    var th = h("th", attrs || {});
    th.setAttribute("scope", "col");
    th.setAttribute("aria-sort", active ? (st.dir === "desc" ? "descending" : "ascending") : "none");
    th.appendChild(h("button", {
      cls: "th-sort", type: "button", text: label,
      "data-active": active ? "true" : null,
      "data-dir": active ? st.dir : null,
      title: "Sort by " + label,
      on: {
        click: function () {
          if (active && st.dir === "asc") state.assetSort = { col: col, dir: "desc" };
          else if (active) state.assetSort = null;
          else state.assetSort = { col: col, dir: "asc" };
          persistView(currentURLState());
          render();
        }
      }
    }));
    return th;
  }

  function renderAssets() {
    var view = $("view");
    var rows = sortAssetRows(visibleAssets());
    var cols = 10;

    var head = h("tr", {},
      h("th", { cls: "c-sel" }, (function () {
        var all = rows.length > 0 && rows.every(function (r) { return state.selected[r.key]; });
        var box = h("input", {
          type: "checkbox", "aria-label": "Select all rows",
          on: {
            change: function (e) {
              rows.forEach(function (r) {
                if (e.target.checked) state.selected[r.key] = true;
                else delete state.selected[r.key];
              });
              render();
            }
          }
        });
        box.checked = all;
        return box;
      })()),
      h("th", { cls: "c-menu", scope: "col" }, h("span", { cls: "sr", text: "Row actions" })),
      assetSortHeader(2, "Asset"),
      assetSortHeader(3, "Address"),
      assetSortHeader(4, "Identity"),
      assetSortHeader(5, "Known by", { title: "agent \u00b7 scan" }),
      assetSortHeader(6, "State"),
      assetSortHeader(7, "Exposure"),
      assetSortHeader(8, "Agent"),
      assetSortHeader(9, "Last seen"));

    var tbody = h("tbody");
    var currentGroup = null;
    var groupCounts = {};
    rows.forEach(function (r) {
      if (!groupCounts[r.groupKey]) groupCounts[r.groupKey] = { n: 0, q: 0, noagent: 0 };
      groupCounts[r.groupKey].n++;
      if (r.isolated || r.meshed) groupCounts[r.groupKey].q++;
      if (!r.evidence.agent) groupCounts[r.groupKey].noagent++;
    });

    rows.forEach(function (r, idx) {
      if (r.groupKey !== currentGroup) {
        currentGroup = r.groupKey;
        var g = groupCounts[currentGroup];
        var collapsed = !!state.collapsedGroups[currentGroup];
        var meta = g.n + " asset" + (g.n === 1 ? "" : "s") +
          (g.noagent ? " \u00b7 " + g.noagent + " without an agent" : "") +
          (g.q ? " \u00b7 " + g.q + " quarantined" : "");
        (function (key) {
          var toggle = function () {
            if (state.collapsedGroups[key]) delete state.collapsedGroups[key];
            else state.collapsedGroups[key] = true;
            render();
          };
          /* aria-expanded was on the <tr>, which is not a control and cannot
             be focused, and the only way to collapse a group was to click the
             row. The twisty is the button; the row still forwards clicks so
             the mouse target stays the whole width. */
          tbody.appendChild(h("tr", {
            cls: "grp",
            on: { click: toggle }
          }, h("td", { colspan: String(cols) },
            h("button", {
              cls: "tw", type: "button",
              "aria-expanded": collapsed ? "false" : "true",
              "aria-label": (collapsed ? "Expand " : "Collapse ") + key + ", " + meta,
              on: { click: function (e) { e.stopPropagation(); toggle(); } }
            },
              (function () { var i = icon("i-twist", true); i.classList.add("ic-twist"); return i; })(),
              h("span", { text: key }),
              h("span", { cls: "cnt", text: "\u2014 " + meta })))));
        })(currentGroup);
      }
      if (state.collapsedGroups[currentGroup]) return;
      tbody.appendChild(assetRow(r, cols, idx, rows));
      if (state.expandedKey === r.key) tbody.appendChild(detailRow(r, cols));
    });

    if (!rows.length) {
      tbody.appendChild(h("tr", {}, h("td", { colspan: String(cols) },
        h("div", { cls: "empty", text: state.loading ? "Loading fleet\u2026" : "No asset matches the current filters." }))));
    }

    var wrap = h("div", { cls: "tblwrap" }, h("table", {}, h("thead", {}, head), tbody));

    var key = h("div", { cls: "evkey" },
      h("span", {}, h("i", { "data-on": "agent" }), h("span", { text: "agent \u2014 ground truth" })),
      h("span", {}, h("i", { "data-on": "scan" }), h("span", { text: "scan \u2014 probed" })),
      h("span", {}, h("i", { "data-on": "none" }), h("span", { text: "nothing yet" })),
      h("span", { text: "j/k move \u00b7 Ctrl/Shift+Click range select \u00b7 i isolate \u00b7 r rescan \u00b7 enter open" }));

    clear(view);
    view.appendChild(wrap);
    view.appendChild(key);

    // Floating Context Action Bar when rows are selected
    var selKeys = selectedKeys();
    if (selKeys.length > 0) {
      var selCount = selKeys.length;
      var selAssets = selKeys.map(function (k) { return state.assetByKey[k]; }).filter(Boolean);
      var agentedSelected = selAssets.filter(function (a) { return a.endpoint; });
      var unmanagedSelected = selAssets.filter(function (a) { return !a.endpoint; });
      var targetVer = HUB_VERSION || "1.8.1";

      var acts = [
        h("span", { cls: "floating-count-pill", text: selCount + " selected" })
      ];

      if (agentedSelected.length > 0) {
        acts.push(h("button", {
          cls: "btn btn-primary mini", type: "button", text: "Upgrade Agents (" + agentedSelected.length + ")",
          on: {
            click: function () {
              var epIds = agentedSelected.map(function (a) { return a.endpoint.id; });
              request("/api/v1/agents/update", "POST", { endpoint_ids: epIds, version: targetVer })
                .then(function () { toast("Queued v" + targetVer + " upgrade for " + epIds.length + " agent(s)", "ok"); refresh(); })
                .catch(function (e) { toast("Upgrade failed: " + e.message, "crit"); });
            }
          }
        }));
        acts.push(h("button", {
          cls: "btn mini", type: "button", text: "Isolate (" + agentedSelected.length + ")",
          on: { click: function () { bulkIsolate(true); } }
        }));
        acts.push(h("button", {
          cls: "btn mini", type: "button", text: "Release",
          on: { click: function () { bulkIsolate(false); } }
        }));
      }

      if (unmanagedSelected.length > 0) {
        acts.push(h("button", {
          cls: "btn btn-primary mini", type: "button", text: "Install Agent (" + unmanagedSelected.length + ")",
          on: {
            click: function () {
              var oses = {};
              unmanagedSelected.forEach(function (a) {
                var os = String((a.os || "")).toLowerCase();
                if (os.indexOf("windows") !== -1) oses.windows = true;
                else if (os) oses.linux = true;
              });
              var kinds = Object.keys(oses);
              openInstallerSheet({
                hosts: unmanagedSelected.map(function (a) { return a.name || a.ip; }),
                platform: kinds.length === 1 ? kinds[0] : null
              });
            }
          }
        }));
      }

      acts.push(h("button", {
        cls: "btn mini", type: "button", text: "Rescan (" + selCount + ")",
        on: { click: function () { selKeys.forEach(function (k) { if (state.assetByKey[k]) rescan(state.assetByKey[k]); }); } }
      }));

      acts.push(h("button", {
        cls: "btn mini", type: "button", text: "Export CSV",
        on: { click: exportSelectedAssetsCSV }
      }));

      acts.push(h("button", {
        cls: "btn mini", type: "button", text: "✕ Deselect",
        on: { click: function () { state.selected = {}; render(); } }
      }));

      var floatBar = h("div", { cls: "assets-floating-bar" }, acts);
      view.appendChild(floatBar);
    }
  }

  /* ------------------------------------------------------- other sections */

  function card(title, body, actions, wide) {
    var head = h("h3", {}, h("span", { cls: "fill", text: title }));
    if (actions) actions.forEach(function (a) { head.appendChild(a); });
    return h("section", { cls: wide ? "card card-wide" : "card" }, head, body);
  }

  /* Text of a rendered cell, for sorting. Cells arrive as strings or as nodes,
     and a node's own text is what the operator is reading, so that is what a
     sort has to order on. */
  function cellText(c) {
    if (c === null || c === undefined) return "";
    if (typeof c === "string" || typeof c === "number") return String(c);
    if (c.dataset && c.dataset.sort !== undefined) return c.dataset.sort;
    return c.textContent || "";
  }

  /* Numbers, byte figures and timestamps must not sort as strings: "9 KB"
     before "10 KB" is worse than no sort at all. A cell that is entirely a
     number (with the usual separators and a unit) compares numerically. */
  var NUM_CELL = /^[<>~]?\s*-?[\d,.]+\s*(%|B|KB|MB|GB|TB|ms|s|m|h|d)?$/i;
  var UNIT_MUL = { b: 1, kb: 1024, mb: 1048576, gb: 1073741824, tb: 1099511627776 };

  function cellSortKey(txt) {
    var t = String(txt).trim();
    if (!t || !NUM_CELL.test(t)) return null;
    var m = t.match(/-?[\d,.]+/);
    if (!m) return null;
    var n = parseFloat(m[0].replace(/,/g, ""));
    if (isNaN(n)) return null;
    var unit = (t.match(/(kb|mb|gb|tb|b)$/i) || [])[0];
    if (unit && UNIT_MUL[unit.toLowerCase()]) n *= UNIT_MUL[unit.toLowerCase()];
    return n;
  }

  var tableSortState = {};

  /* Backs every table in Response, Forensics, Audit, Access and the DNS policy
     list. Three things it did not have and needed:
       - a caller-supplied empty string. "Nothing recorded." was fixed, so a
         failed operator load and a genuinely empty evidence bundle read
         identically and neither told you which it was.
       - `scope="col"`, so a screen reader associates a cell with its heading.
       - a sort. "Who is oldest on agent version" and "who was seen least
         recently" are the questions these tables exist to answer.
     `key` namespaces the sort so two tables on one page do not share it. */
  /* An empty panel that says which kind of empty it is. Before the first
     answer from the hub arrives this is a spinner, not a statement that the
     fleet has nothing - Traffic showed seven "no data" boxes and Policy five
     "Nothing recorded." tables for the whole of a cold start. */
  /* A <label> that is actually attached to its control.
     51 of the console's 61 labels were floating text next to an input: no
     `for`, not wrapping it, so a screen reader announced an unlabelled edit
     field and clicking the words did nothing. Where the thing being labelled
     is not a form control - a container of checkboxes, a row of buttons -
     there is nothing to point `for` at, and a caption is the honest markup. */
  var autoIdSeq = 0;

  function labelFor(text, control) {
    var tag = control && control.tagName ? control.tagName.toLowerCase() : "";
    if (tag !== "input" && tag !== "select" && tag !== "textarea") {
      return h("div", { cls: "label-meta", text: text });
    }
    if (!control.id) control.id = "f" + (++autoIdSeq);
    return h("label", { "for": control.id, text: text });
  }

  /* A removable filter chip. The delete affordance was a bare span with a
     click handler: not focusable, not announced, and unreachable without a
     mouse, so a keyboard operator could add a traffic filter and then had no
     way to take it off again. */
  function filterChip(label, onRemove) {
    return h("span", { cls: "traffic-chip" },
      h("span", { text: label }),
      h("button", {
        cls: "chip-del", type: "button", text: "\u00d7",
        "aria-label": "Remove filter " + label,
        title: "Remove filter",
        on: { click: onRemove }
      }));
  }

  function emptyBox(text, loadingText) {
    if (state.loading) {
      return h("div", { cls: "empty" },
        h("span", { cls: "spin", "aria-hidden": "true" }),
        h("span", { text: loadingText || "Loading\u2026" }));
    }
    return h("div", { cls: "empty", text: text });
  }

  function simpleTable(headers, rows, opts) {
    opts = opts || {};
    var key = opts.key || ("t:" + headers.join("|"));
    var sortable = opts.sortable !== false;
    var st = tableSortState[key];

    var body = rows.slice();
    if (sortable && st && st.col < headers.length) {
      var dir = st.dir === "desc" ? -1 : 1;
      body.sort(function (a, b) {
        var ta = cellText(a[st.col]), tb = cellText(b[st.col]);
        var na = cellSortKey(ta), nb = cellSortKey(tb);
        if (na !== null && nb !== null) return (na - nb) * dir;
        return ta.localeCompare(tb, undefined, { numeric: true, sensitivity: "base" }) * dir;
      });
    }

    var thead = h("tr");
    headers.forEach(function (t, i) {
      var active = sortable && st && st.col === i;
      var th = h("th", { scope: "col" });
      if (!sortable) { th.textContent = String(t); thead.appendChild(th); return; }
      th.setAttribute("aria-sort", active ? (st.dir === "desc" ? "descending" : "ascending") : "none");
      th.appendChild(h("button", {
        cls: "th-sort", type: "button", text: String(t),
        "data-active": active ? "true" : null,
        "data-dir": active ? st.dir : null,
        title: "Sort by " + t,
        on: {
          click: function () {
            var cur = tableSortState[key];
            if (cur && cur.col === i) {
              tableSortState[key] = cur.dir === "asc" ? { col: i, dir: "desc" } : null;
            } else {
              tableSortState[key] = { col: i, dir: "asc" };
            }
            render();
          }
        }
      }));
      thead.appendChild(th);
    });

    var tbody = h("tbody");
    if (!body.length) {
      /* "Nothing recorded." was printed for a table that had not been fetched
         yet, a fetch that failed, and a genuinely empty result. A booting
         console was indistinguishable from an idle fleet, and five of these in
         a column read as "the hub knows nothing" when it simply had not
         answered yet. */
      tbody.appendChild(h("tr", {}, h("td", { colspan: String(headers.length) },
        state.loading
          ? h("div", { cls: "empty" },
              h("span", { cls: "spin", "aria-hidden": "true" }),
              h("span", { text: opts.loading || "Loading\u2026" }))
          : h("div", { cls: "empty", text: opts.empty || "Nothing recorded." }))));
    }
    body.forEach(function (cells) {
      var tr = h("tr", { cls: "row" });
      cells.forEach(function (c) {
        tr.appendChild(h("td", {}, typeof c === "string" ? document.createTextNode(c) : c));
      });
      tbody.appendChild(tr);
    });
    return h("div", { cls: "tblwrap" },
      h("table", { vars: { "--tbl-cols": String(headers.length) } }, h("thead", {}, thead), tbody));
  }

  /* ------------------------------------------------------- scan progress */

  /* A sweep takes minutes and the console had nowhere to say so: it kept the
     scan id, printed it as "Last job: scan-…", and never asked the hub what
     became of it. The hub has carried progress, a found count and a host total
     the whole time. */

  function stopScanPoll() {
    if (state.scanPoll) { clearInterval(state.scanPoll); state.scanPoll = null; }
  }

  function watchScan(scanID) {
    stopScanPoll();
    state.scanJob = scanID;
    var check = function () {
      request("/api/v1/scanner/status?id=" + encodeURIComponent(scanID)).then(function (st) {
        state.scanStatus = st || null;
        if (st && (st.status === "completed" || st.status === "failed")) {
          stopScanPoll();
          toast(st.status === "completed"
            ? "Sweep of " + st.subnet + " finished — " + (st.found_count || 0) + " host(s) found"
            : "Sweep of " + st.subnet + " failed", st.status === "completed" ? "ok" : "crit");
          refresh();
          return;
        }
        if (state.section === "discovery") renderBody();
      }).catch(function () {
        /* A status the hub cannot answer for is a finished scan it has
           forgotten, not a reason to keep asking. */
        stopScanPoll();
      });
    };
    check();
    state.scanPoll = setInterval(check, 2000);
  }

  function scanProgressCard() {
    var st = state.scanStatus;
    if (!st) {
      return card("Sweep status", h("div", { cls: "empty",
        text: "No sweep has been started from this console. Progress, host counts and what was found appear here while one runs." }));
    }

    var running = st.status === "running" || st.status === "pending";
    var pct = Math.max(0, Math.min(100, Number(st.progress) || 0));
    var started = parseTime(st.start_time);
    var ended = parseTime(st.end_time);
    /* EndTime is a time.Time, and omitempty does not drop a zero struct, so a
       running scan reports "0001-01-01T00:00:00Z" rather than nothing. */
    if (ended && started && ended < started) ended = null;
    var elapsed = started ? Math.round((((ended && !running) ? ended : new Date()) - started) / 1000) : 0;

    var bar = h("div", { cls: "bar", role: "progressbar", vars: { "--pct": pct + "%" },
      "aria-valuenow": String(pct), "aria-valuemin": "0", "aria-valuemax": "100",
      "aria-label": "Sweep progress" },
      h("i", { cls: "bar-fill" }));

    var stateWord = running ? "Sweeping" : st.status === "completed" ? "Complete" : "Failed";

    return card("Sweep status", h("div", { cls: "card-body stack" },
      h("div", { cls: "scanhead" },
        h("span", { cls: "st", "data-state": running ? "info" : st.status === "completed" ? "ok" : "crit" },
          icon(running ? "g-watch" : st.status === "completed" ? "g-online" : "g-quarantine", true),
          h("span", { text: stateWord })),
        h("span", { cls: "ip", text: st.subnet || "" }),
        h("span", { cls: "dim-3", text: st.profile || "" }),
        h("span", { cls: "fill" }),
        h("span", { cls: "ago", text: pct + "%" })),
      bar,
      h("dl", { cls: "kv" },
        h("dt", { text: "Hosts probed" }), h("dd", {}, h("b", { text: String(st.total_hosts || 0) })),
        h("dt", { text: "Live hosts found" }), h("dd", {}, h("b", { text: String(st.found_count || 0) })),
        h("dt", { text: "Elapsed" }), h("dd", { text: elapsed + "s" }),
        h("dt", { text: "Started" }), h("dd", {}, stamp(started)),
        h("dt", { text: "Job" }), h("dd", { cls: "ip", text: st.id || "" }))));
  }

  /* The bootstrap routes never went away; the button that reached them did.
     Discovery is where an operator is already looking at a host with no agent
     on it, so the door belongs on this page as well as in the topbar. */
  function addEndpointCard() {
    return card("Install an agent",
      h("div", { cls: "card-body stack" },
        h("p", { cls: "pending", text: "Generate a Windows or Linux install script for one host, an expiring rollout, or a protected GPO/MDM deployment. For workstations on the same LAN, temporarily allow that network and let each workstation download its own installer from /install." }),
        h("div", { cls: "row-acts" },
          h("button", {
            cls: "btn btn-primary", type: "button", text: "Create an installer",
            on: { click: function () { openInstallerSheet(); } }
          }),
          h("button", {
            cls: "btn", type: "button", text: "Set up LAN installs",
            on: { click: function () { openSelfServiceSheet(); } }
          }),
          h("button", {
            cls: "btn", type: "button", text: "Manage enrollment keys",
            on: { click: function () { openEnrollmentProfilesSheet(); } }
          })
        )));
  }

  var accountPop = null;

  function closeAccountPop() {
    if (accountPop && accountPop.parentNode) accountPop.parentNode.removeChild(accountPop);
    accountPop = null;
    var btn = $("user-avatar-btn");
    if (btn) btn.setAttribute("aria-expanded", "false");
  }

  function openAccountPop() {
    closeAccountPop();
    var btn = $("user-avatar-btn");
    if (!btn) return;

    var pop = h("div", { cls: "account-pop", role: "dialog", "aria-label": "Account & Hub Settings" });

    var opName = state.you || OPERATOR || "admin";
    var initial = (opName[0] || "A").toUpperCase();
    var roleLbl = roleName(ROLE) || "Operator";

    var header = h("div", { cls: "account-pop-header" },
      h("div", { cls: "account-pop-avatar", text: initial }),
      h("div", { cls: "account-pop-user" },
        h("span", { cls: "account-pop-email", text: opName, title: opName }),
        h("span", { cls: "account-pop-role", text: roleLbl })));

    var themeOpts = THEMES.map(function (t) {
      return h("button", {
        cls: "account-theme-opt", type: "button",
        "aria-checked": state.theme === t ? "true" : "false",
        on: {
          click: function () {
            applyTheme(t, true);
            closeAccountPop();
            toast("Theme: " + THEME_NAMES[t], "ok");
          }
        }
      },
        h("span", { text: THEME_NAMES[t] }),
        h("span", { cls: "chips" },
          ["brand", "ok", "warn", "crit"].map(function (role) {
            return h("i", { cls: "sw-" + role + "-" + t });
          })));
    });

    var statusUrl = "/status" + (API_KEY ? "?key=" + encodeURIComponent(API_KEY) : "");

    var links = h("div", { cls: "account-links" },
      h("a", { cls: "account-link-btn", href: statusUrl, target: "_blank" },
        icon("i-external"), h("span", { text: "System Status & Diagnostics" })),
      h("a", { cls: "account-link-btn", href: "/install", target: "_blank" },
        icon("i-download"), h("span", { text: "Agent Enrollment Portal" })));

    var body = h("div", { cls: "account-pop-body" },
      h("div", { cls: "account-section" },
        h("div", { cls: "account-section-title", text: "Color Theme" }),
        h("div", { cls: "account-theme-grid" }, themeOpts)),
      links);

    var footer = h("div", { cls: "account-pop-footer" },
      h("span", { text: "Ominull Hub v" + (HUB_VERSION || "1.8.1") }),
      h("span", { text: "ECDSA Verified" }));

    pop.appendChild(header);
    pop.appendChild(body);
    pop.appendChild(footer);

    document.body.appendChild(pop);
    var r = btn.getBoundingClientRect();
    var pr = pop.getBoundingClientRect();
    placeOverlay(pop, Math.max(8, r.right - pr.width), r.bottom + 8);
    accountPop = pop;
    btn.setAttribute("aria-expanded", "true");
  }

  function openSweepModal() {
    var defaultSubnet = suggestedSubnet();
    var subnetInput = h("input", { type: "text", id: "modal-scan-subnet", value: defaultSubnet, placeholder: defaultSubnet });
    var profileSel = h("select", { id: "modal-scan-profile" },
      h("option", { value: "quick", text: "Quick (fast port sweep)" }),
      h("option", { value: "standard", text: "Standard (OS + SYN fingerprint)" }),
      h("option", { value: "deep", text: "Deep (Full port & service analysis)" }));
    profileSel.value = "standard";

    var cov = state.coverage || {};
    var covered = (cov.total_discovered !== undefined ? cov.total_discovered : state.scanAssets.length) > 0;

    var statusSummary = h("div", { cls: "stack" },
      h("p", { cls: "sub", text: "Active subnet asset sweep and OS fingerprinting engine." }),
      scanProgressCard(),
      h("div", { cls: "dns-grid" },
        h("div", { cls: "dns-stat-box" },
          h("span", { cls: "dns-stat-val", text: String(covered ? cov.total_discovered : state.assets.length) }),
          h("span", { cls: "dns-stat-label", text: "Total Network Assets" })),
        h("div", { cls: "dns-stat-box" },
          h("span", { cls: "dns-stat-val", text: covered ? pct(cov.coverage_percent) : "—" }),
          h("span", { cls: "dns-stat-label", text: "Fleet Agent Coverage" })),
        h("div", { cls: "dns-stat-box" },
          h("span", { cls: "dns-stat-val", text: String(cov.critical_risks || 0), "data-tone": cov.critical_risks ? "crit" : null }),
          h("span", { cls: "dns-stat-label", text: "Critical Risk Weakpoints" }))),
      h("div", { cls: "form-row" },
        h("label", { cls: "field" }, h("span", { text: "Target Subnet CIDR" }), subnetInput),
        h("label", { cls: "field" }, h("span", { text: "Sweep Profile" }), profileSel)));

    var actions = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-primary", type: "button", text: "Start Subnet Sweep",
        on: {
          click: function () {
            request("/api/v1/scanner/scan", "POST", { subnet: subnetInput.value, profile: profileSel.value })
              .then(function (res) {
                toast("Sweeping subnet " + subnetInput.value, "ok");
                closeSheet();
                if (res && res.scan_id) watchScan(res.scan_id);
                else { state.scanJob = "running"; setTimeout(refresh, 2500); }
              })
              .catch(function (e) { toast("Sweep failed: " + e.message, "crit"); });
          }
        }
      })
    ];

    /* The fourth argument is a CSS class, not a flag: passing `true` produced
       class="sheet true". */
    openSheet("Subnet Sweep & Asset Discovery", statusSummary, actions);
  }

  function exportSelectedAssetsCSV() {
    var keys = selectedKeys();
    if (!keys.length) { toast("No assets selected for export", "warn"); return; }
    var rows = keys.map(function (k) { return state.assetByKey[k]; }).filter(Boolean);
    var csv = "Asset,Address,Identity,State,Exposure,Agent,LastSeen\n";
    rows.forEach(function (r) {
      var name = '"' + (r.name || "").replace(/"/g, '""') + '"';
      var ip = '"' + (r.ip || "").replace(/"/g, '""') + '"';
      var ident = '"' + (r.identity || "").replace(/"/g, '""') + '"';
      var st = '"' + ((r.state && r.state.word) || "Unknown") + '"';
      var exp = String(r.ports ? r.ports.length : 0);
      var ag = '"' + (r.endpoint ? r.endpoint.driver_version : "None") + '"';
      var seen = '"' + (r.lastSeen ? r.lastSeen.toISOString() : "") + '"';
      csv += [name, ip, ident, st, exp, ag, seen].join(",") + "\n";
    });
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "ominull_assets_export_" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    toast("Exported " + rows.length + " assets to CSV", "ok");
  }

  function renderAlerts() {
    var view = $("view");
    clear(view);

    var allAnomalies = state.anomalies || [];
    var af = state.alertsFilter || { page: 1, limit: 50, unacknowledged_only: true, severity: "", endpoint_id: "", search: "" };

    /* The per-host breakdown comes from the hub and covers every alert that
       matches the current filters. Grouping the fifty rows of the current page
       instead - which is what this did - drew a strip that summed to fifty
       under a header reporting thousands. Older hubs do not send it, so the
       page grouping stays as the fallback and says so. */
    var breakdown = (state.alertsData && Array.isArray(state.alertsData.breakdown)) ? state.alertsData.breakdown : null;
    var sysMap = {};
    if (breakdown) {
      breakdown.forEach(function (g) {
        var types = {};
        arrayOf(g.types).forEach(function (t) { if (t && t.type) types[t.type] = Number(t.count) || 0; });
        sysMap[g.endpoint_id || g.hostname || "Unknown Host"] = {
          host: g.hostname || g.endpoint_id || "Unknown Host",
          epId: g.endpoint_id || "",
          total: Number(g.total) || 0,
          crit: Number(g.critical) || 0,
          high: Number(g.high) || 0,
          med: Number(g.medium) || 0,
          low: Number(g.low) || 0,
          types: types
        };
      });
    }
    if (!breakdown) allAnomalies.forEach(function (a) {
      /* Group on the endpoint id and *label* with the hostname. Grouping on
          the hostname made `s.host` a hostname, which the click handler then
          assigned to `af.endpoint_id`; the client-side filter matched it
          instantly, and up to five seconds later refresh() sent it to the hub
          as `&endpoint_id=<hostname>`, which matches nothing - so the list
          the operator had just filtered emptied itself with no explanation. */
      var gkey = a.endpoint_id || a.hostname || "Unknown Host";
      if (!sysMap[gkey]) {
        sysMap[gkey] = {
          host: a.hostname || a.endpoint_id || "Unknown Host",
          epId: a.endpoint_id || "",
          total: 0, crit: 0, high: 0, med: 0, low: 0, types: {}
        };
      }
      var s = sysMap[gkey];
      s.total++;
      var sev = (a.severity || "LOW").toUpperCase();
      if (sev === "CRITICAL") s.crit++;
      else if (sev === "HIGH") s.high++;
      else if (sev === "MEDIUM") s.med++;
      else s.low++;
      var t = a.anomaly_type || "ANOMALY";
      s.types[t] = (s.types[t] || 0) + 1;
    });

    var topSystems = Object.keys(sysMap).map(function (k) { return sysMap[k]; })
      .sort(function (a, b) { return b.total - a.total; })
      .slice(0, 6);

    // 1. Top Graphic Card: Systems with Most Alerts by Type
    var chartBoxes = topSystems.map(function (s) {
      var wCrit = Math.round((s.crit / s.total) * 100);
      var wHigh = Math.round((s.high / s.total) * 100);
      var wMed = Math.round((s.med / s.total) * 100);
      var wLow = Math.round((s.low / s.total) * 100);

      var isSelected = !!s.epId && af.endpoint_id === s.epId;

      return h("div", {
        cls: "alerts-sys-box" + (isSelected ? " selected" : ""),
        on: {
          click: function () {
            /* An alert group with no endpoint id cannot be filtered on the
               hub, so it is not offered as a filter at all rather than
               offered and then silently emptied. */
            if (!s.epId) { toast("No endpoint id on these alerts \u2014 cannot filter", "warn"); return; }
            af.endpoint_id = (af.endpoint_id === s.epId) ? "" : s.epId;
            af.page = 1;
            renderBody();
            refresh();
          }
        }
      },
        h("div", { cls: "alerts-sys-header" },
          h("span", { text: s.host }),
          h("b", { text: s.total + " alert" + (s.total === 1 ? "" : "s") })),
        h("div", { cls: "alerts-sys-bars" },
          s.crit ? h("div", { cls: "alerts-bar-seg alerts-bar-crit", vars: { "--seg-w": wCrit + "%" } }) : null,
          s.high ? h("div", { cls: "alerts-bar-seg alerts-bar-high", vars: { "--seg-w": wHigh + "%" } }) : null,
          s.med ? h("div", { cls: "alerts-bar-seg alerts-bar-med", vars: { "--seg-w": wMed + "%" } }) : null,
          s.low ? h("div", { cls: "alerts-bar-seg alerts-bar-low", vars: { "--seg-w": wLow + "%" } }) : null),
        h("div", { cls: "dim-3 pad-y u-t2" },
          h("span", { text: Object.keys(s.types).slice(0, 2).join(", ").replace(/_/g, " ").toLowerCase() })));
    });

    var stripHosts = Object.keys(sysMap).length;
    var stripTotal = Object.keys(sysMap).reduce(function (n, k) { return n + sysMap[k].total; }, 0);
    var stripScope = breakdown
      ? (af.unacknowledged_only ? "Every open alert matching the current filters" : "Every alert matching the current filters")
      : "Only the " + allAnomalies.length + " alerts on this page - this hub reports no fleet summary";
    stripScope += ": " + stripTotal.toLocaleString() + " alert" + (stripTotal === 1 ? "" : "s") +
      " across " + stripHosts + " host" + (stripHosts === 1 ? "" : "s") +
      (stripHosts > topSystems.length ? " (busiest " + topSystems.length + " shown)" : "") + ".";

    var chartCard = card("Systems with the Most Alerts by Alert Type",
      h("div", { cls: "stack" },
        h("p", { cls: "dim-3 u-t2", text: stripScope }),
        chartBoxes.length
          ? h("div", { cls: "alerts-sys-grid" }, chartBoxes)
          : emptyBox("No active anomaly alerts recorded across fleet."),
        h("div", { cls: "legend pad-x" },
          h("span", { text: "■ Red: Critical" }),
          h("span", { text: "■ Amber: High" }),
          h("span", { text: "■ Blue: Medium" }),
          h("span", { text: "■ Gray: Low" }),
          h("span", { text: "Click any host to filter table" }))));

    // 2. Filter Bar
    var sevBtns = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(function (sev) {
      var active = (af.severity || "") === sev;
      return h("button", {
        cls: "btn mini" + (active ? " btn-primary" : ""),
        type: "button",
        "aria-pressed": active ? "true" : "false",
        text: sev ? sev : "ALL SEVERITIES",
        on: {
          click: function () {
            af.severity = sev;
            af.page = 1;
            refresh();
          }
        }
      });
    });

    var unackBtn = h("button", {
      cls: "btn mini" + (af.unacknowledged_only ? " btn-primary" : ""),
      type: "button",
      "aria-pressed": af.unacknowledged_only ? "true" : "false",
      text: af.unacknowledged_only ? "UNACKNOWLEDGED ONLY" : "ALL STATUSES",
      on: {
        click: function () {
          af.unacknowledged_only = !af.unacknowledged_only;
          af.page = 1;
          refresh();
        }
      }
    });

    /* Held findings are the ones a learning window is sitting on. The button
       appears only when there are some, so a console with no window open is
       not carrying a control for a state it is not in - but when findings are
       being held, it says so and how many, because a quiet alert list that is
       quiet for an invisible reason is worse than a noisy one. */
    var heldTotal = Number(state.heldAlertsTotal) || 0;
    var heldBtn = (heldTotal > 0 || af.held) ? h("button", {
      cls: "btn mini" + (af.held ? " btn-primary" : ""),
      type: "button",
      "aria-pressed": af.held ? "true" : "false",
      title: "Findings recorded during a learning window. They are kept in full and are not counted as open work.",
      text: af.held ? "HELD (LEARNING)" : "HELD: " + heldTotal,
      on: {
        click: function () {
          af.held = !af.held;
          af.page = 1;
          refresh();
        }
      }
    }) : null;

    /* Reused, never rebuilt. `input` calls renderAlerts(), renderAlerts()
       calls clear(view), and clearing the view destroys the very input being
       typed into - so focus and caret were lost on every keystroke and the
       operator typed one character at a time. The console already had this
       pattern twice (the Assets filter field, renderAccess's focus guard);
       it was simply not applied here. */
    if (!alertsSearchInput) {
      alertsSearchInput = h("input", {
        type: "search",
        placeholder: "Search alerts (host, process, IP)...",
        "aria-label": "Search alerts"
      });
      alertsSearchInput.value = af.search || "";
      alertsSearchInput.addEventListener("input", function () {
        (state.alertsFilter || af).search = alertsSearchInput.value;
        (state.alertsFilter || af).page = 1;
        refresh();
      });
    } else if (document.activeElement !== alertsSearchInput) {
      alertsSearchInput.value = af.search || "";
    }
    var searchInput = alertsSearchInput;

    // Filter anomalies by search text
    var filteredAnomalies = allAnomalies.filter(function (a) {
      if (af.endpoint_id && a.hostname !== af.endpoint_id && a.endpoint_id !== af.endpoint_id) return false;
      if (af.severity && (a.severity || "").toUpperCase() !== af.severity) return false;
      if (af.unacknowledged_only && a.acknowledged) return false;
      if (af.search) {
        var q = af.search.toLowerCase();
        var match = (a.hostname || "").toLowerCase().includes(q) ||
          (a.endpoint_id || "").toLowerCase().includes(q) ||
          (a.process_path || "").toLowerCase().includes(q) ||
          (a.dst_ip || "").toLowerCase().includes(q) ||
          (a.title || "").toLowerCase().includes(q) ||
          (a.description || "").toLowerCase().includes(q) ||
          (a.anomaly_type || "").toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });

    // Bulk actions
    var selectedAlertIds = Object.keys(state.selectedAlerts || {}).filter(function (k) { return state.selectedAlerts[k]; });
    var bulkAckBtn = selectedAlertIds.length ? h("button", {
      cls: "btn btn-primary mini", type: "button",
      text: "Acknowledge Selected (" + selectedAlertIds.length + ")",
      on: {
        click: function () {
          request("/api/v1/anomalies/acknowledge", "POST", { ids: selectedAlertIds })
            .then(function () {
              toast("Acknowledged " + selectedAlertIds.length + " alerts", "ok");
              state.selectedAlerts = {};
              refresh();
            })
            .catch(function (e) { toast("Action failed: " + e.message, "crit"); });
        }
      }
    }) : null;

    var ackAllBtn = h("button", {
      cls: "btn mini", type: "button",
      text: "Acknowledge page (" + filteredAnomalies.filter(function (a) { return !a.acknowledged; }).length + ")",
      disabled: !filteredAnomalies.some(function (a) { return !a.acknowledged; }),
      on: {
        click: function () {
          var ids = filteredAnomalies.filter(function (a) { return !a.acknowledged; }).map(function (a) { return a.id; });
          if (!ids.length) return;
          confirmSheet({
            title: "Acknowledge this page",
            consequence: ids.length + " visible open alerts will be marked as seen. This cannot be undone.",
            confirmLabel: "Acknowledge " + ids.length,
            confirmTone: "primary",
            onConfirm: function () {
              request("/api/v1/anomalies/acknowledge", "POST", { ids: ids })
                .then(function () {
                  toast("Acknowledged " + ids.length + " alerts", "ok");
                  state.selectedAlerts = {};
                  refresh();
                })
                .catch(function (e) { toast("Action failed: " + e.message, "crit"); });
            }
          });
        }
      }
    });

    var clearResolvedBtn = h("button", {
      cls: "btn mini", type: "button", text: "Clear Acknowledged",
      on: {
        click: function () {
          /* "Clear" reads like clearing a filter. It deletes rows. */
          confirmSheet({
            title: "Delete acknowledged alerts",
            consequence: "Every acknowledged alert is deleted from the hub's storage, not hidden. The detections themselves and anything built on them are gone and cannot be recovered from the console.",
            detail: "Open, unacknowledged alerts are not affected.",
            confirmLabel: "Delete them",
            onConfirm: function () {
              request("/api/v1/anomalies/clear", "POST", {})
                .then(function () {
                  toast("Cleared resolved alerts from storage", "ok");
                  refresh();
                })
                .catch(function (e) { toast("Action failed: " + e.message, "crit"); });
            }
          });
        }
      }
    });

    var filterBar = h("div", { cls: "traffic-filter-bar" },
      h("div", { cls: "traffic-filter-group", role: "group", "aria-label": "Alert filters" }, unackBtn, heldBtn, sevBtns),
      h("div", { cls: "actions" }, searchInput, bulkAckBtn, ackAllBtn, clearResolvedBtn));

    // 3. Alerts Table
    var tableRows = [];
    var allRowsSelected = filteredAnomalies.length > 0 && filteredAnomalies.every(function (a) { return state.selectedAlerts && state.selectedAlerts[a.id]; });

    var headCheckbox = h("input", {
      type: "checkbox",
      checked: allRowsSelected,
      on: {
        change: function (e) {
          state.selectedAlerts = state.selectedAlerts || {};
          filteredAnomalies.forEach(function (a) {
            if (e.target.checked) state.selectedAlerts[a.id] = true;
            else delete state.selectedAlerts[a.id];
          });
          renderBody();
        }
      }
    });

    filteredAnomalies.forEach(function (a) {
      var isExpanded = state.expandedAlertId === a.id;
      var isSelected = state.selectedAlerts && state.selectedAlerts[a.id];

      var rowCheckbox = h("input", {
        type: "checkbox",
        checked: !!isSelected,
        on: {
          click: function (e) { e.stopPropagation(); },
          change: function (e) {
            state.selectedAlerts = state.selectedAlerts || {};
            state.selectedAlerts[a.id] = e.target.checked;
            if (!e.target.checked) delete state.selectedAlerts[a.id];
            renderBody();
          }
        }
      });

      /* Two different answers, and the difference matters. "Acknowledge" says
         I have read this one. "Expected" says this conversation is ordinary
         here and should stop being reported - it writes the process and the
         counterparty into the tuning as a pair, which is the loop that turns
         triage into fewer alerts instead of the same alert tomorrow. The hub
         refuses the pair if the process is unattributed or the destination is
         rented compute, and says why. */
      var ackAction = a.acknowledged
        ? h("span", { cls: "dim-3", text: "Acknowledged" })
        : h("span", { cls: "row-actions" },
          h("button", {
            cls: "btn mini", type: "button", text: "Acknowledge",
            on: {
              click: function (e) {
                e.stopPropagation();
                request("/api/v1/anomalies/acknowledge", "POST", { id: a.id })
                  .then(function () { toast("Alert acknowledged", "ok"); refresh(); })
                  .catch(function (err) { toast("Error: " + err.message, "crit"); });
              }
            }
          }),
          h("button", {
            cls: "btn mini", type: "button", text: "Expected",
            title: "Mark this program talking to this counterparty as normal here",
            on: {
              click: function (e) {
                e.stopPropagation();
                request("/api/v1/detection/tuning/suppress", "POST", { id: a.id })
                  .then(function (res) {
                    var pair = (res && res.pair) || "this conversation";
                    toast(res && res.added
                      ? "Silenced " + pair + " - see Detection tuning"
                      : pair + " was already expected", "ok");
                    refresh();
                  })
                  .catch(function (err) { toast(err.message, "crit"); });
              }
            }
          }));

      var tr = h("tr", {
        cls: "alert-row-interactive" + (isSelected ? " selected" : ""),
        on: {
          click: function () {
            state.expandedAlertId = isExpanded ? "" : a.id;
            renderBody();
          }
        }
      },
        h("td", {}, rowCheckbox),
        h("td", {}, stamp(parseTime(a.timestamp))),
        h("td", {}, h("span", { cls: "st", "data-state": (a.severity || "LOW").toLowerCase() === "critical" ? "crit" : (a.severity === "HIGH" ? "warn" : "idle"), text: a.severity || "LOW" })),
        h("td", {}, h("span", { cls: "dim", text: (a.anomaly_type || "").replace(/_/g, " ") }),
          a.technique ? h("span", { cls: "dim-3", text: " " + a.technique }) : null,
          a.held_reason ? h("span", { cls: "dim-3", title: "Recorded during a learning window and not counted as open work", text: " \u00b7 held" }) : null),
        h("td", {}, h("span", { cls: "host", text: a.hostname || a.endpoint_id || "—" })),
        h("td", {}, h("span", { cls: "ip", text: (a.dst_ip || "—") + (a.dst_port ? ":" + a.dst_port : "") })),
        h("td", {}, h("span", { cls: "dim", text: a.process_path ? a.process_path.split("\\").pop().split("/").pop() : "—" })),
        h("td", {}, h("span", { text: a.title || a.description || "—" })),
        h("td", {}, ackAction));

      tableRows.push(tr);

      // Inline Expansion Card
      if (isExpanded) {
        var expBox = h("div", { cls: "alert-exp-card" },
          h("div", { cls: "stack" },
            h("b", { text: a.title || "Anomaly Alert Detail" }),
            h("p", { cls: "why", text: a.description || "" })),
          h("div", { cls: "alert-exp-grid" },
            h("div", { cls: "alert-exp-box" }, h("div", { cls: "alert-exp-label", text: "Endpoint ID" }), h("div", { cls: "alert-exp-val", text: a.endpoint_id || "—" })),
            h("div", { cls: "alert-exp-box" }, h("div", { cls: "alert-exp-label", text: "Process Path" }), h("div", { cls: "alert-exp-val", text: a.process_path || "—" })),
            h("div", { cls: "alert-exp-box" }, h("div", { cls: "alert-exp-label", text: "Target Destination" }), h("div", { cls: "alert-exp-val", text: (a.dst_ip || "—") + ":" + (a.dst_port || 0) })),
            h("div", { cls: "alert-exp-box" }, h("div", { cls: "alert-exp-label", text: "Diagnostic Details" }), h("div", { cls: "alert-exp-val", text: a.details || "None" }))),
          evidencePanel(a),
          h("div", { cls: "actions pad-y" },
            h("button", {
              cls: "btn mini btn-crit", type: "button", text: "Isolate Endpoint (" + (a.hostname || a.endpoint_id) + ")",
              on: {
                click: function (e) {
                  e.stopPropagation();
                  var ast = assetForAlert(a);
                  if (ast) setIsolation(ast, true);
                  else toast("No asset row for " + (a.hostname || a.endpoint_id || "this alert"), "warn");
                }
              }
            }),
            h("button", {
              cls: "btn mini", type: "button", text: "Copy Alert ID",
              on: { click: function (e) { e.stopPropagation(); copyText(a.id); toast("Copied alert ID", "ok"); } }
            })));

        var expTr = h("tr", { cls: "exp" }, h("td", { colspan: "9" }, expBox));
        tableRows.push(expTr);
      }
    });

    var alertsTable = h("div", { cls: "tblwrap" },
      h("table", {},
        h("thead", {},
          h("tr", {},
            h("th", { cls: "c-sel" }, headCheckbox),
            h("th", { text: "Time" }),
            h("th", { text: "Severity" }),
            h("th", { text: "Anomaly Type" }),
            h("th", { text: "System / Host" }),
            h("th", { text: "Destination" }),
            h("th", { text: "Process" }),
            h("th", { text: "Title / Finding" }),
            h("th", { text: "Action" }))),
        h("tbody", {}, tableRows.length ? tableRows : h("tr", {}, h("td", { colspan: "9" }, emptyBox("No alerts match active filters."))))));

    var totalAlerts = state.alertsData && typeof state.alertsData.total === "number" ? state.alertsData.total : allAnomalies.length;
    var pageCount = Math.max(1, Math.ceil(totalAlerts / af.limit));
    var pager = h("nav", { cls: "actions", "aria-label": "Alert pages" },
      h("button", {cls: "btn mini", type: "button", text: "Previous", disabled: af.page <= 1,
        on: {click: function () { af.page--; state.selectedAlerts = {}; refresh(); }}}),
      h("span", {text: "Page " + af.page + " of " + pageCount + " · " + totalAlerts + " matching alerts"}),
      h("button", {cls: "btn mini", type: "button", text: "Next", disabled: af.page >= pageCount,
        on: {click: function () { af.page++; state.selectedAlerts = {}; refresh(); }}}));
    var alertsCard = card("Active Security Anomaly Stream (" + filteredAnomalies.length + " matching of " + totalAlerts + " total)",
      h("div", { cls: "stack" }, alertsTable, pager));

    view.appendChild(h("div", { cls: "pad stack alerts-workspace" },
      chartCard,
      filterBar,
      alertsCard));
  }

  /* Radial layout: highest-degree node in the centre, its neighbours on the
     inner ring, everything else outside. Deterministic in node id so the graph
     does not jump between five-second refreshes. */
  function getClusterCategory(node) {
    if (node.is_isolated || node.type === "threat" || node.risk === "CRITICAL" || node.risk === "HIGH") return "threats";
    if (node.type === "gateway") return "infra";
    if (node.type === "managed" || node.is_managed === true) return "fleet";
    if (node.estate_member || (node.address_scope && node.address_scope !== "public" && node.address_scope !== "invalid")) return "iot";
    return "cloud";
  }

  function layoutTopology(nodes, edges) {
    state.topoCustomPos = state.topoCustomPos || {};
    var W = 1360, H = 840;

    // Define 5 clean semantic visual cluster zones
    var clusters = {
      infra:   { id: "infra", label: "Gateways", x: 680, y: 170, color: "var(--info)", nodes: [] },
      fleet:   { id: "fleet", label: "Managed endpoints", x: 300, y: 440, color: "var(--ok)", nodes: [] },
      iot:     { id: "iot", label: "Local and estate assets", x: 680, y: 650, color: "var(--warn)", nodes: [] },
      cloud:   { id: "cloud", label: "External destinations", x: 1060, y: 440, color: "var(--brand)", nodes: [] },
      threats: { id: "threats", label: "Isolated & Flagged Hosts", x: 1060, y: 170, color: "var(--crit)", nodes: [] }
    };

    nodes.forEach(function (n) {
      var k = getClusterCategory(n);
      if (clusters[k]) clusters[k].nodes.push(n);
      else clusters.cloud.nodes.push(n);
    });

    var pos = {};
    var clusterHulls = [];

    Object.keys(clusters).forEach(function (ck) {
      var c = clusters[ck];
      if (!c.nodes.length) return;

      var nMembers = c.nodes.length;
      var orbitR = Math.min(170, Math.max(50, Math.round(Math.sqrt(nMembers) * 36)));
      
      clusterHulls.push({
        id: c.id,
        label: c.label,
        color: c.color,
        x: c.x,
        y: c.y,
        r: orbitR + 40,
        count: nMembers
      });

      c.nodes.forEach(function (n, idx) {
        if (state.topoCustomPos[n.id]) {
          pos[n.id] = {
            x: state.topoCustomPos[n.id].x,
            y: state.topoCustomPos[n.id].y,
            r: nMembers === 1 ? 12 : (n.is_managed ? 10 : 8),
            cluster: ck
          };
          return;
        }

        if (nMembers === 1) {
          pos[n.id] = { x: c.x, y: c.y, r: 12, cluster: ck };
          return;
        }

        var angle = (idx / nMembers) * Math.PI * 2 - (Math.PI / 2);
        var dist = (idx % 2 === 0) ? orbitR : orbitR * 0.72;
        pos[n.id] = {
          x: Math.round(c.x + Math.cos(angle) * dist),
          y: Math.round(c.y + Math.sin(angle) * dist),
          r: n.is_managed ? 10 : 8,
          cluster: ck
        };
      });
    });

    return { pos: pos, width: W, height: H, clusters: clusterHulls };
  }

  function nodeKind(n) {
    if (n.is_isolated) return "isolated";
    if (n.type === "threat") return "threat";
    if (n.type === "gateway") return "gateway";
    if (n.type === "managed") return "managed";
    return "unmanaged";
  }

  function nodeLabelFor(nodes, id) {
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].id === id) return nodes[i].label || id;
    }
    return id;
  }

  /* ------------------------------------------------------------ topo view */

  /* Five hundred nodes and four hundred edges drawn as circles on rings is a
     picture of a network, not a view of one: everything is on screen and
     nothing can be read. So the graph is reduced before it is drawn.

     By default it answers the question a topology page is actually for - which
     parts of the estate talk to which other parts - by collapsing hosts into
     the segment they sit in and drawing traffic between segments. Traffic
     inside a segment is a count on the box, because "these forty machines in
     one subnet talk to each other" is the expected case, and drawing it is
     what produced the dot cloud.

     Nothing is hidden. The header says exactly what was collapsed and what was
     left out, every control is on the page, and a segment opens to its hosts. */

  var TOPO_HOST_CEILING = 80;

  /* A byte total on its own reads as a measurement of everything on a link.
     Usually it is not: a collector may report an unmeasured byte count. The
     figure is shown with the share of traffic it was actually taken from, and
     is replaced by the honest answer when that share is none. */
  function volume(b, flows, measured) {
    flows = Number(flows) || 0;
    measured = Number(measured) || 0;
    if (!measured) return flows ? "not measured on any of these " + flows + " flow(s)" : "\u2014";
    if (measured < flows) return bytes(b) + ", measured on " + measured + " of " + flows + " flow(s)";
    return bytes(b);
  }

  function topoGroupKey(n, mode) {
    if (mode === "category") return n.group || (n.type === "threat" ? "External" : "Unclassified");
    if (mode === "kind") {
      return { managed: "Agented", unmanaged: "No agent", gateway: "Gateways",
               isolated: "Quarantined", threat: "External" }[nodeKind(n)] || "Other";
    }
    // Scope and estate membership come from the hub, never a second IP parser.
    return n.network_id || "unknown";
  }

  var TOPO_RISK_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, CLEAN: 0 };

  /* A host worth drawing on its own even when everything else is collapsed. */
  function topoNotable(n, hotIDs) {
    return !!n.is_isolated || n.type === "threat" ||
      (TOPO_RISK_ORDER[n.risk] || 0) >= 3 || hotIDs[n.id] === true;
  }

  function buildTopoView(nodes, edges) {
    var mode = state.topoGroupBy || "subnet";

    /* Hosts on a blocked or unusual link. Those edges are the reason a security
       graph exists, so their endpoints survive every reduction. */
    var hot = {};
    edges.forEach(function (e) {
      if (e.verdict === "blocked" || e.verdict === "anomalous") { hot[e.source] = true; hot[e.target] = true; }
    });

    if (state.topoScope === "hosts") {
      var subset = nodes, note = "";
      if (state.topoDrill) {
        subset = nodes.filter(function (n) { return topoGroupKey(n, mode) === state.topoDrill; });
        note = "The " + subset.length + " host(s) in " + state.topoDrill + ", and the traffic between them.";
      } else if (state.topoFocus !== "all") {
        subset = nodes.filter(function (n) { return topoNotable(n, hot); });
        note = "The " + subset.length + " host(s) that are quarantined, high risk, external, or on a blocked or unusual link. " +
          (nodes.length - subset.length) + " ordinary host(s) are not drawn.";
      } else {
        note = "Every host the graph knows about: " + nodes.length + ".";
      }

      /* Past the ceiling the circles overlap into a band that can be neither
         read nor clicked, which is what this page used to do. Rather than
         refuse - a page that draws nothing is no more use than one that draws
         everything - it keeps the hosts worth looking at, fills the rest with
         the busiest, and says exactly how many were left out. */
      var drawn = subset;
      if (subset.length > TOPO_HOST_CEILING) {
        var weight = {};
        edges.forEach(function (e) {
          var f = Number(e.flow_count) || 0;
          weight[e.source] = (weight[e.source] || 0) + f;
          weight[e.target] = (weight[e.target] || 0) + f;
        });
        drawn = subset.slice().sort(function (a, b) {
          var na = topoNotable(a, hot) ? 0 : 1, nb = topoNotable(b, hot) ? 0 : 1;
          if (na !== nb) return na - nb;
          return (weight[b.id] || 0) - (weight[a.id] || 0);
        }).slice(0, TOPO_HOST_CEILING);
        note += " More than " + TOPO_HOST_CEILING + " circles cannot be told apart, so this is the " + drawn.length +
          " that matter most - everything quarantined, high risk, external or on a blocked link first, then the busiest. " +
          (subset.length - drawn.length) + " quieter host(s) are not drawn.";
      }

      var keep = {};
      drawn.forEach(function (n) { keep[n.id] = true; });
      return {
        nodes: drawn, grouped: false, note: note,
        edges: edges.filter(function (e) { return keep[e.source] && keep[e.target]; })
      };
    }

    /* ---- collapsed to segments ----------------------------------------- */
    var groups = {}, keyOf = {};
    nodes.forEach(function (n) {
      var k = topoGroupKey(n, mode);
      keyOf[n.id] = k;
      var g = groups[k];
      if (!g) {
        g = groups[k] = {
          label: mode === "subnet" ? (n.network_label || "Address unknown") : k, members: [], risk: "CLEAN", managed: 0, unmanaged: 0,
          isolated: 0, threat: 0, quietAll: true,
          internalFlows: 0, internalBytes: 0, internalMeasured: 0
        };
      }
      g.members.push(n);
      if ((TOPO_RISK_ORDER[n.risk] || 0) > (TOPO_RISK_ORDER[g.risk] || 0)) g.risk = n.risk;
      if (n.is_isolated) g.isolated++;
      if (n.type === "threat") g.threat++;
      if (n.type === "managed") g.managed++; else g.unmanaged++;
      if (!n.quiet) g.quietAll = false;
    });

    var gEdges = {};
    edges.forEach(function (e) {
      var a = keyOf[e.source], b = keyOf[e.target];
      if (a === undefined || b === undefined) return;
      if (a === b) {
        groups[a].internalFlows += Number(e.flow_count) || 0;
        groups[a].internalBytes += Number(e.total_bytes) || 0;
        groups[a].internalMeasured += Number(e.measured_flows) || 0;
        return;
      }
      var lo = a < b ? a : b, hi = a < b ? b : a;
      var id = "grp:" + lo + " grp:" + hi;
      var ge = gEdges[id];
      if (!ge) {
        ge = gEdges[id] = {
          source: "grp:" + lo, target: "grp:" + hi, flow_count: 0, total_bytes: 0,
          measured_flows: 0, verdict: "clean", port: 0, ports: [], pairs: 0
        };
      }
      ge.flow_count += Number(e.flow_count) || 0;
      ge.total_bytes += Number(e.total_bytes) || 0;
      ge.measured_flows += Number(e.measured_flows) || 0;
      ge.pairs++;
      if (e.verdict === "blocked") ge.verdict = "blocked";
      else if (e.verdict === "anomalous" && ge.verdict !== "blocked") ge.verdict = "anomalous";
      arrayOf(e.ports).forEach(function (ps) { ge.ports.push(ps); });
      if (!ge.port) ge.port = e.port;
    });

    var gNodes = Object.keys(groups).sort().map(function (k) {
      var g = groups[k];
      return {
        id: "grp:" + k, label: g.label + " (" + g.members.length + ")",
        type: g.threat ? "threat" : (g.managed >= g.unmanaged ? "managed" : "unmanaged"),
        ip: "", os: "", role: "", risk: g.risk, group: g.label, evidence: [],
        estate_member: g.members.some(function (n) { return n.estate_member; }),
        address_scope: g.members[0].address_scope, network_id: k, network_label: g.label,
        is_isolated: g.isolated > 0 && g.isolated === g.members.length,
        quiet: g.quietAll, _group: g
      };
    });

    var bundled = Object.keys(gEdges).length;
    return {
      nodes: gNodes, edges: Object.keys(gEdges).sort().map(function (k) { return gEdges[k]; }),
      grouped: true,
      note: nodes.length + " hosts collapsed into " + gNodes.length + " segment(s); " +
        edges.length + " link(s) bundled into " + bundled + ". Traffic inside a segment is counted on the segment rather than drawn. Click one to look inside."
    };
  }

  function topoControls() {
    var bar = h("div", { cls: "topo-bar" });
    var reset = function () { state.topoAuto = false; state.topoSelected = ""; state.topoEdgeSelected = ""; };

    if (state.topoDrill) {
      bar.appendChild(h("button", {
        cls: "mini", type: "button", text: "← All segments",
        on: { click: function () { state.topoDrill = ""; state.topoScope = "groups"; reset(); render(); } }
      }));
      bar.appendChild(h("span", { cls: "crumb", text: state.topoDrill }));
    } else {
      [["groups", "Segments"], ["hosts", "Hosts"]].forEach(function (o) {
        bar.appendChild(h("button", {
          cls: state.topoScope === o[0] ? "mini mini-on" : "mini", type: "button", text: o[1],
          "aria-pressed": state.topoScope === o[0] ? "true" : "false",
          on: { click: function () { state.topoScope = o[0]; reset(); render(); } }
        }));
      });
    }

    bar.appendChild(h("span", { cls: "sep" }));
    bar.appendChild(h("span", { cls: "bar-label", text: "Group by" }));
    [["subnet", "Subnet"], ["category", "Category"], ["kind", "Coverage"]].forEach(function (o) {
      bar.appendChild(h("button", {
        cls: state.topoGroupBy === o[0] ? "mini mini-on" : "mini", type: "button", text: o[1],
        "aria-pressed": state.topoGroupBy === o[0] ? "true" : "false",
        on: { click: function () { state.topoGroupBy = o[0]; state.topoDrill = ""; reset(); render(); } }
      }));
    });

    if (state.topoScope === "hosts" && !state.topoDrill) {
      bar.appendChild(h("span", { cls: "sep" }));
      [["notable", "Worth looking at"], ["all", "Everything"]].forEach(function (o) {
        bar.appendChild(h("button", {
          cls: state.topoFocus === o[0] ? "mini mini-on" : "mini", type: "button", text: o[1],
          "aria-pressed": state.topoFocus === o[0] ? "true" : "false",
          on: { click: function () { state.topoFocus = o[0]; reset(); render(); } }
        }));
      });
    }

    bar.appendChild(h("span", { cls: "sep" }));
    bar.appendChild(h("button", {
      cls: "mini", type: "button", text: "Reset layout",
      title: "Reset custom node positions back to smart clusters",
      on: {
        click: function () {
          state.topoCustomPos = {};
          render();
        }
      }
    }));
    return bar;
  }

  /* The hub sends a ratio, not a rounded display value. Pasting it straight
     into the page printed "10.256410256410255%". */
  function pct(v) {
    var n = Number(v) || 0;
    return (n >= 10 || n === 0 ? Math.round(n) : Math.round(n * 10) / 10) + "%";
  }

  function measuredStat(m) {
    var total = Number(m.total_flow_count) || 0;
    var meas = Number(m.measured_flow_count) || 0;
    if (!total) return { label: "Byte counts", value: "\u2014" };
    var pct = Math.round((meas / total) * 100);
    return {
      label: "Flows with byte counts",
      value: (pct === 0 && meas > 0 ? "<1" : String(pct)) + "%",
      tone: pct >= 95 ? "" : "warn"
    };
  }

  function renderTopology() {
    var view = $("view");
    var data = state.topology;
    clear(view);

    if (!data || !arrayOf(data.nodes).length) {
      view.appendChild(h("div", { cls: "empty", text: state.loading ? "Loading graph\u2026" : "No flow recorded in this window." }));
      return;
    }

    if (state.topoAuto) {
      var count = arrayOf(data.nodes).length;
      state.topoScope = count > TOPO_HOST_CEILING ? "groups" : "hosts";
      state.topoFocus = count > TOPO_HOST_CEILING ? "notable" : "all";
    }

    var reduced = buildTopoView(arrayOf(data.nodes), arrayOf(data.edges));
    var nodes = reduced.nodes;
    var edges = reduced.edges;

    view.appendChild(topoControls());
    view.appendChild(h("p", { cls: "topo-note", text: reduced.note }));
    if (!nodes.length) {
      view.appendChild(emptyBox("Nothing left to draw with this filter."));
      return;
    }

    var layout = layoutTopology(nodes, edges);
    var pos = layout.pos;

    var maxFlow = Math.max.apply(null, edges.map(function (e) { return Number(e.flow_count) || 1; }).concat([1]));

    /* role="img" removes every descendant from the accessibility tree, and this
       one contains dozens of clickable nodes - the graph announced itself as a
       single picture and the hosts inside it did not exist. It is a group of
       controls, so it is described as one. */
    var svg = s("svg", { viewBox: "0 0 " + layout.width + " " + layout.height, preserveAspectRatio: "xMidYMid meet", role: "group", "aria-label": "Communications topology" });

    /* Aggregate to asset-pair edges and label only the heaviest port per pair;
       labelling every 5-tuple is what makes these graphs unreadable. */
    var pairs = {};
    edges.forEach(function (e) {
      var a = e.source < e.target ? e.source : e.target;
      var b = e.source < e.target ? e.target : e.source;
      var id = a + "\u0000" + b;
      var p = pairs[id];
      if (!p) {
        p = pairs[id] = { id: id, source: a, target: b, flow: 0, bytes: 0, measured: 0, verdict: "clean", topPort: e.port, topFlow: 0, ports: {} };
      }
      p.flow += Number(e.flow_count) || 0;
      p.bytes += Number(e.total_bytes) || 0;
      p.measured += Number(e.measured_flows) || 0;
      if (e.verdict === "blocked") p.verdict = "blocked";
      else if (e.verdict === "anomalous" && p.verdict !== "blocked") p.verdict = "anomalous";
      if ((Number(e.flow_count) || 0) >= p.topFlow) { p.topFlow = Number(e.flow_count) || 0; p.topPort = e.port; }

      /* The hub aggregates to the asset pair and hands the ports over with
         it, so the graph can stay one line per pair and still answer "which
         ports" without another round trip. */
      arrayOf(e.ports).forEach(function (ps) {
        var k = (ps.protocol || "TCP") + "/" + ps.port;
        var slot = p.ports[k] || (p.ports[k] = { port: ps.port, protocol: ps.protocol || "TCP", flow: 0, bytes: 0, measured: 0, verdict: "clean" });
        slot.flow += Number(ps.flow_count) || 0;
        slot.bytes += Number(ps.total_bytes) || 0;
        slot.measured += Number(ps.measured_flows) || 0;
        if (ps.verdict && ps.verdict !== "clean") slot.verdict = ps.verdict;
      });
    });

    var clusterLayer = s("g", { "class": "cluster-layer" });
    if (layout.clusters && layout.clusters.length) {
      layout.clusters.forEach(function (c) {
        var rx = Math.max(80, c.r * 1.15);
        var ry = Math.max(65, c.r * 0.95);
        clusterLayer.appendChild(s("ellipse", {
          "class": "cluster-hull",
          cx: c.x, cy: c.y, rx: rx, ry: ry
        }));
        clusterLayer.appendChild(s("text", {
          "class": "cluster-label",
          x: c.x, y: c.y - ry + 16,
          "text-anchor": "middle",
          text: c.label + " (" + c.count + ")"
        }));
      });
    }

    var edgeLayer = s("g", { "class": "edge-layer" });
    var labelLayer = s("g", { "class": "label-layer" });

    /* Where the node circles and their captions will land. */
    var occupied = [];
    nodes.forEach(function (n) {
      var pt = pos[n.id];
      if (pt) occupied.push({ x0: pt.x - pt.r, x1: pt.x + pt.r, y0: pt.y - pt.r, y1: pt.y + pt.r });
    });

    var captionOrder = nodes.slice().sort(function (a, b) {
      var sa = a.id === state.topoSelected ? 0 : 1;
      var sb = b.id === state.topoSelected ? 0 : 1;
      if (sa !== sb) return sa - sb;
      var ka = nodeKind(a) === "unmanaged" ? 1 : 0;
      var kb = nodeKind(b) === "unmanaged" ? 1 : 0;
      if (ka !== kb) return ka - kb;
      return ((pos[b.id] && pos[b.id].r) || 0) - ((pos[a.id] && pos[a.id].r) || 0);
    });
    var showCaption = {};
    var captionBoxes = [];
    captionOrder.forEach(function (n) {
      var pt = pos[n.id];
      if (!pt) return;
      var text = n.label || n.id;
      var half = Math.max(pt.r, text.length * 2.6);
      var box = { x0: pt.x - half, x1: pt.x + half, y0: pt.y + pt.r + 4, y1: pt.y + pt.r + 15 };
      for (var i = 0; i < captionBoxes.length; i++) {
        var o = captionBoxes[i];
        if (box.x0 < o.x1 + 2 && box.x1 > o.x0 - 2 && box.y0 < o.y1 + 2 && box.y1 > o.y0 - 2) return;
      }
      captionBoxes.push(box);
      occupied.push(box);
      showCaption[n.id] = true;
    });
    function boxIsClear(box) {
      for (var i = 0; i < occupied.length; i++) {
        var o = occupied[i];
        if (box.x0 < o.x1 + 2 && box.x1 > o.x0 - 2 && box.y0 < o.y1 + 2 && box.y1 > o.y0 - 2) return false;
      }
      return true;
    }

    var pairFlows = Object.keys(pairs).map(function (k) { return pairs[k].flow; }).sort(function (x, y) { return y - x; });
    var labelFloor = pairFlows.length > 24 ? pairFlows[23] : 0;

    Object.keys(pairs).sort().forEach(function (id) {
      var p = pairs[id];
      var a = pos[p.source], b = pos[p.target];
      if (!a || !b) return;
      var w = 0.8 + (p.flow / maxFlow) * 2.6;
      var edgeEl = s("line", {
        "class": "edge", "data-verdict": p.verdict,
        "data-source": p.source,
        "data-target": p.target,
        "data-selected": state.topoEdgeSelected === id ? "true" : "false",
        x1: a.x, y1: a.y, x2: b.x, y2: b.y, "stroke-width": w.toFixed(2),
        on: {
          click: function (ev) {
            ev.stopPropagation();
            state.topoEdgeSelected = state.topoEdgeSelected === id ? "" : id;
            state.topoSelected = "";
            render();
          }
        }
      });
      edgeEl.appendChild(s("title", {
        text: nodeLabelFor(nodes, p.source) + " ↔ " + nodeLabelFor(nodes, p.target) + " (" + p.flow + " flows, " + volume(p.bytes, p.flow, p.measured) + ")"
      }));
      edgeLayer.appendChild(edgeEl);

      var lx = (a.x + b.x) / 2, ly = (a.y + b.y) / 2 - 3;
      var worthLabelling = id === state.topoEdgeSelected || p.flow >= labelFloor;
      if (p.topPort && worthLabelling) {
        var txt = String(p.topPort);
        var lhalf = txt.length * 2.6 + 1;
        var lbox = { x0: lx - lhalf, x1: lx + lhalf, y0: ly - 5, y1: ly + 3 };
        if (boxIsClear(lbox)) {
          occupied.push(lbox);
          labelLayer.appendChild(s("text", {
            "class": "elabel", x: lx, y: ly, "text-anchor": "middle",
            text: txt
          }));
        }
      }
    });

    var nodeLayer = s("g", { "class": "node-layer" });
    var activeDrag = null;

    function getSVGPoint(event, svgEl) {
      var pt = svgEl.createSVGPoint();
      pt.x = event.clientX;
      pt.y = event.clientY;
      var ctm = svgEl.getScreenCTM();
      return ctm ? pt.matrixTransform(ctm.inverse()) : { x: event.clientX, y: event.clientY };
    }

    svg.addEventListener("pointermove", function (ev) {
      if (!activeDrag) return;
      var pt = getSVGPoint(ev, svg);
      var nx = Math.round(pt.x - activeDrag.offX);
      var ny = Math.round(pt.y - activeDrag.offY);
      activeDrag.currX = nx;
      activeDrag.currY = ny;

      // Update node DOM circle & label
      activeDrag.circle.setAttribute("cx", nx);
      activeDrag.circle.setAttribute("cy", ny);
      if (activeDrag.label) {
        activeDrag.label.setAttribute("x", nx);
        activeDrag.label.setAttribute("y", ny + activeDrag.r + 11);
      }

      // Update connected edges
      var srcLines = svg.querySelectorAll('.edge[data-source="' + CSS.escape(activeDrag.nodeId) + '"]');
      for (var i = 0; i < srcLines.length; i++) {
        srcLines[i].setAttribute("x1", nx);
        srcLines[i].setAttribute("y1", ny);
      }
      var dstLines = svg.querySelectorAll('.edge[data-target="' + CSS.escape(activeDrag.nodeId) + '"]');
      for (var j = 0; j < dstLines.length; j++) {
        dstLines[j].setAttribute("x2", nx);
        dstLines[j].setAttribute("y2", ny);
      }
    });

    svg.addEventListener("pointerup", function (ev) {
      if (activeDrag) {
        state.topoCustomPos[activeDrag.nodeId] = { x: activeDrag.currX, y: activeDrag.currY };
        activeDrag = null;
      }
    });

    svg.addEventListener("pointercancel", function () {
      activeDrag = null;
    });

    nodes.forEach(function (n) {
      var pt = pos[n.id];
      if (!pt) return;

      /* Node kind was fill colour and nothing else, and --crit against
         --crit-hot at r=8px is about a five percent difference - the two most
         important states in the graph were the two hardest to tell apart. The
         label carries the same fact in words. */
      var kindWord = nodeKind(n);
      var nodeLabel = n._group
        ? n._group.label + ", " + n._group.members.length + " hosts, worst risk " + (n._group.risk || "clean")
        : (n.label || n.id) + (n.ip ? ", " + n.ip : "") + ", " + kindWord +
          (n.quiet ? ", quiet in this window" : "");

      var nodeGroup = s("g", {
        "class": "node-item",
        "data-node-id": n.id,
        role: "button",
        tabindex: "0",
        "aria-label": nodeLabel,
        "aria-pressed": state.topoSelected === n.id ? "true" : "false"
      });

      var circle = s("circle", {
        "class": "node", "data-kind": nodeKind(n),
        "data-selected": state.topoSelected === n.id ? "true" : "false",
        "data-quiet": n.quiet ? "true" : "false",
        cx: pt.x, cy: pt.y, r: pt.r
      });

      var titleEl = s("title", {
        text: n._group
          ? n._group.label + " · " + n._group.members.length + " host(s) · worst risk " + (n._group.risk || "CLEAN") + " · click to view"
          : (n.label || n.id) + " · " + (n.ip || "") +
            (n.role && n.role !== "unknown" ? " · " + n.role : "") +
            (n.quiet ? " · quiet in this window" : "") + " (Drag to move)"
      });
      circle.appendChild(titleEl);
      nodeGroup.appendChild(circle);

      var lbl = null;
      if (showCaption[n.id]) {
        lbl = s("text", {
          "class": "nlabel", x: pt.x, y: pt.y + pt.r + 11, "text-anchor": "middle",
          text: n.label || n.id
        });
        nodeGroup.appendChild(lbl);
      }

      nodeGroup.addEventListener("pointerdown", function (ev) {
        if (ev.button !== 0) return;
        ev.stopPropagation();
        var p = getSVGPoint(ev, svg);
        activeDrag = {
          nodeId: n.id,
          circle: circle,
          label: lbl,
          r: pt.r,
          offX: p.x - pt.x,
          offY: p.y - pt.y,
          currX: pt.x,
          currY: pt.y
        };
        try { nodeGroup.setPointerCapture(ev.pointerId); } catch (e) {}
      });

      var selectNode = function () {
        state.topoSelected = n.id;
        state.topoEdgeSelected = "";
        render();
      };

      nodeGroup.addEventListener("click", function (ev) {
        if (activeDrag && (Math.abs(activeDrag.currX - pt.x) > 4 || Math.abs(activeDrag.currY - pt.y) > 4)) {
          return;
        }
        selectNode();
      });

      /* Tab reaches the node; Enter and Space act on it. The graph had no
         keyboard path to any host at all. */
      nodeGroup.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") {
          ev.preventDefault();
          selectNode();
        }
      });

      nodeLayer.appendChild(nodeGroup);
    });

    svg.appendChild(clusterLayer);
    svg.appendChild(edgeLayer);
    svg.appendChild(nodeLayer);
    svg.appendChild(labelLayer);

    var sel = null;
    nodes.forEach(function (n) { if (n.id === state.topoSelected) sel = n; });

    var selEdge = state.topoEdgeSelected ? pairs[state.topoEdgeSelected] : null;

    var side = h("div", { cls: "topo-side" }, h("h4", { text: selEdge ? "Selected link" : "Selected node" }));
    if (selEdge) {
      /* Ports expand on selection rather than being drawn on every edge. */
      side.appendChild(h("dl", { cls: "kv" },
        h("dt", { text: "Between" }), h("dd", {}, h("b", { text: nodeLabelFor(nodes, selEdge.source) })),
        h("dt", { text: "and" }), h("dd", {}, h("b", { text: nodeLabelFor(nodes, selEdge.target) })),
        h("dt", { text: "Flows" }), h("dd", { text: String(selEdge.flow) }),
        h("dt", { text: "Volume" }), h("dd", { text: volume(selEdge.bytes, selEdge.flow, selEdge.measured) }),
        h("dt", { text: "Verdict" }), h("dd", { text: selEdge.verdict })));

      var portKeys = Object.keys(selEdge.ports).sort(function (a, b) {
        if (selEdge.ports[b].bytes !== selEdge.ports[a].bytes) return selEdge.ports[b].bytes - selEdge.ports[a].bytes;
        return selEdge.ports[b].flow - selEdge.ports[a].flow;
      });
      if (portKeys.length) {
        side.appendChild(h("h4", { text: "Ports on this link" }));
        var plist = h("div", { cls: "portlist" });
        portKeys.forEach(function (k) {
          var ps = selEdge.ports[k];
          plist.appendChild(h("span", {
            cls: "port", "data-risk": ps.verdict === "blocked" ? "CRITICAL" : "LOW",
            /* Flows, not "0 B", when nothing on this port was measured. */
            text: ps.port + " " + ps.protocol + " \u00b7 " +
              (ps.measured ? bytes(ps.bytes) : ps.flow + " flow(s)")
          }));
        });
        side.appendChild(plist);
      }
      side.appendChild(h("div", { cls: "detail-acts" },
        h("button", {
          cls: "mini", type: "button", text: "Clear selection",
          on: { click: function () { state.topoEdgeSelected = ""; render(); } }
        })));
    } else if (!sel) {
      side.appendChild(h("p", { cls: "pending", text: reduced.grouped
        ? "Click a segment to see what is in it, or a link to see the ports carrying traffic between two segments."
        : "Click a node, or a link to see its ports. Selection is shared with the Assets table \u2014 the graph is a lens, not a destination." }));
    } else if (sel._group) {
      /* A collapsed segment. The counts that were folded into the box are
         spelled out here, so nothing disappears by being grouped. */
      var g = sel._group;
      var out = Object.keys(pairs).map(function (k) { return pairs[k]; })
        .filter(function (pr) { return pr.source === sel.id || pr.target === sel.id; });
      side.appendChild(h("dl", { cls: "kv" },
        h("dt", { text: "Segment" }), h("dd", {}, h("b", { text: g.label })),
        h("dt", { text: "Hosts" }), h("dd", { text: String(g.members.length) }),
        h("dt", { text: "Agented" }), h("dd", { text: g.managed + " of " + g.members.length }),
        h("dt", { text: "Quarantined" }), h("dd", { text: String(g.isolated) }),
        h("dt", { text: "Worst risk" }), h("dd", { text: g.risk || "CLEAN" }),
        h("dt", { text: "Inside the segment" }), h("dd", { text: g.internalFlows + " flow(s), counted here rather than drawn \u00b7 " + volume(g.internalBytes, g.internalFlows, g.internalMeasured) }),
        h("dt", { text: "Segments reached" }), h("dd", {}, h("b", { text: String(out.length) })),
        h("dt", { text: "Flows out" }), h("dd", { text: String(out.reduce(function (t, pr) { return t + pr.flow; }, 0)) }),
        h("dt", { text: "Volume out" }), h("dd", { text: volume(
          out.reduce(function (t, pr) { return t + pr.bytes; }, 0),
          out.reduce(function (t, pr) { return t + pr.flow; }, 0),
          out.reduce(function (t, pr) { return t + pr.measured; }, 0)) })));
      side.appendChild(h("div", { cls: "detail-acts" },
        h("button", {
          cls: "mini", type: "button", text: "Open this segment",
          on: {
            click: function () {
              state.topoAuto = false;
              state.topoDrill = g.label; state.topoScope = "hosts";
              state.topoSelected = ""; state.topoEdgeSelected = ""; render();
            }
          }
        })));
    } else {
      var linked = Object.keys(pairs).map(function (k) { return pairs[k]; })
        .filter(function (p) { return p.source === sel.id || p.target === sel.id; });
      var kv = h("dl", { cls: "kv" },
        h("dt", { text: "Asset" }), h("dd", {}, h("b", { text: sel.label || sel.id })),
        h("dt", { text: "Address" }), h("dd", { text: sel.ip || "\u2014" }),
        h("dt", { text: "Identity" }), h("dd", { text: sel.os || "\u2014" }),
        h("dt", { text: "Role" }), h("dd", { text: (sel.role && sel.role !== "unknown" ? roleLabel(sel.role) : "\u2014") }),
        h("dt", { text: "Known by" }), h("dd", { text: arrayOf(sel.evidence).join(", ") || "flow only" }),
        h("dt", { text: "Risk" }), h("dd", { text: sel.risk || "\u2014" }),
        h("dt", { text: "In window" }), h("dd", { text: sel.quiet ? "quiet" : "active" }),
        h("dt", { text: "Peers" }), h("dd", {}, h("b", { text: String(linked.length) })),
        h("dt", { text: "Flows" }), h("dd", { text: String(linked.reduce(function (t, p) { return t + p.flow; }, 0)) }),
        h("dt", { text: "Volume" }), h("dd", { text: volume(
          linked.reduce(function (t, p) { return t + p.bytes; }, 0),
          linked.reduce(function (t, p) { return t + p.flow; }, 0),
          linked.reduce(function (t, p) { return t + p.measured; }, 0)) }));
      side.appendChild(kv);
      var asset = state.assetByKey[sel.id] || state.assets.filter(function (a) { return a.ip && a.ip === sel.ip; })[0];
      var acts = h("div", { cls: "detail-acts" });
      if (asset) {
        acts.appendChild(h("button", { cls: "mini", type: "button", text: "Open asset", on: { click: function () { openRoute(asset.key); } } }));
        acts.appendChild(h("button", {
          cls: "mini", type: "button", text: "Show in table",
          on: {
            click: function () {
              state.filters = {};
              state.query = asset.ip || asset.name;
              state.expandedKey = asset.key;
              state.cursorKey = asset.key;
              go("assets");
            }
          }
        }));
      } else {
        acts.appendChild(h("span", { cls: "pending", text: "Seen in traffic only \u2014 no asset record, no agent and no probe has reached this address." }));
      }
      side.appendChild(acts);
    }

    var legend = h("div", { cls: "legend" });
    [["managed", "agented"], ["unmanaged", "no agent"], ["gateway", "gateway"], ["isolated", "quarantined"], ["threat", "external threat"]]
      .forEach(function (pair) {
        legend.appendChild(h("span", {}, h("i", { "data-kind": pair[0] }), h("span", { text: pair[1] })));
      });
    legend.appendChild(h("span", {
      text: (reduced.grouped ? "one circle = one segment \u00b7 " : "one circle = one host \u00b7 ") +
        "edge width = flow volume \u00b7 dashed = blocked \u00b7 label = heaviest port per pair \u00b7 hollow = quiet in this window"
    }));

    view.appendChild(h("div", { cls: "topo" }, h("div", { cls: "topo-canvas" }, svg), side));
    view.appendChild(legend);
  }

  /* opts.onPick makes a row a filter control; opts.spark draws the per-item
     history the hub already returns on every RankingItem and the console threw
     away, so "top talker" can be read as "top talker, and rising". */
  function barList(items, valueFn, labelFn, textFn, opts) {
    opts = opts || {};
    var max = Math.max.apply(null, items.map(valueFn).concat([1]));
    var list = h("div", { cls: "barlist" });
    items.forEach(function (it) {
      var frac = Math.max(0, Math.min(1, valueFn(it) / max));
      var svg = s("svg", { viewBox: "0 0 118 8", preserveAspectRatio: "none", "aria-hidden": "true" });
      svg.appendChild(s("rect", { "class": "track", x: 0, y: 2, width: 118, height: 4, rx: 2 }));
      svg.appendChild(s("rect", { "class": "fill", x: 0, y: 2, width: (frac * 118).toFixed(1), height: 4, rx: 2 }));

      var spark = opts.spark && it.sparkline && it.sparkline.length > 1
        ? sparkline(it.sparkline.map(function (v) { return Number(v) || 0; }))
        : null;

      var label = labelFn(it);
      var name = opts.onPick
        ? h("button", {
            cls: "n n-pick", type: "button", text: label, title: "Filter on " + label,
            on: { click: function () { opts.onPick(it); } }
          })
        : h("span", { cls: "n", text: label, title: label });

      list.appendChild(h("div", { cls: "barrow" },
        name, svg, spark,
        h("span", { cls: "v", text: textFn(it) })));
    });
    return list;
  }

  /* --------------------------------- Process Lineage & Forensics Components */

  function processAttributionBadge(status) {
    var st = status || "unknown";
    var label = st;
    var tip = "Unknown process attribution confidence";
    if (st === "authoritative") {
      label = "authoritative";
      tip = "Authoritative process lineage and hash verified directly via OS kernel / ETW";
    } else if (st === "inferred_cached") {
      label = "inferred (cached)";
      tip = "Cryptographic hash inferred from stable filesystem inode / file ID LRU cache";
    } else if (st === "race_suspected") {
      label = "race suspected";
      tip = "Process exited or terminated rapidly before socket attribution completed; zero lineage invented";
    } else if (st === "permission_denied") {
      label = "permission denied";
      tip = "OS security boundaries prevented process descriptor or token inspection";
    }
    return h("span", { cls: "attribution-badge", "data-status": st, title: tip },
      h("span", { text: label }));
  }

  function processHashBadge(hash, onSearch) {
    if (!hash) return null;
    var short = hash.length > 16 ? (hash.slice(0, 8) + "…" + hash.slice(-6)) : hash;
    var nodes = [
      h("span", { cls: "hash-text", text: short, title: hash }),
      h("button", {
        cls: "btn-icon-mini", type: "button", title: "Copy SHA-256 Digest (" + hash + ")",
        on: {
          click: function (e) {
            e.stopPropagation();
            copyText(hash, "executable SHA-256");
          }
        }
      }, icon("i-copy"))
    ];
    if (typeof onSearch === "function") {
      nodes.push(h("button", {
        cls: "btn-icon-mini", type: "button", title: "Filter Fleet Telemetry by this SHA-256",
        on: {
          click: function (e) {
            e.stopPropagation();
            onSearch(hash);
          }
        }
      }, icon("i-search")));
    }
    return h("span", { cls: "hash-badge" }, nodes);
  }

  function processLineageTree(item) {
    var tree = h("div", { cls: "process-lineage-tree" });
    var hasParent = !!(item.parent_pid || item.parent_process_instance_id);

    // Parent Node
    var parentNode;
    if (hasParent) {
      parentNode = h("div", { cls: "lineage-node parent-node" },
        h("div", { cls: "lineage-node-header" },
          h("span", { cls: "lineage-role", text: "Parent Process" }),
          h("span", { cls: "lineage-pid", text: "PPID " + (item.parent_pid || "—") })),
        item.parent_process_instance_id
          ? h("div", { cls: "lineage-instance-id", text: item.parent_process_instance_id, title: "Parent Process Instance ID: " + item.parent_process_instance_id })
          : h("div", { cls: "lineage-dim", text: "(Parent exited before start time verification — zero false state invented)" }));
    } else {
      parentNode = h("div", { cls: "lineage-node parent-node muted" },
        h("div", { cls: "lineage-node-header" },
          h("span", { cls: "lineage-role", text: "Parent Process" }),
          h("span", { cls: "lineage-dim", text: "Root or Ancestor terminated prior to observation" })));
    }

    // Tree branch connector
    var connector = h("div", { cls: "lineage-tree-connector", "aria-hidden": "true" },
      h("span", { cls: "connector-glyph", text: "↳" }));

    // Child Node
    var childNode = h("div", { cls: "lineage-node child-node" },
      h("div", { cls: "lineage-node-header" },
        h("span", { cls: "lineage-role", text: "Observed Process" }),
        h("span", { cls: "lineage-pid", text: "PID " + (item.process_id || item.pid || "—") }),
        processAttributionBadge(item.attribution_status)),
      (item.process_path || item.process_name)
        ? h("div", { cls: "lineage-path", text: item.process_path || item.process_name })
        : null,
      item.process_instance_id
        ? h("div", { cls: "lineage-instance-id", text: item.process_instance_id, title: "Process Instance ID: " + item.process_instance_id })
        : null);

    tree.appendChild(parentNode);
    tree.appendChild(connector);
    tree.appendChild(childNode);
    return tree;
  }

  function commandLineInspector(cmdline) {
    if (!cmdline) {
      return h("div", { cls: "dim u-italic", text: "No command line arguments captured for this process." });
    }
    return h("div", { cls: "cmdline-inspector-wrap" },
      h("div", { cls: "cmdline-inspector-head" },
        h("span", { cls: "dim-3", text: "Full Execution Command Line" }),
        h("button", {
          cls: "btn mini", type: "button", text: "Copy Command",
          on: { click: function () { copyText(cmdline, "command line"); } }
        })),
      h("pre", { cls: "cmdline-box" }, h("code", { text: cmdline })));
  }

  function openEventInspectionSheet(item) {
    var action = item.action || "PERMIT";
    var direction = item.direction || "OUTBOUND";
    var proto = item.proto_name || (item.protocol === 6 ? "TCP" : item.protocol === 17 ? "UDP" : String(item.protocol || "IP"));
    var epID = item.endpoint_id || "—";

    var headGroup = h("div", { cls: "drawer-kv-group" },
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Verdict & Direction" }),
        h("div", { cls: "uf uf-g2" },
          h("span", { cls: "st", "data-state": action === "BLOCK" ? "crit" : "ok", text: action }),
          h("span", { cls: "dim-3", text: direction }))),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Timestamp" }),
        h("span", { cls: "drawer-kv-val", text: item.timestamp ? String(item.timestamp) : "—" })),
      item.observed_at ? h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Observed At (Host Clock)" }),
        h("span", { cls: "drawer-kv-val", text: String(item.observed_at) })) : null,
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Endpoint" }),
        h("span", { cls: "drawer-kv-val", text: epID })),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Transport / Protocol" }),
        h("span", { cls: "drawer-kv-val", text: proto + (item.layer ? " (" + item.layer + ")" : "") })),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Source Socket" }),
        h("span", { cls: "drawer-kv-val", text: (item.src_ip || "—") + (item.src_port ? ":" + item.src_port : "") })),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Destination Socket" }),
        h("span", { cls: "drawer-kv-val", text: (item.dst_ip || "—") + (item.dst_port ? ":" + item.dst_port : "") })),
      item.domain ? h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Queried Domain" }),
        h("span", { cls: "drawer-kv-val", text: item.domain })) : null,
      (item.bytes_in || item.bytes_out) ? h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Traffic Volume" }),
        h("span", { cls: "drawer-kv-val", text: bytes(item.bytes_in) + " in / " + bytes(item.bytes_out) + " out" })) : null);

    var treeCard = card("Process Hierarchy & Instance Identity", processLineageTree(item));

    var binRows = [
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Process Path" }),
        h("span", { cls: "drawer-kv-val", text: item.process_path || item.process_name || "—" })),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "User Principal" }),
        h("span", { cls: "drawer-kv-val", text: item.user_identity || "—" })),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Attribution Status" }),
        processAttributionBadge(item.attribution_status))
    ];
    if (item.executable_sha256) {
      binRows.push(h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Executable SHA-256" }),
        processHashBadge(item.executable_sha256, function (hsh) {
          closeSheet();
          state.section = "traffic";
          state.trafficFilter = state.trafficFilter || {};
          state.trafficFilter.hash = hsh;
          refresh();
        })));
    }
    var binGroup = h("div", { cls: "drawer-kv-group" }, binRows);
    var binCard = card("Binary Provenance & Cryptographic Signature", binGroup);

    var cmdCard = card("Command Line Execution Arguments", commandLineInspector(item.command_line));

    var body = h("div", { cls: "stack uf-g4" },
      headGroup,
      treeCard,
      binCard,
      cmdCard);

    var actions = [];
    if (item.executable_sha256) {
      actions.push(h("button", {
        cls: "btn btn-primary", type: "button", text: "Filter Fleet by Hash",
        on: {
          click: function () {
            closeSheet();
            state.section = "traffic";
            state.trafficFilter = state.trafficFilter || {};
            state.trafficFilter.hash = item.executable_sha256;
            refresh();
          }
        }
      }));
    }
    if (item.user_identity) {
      actions.push(h("button", {
        cls: "btn", type: "button", text: "Filter by User (" + item.user_identity + ")",
        on: {
          click: function () {
            closeSheet();
            state.section = "traffic";
            state.trafficFilter = state.trafficFilter || {};
            state.trafficFilter.user = item.user_identity;
            refresh();
          }
        }
      }));
    }
    if (item.process_name || item.process_path) {
      var procName = item.process_name || (item.process_path ? item.process_path.split("/").pop() : "");
      actions.push(h("button", {
        cls: "btn", type: "button", text: "Filter by Process (" + procName + ")",
        on: {
          click: function () {
            closeSheet();
            state.section = "traffic";
            state.trafficFilter = state.trafficFilter || {};
            state.trafficFilter.process = procName;
            refresh();
          }
        }
      }));
    }
    actions.push(h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }));

    openSheet("Process Forensics & Event Inspection", body, actions, "sheet-forensics");
  }

  function renderTraffic() {
    var view = $("view");
    clear(view);

    var ov = state.trafficOverview || {};
    var flowsData = state.trafficFlows || {};
    var tf = state.trafficFilter || { range: "1h" };

    // 1. Filter Bar
    var rangeButtons = ["15m", "1h", "6h", "24h", "7d", "all"].map(function (r) {
      var active = (tf.range || "1h") === r;
      return h("button", {
        cls: "btn mini" + (active ? " btn-primary" : ""),
        type: "button",
        /* The class alone was the whole answer to "which window am I looking
           at", and it was drawing nothing; this states it to a reader who
           cannot see the colour either way. */
        "aria-pressed": active ? "true" : "false",
        text: r.toUpperCase(),
        on: {
          click: function () {
            tf.range = r;
            tf.cursor = "";
            refresh();
          }
        }
      });
    });

    var chips = [];
    if (tf.endpoint_id) {
      chips.push(filterChip("Endpoint: " + tf.endpoint_id, function () { delete tf.endpoint_id; refresh(); }));
    }
    if (tf.dst_ip) {
      chips.push(filterChip("Dest: " + tf.dst_ip, function () { delete tf.dst_ip; refresh(); }));
    }
    if (tf.process) {
      chips.push(filterChip("Process: " + tf.process, function () { delete tf.process; refresh(); }));
    }
    if (tf.domain) {
      chips.push(filterChip("Domain: " + tf.domain, function () { delete tf.domain; refresh(); }));
    }
    if (tf.protocol) {
      chips.push(filterChip("Proto: " + tf.protocol, function () { delete tf.protocol; refresh(); }));
    }
    if (tf.action) {
      chips.push(filterChip("Action: " + tf.action, function () { delete tf.action; refresh(); }));
    }
    if (tf.hash) {
      chips.push(filterChip("Hash: " + tf.hash.slice(0, 10) + "…", function () { delete tf.hash; refresh(); }));
    }
    if (tf.user) {
      chips.push(filterChip("User: " + tf.user, function () { delete tf.user; refresh(); }));
    }
    if (tf.attribution) {
      chips.push(filterChip("Attribution: " + tf.attribution, function () { delete tf.attribution; refresh(); }));
    }

    var measuredCheck = h("label", { cls: "traffic-chip u-pointer" },
      h("input", {
        type: "checkbox",
        checked: !!tf.measured_only,
        on: {
          change: function (e) {
            tf.measured_only = e.target.checked;
            tf.cursor = "";
            refresh();
          }
        }
      }),
      h("span", { text: " Measured bytes only" }));

    var filterBar = h("div", { cls: "traffic-filter-bar" },
      h("div", { cls: "traffic-filter-group" }, rangeButtons),
      h("div", { cls: "traffic-chips" }, measuredCheck, chips));

    // 2. Measured Coverage Banner & Stat Cards
    var totalFlows = Number(ov.total_flows) || 0;
    var measuredFlows = Number(ov.measured_flows) || 0;
    var covPct = Math.round((Number(ov.measured_flow_coverage) || 0) * 100);

    var totals = ov.totals || {};
    var statsGrid = h("div", { cls: "dns-grid" },
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: bytes((Number(totals.bytes_in) || 0) + (Number(totals.bytes_out) || 0)) }),
        h("span", { cls: "dns-stat-label", text: "Total Volume (" + bytes(totals.bytes_in) + " in / " + bytes(totals.bytes_out) + " out)" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(totals.flow_count || totalFlows) }),
        h("span", { cls: "dns-stat-label", text: "Tracked Flow Events (" + covPct + "% Socket Measured)" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(totals.block_count || 0), "data-tone": totals.block_count ? "crit" : null }),
        h("span", { cls: "dns-stat-label", text: "Threat & Policy Block Drops" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(totals.anomaly_count || 0), "data-tone": totals.anomaly_count ? "warn" : null }),
        h("span", { cls: "dns-stat-label", text: "Anomalous Behavioral Detections" })));

    // 3. Dual Synchronized Time Lanes
    var trends = arrayOf(ov.trends);
    var dualChartCard;
    if (trends.length > 1) {
      var maxB = Math.max.apply(null, trends.map(function (p) {
        return Math.max(Number(p.bytes_in) || 0, Number(p.bytes_out) || 0);
      }).concat([1]));
      var maxF = Math.max.apply(null, trends.map(function (p) {
        return Number(p.flows) || 0;
      }).concat([1]));

      var n = trends.length;
      var W = 100;
      var slot = W / n;
      var barW = slot * 0.35;

      var svg = s("svg", { "class": "chart dual-chart-svg", viewBox: "0 0 " + W + " 150", preserveAspectRatio: "none", role: "img", "aria-label": "Dual synchronized traffic lanes" });

      /* An empty stretch of chart has two readings that look identical and mean
         opposite things: nothing was talking, or the hub has nothing from those
         minutes. retained_from is the oldest telemetry the hub still holds, so
         the part of the window that predates it is drawn as uncovered rather
         than as quiet, and said in words underneath. */
      var winStart = parseTime(ov.window_start);
      var winEnd = parseTime(ov.window_end);
      var retainedFrom = parseTime(ov.retained_from);
      var uncoveredTo = 0;
      if (winStart && winEnd && retainedFrom && retainedFrom.getTime() > winStart.getTime() && winEnd.getTime() > winStart.getTime()) {
        var span = winEnd.getTime() - winStart.getTime();
        var gap = Math.min(retainedFrom.getTime(), winEnd.getTime()) - winStart.getTime();
        uncoveredTo = Math.max(0, Math.min(W, (gap / span) * W));
      }
      if (uncoveredTo > 0) {
        svg.appendChild(s("rect", { "class": "chart-uncovered", x: 0, y: 10, width: uncoveredTo, height: 55 }));
        svg.appendChild(s("rect", { "class": "chart-uncovered", x: 0, y: 85, width: uncoveredTo, height: 55 }));
      }

      // Lane 1 (Top: Bandwidth In/Out) - y: 10 to 65
      // Lane 2 (Bottom: Flows / Blocks) - y: 85 to 140
      trends.forEach(function (p, i) {
        var x0 = i * slot + slot * 0.1;
        var bin = Number(p.bytes_in) || 0;
        var bout = Number(p.bytes_out) || 0;
        var flows = Number(p.flows) || 0;
        var blocks = Number(p.blocks) || 0;
        var anomalies = Number(p.anomalies) || 0;

        var hIn = bin ? Math.max(1, Math.round((bin / maxB) * 50)) : 0;
        var hOut = bout ? Math.max(1, Math.round((bout / maxB) * 50)) : 0;
        var hFlow = flows ? Math.max(1, Math.round((flows / maxF) * 45)) : 0;
        var hBlock = blocks ? Math.max(2, Math.round((blocks / maxF) * 45)) : 0;

        if (hIn) svg.appendChild(s("rect", { "class": "series-in", x: x0, y: 65 - hIn, width: barW, height: hIn }));
        if (hOut) svg.appendChild(s("rect", { "class": "series-out", x: x0 + barW + 0.2, y: 65 - hOut, width: barW, height: hOut }));
        if (hFlow) svg.appendChild(s("rect", { "class": "series-flow", fill: "var(--dim)", opacity: "0.4", x: x0, y: 140 - hFlow, width: barW * 2 + 0.2, height: hFlow }));
        if (hBlock) svg.appendChild(s("rect", { "class": "series-block", fill: "var(--crit)", x: x0, y: 140 - hBlock, width: barW * 2 + 0.2, height: hBlock }));

        /* Every trend point carries the detector's anomaly count for that
           bucket and the chart drew neither it nor any hint that it existed.
           A tick above the flow lane says "the detector fired here", which is
           the point at which an operator wants the flow table filtered. */
        if (anomalies) {
          svg.appendChild(s("rect", {
            "class": "series-anom", fill: "var(--warn)",
            x: x0, y: 78, width: barW * 2 + 0.2, height: 4
          }));
        }
      });

      svg.appendChild(s("line", { "class": "axis", x1: 0, y1: 66, x2: W, y2: 66, stroke: "var(--line)" }));
      svg.appendChild(s("line", { "class": "axis", x1: 0, y1: 141, x2: W, y2: 141, stroke: "var(--line)" }));

      var ticks = h("div", { cls: "chart-ticks" });
      var step = Math.max(1, Math.floor((trends.length - 1) / 5));
      for (var idx = 0; idx < trends.length; idx += step) {
        var p = trends[idx];
        var d = parseTime(p.timestamp);
        if (d) {
          var label = (tf.range === "7d" || tf.range === "all")
            ? (d.getMonth() + 1) + "/" + d.getDate() + " " + pad(d.getHours(), 2) + ":00"
            : pad(d.getHours(), 2) + ":" + pad(d.getMinutes(), 2);
          ticks.appendChild(h("span", { text: label }));
        }
      }
      if ((trends.length - 1) % step !== 0 && trends.length > 1) {
        var lastP = trends[trends.length - 1];
        var lastD = parseTime(lastP.timestamp);
        if (lastD) {
          var lastLabel = (tf.range === "7d" || tf.range === "all")
            ? (lastD.getMonth() + 1) + "/" + lastD.getDate() + " " + pad(lastD.getHours(), 2) + ":00"
            : pad(lastD.getHours(), 2) + ":" + pad(lastD.getMinutes(), 2);
          ticks.appendChild(h("span", { text: lastLabel }));
        }
      }

      /* Said in words as well as drawn, because the shading answers "how much of
         this window does the hub have" and nothing else on the card does. A
         window the hub covers in full and still has no bars in it is a quiet
         estate, and says so rather than leaving the reader to guess which of the
         two they are looking at. */
      var busy = trends.some(function (p) {
        return (Number(p.flows) || 0) || (Number(p.bytes_in) || 0) || (Number(p.bytes_out) || 0) || (Number(p.blocks) || 0);
      });
      var coverageNote = null;
      if (uncoveredTo > 0 && retainedFrom) {
        var floorLabel = (tf.range === "7d" || tf.range === "all")
          ? (retainedFrom.getMonth() + 1) + "/" + retainedFrom.getDate() + " " + pad(retainedFrom.getHours(), 2) + ":" + pad(retainedFrom.getMinutes(), 2)
          : pad(retainedFrom.getHours(), 2) + ":" + pad(retainedFrom.getMinutes(), 2);
        coverageNote = h("p", {
          cls: "chart-note", "data-tone": "warn",
          text: "Shaded: the hub retains no telemetry before " + floorLabel + ". This " + (tf.range || "1h")
            + " window is covered for " + spanText(winEnd.getTime() - retainedFrom.getTime())
            + " of " + spanText(winEnd.getTime() - winStart.getTime())
            + " \u2014 an empty lane on the left is missing data, not a quiet network."
        });
      } else if (!busy) {
        coverageNote = h("p", { cls: "chart-note", text: "The hub covers this whole window and recorded no flows in it." });
      }

      dualChartCard = card("Dual Synchronized Flow & Volume Timeline",
        h("div", { cls: "card-body" },
          h("div", { cls: "dual-timeline-container" },
            h("div", { cls: "dual-lane-label u-mb1 uf uf-between", text: "Lane 1: Bandwidth Volume (Top) · Lane 2: Event Counts (Bottom)" }),
            svg,
            ticks,
            coverageNote,
            h("div", { cls: "legend pad-x u-mt1" },
              h("span", { text: "■ Blue: Bytes In" }),
              h("span", { text: "■ Indigo: Bytes Out" }),
              h("span", { text: "■ Gray: Total Flows" }),
              h("span", { text: "■ Red: Block Drops" }),
              h("span", { text: "■ Amber: Detector Anomalies" }),
              h("span", { text: "Window: " + (tf.range || "1h") })))));
    } else {
      dualChartCard = card("Traffic Timeline", emptyBox("No timeline points captured in this window."));
    }

    // 4. Composition Breakdowns
    var dist = ov.distributions || {};
    var protoCards = card("Protocol Distribution",
      h("div", { cls: "card-body" },
        arrayOf(dist.protocols).length
          ? barList(dist.protocols, function (p) { return p.count; },
              function (p) { return p.label + " (" + Math.round(p.percentage * 100) + "%)"; },
              function (p) { return p.count + " flows · " + bytes(p.total_bytes); })
          : emptyBox("No protocols active.")));

    var actCards = card("Action Breakdown",
      h("div", { cls: "card-body" },
        arrayOf(dist.actions).length
          ? barList(dist.actions, function (a) { return a.count; },
              function (a) { return a.label + " (" + Math.round(a.percentage * 100) + "%)"; },
              function (a) { return a.count + " flows"; })
          : emptyBox("No action distribution.")));

    var dirCards = card("Direction Distribution",
      h("div", { cls: "card-body" },
        arrayOf(dist.directions).length
          ? barList(dist.directions, function (d) { return d.count; },
              function (d) { return d.label + " (" + Math.round(d.percentage * 100) + "%)"; },
              function (d) { return d.count + " flows"; })
          : emptyBox("No direction distribution.")));

    // 5. Multi-column Rankings
    var rankings = ov.rankings || {};

    /* top_endpoints and top_countries were computed on every overview and
       dropped: "which host is loudest" and "where is this estate talking to"
       are the two questions this page is opened with, and neither was on it. */
    var epCard = card("Top Talking Endpoints",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_endpoints).length
          ? barList(rankings.top_endpoints, function (e) { return e.total_bytes || e.flow_count; },
              function (e) { return e.label || e.key; },
              function (e) { return e.flow_count + " flows" + (e.total_bytes ? " \u00b7 " + bytes(e.total_bytes) : ""); },
              { spark: true, onPick: function (e) { tf.endpoint_id = e.key || e.label; refresh(); } })
          : emptyBox("No endpoint has reported a flow in this window.")));

    var ctryCard = card("Top Destination Countries",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_countries).length
          ? barList(rankings.top_countries, function (c) { return c.total_bytes || c.flow_count; },
              function (c) { return c.label || c.key; },
              function (c) { return c.flow_count + " flows" + (c.total_bytes ? " \u00b7 " + bytes(c.total_bytes) : ""); },
              { spark: true, onPick: function (c) { tf.country = c.key || c.label; refresh(); } })
          : emptyBox("No destination has been geolocated in this window.")));

    var procCard = card("Top Active Processes",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_processes).length
          ? barList(rankings.top_processes, function (p) { return p.total_bytes || p.flow_count; },
              function (p) { return p.label; },
              function (p) { return p.flow_count + " flows" + (p.total_bytes ? " · " + bytes(p.total_bytes) : ""); },
              { spark: true, onPick: function (p) { tf.process = p.label; refresh(); } })
          : emptyBox("No process attribution yet.")));

    var dstCard = card("Top Remote Destinations",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_destinations).length
          ? barList(rankings.top_destinations, function (d) { return d.total_bytes || d.flow_count; },
              function (d) { return d.label; },
              function (d) { return d.flow_count + " flows" + (d.total_bytes ? " · " + bytes(d.total_bytes) : ""); },
              { spark: true })
          : emptyBox("No destination data.")));

    var domCard = card("Top Queried Domains",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_domains).length
          ? barList(rankings.top_domains, function (d) { return d.flow_count; },
              function (d) { return d.label; },
              function (d) { return d.flow_count + " queries"; })
          : emptyBox("No domain queries.")));

    var portCard = card("Top Destination Ports",
      h("div", { cls: "card-body" },
        arrayOf(rankings.top_ports).length
          ? barList(rankings.top_ports, function (p) { return p.flow_count; },
              function (p) { return "Port " + p.label; },
              function (p) { return p.flow_count + " flows"; })
          : emptyBox("No port data.")));

    // 6. Live Filtered Flow Stream Table
    var flowsList = arrayOf(flowsData.flows);
    var flowRows = flowsList.map(function (f) {
      var isSelected = state.selectedFlow && state.selectedFlow.id === f.id;
      var procCell = [
        h("span", { cls: "dim", text: f.process_name || f.domain || "—", on: { click: function (e) { e.stopPropagation(); if (f.process_name) tf.process = f.process_name; refresh(); } } })
      ];
      if (f.attribution_status && f.attribution_status !== "unknown") {
        procCell.push(h("span", { cls: "u-ml2" }, processAttributionBadge(f.attribution_status)));
      }
      if (f.executable_sha256) {
        procCell.push(h("span", { cls: "u-ml2" }, processHashBadge(f.executable_sha256, function (hsh) { tf.hash = hsh; refresh(); })));
      }
      var verdict = f.is_anomalous
        ? h("span", { cls: "st", "data-state": "warn", title: "The detector flagged this flow" },
            icon("i-alert", true), h("span", { text: "anomalous" }))
        : h("span", { cls: "st", "data-state": f.action === "BLOCK" ? "crit" : "ok" },
            icon(f.action === "BLOCK" ? "g-quarantine" : "g-online", true),
            h("span", { text: f.action || "PERMIT" }));

      var row = [
        stamp(parseTime(f.timestamp)),
        verdict,
        h("span", { cls: "dim-3", text: f.direction || "OUT" }),
        h("span", { cls: "ip", text: f.endpoint_id || "—", on: { click: function (e) { e.stopPropagation(); tf.endpoint_id = f.endpoint_id; refresh(); } } }),
        h("span", { cls: "ip", text: f.src_ip + (f.src_port ? ":" + f.src_port : "") }),
        h("span", { cls: "ip", text: f.dst_ip + (f.dst_port ? ":" + f.dst_port : ""), on: { click: function (e) { e.stopPropagation(); tf.dst_ip = f.dst_ip; refresh(); } } }),
        h("span", { cls: "dim-3", text: f.proto_name || "TCP" }),
        h("div", { cls: "uf uf-wrap uf-g1" }, procCell),
        h("span", { cls: "ago", text: (Number(f.bytes_in) || 0) + (Number(f.bytes_out) || 0)
          ? bytes((Number(f.bytes_in) || 0) + (Number(f.bytes_out) || 0))
          : "—" })
      ];
      return row;
    });

    var flowsTable = flowRows.length
      ? simpleTable(["Time", "Action", "Dir", "Endpoint", "Source", "Destination", "Proto", "Process / Domain", "Volume"], flowRows)
      : emptyBox("No flow events match active filters.");

    // Make table rows interactive for drawer selection
    var tableEl = flowsTable.querySelector("tbody");
    if (tableEl) {
      var trs = tableEl.querySelectorAll("tr");
      trs.forEach(function (tr, idx) {
        tr.classList.add("flow-table-row");
        if (flowsList[idx] && state.selectedFlow && state.selectedFlow.id === flowsList[idx].id) {
          tr.classList.add("selected");
        }
        tr.addEventListener("click", function () {
          state.selectedFlow = flowsList[idx];
          renderBody();
        });
      });
    }

    var nextBtn = flowsData.next_cursor ? h("button", {
      cls: "btn mini btn-primary", type: "button", text: "Next Page →",
      on: { click: function () { tf.cursor = flowsData.next_cursor; refresh(); } }
    }) : null;
    var prevBtn = tf.cursor ? h("button", {
      cls: "btn mini", type: "button", text: "← First Page",
      on: { click: function () { tf.cursor = ""; refresh(); } }
    }) : null;

    var pagination = h("div", { cls: "actions pad-x" }, prevBtn, nextBtn);
    var flowStreamCard = card("Active Flow Telemetry (" + (flowsData.total || flowsList.length) + " matching events)",
      h("div", { cls: "stack" }, flowsTable, pagination));

    // 7. DNS Gateway & Threat Sinkhole Telemetry (Driven by real DNS APIs)
    var dnsStatus = state.dnsStatus || {};
    var dnsEventsList = arrayOf(state.dnsEvents);
    var dnsGrid = h("div", { cls: "card-body dns-grid" },
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(dnsStatus.state || "active").toUpperCase() }),
        h("span", { cls: "dns-stat-label", text: "DNS Gateway State" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(dnsStatus.queries_total || 0) }),
        h("span", { cls: "dns-stat-label", text: "RFC-53 Queries Handled" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: String(dnsStatus.blocked_total || 0), "data-tone": dnsStatus.blocked_total ? "crit" : null }),
        h("span", { cls: "dns-stat-label", text: "Domain Threat Drops (0.0.0.0)" })),
      h("div", { cls: "dns-stat-box" },
        h("span", { cls: "dns-stat-val", text: Math.round((Number(dnsStatus.cache_hit_ratio) || 0) * 100) + "%" }),
        h("span", { cls: "dns-stat-label", text: "RAM Cache Hit Ratio" })));

    var dnsRows = dnsEventsList.map(function (e) {
      return [
        stamp(parseTime(e.timestamp)),
        h("span", { cls: "st", "data-state": e.action === "BLOCK" ? "crit" : "ok" },
          icon(e.action === "BLOCK" ? "g-quarantine" : "g-online", true),
          h("span", { text: e.action || "PERMIT" })),
        h("span", { cls: "ip", text: e.client_ip || "—" }),
        h("span", { cls: "ip", text: e.domain || "—" }),
        h("span", { cls: "dim-3", text: (e.transport || "udp").toUpperCase() + " · " + (e.qtype || "A") }),
        h("span", { cls: "dim", text: (e.latency_us ? (e.latency_us / 1000).toFixed(2) + " ms" : "< 1 ms") + " · " + (e.status || "HIT") })
      ];
    });

    /* The rules behind the verdicts above. A blocked query with no visible rule
       is an unexplained block, which is how an operator ends up disabling the
       whole sinkhole to get a host working again. */
    var dnsPolicyRules = arrayOf(state.dnsPolicy);
    var dnsPolicyRows = dnsPolicyRules.map(function (r) {
      return [
        chip(r.action === "BLOCK" ? "crit" : "ok", r.action || "BLOCK"),
        h("span", { cls: "ip", text: r.domain || "—" }),
        h("span", { cls: "dim-3", text: r.source || "local" }),
        h("span", { cls: "dim", text: r.comment || "—" }),
        stamp(parseTime(r.created_at))
      ];
    });

    var dnsStreamCard = card("RFC-Compliant DNS Gateway & Threat Sinkhole",
      h("div", { cls: "stack" },
        dnsGrid,
        dnsRows.length
          ? simpleTable(["Time", "Verdict", "Client IP", "Queried Domain", "Proto/Type", "Latency & Cache"], dnsRows)
          : emptyBox("No DNS queries recorded."),
        h("div", { cls: "card-sub", text: "Sinkhole policy — " + dnsPolicyRules.length + " rule(s)" }),
        dnsPolicyRows.length
          ? simpleTable(["Verdict", "Domain", "Source", "Comment", "Added"], dnsPolicyRows,
              { empty: "No sinkhole rules configured — every query resolves upstream." })
          : emptyBox("No sinkhole rules configured — every query resolves upstream.")));

    /* The hub bins every flow by day-of-week and hour-of-day whenever the
       window is a day or longer, and the console never asked for the grid.
       "Is this host talking at 3am on a Sunday" is a beaconing question that
       the trend lane, which is one continuous line, cannot answer. */
    var heat = arrayOf(ov.heatmap);
    var heatCard;
    if (heat.length) {
      var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      var byCell = {};
      var heatMax = 0;
      heat.forEach(function (c) {
        var v = Number(c.total_bytes) || Number(c.flows) || 0;
        byCell[c.day_of_week + ":" + c.hour_of_day] = c;
        if (v > heatMax) heatMax = v;
      });

      var grid = h("div", { cls: "heatgrid", role: "table", "aria-label": "Flows by day and hour" });
      grid.appendChild(h("span", { cls: "heat-corner", "aria-hidden": "true" }));
      for (var hr = 0; hr < 24; hr++) {
        grid.appendChild(h("span", { cls: "heat-hour", text: hr % 3 === 0 ? pad(hr, 2) : "" }));
      }
      DAYS.forEach(function (dayName, day) {
        grid.appendChild(h("span", { cls: "heat-day", text: dayName }));
        for (var hour = 0; hour < 24; hour++) {
          var cell = byCell[day + ":" + hour];
          var flows = cell ? (Number(cell.flows) || 0) : 0;
          var vol = cell ? (Number(cell.total_bytes) || 0) : 0;
          var level = heatMax > 0 && (vol || flows)
            ? Math.min(4, Math.max(1, Math.ceil(((vol || flows) / heatMax) * 4)))
            : 0;
          grid.appendChild(h("span", {
            cls: "heat-cell", "data-level": String(level),
            title: dayName + " " + pad(hour, 2) + ":00 \u2014 " + flows + " flow" + (flows === 1 ? "" : "s") +
              (vol ? " \u00b7 " + bytes(vol) : "")
          }));
        }
      });

      heatCard = card("When This Estate Talks",
        h("div", { cls: "card-body" },
          grid,
          h("div", { cls: "legend u-mt1" },
            h("span", { text: "quiet" }),
            h("span", { cls: "heat-cell", "data-level": "1", "aria-hidden": "true" }),
            h("span", { cls: "heat-cell", "data-level": "2", "aria-hidden": "true" }),
            h("span", { cls: "heat-cell", "data-level": "3", "aria-hidden": "true" }),
            h("span", { cls: "heat-cell", "data-level": "4", "aria-hidden": "true" }),
            h("span", { text: "busiest" }))));
    } else {
      heatCard = card("When This Estate Talks",
        emptyBox("The hub bins the week only over a window of a day or more. Widen the range to see it."));
    }

    /* The diurnal pair is the whole point of the summary: the baseline is what
       this hour of the day normally looks like and the live curve is what it
       looks like now, and reading them apart is how "quiet Sunday 3am" becomes
       a finding rather than a feeling. */
    var an = state.analytics || {};
    var base = an.diurnal_baseline || {};
    var live = an.diurnal_live || {};
    var diurnalCard;
    if (Object.keys(base).length || Object.keys(live).length) {
      var hours = [];
      for (var dh = 0; dh < 24; dh++) hours.push(dh);
      var dMax = 1;
      hours.forEach(function (hour) {
        dMax = Math.max(dMax, Number(base[hour]) || 0, Number(live[hour]) || 0);
      });
      var dsvg = s("svg", { "class": "chart", viewBox: "0 0 120 60", preserveAspectRatio: "none", role: "img", "aria-label": "Estate event counts by UTC hour: last 24 hours and seven-day baseline" });
      var baseLine = [], liveLine = [];
      hours.forEach(function (hour, i) {
        var x = (i / 23) * 118 + 1;
        baseLine.push(x.toFixed(1) + "," + (55 - ((Number(base[hour]) || 0) / dMax) * 50).toFixed(1));
        liveLine.push(x.toFixed(1) + "," + (55 - ((Number(live[hour]) || 0) / dMax) * 50).toFixed(1));
      });
      dsvg.appendChild(s("polyline", { points: baseLine.join(" "), fill: "none", stroke: "var(--ink-3)", "stroke-width": "1", "stroke-dasharray": "3 2" }));
      dsvg.appendChild(s("polyline", { points: liveLine.join(" "), fill: "none", stroke: "var(--brand)", "stroke-width": "1.5" }));
      dsvg.appendChild(s("line", { x1: 0, y1: 56, x2: 120, y2: 56, stroke: "var(--line)" }));

      var dticks = h("div", { cls: "chart-ticks" });
      [0, 6, 12, 18, 23].forEach(function (hour) { dticks.appendChild(h("span", { text: pad(hour, 2) + ":00" })); });

      diurnalCard = card("Estate activity by UTC hour",
        h("div", { cls: "card-body" },
          h("p", {cls: "why", text: "Whole-estate comparison, independent of the traffic filters above. Event counts, not bytes."}), dsvg, dticks,
          h("div", { cls: "legend u-mt1" },
            h("span", { text: "\u2504 Grey: mean hourly events over the preceding seven days" }),
            h("span", { text: "\u2500 Blue: events in the last 24 hours" }))));
    } else {
      diurnalCard = card("Estate activity by UTC hour",
        emptyBox("The hub needs a day of history before it can say what normal looks like."));
    }

    // Assemble View
    view.appendChild(h("div", { cls: "pad stack traffic-workspace" },
      filterBar,
      statsGrid,
      dualChartCard,
      diurnalCard,
      heatCard,
      h("div", { cls: "distrib-grid" }, protoCards, actCards, dirCards),
      h("div", { cls: "cols" }, epCard, ctryCard),
      h("div", { cls: "cols" }, procCard, dstCard),
      h("div", { cls: "cols" }, domCard, portCard),
      dnsStreamCard,
      flowStreamCard));

    // Render Drawer if Flow is Selected
    if (state.selectedFlow) {
      var sel = state.selectedFlow;
      var drawer = h("div", { cls: "flow-drawer" },
        h("div", { cls: "drawer-header" },
          h("div", { cls: "stack" },
            h("b", { text: "Flow Investigation #" + (sel.id || sel.ID || "") }),
            h("span", { cls: "dim-3", text: sel.timestamp ? String(sel.timestamp) : "" })),
          h("div", { cls: "uf uf-g2" },
            h("button", {
              cls: "btn mini btn-primary", type: "button", text: "Forensics Sheet ↗",
              on: { click: function () { openEventInspectionSheet(sel); } }
            }),
            h("button", {
              cls: "btn mini", type: "button", text: "✕ Close",
              on: { click: function () { state.selectedFlow = null; renderBody(); } }
            }))),
        h("div", { cls: "drawer-body" },
          h("div", { cls: "drawer-kv-group" },
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Action Verdict" }), h("span", { cls: "st", "data-state": sel.action === "BLOCK" ? "crit" : "ok", text: sel.action || "PERMIT" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Direction" }), h("span", { cls: "drawer-kv-val", text: sel.direction || "OUTBOUND" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Protocol" }), h("span", { cls: "drawer-kv-val", text: (sel.proto_name || "TCP") + " (" + sel.protocol + ")" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Endpoint ID" }), h("span", { cls: "drawer-kv-val", text: sel.endpoint_id || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Source IP:Port" }), h("span", { cls: "drawer-kv-val", text: sel.src_ip + ":" + sel.src_port })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Destination IP:Port" }), h("span", { cls: "drawer-kv-val", text: sel.dst_ip + ":" + sel.dst_port })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Remote Country" }), h("span", { cls: "drawer-kv-val", text: sel.country || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Queried Domain" }), h("span", { cls: "drawer-kv-val", text: sel.domain || "—" })),
            /* The agent reports which collection layer saw the flow, the TLS
               server name it was opened for, the host it resolved through, and
               whether the detector called it anomalous. All four were in the
               payload and none of them were on the screen, which is most of
               what "why am I looking at this flow" means. */
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "TLS Server Name" }), h("span", { cls: "drawer-kv-val", text: sel.sni || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Reported Hostname" }), h("span", { cls: "drawer-kv-val", text: sel.hostname || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Collection Layer" }), h("span", { cls: "drawer-kv-val", text: sel.layer || "—" })),
            h("div", { cls: "drawer-kv-row" },
              h("span", { cls: "drawer-kv-label", text: "Detector Verdict" }),
              sel.is_anomalous
                ? h("span", { cls: "st", "data-state": "warn", text: "anomalous" })
                : h("span", { cls: "st", "data-state": "idle", text: "nothing flagged" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Bytes In / Out" }), h("span", { cls: "drawer-kv-val", text: bytes(sel.bytes_in) + " / " + bytes(sel.bytes_out) }))),

          // Process Lineage Hierarchy Tree
          h("div", { cls: "stack uf-g1" },
            h("span", { cls: "drawer-kv-label", text: "Process Lineage Tree" }),
            processLineageTree(sel)),

          // Process Provenance & Signature
          h("div", { cls: "drawer-kv-group" },
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Process Path" }), h("span", { cls: "drawer-kv-val", text: sel.process_path || sel.process_name || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "User Principal" }), h("span", { cls: "drawer-kv-val", text: sel.user_identity || "—" })),
            h("div", { cls: "drawer-kv-row" }, h("span", { cls: "drawer-kv-label", text: "Attribution Status" }), processAttributionBadge(sel.attribution_status)),
            sel.executable_sha256 ? h("div", { cls: "drawer-kv-row" },
              h("span", { cls: "drawer-kv-label", text: "Executable SHA-256" }),
              processHashBadge(sel.executable_sha256, function (hsh) { tf.hash = hsh; state.selectedFlow = null; refresh(); })) : null),

          // Command Line Inspector
          h("div", { cls: "stack uf-g1" },
            commandLineInspector(sel.command_line)),

          h("div", { cls: "drawer-actions" },
            h("button", {
              cls: "btn mini btn-primary", type: "button", text: "Filter by this Endpoint",
              on: { click: function () { tf.endpoint_id = sel.endpoint_id; state.selectedFlow = null; refresh(); } }
            }),
            h("button", {
              cls: "btn mini", type: "button", text: "Filter by this Destination IP",
              on: { click: function () { tf.dst_ip = sel.dst_ip; state.selectedFlow = null; refresh(); } }
            }),
            sel.executable_sha256 ? h("button", {
              cls: "btn mini", type: "button", text: "Filter by Executable Hash",
              on: { click: function () { tf.hash = sel.executable_sha256; state.selectedFlow = null; refresh(); } }
            }) : null,
            sel.user_identity ? h("button", {
              cls: "btn mini", type: "button", text: "Filter by User (" + sel.user_identity + ")",
              on: { click: function () { tf.user = sel.user_identity; state.selectedFlow = null; refresh(); } }
            }) : null,
            sel.process_name ? h("button", {
              cls: "btn mini", type: "button", text: "Filter by Process (" + sel.process_name + ")",
              on: { click: function () { tf.process = sel.process_name; state.selectedFlow = null; refresh(); } }
            }) : null)));
      view.appendChild(drawer);
    }
  }

  /* ------------------------------------------------------------- sheet */

  /* One centred dialog. The console had a side drawer and a full-screen route
     and nothing between them, and "here is exactly what this button is about
     to do" is a between-sized question. It sits above the route, so Escape
     closes it first. */

  var sheetEl = null;
  var sheetScrim = null;

  /* Sheets that were open when this one opened. `openSheet` began with
     `closeSheet()`, so every "sheet opens a sheet" flow - the shell and
     forensics target pickers, the response unlock gate - was a *replace* with
     no way back, and opening any sheet from anywhere tore down a live
     terminal along with the process it was attached to. */
  var sheetStack = [];

  var FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  /* Overlays trap Tab and give focus back to whatever opened them. All six -
     sheet, route, drawer, palette, account popover, context menu - used to
     close by dropping focus on <body>, which puts a keyboard operator at the
     top of the document every time they dismiss anything. */
  function trapFocus(container) {
    return function (e) {
      if (e.key !== "Tab") return;
      var items = Array.prototype.filter.call(container.querySelectorAll(FOCUSABLE), function (el) {
        return el.offsetParent !== null || el === document.activeElement;
      });
      if (!items.length) { e.preventDefault(); return; }
      var first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
  }

  function restoreFocus(el) {
    if (el && typeof el.focus === "function" && document.contains(el)) {
      try { el.focus(); } catch (e) {}
    }
  }

  /* Detaches the current sheet's DOM without running its cleanup, so it can be
     put back when the sheet stacked on top of it closes. A live terminal keeps
     its socket and its xterm instance while a picker sits over it. */
  function suspendSheet() {
    if (!sheetEl) return null;
    var frame = { el: sheetEl, scrim: sheetScrim, opener: sheetEl._opener, trap: sheetEl._trap };
    if (sheetEl.parentNode) sheetEl.parentNode.removeChild(sheetEl);
    if (sheetScrim && sheetScrim.parentNode) sheetScrim.parentNode.removeChild(sheetScrim);
    sheetEl = null;
    sheetScrim = null;
    return frame;
  }

  function resumeSheet(frame) {
    if (!frame) return;
    sheetEl = frame.el;
    sheetScrim = frame.scrim;
    document.body.appendChild(sheetScrim);
    document.body.appendChild(sheetEl);
    if (sheetEl._restoreFocus) { try { sheetEl._restoreFocus(); } catch (e) {} }
  }

  function closeSheet() {
    if (sheetEl && typeof sheetEl._cleanup === "function") {
      try { sheetEl._cleanup(); } catch (e) {}
    }
    var opener = sheetEl && sheetEl._opener;
    if (sheetEl && sheetEl._trap) document.removeEventListener("keydown", sheetEl._trap, true);
    if (sheetEl && sheetEl.parentNode) sheetEl.parentNode.removeChild(sheetEl);
    if (sheetScrim && sheetScrim.parentNode) sheetScrim.parentNode.removeChild(sheetScrim);
    sheetEl = null;
    sheetScrim = null;

    if (sheetStack.length) {
      resumeSheet(sheetStack.pop());
      return;
    }
    restoreFocus(opener);
  }

  /* Closes the whole stack. `go()` and anything else that changes what the
     console is showing wants this, not a one-level pop. */
  function closeAllSheets() {
    var guard = 0;
    while (sheetEl && guard++ < 16) closeSheet();
    sheetStack.length = 0;
  }

  /* opts:
       stack        - keep the sheet underneath alive and restore it on close
       initialFocus - the node to focus, or false for none
       guardDirty   - false to let Escape and the scrim discard typed input
                      without asking (confirmations and prompts, where the
                      typed value only exists to arm the button)
     openSheet used to guess with `querySelector("input, select, button.btn-primary")`,
     and it misfired both ways: in openIsolateSheet the first match is the
     Isolate confirm button, one Space away from cutting a host off the network,
     while the retire and cancel confirms have no input and no primary button so
     nothing was focused at all. A confirming button is never auto-focused. */
  function openSheet(title, body, actions, extraCls, opts) {
    opts = opts || {};
    var opener = document.activeElement;
    if (opts.stack && sheetEl) {
      var suspended = suspendSheet();
      if (suspended) sheetStack.push(suspended);
    } else {
      closeAllSheets();
    }

    sheetScrim = h("div", { cls: "scrim scrim-sheet", on: { click: function () { requestCloseSheet(); } } });
    sheetEl = h("div", { cls: "sheet" + (extraCls ? " " + extraCls : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
      h("div", { cls: "sheet-head" },
        h("h2", { text: title }),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn btn-icon", type: "button", "aria-label": "Close", on: { click: function () { requestCloseSheet(); } } }, icon("i-close"))),
      h("div", { cls: "sheet-body" }, body),
      h("div", { cls: "sheet-foot" }, actions || []));
    sheetEl._opener = opener && opener !== document.body ? opener : null;
    document.body.appendChild(sheetScrim);
    document.body.appendChild(sheetEl);

    sheetEl._trap = trapFocus(sheetEl);
    document.addEventListener("keydown", sheetEl._trap, true);

    /* A dialog whose focus is still on the page behind it is not modal in any
       useful sense: the trap only cycles Tab between the items it contains, so
       from outside, Tab walks the document underneath instead. When there is
       nothing safe to focus - a confirmation, where the only controls are
       Cancel and a destructive button - the sheet itself takes focus. */
    sheetEl.setAttribute("tabindex", "-1");
    var focusTarget = null;
    if (opts.initialFocus === false) focusTarget = sheetEl;
    else if (opts.initialFocus) focusTarget = opts.initialFocus;
    else {
      focusTarget = sheetEl.querySelector("input:not([type=hidden]), select, textarea");
      if (!focusTarget) focusTarget = sheetEl.querySelector(".sheet-head button");
    }
    sheetEl._restoreFocus = function () { if (focusTarget) { try { focusTarget.focus(); } catch (e) {} } };
    if (focusTarget) { try { focusTarget.focus(); } catch (e) {} }

    /* Escape and a click on the scrim used to throw away a half-filled
       installer, script or tuning form with no warning and no way back. A
       sheet that wants its own dismissal behaviour - the terminal does -
       overwrites this after openSheet returns. */
    if (opts.guardDirty !== false) {
      var el = sheetEl;
      /* One delegated listener rather than a snapshot of every field: several
         sheets render their form only after a fetch resolves, and a snapshot
         taken at open time either misses those fields or, worse, reports them
         as edited the moment they appear. "The operator typed something" is
         the question being asked, and this asks exactly that. */
      el._dirty = false;
      el.addEventListener("input", function () { el._dirty = true; }, true);
      el.addEventListener("change", function () { el._dirty = true; }, true);
      el._confirmClose = function () {
        if (!el._dirty) return true;
        confirmSheet({
          title: "Discard what you have entered?",
          consequence: "This form has values you typed that have not been submitted. Closing it discards them; there is no draft.",
          confirmLabel: "Discard",
          stack: true,
          onConfirm: function () { closeSheet(); }
        });
        return false;
      };
    }
  }

  /* A dismissal the sheet is allowed to intervene in - a live terminal asks
     first, a filled form warns before discarding. Programmatic closes call
     closeSheet() directly and are not questioned. */
  function requestCloseSheet() {
    if (sheetEl && typeof sheetEl._confirmClose === "function") {
      var proceed = false;
      try { proceed = sheetEl._confirmClose(); } catch (e) { proceed = true; }
      if (!proceed) return;
    }
    closeSheet();
  }

  /* ------------------------------------------------- adding an endpoint */

  /* Getting an agent onto a host that has none is package enrolment: the hub
     renders a short-lived command or script, and the host invokes its native
     package manager locally. */

  function tenantOptions() {
    var out = [];
    arrayOf(state.hierarchy).forEach(function (c) {
      if (c && c.tenant && c.tenant.id) out.push({ id: c.tenant.id, name: c.tenant.name || c.tenant.id });
    });
    if (!out.length) out.push({ id: "default", name: "default" });
    return out;
  }

  function fillLocationOptions(select, tenantID) {
    var previous = select.value;
    select.textContent = "";
    select.appendChild(h("option", { value: "", text: "—" }));
    arrayOf(state.locations).forEach(function (location) {
      if (location.tenant_id && location.tenant_id !== tenantID) return;
      select.appendChild(h("option", { value: location.id, text: location.name || location.id }));
    });
    if (previous && select.querySelector('option[value="' + cssEscape(previous) + '"]')) select.value = previous;
  }

  function copyText(value, what) {
    var done = function () { toast("Copied " + what, "ok"); };
    var fallback = function () {
      var field = h("textarea", { cls: "clipboard-fallback", "aria-hidden": "true" });
      field.value = value;
      document.body.appendChild(field);
      field.focus();
      field.select();
      var copied = false;
      try { copied = document.execCommand("copy"); } catch (e) { copied = false; }
      document.body.removeChild(field);
      if (copied) done();
      else toast("Could not copy — select the text and copy it", "warn");
    };
    if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(done, fallback);
    } else {
      fallback();
    }
  }

  /* A download the browser makes from a string we already hold. The script is a
     credential, so it is never fetched through a URL that could be logged or
     replayed - it came down the authenticated API call that rendered it. */
  function downloadText(filename, body) {
    var blob = new Blob([body], { type: "text/plain" });
    var url = URL.createObjectURL(blob);
    var a = h("a", { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function openInstallerSheet(prefill) {
    var pre = prefill || {};

    var platform = h("select", { "aria-label": "Platform" },
      h("option", { value: "linux", text: "Linux" }),
      h("option", { value: "windows", text: "Windows" }));
    if (pre.platform) platform.value = pre.platform;

    var tenant = h("select", { "aria-label": "Client" },
      tenantOptions().map(function (t) { return h("option", { value: t.id, text: t.name }); }));

    var location = h("select", { "aria-label": "Location" });
    fillLocationOptions(location, tenant.value);
    tenant.addEventListener("change", function () { fillLocationOptions(location, tenant.value); });

    var role = h("select", { "aria-label": "Role" },
      h("option", { value: "workstation", text: "Workstation" }),
      h("option", { value: "server", text: "Server" }),
      h("option", { value: "kiosk", text: "Kiosk" }),
      h("option", { value: "appliance", text: "Appliance" }));

    var endpointID = h("input", { type: "text", value: pre.endpoint_id || "", placeholder: "Use target hostname" });
    var profileKind = h("select", { "aria-label": "Enrollment profile" },
      h("option", { value: "invitation", text: "One computer (30-minute invitation)" }),
      h("option", { value: "campaign", text: "Multiple computers (expiring campaign)" }),
      h("option", { value: "deployment", text: "GPO / MDM (persistent key)" }));
    var profileHours = h("select", { "aria-label": "Profile lifetime" },
      h("option", { value: "1", text: "1 hour" }),
      h("option", { value: "8", text: "8 hours" }),
      h("option", { value: "24", text: "24 hours" }),
      h("option", { value: "168", text: "7 days" }));
    profileHours.value = "8";
    var profileMaxUses = h("input", { type: "text", inputmode: "numeric", placeholder: "No limit" });

    /* Opened from "Install Agent (N)" with the selected hosts. The button
       counted them and then called this with no arguments at all, so the
       label promised a bulk operation and the sheet performed a generic
       single-computer one. N unmanaged hosts is a campaign with an install
       cap of N - the machinery for that was already here and unreachable. */
    var preHosts = arrayOf(pre.hosts);
    if (preHosts.length > 1) {
      profileKind.value = "campaign";
      profileMaxUses.value = String(preHosts.length);
    } else if (pre.kind) {
      profileKind.value = pre.kind;
    }

    var platformField = h("label", { cls: "field" }, h("span", { text: "Operating system" }), platform);
    var tenantField = h("label", { cls: "field" }, h("span", { text: "Client" }), tenant);
    var locationField = h("label", { cls: "field" }, h("span", { text: "Location" }), location);
    var roleField = h("label", { cls: "field" }, h("span", { text: "Role" }), role);
    var endpointField = h("label", { cls: "field" }, h("span", { text: "Endpoint ID (optional)" }), endpointID);
    var profileField = h("label", { cls: "field field-wide" }, h("span", { text: "Deployment method" }), profileKind);
    var hoursField = h("label", { cls: "field" }, h("span", { text: "Campaign expires after" }), profileHours);
    var maxUsesField = h("label", { cls: "field" }, h("span", { text: "Optional install cap" }), profileMaxUses);
    var profileHelp = h("p", { cls: "why field-wide" });

    var out = h("div", { cls: "stack", "aria-live": "polite" });
    var rendered = null;
    var generation = 0;
    var renderButton = null;
    var setupBlocks = [];
    var controls = [platform, tenant, location, role, endpointID, profileKind, profileHours, profileMaxUses];

    var setControlsDisabled = function (disabled) {
      controls.forEach(function (control) { control.disabled = disabled; });
    };

    var syncProfile = function () {
      var kind = profileKind.value;
      hoursField.hidden = kind !== "campaign";
      maxUsesField.hidden = kind !== "campaign";
      endpointField.hidden = kind !== "invitation";
      if (kind !== "invitation") endpointID.value = "";
      profileHelp.textContent = kind === "campaign"
        ? "Reusable until the selected expiry. Install cap is optional; leave it blank for no limit. Each computer still receives a unique identity."
        : kind === "deployment"
          ? "For protected GPO, MDM, or scripted rollout. The shared enrollment key stays valid until an administrator revokes it; each computer still receives a unique identity."
          : "Best for one computer. The code works once and expires after 30 minutes.";
    };

    var reset = function () {
      generation++;
      rendered = null;
      setControlsDisabled(false);
      syncProfile();
      setupBlocks.forEach(function (block) { block.hidden = false; });
      out.textContent = "";
      out.appendChild(h("p", { cls: "why", text: "Choose the target and deployment method, then generate the correct download and command." }));
      renderButton.disabled = false;
      renderButton.textContent = "Generate install options";
      platform.focus();
    };

    var revokeRendered = function () {
      if (!rendered || !rendered.profile_id) return;
      var id = rendered.profile_id;
      request("/api/v1/enrollment/profiles?id=" + encodeURIComponent(id), "DELETE")
        .then(function () {
          rendered = null;
          setControlsDisabled(false);
          syncProfile();
          setupBlocks.forEach(function (block) { block.hidden = false; });
          out.textContent = "";
          out.appendChild(h("p", { cls: "note note-warn", role: "alert", text: "Enrollment code revoked. Any downloaded copy of this installer can no longer enroll a computer." }));
          renderButton.textContent = "Generate install options";
          toast("Enrollment code revoked", "ok");
        })
        .catch(function (e) { toast("Could not revoke the code: " + e.message, "crit"); });
    };

    var showResult = function (res) {
      var isWindows = res.platform === "windows";
      var platformLabel = isWindows ? "Windows" : "Linux";
      var packageLabel = isWindows ? "MSI" : ".deb";
      var runHint = isWindows
        ? "Open PowerShell as Administrator and run the downloaded .ps1 file."
        : "From the download folder, run: sudo bash " + (res.filename || "ominull-install.sh");
      out.textContent = "";
      setupBlocks.forEach(function (block) { block.hidden = true; });

      var downloadChoice = h("div", { cls: "installer-choice" },
        h("h3", { text: "Option 1 · Download the prepared script" }),
        h("p", { cls: "why", text: "Recommended when you are on the target computer. This script contains the enrollment code, downloads and verifies the signed " + packageLabel + " package, installs it through the operating system, and starts the agent." }),
        h("div", { cls: "form-row" },
          h("button", {
            cls: "btn btn-primary", type: "button", text: "Download " + (res.filename || "install script"),
            on: { click: function () { downloadText(res.filename || "ominull-install.txt", res.script || ""); } }
          }),
          h("span", { cls: "pending", text: runHint })));
      var commandChoice = null;
      if (res.one_liner) {
        commandChoice = h("div", { cls: "installer-choice" },
          h("h3", { text: "Option 2 · Run a command on the target" }),
          h("p", { cls: "why", text: "The command downloads a generic installer. It prompts for the separate enrollment code, keeping that code out of shell history and URLs." }),
          h("span", { cls: "pending", text: "Command" }),
          h("pre", { cls: "cmd", text: res.one_liner }),
          h("div", { cls: "form-row" },
            h("button", {
              cls: "btn", type: "button", text: "Copy command",
              on: { click: function () { copyText(res.one_liner, "the install command"); } }
            })),
          h("span", { cls: "pending", text: "Enrollment code" }),
          h("pre", { cls: "cmd", text: res.enrollment_code || "" }),
          h("div", { cls: "form-row" },
            h("button", {
              cls: "btn", type: "button", text: "Copy code",
              on: { click: function () { copyText(res.enrollment_code || "", "the enrollment code"); } }
            })),
          res.one_liner_warning ? h("p", { cls: "note note-warn", role: "alert", text: res.one_liner_warning }) : null);
      }
      var result = h("section", { cls: "installer-result" },
        h("div", { cls: "installer-result-head" },
          h("div", {},
            h("h3", { text: platformLabel + " install options ready" }),
            h("p", { cls: "why", text: (profileKind.options[profileKind.selectedIndex].text || "Enrollment") + " · " + (res.expires_in || res.one_liner_expires_in || "ready") })),
          h("button", { cls: "btn btn-crit", type: "button", text: "Revoke code", on: { click: revokeRendered } })),
        downloadChoice,
        commandChoice,
        h("details", { cls: "script-review" },
          h("summary", { text: "Review generated " + platformLabel + " script" }),
          h("pre", { cls: "cmd cmd-scroll", text: res.script || "" })),
        h("p", { cls: "note", text: res.note || "" }));
      out.appendChild(result);
      result.scrollIntoView({ block: "nearest" });
    };

    var render = function () {
      if (rendered) { reset(); return; }
      var requestedPlatform = platform.value;
      var requestID = ++generation;
      setControlsDisabled(true);
      renderButton.disabled = true;
      renderButton.textContent = "Generating…";
      out.textContent = "";
      out.appendChild(h("div", { cls: "empty", text: "Generating secure " + (requestedPlatform === "windows" ? "Windows" : "Linux") + " install options…" }));
      request("/api/v1/enrolment/script", "POST", {
        platform: requestedPlatform,
        tenant_id: tenant.value,
        location_id: location.value,
        role: role.value,
        endpoint_id: endpointID.value.trim(),
        kind: profileKind.value,
        hours: profileKind.value === "campaign" ? (parseFloat(profileHours.value) || 8) : 0,
        max_uses: profileKind.value === "campaign" ? (parseInt(profileMaxUses.value, 10) || 0) : (profileKind.value === "invitation" ? 1 : 0),
        persistent: profileKind.value === "deployment",
        one_liner: true
      }).then(function (res) {
        if (requestID !== generation) return;
        if (!res || res.platform !== requestedPlatform) throw new Error("the hub returned an installer for the wrong platform");
        rendered = res || {};
        renderButton.disabled = false;
        renderButton.textContent = "Create another";
        showResult(rendered);
      }).catch(function (e) {
        if (requestID !== generation) return;
        rendered = null;
        setControlsDisabled(false);
        syncProfile();
        renderButton.disabled = false;
        renderButton.textContent = "Try again";
        out.textContent = "";
        out.appendChild(h("p", { cls: "note note-crit", role: "alert", text: "Could not generate install options: " + e.message }));
      });
    };

    var intro = h("p", { cls: "why", text: "Prepare a platform-correct installer for one computer, an expiring rollout, or a protected GPO/MDM deployment. Every installed agent receives its own device credential and client certificate." });
    var selectionNote = preHosts.length > 1
      ? h("p", { cls: "note note-ok", text: "Prepared for " + preHosts.length + " selected host(s): "
          + preHosts.slice(0, 6).join(", ") + (preHosts.length > 6 ? ", and " + (preHosts.length - 6) + " more" : "")
          + ". One code, capped at " + preHosts.length + " installs." })
      : null;
    var lanPath = h("section", { cls: "installer-paths" },
        h("div", {},
          h("h3", { text: "Installing computers from the same LAN?" }),
          h("p", { cls: "why", text: "Allow the LAN temporarily, then open the hub's /install page on each workstation to download its installer." })),
        h("button", { cls: "btn", type: "button", text: "Set up LAN installs", on: { click: function () { closeSheet(); openSelfServiceSheet(); } } }));
    var targetSection = h("section", { cls: "installer-section" },
        h("h3", { text: "1 · Target and assignment" }),
        h("div", { cls: "installer-grid" }, platformField, tenantField, locationField, roleField, endpointField));
    var profileSection = h("section", { cls: "installer-section" },
        h("h3", { text: "2 · Enrollment lifetime" }),
        h("div", { cls: "installer-grid" }, profileField, hoursField, maxUsesField, profileHelp));
    setupBlocks = [intro, selectionNote, lanPath, targetSection, profileSection].filter(Boolean);
    var body = h("div", { cls: "stack" }, setupBlocks, out);

    renderButton = h("button", { cls: "btn btn-primary", type: "button", text: "Generate install options", on: { click: render } });

    openSheet("Install an agent", body, [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      renderButton
    ]);

    profileKind.addEventListener("change", syncProfile);
    syncProfile();
    out.appendChild(h("p", { cls: "why", text: "Nothing is created until you generate the install options." }));
  }

  function enrollmentProfileState(profile) {
    if (profile.revoked_at) return "revoked";
    if (profile.kind !== "deployment" && parseTime(profile.expires_at) && parseTime(profile.expires_at) <= new Date()) return "expired";
    if (Number(profile.max_uses) > 0 && Number(profile.used) >= Number(profile.max_uses)) return "spent";
    return "open";
  }

  function openEnrollmentProfilesSheet() {
    var out = h("div", { cls: "stack", "aria-live": "polite" });

    var load = function () {
      out.textContent = "";
      out.appendChild(emptyBox("Loading enrollment keys…"));
      request("/api/v1/enrollment/profiles").then(function (res) {
        out.textContent = "";
        var profiles = arrayOf(res && res.profiles);
        if (!profiles.length) {
          out.appendChild(emptyBox("No enrollment keys have been created."));
          return;
        }
        var rows = profiles.map(function (profile) {
          var state_ = enrollmentProfileState(profile);
          var limit = Number(profile.max_uses) > 0 ? String(profile.used || 0) + " of " + profile.max_uses : String(profile.used || 0) + " · no cap";
          var scope = [profile.tenant_id, profile.location_id, profile.role].filter(Boolean).join(" · ") || "default";
          var expiry = profile.kind === "deployment" ? h("span", { text: "until revoked" }) : stamp(parseTime(profile.expires_at));
          return [
            h("div", {}, h("div", { text: profile.kind || "invitation" }), h("div", { cls: "pending ip", text: profile.id || "" })),
            h("span", { text: profile.platform || "any" }),
            h("span", { text: scope }),
            h("span", { text: limit }),
            expiry,
            h("span", { cls: "st", "data-state": windowStateTone(state_) }, h("span", { text: state_ })),
            state_ === "open" ? h("button", {
              cls: "btn btn-crit", type: "button", text: "Revoke",
              on: { click: function () { revoke(profile.id); } }
            }) : h("span", { cls: "pending", text: "—" })
          ];
        });
        out.appendChild(h("p", { cls: "why", text: "Codes are shown only once when generated. Revoke any campaign or persistent GPO/MDM key that is no longer needed." }));
        out.appendChild(simpleTable(["Method", "OS", "Assignment", "Installs", "Expires", "State", ""], rows));
      }).catch(function (e) {
        out.textContent = "";
        out.appendChild(h("p", { cls: "note note-crit", role: "alert", text: "Could not load enrollment keys: " + e.message }));
      });
    };

    var revoke = function (id) {
      /* A revoked key is not reissued. Every GPO, MDM profile or scripted
         rollout still carrying it stops being able to enroll, silently, from
         the next attempt onwards. */
      confirmSheet({
        title: "Revoke enrollment key",
        consequence: "Any deployment still carrying this key stops enrolling immediately. GPO policies, MDM profiles and rollout scripts that reference it have to be updated with a new key before they will work again.",
        detail: "Key " + String(id).slice(0, 12) + "\u2026 \u00b7 already-enrolled computers keep their own identities and are unaffected.",
        confirmLabel: "Revoke key",
        stack: true,
        onConfirm: function () {
          request("/api/v1/enrollment/profiles?id=" + encodeURIComponent(id), "DELETE")
            .then(function () { toast("Enrollment key revoked", "ok"); load(); })
            .catch(function (e) { toast("Could not revoke the key: " + e.message, "crit"); });
        }
      });
    };

    openSheet("Enrollment keys", out, [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      h("button", { cls: "btn btn-primary", type: "button", text: "Create new", on: { click: function () { closeSheet(); openInstallerSheet(); } } })
    ], "sheet-wide");
    load();
  }

  /* -------------------------------------------- self-service enrolment */

  /* Pre-authorising a network instead of a host.

     Minting a link per host is right for one host and wrong for forty: the
     operator ends up in the console while somebody else walks the building.
     A window says "for the next few hours, a machine on this network may ask
     the hub for its own install command", and the hub still mints an ordinary
     single-use enrollment code for each one. Everything that bounds it - the networks,
     the expiry, the budget, whether a passcode is needed - is on this screen,
     and so is the button that closes it. */

  function windowStateTone(state_) {
    return state_ === "open" ? "ok" : state_ === "revoked" ? "crit" : "warn";
  }

  function openSelfServiceSheet() {
    var out = h("div", { cls: "stack" });
    var portalURL = "";

    var label = h("input", { type: "text", placeholder: "Tuesday workstation rollout" });
    var cidrs = h("input", { type: "text", placeholder: "10.0.0.0/24" });
    var hours = h("select", {},
      h("option", { value: "1", text: "1 hour" }),
      h("option", { value: "4", text: "4 hours" }),
      h("option", { value: "8", text: "8 hours" }),
      h("option", { value: "24", text: "24 hours" }),
      h("option", { value: "168", text: "7 days" }));
    hours.value = "8";
    var maxUses = h("input", { type: "text", inputmode: "numeric", value: "", placeholder: "No limit" });
    var passcode = h("input", { type: "password", value: "", placeholder: "Optional" });
    var tenant = h("select", { "aria-label": "Client" },
      tenantOptions().map(function (t) { return h("option", { value: t.id, text: t.name }); }));
    var location = h("select", { "aria-label": "Location" });
    fillLocationOptions(location, tenant.value);
    tenant.addEventListener("change", function () { fillLocationOptions(location, tenant.value); });
    var role = h("select", { "aria-label": "Role" },
      h("option", { value: "workstation", text: "Workstation" }),
      h("option", { value: "server", text: "Server" }),
      h("option", { value: "kiosk", text: "Kiosk" }),
      h("option", { value: "appliance", text: "Appliance" }));

    var renderList = function (res) {
      out.textContent = "";
      var windows = arrayOf(res && res.windows);
      portalURL = (res && res.portal_url) || "";

      /* The hub's own networks, offered rather than prefilled. Joining them all
         into the box is how a container or virtualisation bridge ends up
         pre-authorised alongside the LAN that was actually meant. */
      var suggestions = arrayOf(res && res.suggested_cidrs);
      if (suggestions.length) {
        var picks = h("div", { cls: "row-acts" },
          h("span", { cls: "pending", text: "Detected private networks — verify before allowing:" }));
        suggestions.forEach(function (cidr) {
          picks.appendChild(h("button", {
            cls: "btn", type: "button", text: cidr,
            on: { click: function () { cidrs.value = cidr; cidrs.focus(); } }
          }));
        });
        out.appendChild(picks);
        if (!cidrs.value) cidrs.value = suggestions[0];
      }

      /* The address to hand out is the point of the whole screen, so it is the
         first thing on it rather than something to derive from the hub URL. */
      out.appendChild(h("div", { cls: "field" },
        h("span", { text: "2 · On each workstation, open this address" }),
        h("pre", { cls: "cmd", text: portalURL }),
        h("div", { cls: "form-row" },
          h("button", {
            cls: "btn", type: "button", text: "Copy address",
            on: { click: function () { copyText(portalURL, "the enrolment address"); } }
          }),
          h("span", { cls: "pending", text: "Each workstation chooses Windows or Linux, then downloads its prepared install script. Access works only from an allowed network below." }))));

      var rows = windows.map(function (win) {
        var state_ = win.state || "open";
        var used = String(win.used || 0) + (win.max_uses > 0 ? " of " + win.max_uses : "");
        return [
          h("div", {},
            h("div", { text: win.label || "(unlabelled)" }),
            h("div", { cls: "pending ip", text: arrayOf(win.cidrs).join(", ") +
              (win.has_passcode ? " \u00b7 passcode" : "") })),
          h("span", { cls: "st", "data-state": windowStateTone(state_) }, h("span", { text: state_ })),
          h("span", { text: used }),
          stamp(parseTime(win.expires_at)),
          state_ === "open"
            ? h("button", {
                cls: "btn", type: "button", text: "Close",
                on: { click: function () { revoke(win.id); } }
              })
            : h("span", { cls: "pending", text: "\u2014" })
        ];
      });

      out.appendChild(card("LAN install access",
        h("div", { cls: "card-body" },
          simpleTable(["Access", "State", "Installed", "Expires", ""], rows))));

    };

    var load = function () {
      request("/api/v1/enrolment/windows").then(renderList).catch(function (e) {
        out.textContent = "";
        out.appendChild(h("p", { cls: "note note-crit", role: "alert", text: "Could not read LAN install access: " + e.message }));
      });
    };

    var revoke = function (id) {
      confirmSheet({
        title: "Close LAN install access",
        consequence: "The install window shuts immediately. Anyone part-way through installing an agent over the LAN fails, and a new window has to be opened before another computer can enroll this way.",
        detail: "Computers that already finished installing stay enrolled.",
        confirmLabel: "Close access",
        stack: true,
        onConfirm: function () {
          request("/api/v1/enrolment/windows?id=" + encodeURIComponent(id), "DELETE")
            .then(function () { toast("LAN install access closed", "ok"); load(); })
            .catch(function (e) { toast("Could not close LAN access: " + e.message, "crit"); });
        }
      });
    };

    var open = function () {
      var nets = cidrs.value.split(",").map(function (x) { return x.trim(); }).filter(Boolean);
      if (!nets.length) { toast("Name at least one network", "warn"); return; }
      request("/api/v1/enrolment/windows", "POST", {
        label: label.value.trim(),
        cidrs: nets,
        tenant_id: tenant.value,
        location_id: location.value,
        role: role.value,
        hours: parseFloat(hours.value) || 8,
        max_uses: parseInt(maxUses.value, 10) || 0,
        passcode: passcode.value.trim()
      }).then(function (res) {
        toast("LAN install access is active", "ok");
        label.value = ""; maxUses.value = ""; passcode.value = "";
        load();
      }).catch(function (e) { toast("Could not allow LAN installs: " + e.message, "crit"); });
    };

    var body = h("div", { cls: "stack" },
      h("p", { cls: "why", text: "Temporarily allow a trusted LAN. Then visit /install from each workstation to download a Windows or Linux installer. Every workstation receives a unique one-use code, device credential, and client certificate." }),
      h("section", { cls: "installer-section" },
        h("h3", { text: "1 · Allow a trusted LAN" }),
        h("div", { cls: "installer-grid" },
          h("label", { cls: "field" }, h("span", { text: "Label" }), label),
          h("label", { cls: "field" }, h("span", { text: "Network (CIDR)" }), cidrs),
          h("label", { cls: "field" }, h("span", { text: "Client" }), tenant),
          h("label", { cls: "field" }, h("span", { text: "Location" }), location),
          h("label", { cls: "field" }, h("span", { text: "Role" }), role),
          h("label", { cls: "field" }, h("span", { text: "Access duration" }), hours),
          h("label", { cls: "field" }, h("span", { text: "Optional install cap" }), maxUses),
          h("label", { cls: "field" }, h("span", { text: "Optional passcode" }), passcode))),
      out);

    openSheet("LAN self-service installs", body, [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      h("button", { cls: "btn btn-primary", type: "button", text: "Allow this LAN", on: { click: open } })
    ], "sheet-wide");

    load();
  }

  /* -------------------------------------------------- isolation baseline */

  /* What an isolated host may still reach. Two permits - the hub pinhole and
     loopback - are compiled into every agent and are deliberately not policy:
     they are what makes an isolation reversible, and an allow-list an operator
     can empty by accident is a way to lose a host. Everything else is authored
     here and shown before the button is pressed. */

  var BASELINE_SCOPES = ["global", "tenant", "location", "endpoint"];

  function baselineSpec(name) {
    var found = null;
    state.baselineServices.forEach(function (sp) { if (sp.service === name) found = sp; });
    return found;
  }

  function baselineScopeText(p) {
    return p.scope + (p.scope_value ? " · " + p.scope_value : "");
  }

  function ruleEditorRow(rule, onRemove) {
    var svc = h("select", { "aria-label": "Service" });
    var services = state.baselineServices.length
      ? state.baselineServices
      : [{ service: "dns", label: "DNS" }, { service: "dhcp", label: "DHCP" },
         { service: "ntp", label: "NTP" }, { service: "custom", label: "Custom" }];
    services.forEach(function (sp) {
      svc.appendChild(h("option", { value: sp.service, text: sp.label || sp.service }));
    });
    svc.value = rule.service || "dns";

    var dst = h("input", { type: "text", value: rule.destination || "", placeholder: "address", "aria-label": "Destination" });
    var proto = h("select", { "aria-label": "Protocol" },
      h("option", { value: "udp", text: "udp" }),
      h("option", { value: "tcp", text: "tcp" }));
    proto.value = rule.protocol || "udp";
    var port = h("input", { type: "text", value: rule.port ? String(rule.port) : "", placeholder: "port", "aria-label": "Port" });

    /* A named service carries its own wire details and the hub refuses an
       attempt to override them; the row shows what they are rather than
       offering fields that will be rejected. */
    var sync = function () {
      var custom = svc.value === "custom";
      proto.disabled = !custom;
      port.disabled = !custom;
      var sp = baselineSpec(svc.value);
      if (!custom && sp) {
        proto.value = sp.protocol;
        port.value = "";
        port.placeholder = arrayOf(sp.ports).join(", ");
      } else if (custom) {
        port.placeholder = "port";
      }
    };
    svc.addEventListener("change", sync);
    sync();

    var row = h("div", { cls: "rule-row" }, svc, dst, proto, port,
      h("button", { cls: "mini", type: "button", text: "Remove", on: { click: function () { onRemove(row); } } }));
    row.readRule = function () {
      var custom = svc.value === "custom";
      return {
        service: svc.value,
        destination: dst.value.trim(),
        protocol: custom ? proto.value : "",
        port: custom ? (parseInt(port.value, 10) || 0) : 0
      };
    };
    return row;
  }

  function openBaselineEditor(policy, note) {
    var p = policy || { id: "", name: "", scope: "global", scope_value: "", enabled: true, rules: [] };

    var name = h("input", { type: "text", value: p.name || "", placeholder: "Corporate resolvers" });
    var scope = h("select", {}, BASELINE_SCOPES.map(function (sc) { return h("option", { value: sc, text: sc }); }));
    scope.value = p.scope || "global";
    var scopeValue = h("input", { type: "text", value: p.scope_value || "", placeholder: "tenant, location or endpoint id" });
    var enabled = h("input", { type: "checkbox" });
    enabled.checked = p.enabled !== false;

    var list = h("div", { cls: "rule-list" });
    var addRow = function (r) { list.appendChild(ruleEditorRow(r, function (el) { list.removeChild(el); })); };
    arrayOf(p.rules).forEach(addRow);

    var syncScope = function () { scopeValue.disabled = scope.value === "global"; };
    scope.addEventListener("change", syncScope);
    syncScope();

    var body = h("div", { cls: "stack" },
      note ? h("p", { cls: "why", text: note }) : null,
      h("div", { cls: "form-row" },
        h("label", { cls: "field" }, h("span", { text: "Name" }), name),
        h("label", { cls: "field" }, h("span", { text: "Scope" }), scope),
        h("label", { cls: "field" }, h("span", { text: "Applies to" }), scopeValue),
        h("label", { cls: "field field-check" }, h("span", { text: "Enabled" }), enabled)),
      h("div", { cls: "rule-head" },
        h("span", { text: "Service" }), h("span", { text: "Destination" }),
        h("span", { text: "Protocol" }), h("span", { text: "Port" }), h("span", {})),
      list,
      h("div", {}, h("button", {
        cls: "mini", type: "button", text: "Add rule",
        on: { click: function () { addRow({ service: "dns", destination: "" }); } }
      })),
      h("p", { cls: "pending", text: "Policies at every scope are added together, never overridden. The hub pinhole and loopback are permitted on every isolated host and are not listed here." }));

    openSheet(p.id ? "Edit baseline policy" : "New baseline policy", body, [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-primary", type: "button", text: "Save policy",
        on: {
          click: function () {
            var payload = {
              id: p.id || "",
              name: name.value.trim(),
              scope: scope.value,
              scope_value: scope.value === "global" ? "" : scopeValue.value.trim(),
              enabled: enabled.checked,
              rules: Array.prototype.map.call(list.children, function (row) { return row.readRule(); })
            };
            request("/api/v1/baseline/policies", "POST", payload).then(function () {
              toast("Saved " + (payload.name || "baseline policy"), "ok");
              state.baselineByEndpoint = {};
              closeSheet();
              refresh();
            }).catch(function (e) { toast("Save failed: " + e.message, "crit"); });
          }
        }
      })
    ]);
  }

  function deleteBaselinePolicy(p) {
    openSheet("Delete baseline policy", h("div", { cls: "stack" },
      h("p", { cls: "why" },
        h("b", { text: p.name || p.id }),
        document.createTextNode(" stops applying immediately. Hosts isolated under it keep the rules already on them until they next check in.")),
      h("p", { cls: "pending", text: baselineScopeText(p) + " · " + arrayOf(p.rules).length + " rule(s)" })), [
      h("button", { cls: "btn", type: "button", text: "Keep it", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-crit", type: "button", text: "Delete",
        on: {
          click: function () {
            request("/api/v1/baseline/policies/delete", "POST", { id: p.id }).then(function () {
              toast("Deleted " + (p.name || p.id), "ok");
              state.baselineByEndpoint = {};
              closeSheet();
              refresh();
            }).catch(function (e) { toast("Delete failed: " + e.message, "crit"); });
          }
        }
      })
    ]);
  }

  function proposeBaseline(asset) {
    if (!asset.endpoint) return;
    request("/api/v1/baseline/propose", "POST", { endpoint_id: asset.endpoint.id })
      .then(function (res) {
        var rules = arrayOf(res && res.rules);
        if (!rules.length) {
          toast(asset.name + " has not reported any service to propose", "warn");
          return;
        }
        openBaselineEditor({
          id: "", name: "Baseline for " + asset.name, scope: "endpoint",
          scope_value: asset.endpoint.id, enabled: true, rules: rules
        }, "Drawn from what this host reported using. Nothing is applied until you save, and you can edit or drop any row first.");
      })
      .catch(function (e) { toast("Could not propose: " + e.message, "crit"); });
  }

  function wireRows(wire, always) {
    return arrayOf(always).map(function (a) {
      return [
        h("span", { text: a.what }),
        h("span", { cls: "dim-3", text: a.why }),
        h("span", { cls: "dim-3", text: "always" })
      ];
    }).concat(arrayOf(wire).map(function (wr) {
      return [
        h("span", { text: wr.service }),
        h("span", { cls: "ip", text: wr.destination }),
        h("span", { cls: "ip", text: wr.protocol + "/" + wr.port })
      ];
    }));
  }

  function baselineEndpointCard(asset) {
    var info = state.baselineByEndpoint[asset.endpoint.id];
    if (!info) {
      return card("If isolated", emptyBox("Reading the baseline…"), null, true);
    }
    var res = info.resolution || {};
    var uncovered = arrayOf(res.uncovered);
    var observed = arrayOf(res.observed);

    var body = h("div", { cls: "card-body stack" });

    if (info.blocker) body.appendChild(h("p", { cls: "note note-crit", role: "alert", text: info.blocker }));
    else if (info.warning) body.appendChild(h("p", { cls: "note note-warn", role: "alert", text: info.warning }));
    else body.appendChild(h("p", { cls: "note note-ok", text: "This host reported that it can still be released after an isolation, and the baseline covers everything it is using." }));

    body.appendChild(simpleTable(["Permitted", "Destination", "Wire"], wireRows(info.wire, info.always_permitted)));

    if (observed.length) {
      body.appendChild(simpleTable(["Observed", "Destination", "Covered"], observed.map(function (o) {
        var miss = uncovered.some(function (u) { return u.service === o.service && u.destination === o.destination; });
        return [
          h("span", { text: o.service }),
          h("span", { cls: "ip", text: o.destination }),
          h("span", { cls: "st", "data-state": miss ? "crit" : "ok" },
            icon(miss ? "g-quarantine" : "g-online", true),
            h("span", { text: miss ? "Not covered" : "Covered" }))
        ];
      })));
    } else {
      body.appendChild(emptyBox("This host has not reported which services it uses."));
    }

    var policies = arrayOf(res.policies);
    body.appendChild(h("p", { cls: "pending", text: policies.length ? "From: " + policies.join(", ") : "No baseline policy covers this host." }));

    var actions = [];
    if (IS_ADMIN && observed.length) {
      actions.push(h("button", {
        cls: "btn", type: "button", text: "Propose from observed",
        on: { click: function () { proposeBaseline(asset); } }
      }));
    }
    return card("If isolated", body, actions.length ? actions : null, true);
  }

  function baselineCard() {
    var rows = state.baselinePolicies.map(function (p) {
      var rules = arrayOf(p.rules);
      var summary = rules.map(function (r) { return r.service + " → " + r.destination; }).join(", ");
      var acts = h("span", { cls: "row-acts" });
      if (IS_ADMIN) {
        acts.appendChild(h("button", { cls: "mini", type: "button", text: "Edit", on: { click: function () { openBaselineEditor(p); } } }));
        acts.appendChild(h("button", { cls: "mini", type: "button", text: "Delete", on: { click: function () { deleteBaselinePolicy(p); } } }));
      }
      return [
        h("span", { text: p.name || p.id }),
        h("span", { cls: "dim-3", text: baselineScopeText(p) }),
        h("span", { cls: "ip", text: summary || "—" }),
        h("span", { cls: "st", "data-state": p.enabled ? "ok" : "idle" },
          icon(p.enabled ? "g-online" : "g-offline", true),
          h("span", { text: p.enabled ? "Enabled" : "Off" })),
        acts
      ];
    });

    var body = h("div", { cls: "stack" },
      h("p", { cls: "why pad-x", text: "What a host may still reach while it is isolated. The hub pinhole and loopback are permitted on every isolated host and cannot be removed here; everything else an isolated host can talk to is in this list." }),
      simpleTable(["Name", "Scope", "Rules", "State", ""], rows));

    var actions = IS_ADMIN ? [h("button", {
      cls: "btn", type: "button", text: "New policy",
      on: { click: function () { openBaselineEditor(null); } }
    })] : null;
    return card("Isolation baseline", body, actions);
  }

  /* ---------------------------------------------------- detection tuning */

  /* Every number the behavioural detectors run on, on the page rather than in
     the binary. The reason this exists is a console full of alerts nobody could
     argue with: a freshly installed workstation reported command-and-control
     traffic, and an off-hours window written in UTC called an ordinary evening
     suspicious. Neither was adjustable, and neither said what it had measured. */

  /* A row with no label is a switch that speaks for itself, and giving it an
     empty first column leaves a gap the eye reads as a missing word. */
  function tuningRow(label, why, control) {
    if (!label) return h("div", { cls: "tune-row tune-row-wide" }, h("div", { cls: "tune-ctl" }, control));
    return h("div", { cls: "tune-row" },
      h("div", { cls: "tune-label" },
        h("span", { text: label }),
        why ? h("span", { cls: "why", text: why }) : null),
      h("div", { cls: "tune-ctl" }, control));
  }

  function numberField(value, min, max, step) {
    return h("input", {
      type: "number", value: String(value === undefined || value === null ? "" : value),
      min: String(min), max: String(max), step: String(step || 1)
    });
  }

  function toggleField(on, label) {
    var box = h("input", { type: "checkbox" });
    box.checked = !!on;
    return { input: box, node: h("label", { cls: "field-check" }, box, h("span", { text: label })) };
  }

  /* A list of names, edited as text. A table of one-word rows would be more
     ceremony than the content deserves. */
  function listField(items, placeholder) {
    return h("textarea", { rows: "3", placeholder: placeholder }, arrayOf(items).join(", "));
  }

  function parseList(text) {
    return String(text || "").split(/[,\n]/).map(function (v) { return v.trim(); })
      .filter(function (v) { return v.length > 0; });
  }

  function openTuningSheet() {
    var t = (state.tuning && state.tuning.tuning) || {};
    var d = (state.tuning && state.tuning.defaults) || {};

    var beaconOn = toggleField(t.beacon_enabled, "Report periodic beaconing");
    var score = numberField(t.beacon_score_threshold, 0.1, 1, 0.01);
    var samples = numberField(t.beacon_min_samples, 6, 200, 1);
    var span = numberField(t.beacon_min_span_minutes, 1, 1440, 1);
    var loInt = numberField(t.beacon_min_interval_seconds, 1, 3600, 1);
    var hiInt = numberField(t.beacon_max_interval_seconds, 10, 86400, 10);
    var bCool = numberField(t.beacon_cooldown_minutes, 1, 1440, 1);

    var ohOn = toggleField(t.off_hours_enabled, "Report off-hours workstation activity");
    var ohStart = numberField(t.off_hours_start, 0, 23, 1);
    var ohEnd = numberField(t.off_hours_end, 0, 23, 1);
    var ohZone = h("input", { type: "text", value: t.off_hours_zone || "Local", placeholder: "Local, UTC, or America/New_York" });

    var fsOn = toggleField(t.first_seen_enabled, "Report first-seen external destinations");
    var fsCool = numberField(t.first_seen_cooldown_minutes, 1, 1440, 1);
    var bwOn = toggleField(t.bandwidth_enabled, "Report bandwidth spikes");
    var bwCool = numberField(t.bandwidth_cooldown_minutes, 1, 1440, 1);
    var bwSamples = numberField(t.bandwidth_min_samples, 4, 1000, 1);

    var silenceOn = toggleField(t.silence_enabled, "Report agents that stop reporting");
    var silenceAfter = numberField(t.silence_after_minutes, 5, 1440, 1);

    var warmup = numberField(t.warmup_hours, 0, 720, 1);
    var containers = listField(t.container_cidrs, "172.17.0.0/16, fd12:3456::/64");
    var procs = listField(t.quiet_processes, "svchost.exe, apsd, systemd-timesyncd");
    var orgs = listField(t.quiet_orgs, "apple, microsoft, cloudflare");
    var clients = listField(t.quiet_clients, "chrome, firefox, msedge.exe");
    var pairs = listField(t.quiet_pairs, "backup-agent@backblaze, curl@github");

    var body = h("div", { cls: "stack" },
      h("p", { cls: "why", text: "These are the numbers the detectors run on. Every alert names the ones that produced it, so a finding you disagree with can be answered here rather than ignored." }),

      tuningRow("Container networks", "Explicit private CIDRs excluded from lateral fan-out detection. Leave empty when unknown; private addresses alone do not prove container traffic.", containers),
      h("h4", { cls: "tune-head", text: "Periodic beaconing" }),
      h("div", { cls: "tune-list" },
        tuningRow("", "", beaconOn.node),
        tuningRow("Confidence to report", "0 to 1. Combines how regular the interval is, how little it drifts, and how uniform the payload stays. Shipped default " + (d.beacon_score_threshold || "0.8") + ".", score),
        tuningRow("Check-ins required", "Below this there is not enough of a pattern to call one. Shipped default " + (d.beacon_min_samples || 12) + ".", samples),
        tuningRow("Observed for at least", "Minutes. Regular for ninety seconds is a burst, not a beacon.", span),
        tuningRow("Interval band", "Seconds. Conversations faster or slower than this are not considered.", h("div", { cls: "form-row" }, loInt, hiInt)),
        tuningRow("Repeat at most every", "Minutes between alerts about the same conversation.", bCool)),

      h("h4", { cls: "tune-head", text: "Off-hours activity" }),
      h("div", { cls: "tune-list" },
        tuningRow("", "", ohOn.node),
        tuningRow("Window", "Start and end hour. Wraps midnight when the start is later than the end.", h("div", { cls: "form-row" }, ohStart, ohEnd)),
        tuningRow("Time zone", "The hub's own zone unless you name one. Written as UTC, this window called an ordinary evening suspicious.", ohZone)),

      h("h4", { cls: "tune-head", text: "Other detectors" }),
      h("div", { cls: "tune-list" },
        tuningRow("", "", fsOn.node),
        tuningRow("Repeat at most every", "Minutes, per destination.", fsCool),
        tuningRow("", "", bwOn.node),
        tuningRow("Transfers required", "A spike is measured against what this process normally sends. Below this many observed transfers the baseline is guesswork, and every large-ish upload looks like an outlier. Shipped default " + (d.bandwidth_min_samples || 20) + ".", bwSamples),
        tuningRow("Repeat at most every", "Minutes, per process.", bwCool),
        tuningRow("", "", silenceOn.node),
        tuningRow("Silent after", "Minutes without a heartbeat before a host is reported as dark. Every other detector here needs telemetry, so stopping the agent is the cheapest way to blind all of them - and a crashed, rebuilt or disconnected host looks the same. One finding per host, and a recovery note when it returns.", silenceAfter)),

      h("h4", { cls: "tune-head", text: "New endpoints" }),
      h("div", { cls: "tune-list" },
        tuningRow("Learning period", "Hours. A host installed this morning has no baseline to be unusual against, and every ordinary thing it does is a first-seen destination. Behavioural findings are held and logged during this window. Set to 0 to judge a host from its first packet.", warmup)),

      h("h4", { cls: "tune-head", text: "Known-quiet" }),
      h("div", { cls: "tune-list" },
        tuningRow("Processes", "Matched on the program name. These are the operating system's own components, whose job is to talk to their vendor on a timer.", procs),
        tuningRow("Networks", "Matched against the owner of the destination address. On its own this names a network as ordinary; it no longer silences everything that reaches it.", orgs),
        tuningRow("Expected clients", "Programs whose regular traffic to those networks is expected - browsers, updaters, this agent. Beaconing and volume findings are silenced only for a listed program talking to a listed network, because a CDN is exactly where an implant would rather hide.", clients),
        tuningRow("Expected pairs", "One-off exceptions written program@network, the shape the Expected button on an alert produces. Rented cloud ranges are never silenced by either list.", pairs)));

    var save = function () {
      var payload = {
        beacon_enabled: beaconOn.input.checked,
        beacon_score_threshold: parseFloat(score.value) || 0,
        beacon_min_samples: parseInt(samples.value, 10) || 0,
        beacon_min_span_minutes: parseInt(span.value, 10) || 0,
        beacon_min_interval_seconds: parseInt(loInt.value, 10) || 0,
        beacon_max_interval_seconds: parseInt(hiInt.value, 10) || 0,
        beacon_cooldown_minutes: parseInt(bCool.value, 10) || 0,
        off_hours_enabled: ohOn.input.checked,
        off_hours_start: parseInt(ohStart.value, 10) || 0,
        off_hours_end: parseInt(ohEnd.value, 10) || 0,
        off_hours_zone: ohZone.value.trim() || "Local",
        first_seen_enabled: fsOn.input.checked,
        first_seen_cooldown_minutes: parseInt(fsCool.value, 10) || 0,
        bandwidth_enabled: bwOn.input.checked,
        bandwidth_cooldown_minutes: parseInt(bwCool.value, 10) || 0,
        bandwidth_min_samples: parseInt(bwSamples.value, 10) || 0,
        silence_enabled: silenceOn.input.checked,
        silence_after_minutes: parseInt(silenceAfter.value, 10) || 0,
        warmup_hours: parseInt(warmup.value, 10) || 0,
        quiet_processes: parseList(procs.value),
        quiet_orgs: parseList(orgs.value),
        quiet_clients: parseList(clients.value),
        quiet_pairs: parseList(pairs.value),
        container_cidrs: parseList(containers.value)
      };
      request("/api/v1/detection/tuning", "POST", payload).then(function (res) {
        state.tuning = res;
        toast("Detection tuning saved", "ok");
        closeSheet();
        renderBody();
      }).catch(function (e) { toast("Could not save: " + e.message, "crit"); });
    };

    var restore = function () {
      confirmSheet({
        title: "Restore shipped detection thresholds",
        consequence: "Every tuning value on this sheet is discarded and replaced with the defaults Ominull ships. Quiet-process and quiet-org lists built up over time are deleted, and the console has no record of what they were.",
        confirmLabel: "Restore shipped values",
        stack: true,
        onConfirm: sendRestoreTuning
      });
    };

    var sendRestoreTuning = function () {
      request("/api/v1/detection/tuning", "DELETE").then(function (res) {
        state.tuning = res;
        toast("Restored the shipped thresholds", "ok");
        closeSheet();
        renderBody();
      }).catch(function (e) { toast("Could not restore: " + e.message, "crit"); });
    };

    openSheet("Detection tuning", body, [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      IS_ADMIN ? h("button", { cls: "btn", type: "button", text: "Restore shipped values", on: { click: restore } }) : null,
      IS_ADMIN ? h("button", { cls: "btn btn-primary", type: "button", text: "Save", on: { click: save } }) : null
    ].filter(Boolean));
  }

  function tuningCard() {
    var wrap = state.tuning || {};
    var t = wrap.tuning || {};
    var d = wrap.defaults || {};
    var changed = [];
    Object.keys(d).forEach(function (k) {
      if (k === "updated_at" || k === "updated_by") return;
      var a = JSON.stringify(t[k]), b = JSON.stringify(d[k]);
      if (a !== undefined && a !== b) changed.push(k);
    });

    var body = h("div", { cls: "card-body stack" },
      h("dl", { cls: "kv" },
        h("dt", { text: "Beaconing" }),
        h("dd", {}, h("b", { text: t.beacon_enabled === false ? "Off" : "On" }),
          h("span", { cls: "dim-3", text: t.beacon_enabled === false ? "" : "  · " + (t.beacon_min_samples || "—") + " check-ins over " + (t.beacon_min_span_minutes || "—") + " min, confidence " + (t.beacon_score_threshold || "—") })),
        h("dt", { text: "Off-hours" }),
        h("dd", {}, h("b", { text: t.off_hours_enabled === false ? "Off" : "On" }),
          h("span", { cls: "dim-3", text: t.off_hours_enabled === false ? "" : "  · " + (wrap.window || "") })),
        h("dt", { text: "First-seen" }), h("dd", { text: t.first_seen_enabled === false ? "Off" : "On" }),
        h("dt", { text: "Bandwidth" }), h("dd", { text: t.bandwidth_enabled === false ? "Off" : "On" }),
        h("dt", { text: "Learning period" }),
        h("dd", { text: t.warmup_hours ? t.warmup_hours + "h after an endpoint first reports" : "None — hosts are judged from their first packet" }),
        h("dt", { text: "Known-quiet" }),
        h("dd", { text: arrayOf(t.quiet_processes).length + " process(es), " + arrayOf(t.quiet_orgs).length + " network(s), " + (arrayOf(t.quiet_clients).length + arrayOf(t.quiet_pairs).length) + " expected client(s)/pair(s)" }),
        h("dt", { text: "Hub time" }), h("dd", { cls: "ip", text: wrap.now || "—" })),
      changed.length
        ? h("p", { cls: "note note-warn", role: "alert", text: changed.length + " setting(s) differ from the shipped values" + (t.updated_by ? ", last changed by " + t.updated_by : "") })
        : h("p", { cls: "pending", text: "Running the shipped values." }));

    return card("Detection tuning", body, [
      h("button", {
        cls: "btn", type: "button", text: IS_ADMIN ? "Adjust" : "View",
        on: { click: openTuningSheet }
      })
    ]);
  }


  /* Learning mode.

     A window is the answer to "this estate has never been tuned and I am not
     going to read four hundred findings to do it". While one is open the
     detectors still run and their findings are recorded as held; when it
     closes, what was observed becomes proposals with the evidence attached.

     Nothing here applies itself. Each proposal names what it would silence,
     the technique that silence would blunt, and how many machines corroborate
     it - because a pair seen on five workstations is platform traffic and the
     same pair seen on exactly one host is the thing you were looking for. */
  function learningCard() {
    var rows = arrayOf(state.learningWindows).map(function (row) {
      var w = row.window || {};
      var label = row.open ? "Open" : (w.status || "closed");
      return [
        h("span", { cls: "dim", text: (w.scope_type || "") + " \u00b7 " + (w.scope_label || w.scope_id || "") }),
        h("span", { cls: "st", "data-state": row.open ? "ok" : "idle" },
          h("span", { text: label })),
        h("span", { cls: "dim-3", text: row.open ? (row.remaining_minutes + " min left") : stamp(parseTime(w.ends_at)) }),
        h("span", { cls: "dim-3", text: w.note || "" }),
        h("div", { cls: "row-actions" },
          h("button", {
            cls: "btn mini", type: "button", text: "Proposals",
            on: { click: function () { openProposalsSheet(w); } }
          }),
          (IS_ADMIN && row.open) ? h("button", {
            cls: "btn mini", type: "button", text: "Close",
            on: {
              click: function () {
                request("/api/v1/learning/windows/close", "POST", { id: w.id })
                  .then(function () { toast("Learning window closed", "ok"); refresh(); })
                  .catch(function (e) { toast("Close failed: " + e.message, "crit"); });
              }
            }
          }) : null)
      ];
    });

    var body = simpleTable(["Scope", "State", "Ends", "Note", ""], rows, {
      key: "learning-windows",
      empty: "No learning window has been opened. Detections are being judged, not described."
    });

    var actions = IS_ADMIN ? [
      h("button", {
        cls: "btn", type: "button", text: "Open a window",
        on: { click: openLearningSheet }
      })
    ] : [];
    return card("Learning mode", body, actions);
  }

  function openLearningSheet() {
    var scope = h("select", {}, 
      h("option", { value: "endpoint", text: "One endpoint" }),
      h("option", { value: "location", text: "A location" }),
      h("option", { value: "tenant", text: "The whole estate" }));
    var target = h("select", {});
    var note = h("input", { type: "text", placeholder: "Why this window is open" });
    var days = h("input", { type: "number", value: "7", min: "1", max: "90" });

    function fillTargets() {
      clear(target);
      if (scope.value === "endpoint") {
        arrayOf(state.endpoints).forEach(function (ep) {
          if (ep.status === "retired") return;
          target.appendChild(h("option", { value: ep.id, text: ep.hostname || ep.id }));
        });
      } else if (scope.value === "location") {
        arrayOf(state.locations).forEach(function (l) {
          target.appendChild(h("option", { value: l.id, text: l.name || l.id }));
        });
      } else {
        target.appendChild(h("option", { value: "", text: "every endpoint" }));
      }
    }
    scope.addEventListener("change", fillTargets);
    fillTargets();

    var body = h("div", { cls: "stack" },
      h("p", { cls: "note", text: "While this window is open, findings for the endpoints it covers are recorded and held rather than raised. They stay readable under HELD on the alerts page, and the silence detector is deliberately not exempt: a host going dark during its baseline period is exactly when you want to know." }),
      h("div", { cls: "form-row" },
        h("label", { cls: "field" }, h("span", { text: "Scope" }), scope),
        h("label", { cls: "field" }, h("span", { text: "Which" }), target)),
      h("div", { cls: "form-row" },
        h("label", { cls: "field" }, h("span", { text: "Days" }), days),
        h("label", { cls: "field" }, h("span", { text: "Note" }), note)));

    openSheet("Open a learning window", body, [
      h("button", {
        cls: "btn btn-primary", type: "button", text: "Open",
        on: {
          click: function () {
            request("/api/v1/learning/windows", "POST", {
              scope_type: scope.value,
              scope_id: target.value,
              days: Number(days.value) || 7,
              note: note.value
            }).then(function () {
              toast("Learning window open \u2014 findings for that scope are being held", "ok");
              closeSheet();
              refresh();
            }).catch(function (e) { toast("Could not open the window: " + e.message, "crit"); });
          }
        }
      })
    ]);
  }

  function openProposalsSheet(w) {
    request("/api/v1/learning/proposals?window=" + encodeURIComponent(w.id))
      .then(function (d) {
        var proposals = arrayOf(d && d.proposals);
        var chosen = {};
        var rows = proposals.map(function (p) {
          var box = h("input", { type: "checkbox" });
          box.addEventListener("change", function () { chosen[p.id] = box.checked; });
          return [
            IS_ADMIN ? box : h("span", { cls: "dim-3", text: "\u2014" }),
            h("span", { cls: "dim", text: p.kind.replace(/_/g, " ") }),
            h("span", { text: p.subject }),
            h("span", { cls: "dim-3", text: p.silences + (p.technique ? " (" + p.technique + ")" : "") }),
            h("span", { cls: "ip", text: p.evidence + " on " + p.endpoints + " host(s)" }),
            h("span", { cls: "st", "data-state": p.corroboration >= 0.6 ? "ok" : "idle" },
              h("span", { text: p.corroboration.toFixed(2) }))
          ];
        });

        var body = h("div", {},
          h("p", { cls: "note", text: "Corroboration is how many of the machines this window watched agree. A proposal backed by one host scores low on purpose: that is the shape of a finding, not of ordinary traffic." }),
          simpleTable(["", "Kind", "Subject", "Silences", "Evidence", "Corroboration"], rows, {
            key: "learning-proposals",
            empty: "This window has nothing to propose yet."
          }));

        openSheet("Proposals \u00b7 " + (w.scope_label || w.scope_id || ""), body, IS_ADMIN ? [
          h("button", {
            cls: "btn btn-primary", type: "button", text: "Apply selected",
            on: {
              click: function () {
                var ids = Object.keys(chosen).filter(function (k) { return chosen[k]; });
                if (!ids.length) { toast("Nothing selected", "warn"); return; }
                request("/api/v1/learning/proposals/apply", "POST", { window: w.id, ids: ids })
                  .then(function (res) {
                    var n = arrayOf(res && res.applied).length;
                    toast("Applied " + n + " proposal(s) \u2014 see Detection tuning", "ok");
                    closeSheet();
                    refresh();
                  })
                  .catch(function (e) { toast("Apply failed: " + e.message, "crit"); });
              }
            }
          })
        ] : []);
      })
      .catch(function (e) { toast("Could not read the proposals: " + e.message, "crit"); });
  }

  function renderPolicy() {
    var view = $("view");
    clear(view);

    /* An exclusion is a hole in the enforcement policy and the console listed
       them read-only, beside a Baseline card that can be edited freely - so
       the one table where "turn this off" is a security action was the one
       table with no way to do it. The hub has served the toggle all along. */
    var excl = simpleTable(["Name", "Scope", "Process", "Destination", "Port", "State", ""],
      state.exclusions.map(function (x) {
        return [
          h("span", { text: x.name || x.id }),
          h("span", { cls: "dim-3", text: x.scope + (x.scope_value ? " \u00b7 " + x.scope_value : "") }),
          h("span", { cls: "dim", text: x.process_path || "any" }),
          h("span", { cls: "ip", text: x.dst_ip_range || "any" }),
          h("span", { cls: "ip", text: (x.port ? String(x.port) : "any") + "/" + (x.protocol || "any") }),
          h("span", { cls: "st", "data-state": x.active ? "ok" : "idle" },
            icon(x.active ? "g-online" : "g-offline", true),
            h("span", { text: x.active ? "Active" : "Off" })),
          h("div", { cls: "row-actions" }, h("button", {
            cls: "btn mini" + (x.active ? "" : " btn-primary"), type: "button",
            text: x.active ? "Disable" : "Enable",
            on: { click: function () { confirmToggleExclusion(x); } }
          }))
        ];
      }),
      { key: "policy-exclusions", empty: "No exclusion has been carved out of the policy." });

    var iocs = simpleTable(["Indicator", "Type", "Threat", "Source", "Confidence", "Last seen"],
      state.iocs.map(function (i) {
        return [
          h("span", { cls: "ip", text: i.value || i.indicator || "\u2014" }),
          h("span", { cls: "dim-3", text: i.type || "" }),
          h("span", { cls: "dim", text: i.threat_type || i.threat_name || "" }),
          h("span", { cls: "dim-3", text: i.source || "" }),
          h("span", { cls: "ago", text: String(i.confidence !== undefined ? i.confidence : "") }),
          stamp(parseTime(i.last_seen_at || i.created_at))
        ];
      }));

    var mesh = simpleTable(["Address", "MAC", "Subnet", "Reason", "Since", ""],
      state.meshPeers.map(function (p) {
        return [
          h("span", { cls: "ip", text: p.target_ip }),
          h("span", { cls: "ip", text: p.target_mac || "\u2014" }),
          h("span", { cls: "ip", text: p.subnet || "\u2014" }),
          h("span", { cls: "dim", text: p.reason || "" }),
          stamp(parseTime(p.created_at)),
          h("button", {
            cls: "mini", type: "button", text: "Release",
            on: {
              click: function () {
                request("/api/v1/mesh/unquarantine", "POST", { target_ip: p.target_ip })
                  .then(function () { toast("Released " + p.target_ip + " from the mesh", "ok"); refresh(); })
                  .catch(function (e) { toast("Release failed: " + e.message, "crit"); });
              }
            }
          })
        ];
      }));

    if (!state.diagnostics && !state.diagnosticsRunning && !state.diagnosticsError) loadDiagnostics();

    var stackItems = [
      diagnosticsCard(),
      convergenceCard(),
      baselineCard(),
      tuningCard(),
      learningCard(),
      card("Exclusions", excl),
      card("Threat indicators", iocs, [
        h("button", {
          cls: "btn", type: "button", text: "Sync feeds",
          on: {
            click: function () {
              request("/api/v1/threatintel/sync", "POST")
                .then(function () { toast("Indicator feeds synced", "ok"); refresh(); })
                .catch(function (e) { toast("Sync failed: " + e.message, "crit"); });
            }
          }
        })
      ]),
      card("Peer-mesh quarantine", mesh)
    ];

    view.appendChild(h("div", { cls: "pad stack" }, stackItems.filter(Boolean)));
  }

  /* "Is the fleet actually on the release I shipped?"
     The hub answers this on every poll and has done all along: the console
     fetched /api/v1/agents/update-status every five seconds, read
     latest_version off it to colour version chips, and dropped outdated[],
     retired[], provenance_issues[] and native_converged on the floor. The
     words provenance, install_type and update_capability appeared nowhere in
     the console at all, so a host running the right version number from the
     wrong package was indistinguishable from a converged one. */
  function loadDiagnostics() {
    state.diagnosticsRunning = true;
    state.diagnosticsError = "";
    if (state.section === "policy") renderBody();
    return request("/api/v1/diagnostics")
      .then(function (d) {
        state.diagnostics = arrayOf(d && d.results);
        state.diagnosticsAt = Date.now();
      })
      .catch(function (e) { state.diagnosticsError = e.message || "diagnostics request failed"; })
      .then(function () {
        state.diagnosticsRunning = false;
        if (state.section === "policy") renderBody();
      });
  }

  var DIAG_TONE = { pass: "ok", fail: "crit", warn: "warn", not_configured: "idle" };

  /* The hub's own health, with the remediation text it already writes. The
     word "remediation" did not appear in the console at all: a check could
     fail and say exactly what to run, and the operator was shown nothing. */
  function diagnosticsCard() {
    var results = arrayOf(state.diagnostics);
    var counts = { pass: 0, fail: 0, warn: 0, not_configured: 0 };
    results.forEach(function (r) { counts[r.state] = (counts[r.state] || 0) + 1; });

    var head = h("div", { cls: "uf uf-g3 uf-wrap" },
      chip("ok", counts.pass + " passing"),
      counts.fail ? chip("crit", counts.fail + " failing") : null,
      counts.warn ? chip("warn", counts.warn + " warning") : null,
      counts.not_configured ? chip("idle", counts.not_configured + " not configured") : null,
      state.diagnosticsAt ? h("span", { cls: "dim-3", text: "checked " + ago(new Date(state.diagnosticsAt)) }) : null);

    var body = h("div", { cls: "card-body stack" });

    if (state.diagnosticsError) {
      body.appendChild(h("p", { cls: "note note-crit", role: "alert", text: "Could not run diagnostics: " + state.diagnosticsError }));
    } else if (state.diagnosticsRunning && !results.length) {
      body.appendChild(h("div", { cls: "empty" },
        h("span", { cls: "spin", "aria-hidden": "true" }),
        h("span", { text: "Running checks\u2026" })));
    } else {
      body.appendChild(head);
      /* Failures and warnings first: a wall of 24 green checks with one red
         one in the middle is a worse answer than the one red one. */
      var ordered = results.slice().sort(function (a, b) {
        var rank = { fail: 0, warn: 1, not_configured: 2, pass: 3 };
        return (rank[a.state] === undefined ? 4 : rank[a.state]) - (rank[b.state] === undefined ? 4 : rank[b.state]);
      });
      body.appendChild(simpleTable(["Check", "State", "Result", "What to do"],
        ordered.map(function (r) {
          return [
            h("span", { text: r.title || "Check" }),
            chip(DIAG_TONE[r.state] || "idle", (r.state || "unknown").replace("_", " ")),
            h("span", { cls: "dim-2 u-break", text: r.summary || "No result" }),
            r.remediation
              ? h("span", { cls: "why u-break", text: r.remediation })
              : h("span", { cls: "dim-3", text: "\u2014" })
          ];
        }), { key: "diagnostics", empty: "No checks reported." }));
    }

    return card("Hub diagnostics", body, [
      h("button", {
        cls: "btn", type: "button",
        text: state.diagnosticsRunning ? "Running\u2026" : "Run checks",
        disabled: state.diagnosticsRunning ? true : null,
        on: { click: loadDiagnostics }
      })
    ]);
  }

  function convergenceCard() {
    var u = state.updateStatus;
    if (!u) return null;

    var latest = u.latest_version || "\u2014";
    var outdated = arrayOf(u.outdated);
    var issues = arrayOf(u.provenance_issues);
    var retired = arrayOf(u.retired);
    var pending = arrayOf(u.pending);
    var converged = !!u.native_converged;

    var facts = h("div", { cls: "uf uf-g3 uf-wrap" },
      chip(converged ? "ok" : "warn", converged ? "Converged on " + latest : "Not converged"),
      chip(outdated.length ? "warn" : "idle", outdated.length + " behind " + latest),
      chip(issues.length ? "crit" : "idle", issues.length + " provenance issue" + (issues.length === 1 ? "" : "s")),
      chip(pending.length ? "info" : "idle", pending.length + " update" + (pending.length === 1 ? "" : "s") + " queued"),
      retired.length ? chip("idle", retired.length + " retired") : null);

    var body = h("div", { cls: "card-body stack" }, facts);

    if (outdated.length) {
      body.appendChild(h("div", { cls: "card-sub", text: "Behind the shipped release" }));
      body.appendChild(simpleTable(["Host", "Address", "OS", "Running", "Target"],
        outdated.map(function (e) {
          return [
            h("span", { cls: "host", text: e.hostname || e.endpoint_id }),
            h("span", { cls: "ip", text: e.ip || "\u2014" }),
            h("span", { cls: "dim-3", text: e.os || "\u2014" }),
            h("span", { cls: "ver", text: e.driver_version || "\u2014" }),
            h("span", { cls: "ver dim-3", text: latest })
          ];
        }), { key: "converge-outdated", empty: "Every agent is on " + latest + "." }));
    }

    if (issues.length) {
      body.appendChild(h("div", { cls: "card-sub", text: "Right version, wrong provenance" }));
      body.appendChild(h("p", { cls: "why", text: "These hosts report the shipped version number but the hub cannot tie the running agent back to a package it recognises. A self-updated binary on a host that is supposed to be managed by its native package manager is the usual cause, and it will be overwritten the next time that package manager runs." }));
      body.appendChild(simpleTable(["Host", "Install", "Package", "Registered", "Provenance", "Why"],
        issues.map(function (e) {
          return [
            h("span", { cls: "host", text: e.hostname || e.endpoint_id }),
            h("span", { cls: "dim-3", text: e.install_type || "unknown" }),
            h("span", { cls: "ip", text: e.package_identifier || "\u2014" }),
            h("span", { cls: "ver", text: e.registered_package_version || "\u2014" }),
            chip(e.provenance_status === "verified" ? "ok" : "crit", e.provenance_status || "unknown"),
            h("span", { cls: "dim-2 u-break", text: e.reason || "" })
          ];
        }), { key: "converge-provenance" }));
    }

    if (!outdated.length && !issues.length) {
      body.appendChild(h("p", { cls: "why", text: "Every non-retired agent reports " + latest + " from a package the hub recognises." }));
    }

    return card("Fleet convergence", body, IS_ADMIN ? [
      h("button", { cls: "btn", type: "button", text: "Push agent updates", on: { click: pushAgentUpdates } })
    ] : null);
  }

  function renderAudit() {
    var view = $("view");
    clear(view);

    var rows = state.audit.map(function (a) {
      return [
        stamp(parseTime(a.timestamp)),
        h("span", { cls: "dim", text: a.username || a.user_id || "\u2014" }),
        h("span", { text: a.action || "" }),
        h("span", { cls: "ip", text: a.resource || "" }),
        h("span", { cls: "dim-3", text: a.details || "" }),
        h("span", { cls: "ip", text: a.ip_address || "" })
      ];
    });

    view.appendChild(h("div", { cls: "pad stack" },
      card("Audit trail", simpleTable(["Time", "Actor", "Action", "Resource", "Details", "From"], rows))));
  }


  /* ------------------------------------------------- response authority & crypto */

  var ephemeralResponseKey = null;

  function hasWebCrypto() {
    return !!(window.crypto && window.crypto.subtle && window.crypto.subtle.generateKey && window.isSecureContext);
  }

  function bufToHex(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i].toString(16);
      hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex;
  }

  function encodeActionProofV2(proof) {
    var parts = [];
    function writeString(str) {
      var bytes = new TextEncoder().encode(str);
      var lenBuf = new Uint8Array(4);
      new DataView(lenBuf.buffer).setUint32(0, bytes.length, false);
      parts.push(lenBuf, bytes);
    }
    function writeUint32(n) {
      var buf = new Uint8Array(4);
      new DataView(buf.buffer).setUint32(0, n, false);
      parts.push(buf);
    }
    function writeInt64(n) {
      var buf = new Uint8Array(8);
      new DataView(buf.buffer).setBigInt64(0, BigInt(n), false);
      parts.push(buf);
    }
    function writeHexNormalized(hexStr) {
      writeString(String(hexStr || "").toLowerCase().trim());
    }
    function writeStringSlice(arr) {
      writeUint32(arr.length);
      for (var i = 0; i < arr.length; i++) {
        writeString(arr[i]);
      }
    }

    writeString("OMINULL-ACTION-PROOF-V2");
    writeUint32(proof.version || 2);
    writeString(proof.session_id);
    writeString(proof.tenant_id);
    writeString(proof.action_kind);
    writeHexNormalized(proof.action_digest);
    writeStringSlice(proof.target_endpoints || []);
    writeInt64(proof.timestamp);
    writeHexNormalized(proof.nonce);

    var totalLen = 0;
    for (var i = 0; i < parts.length; i++) totalLen += parts[i].length;
    var out = new Uint8Array(totalLen);
    var offset = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], offset);
      offset += parts[j].length;
    }
    return out;
  }

  function digestSHA256(str) {
    var bytes = new TextEncoder().encode(str);
    return window.crypto.subtle.digest("SHA-256", bytes).then(function (digestBuf) {
      return bufToHex(digestBuf);
    });
  }

  function signActionProof(actionKind, actionDigestHex, targetEndpoints) {
    if (!state.responseSession || !ephemeralResponseKey) {
      return Promise.reject(new Error("Response session is locked. Multi-factor unlock required."));
    }
    var nonceBytes = new Uint8Array(16);
    window.crypto.getRandomValues(nonceBytes);
    var nonceHex = bufToHex(nonceBytes);

    var nowSec = Math.floor(Date.now() / 1000);
    var targets = Array.isArray(targetEndpoints) ? targetEndpoints : [targetEndpoints];

    var proof = {
      version: 2,
      session_id: state.responseSession.session_id,
      tenant_id: state.responseSession.tenant_id || "default",
      action_kind: actionKind,
      action_digest: String(actionDigestHex || "").toLowerCase().trim(),
      target_endpoints: targets,
      timestamp: nowSec,
      nonce: nonceHex
    };

    var canonicalBytes = encodeActionProofV2(proof);
    return window.crypto.subtle.sign({ name: "Ed25519" }, ephemeralResponseKey.privateKey, canonicalBytes)
      .then(function (sigBuf) {
        proof.signature = bufToHex(sigBuf);
        return proof;
      });
  }

  function updateResponseButton() {
    var btn = $("topbar-response-btn");
    var txt = $("response-status-text");
    if (!btn || !txt) return;

    if (!state.responseSession) {
      btn.setAttribute("data-status", "locked");
      btn.title = "Response Authority Locked. Click to unlock with MFA/Passkey.";
      txt.textContent = "Response Locked";
      var icon = btn.querySelector("use");
      if (icon) icon.setAttribute("href", "#i-lock");
      return;
    }

    var now = Date.now();
    var exp = state.responseSession.expires_at ? new Date(state.responseSession.expires_at).getTime() : 0;
    var idleExp = state.responseSession.idle_expires_at ? new Date(state.responseSession.idle_expires_at).getTime() : 0;

    if ((exp && now >= exp) || (idleExp && now >= idleExp)) {
      state.responseSession = null;
      ephemeralResponseKey = null;
      btn.setAttribute("data-status", "locked");
      btn.title = "Response session expired. Click to unlock.";
      txt.textContent = "Response Locked";
      var icon = btn.querySelector("use");
      if (icon) icon.setAttribute("href", "#i-lock");
      toast("Response session expired.", "warn");
      if (state.section === "response") renderBody();
      return;
    }

    btn.setAttribute("data-status", "unlocked");
    btn.title = "Response Authority Unlocked. Click to view session details or lock.";
    var icon = btn.querySelector("use");
    if (icon) icon.setAttribute("href", "#i-unlock");

    var remMs = Math.min(exp ? exp - now : 86400000, idleExp ? idleExp - now : 86400000);
    var remSec = Math.max(0, Math.floor(remMs / 1000));
    var min = Math.floor(remSec / 60);
    var sec = remSec % 60;
    var timeStr = (min < 10 ? "0" : "") + min + ":" + (sec < 10 ? "0" : "") + sec;

    txt.textContent = "Unlocked (" + timeStr + ")";
  }

  function updateResponseTimer() {
    if (state.responseSession) {
      updateResponseButton();
    }
  }

  /* Locking throws away the browser signing key. Re-unlocking is a fresh TOTP
     and a fresh key, which is a real interruption mid-incident, so the two
     deliberate "Lock Response Authority" buttons ask first. Expiry and idle
     timeout call lockResponseSession() directly and must not prompt. */
  /* Disabling an exclusion tightens the policy and enabling one loosens it, so
     only the loosening direction is stopped for a sentence. */
  function confirmToggleExclusion(x) {
    var name = x.name || x.id;
    var apply = function () {
      request("/api/v1/exclusions/toggle", "POST", { id: x.id, active: !x.active })
        .then(function () {
          toast((x.active ? "Disabled" : "Enabled") + " exclusion " + name, "ok");
          refresh();
        })
        .catch(function (e) { toast("Could not change the exclusion: " + e.message, "crit"); });
    };
    if (x.active) { apply(); return; }
    confirmSheet({
      title: "Enable exclusion " + name,
      consequence: "Traffic matching this exclusion stops being inspected and stops being enforced against, on every endpoint in scope, until somebody turns it off again.",
      detail: (x.process_path || "any process") + " \u2192 " + (x.dst_ip_range || "any destination") +
        " on " + (x.port ? String(x.port) : "any port") + "/" + (x.protocol || "any"),
      confirmLabel: "Enable exclusion",
      onConfirm: apply
    });
  }

  /* The job lifecycle, named exactly as the hub names it (response.JobState:
     queued, offered, acknowledged, running, succeeded, failed, cancel_requested,
     cancelled). Listing the *finished* states rather than the open ones is the
     safe direction: a state added later shows a Cancel button the hub then
     refuses, instead of silently hiding the button on a job that is very much
     still running. cancel_requested is already on its way out, so it is
     finished for this purpose too. */
  var RESPONSE_JOB_CLOSED = {
    succeeded: true, failed: true, cancelled: true, cancel_requested: true
  };

  function responseJobIsOpen(j) {
    return !RESPONSE_JOB_CLOSED[String((j && j.state) || "queued")];
  }

  function confirmCancelResponseJob(j) {
    /* A job the agent has not taken yet is cancelled outright. Once it has been
       offered or acknowledged the hub can only *ask*: the agent has to notice
       the cancellation and stop. Saying "cancelled" in that case would tell an
       operator the action is over when it may still be running on the host. */
    var takenUp = String(j.state || "queued") !== "queued";
    confirmSheet({
      title: "Cancel response job",
      consequence: takenUp
        ? "The agent on " + (j.endpoint_id || "the endpoint") + " has already taken this job. Cancelling asks it to stop; anything it has already done is not undone, and there is no guarantee it stops before it finishes."
        : "The job stops being offered to " + (j.endpoint_id || "the endpoint") + " and is closed without ever running.",
      detail: (j.action_kind || j.kind || "response job") + " \u00b7 " + (j.id || "") +
        " \u00b7 " + (j.state || "queued") +
        (j.requested_by ? " \u00b7 requested by " + j.requested_by : ""),
      confirmLabel: takenUp ? "Ask the agent to stop" : "Cancel job",
      onConfirm: function () {
        request("/api/v1/response/jobs/cancel", "POST", { job_id: j.id })
          .then(function (res) {
            var requested = !res || res.status !== "cancelled";
            toast(requested && takenUp
              ? "Cancellation sent to " + (j.endpoint_id || "the endpoint") + ". The job closes when the agent acknowledges it."
              : "Response job cancelled.", "ok");
            refresh();
          })
          .catch(function (e) { toast("Could not cancel the job: " + e.message, "crit"); });
      }
    });
  }

  function confirmLockResponseSession() {
    confirmSheet({
      title: "Lock response authority",
      consequence: "The browser signing key is destroyed and active response authority is dropped. Any response action you start after this needs a fresh unlock with your authenticator before it will run.",
      detail: "Response jobs already dispatched to an agent keep running.",
      confirmLabel: "Lock authority",
      stack: true,
      onConfirm: lockResponseSession
    });
  }

  function lockResponseSession() {
    if (state.responseSession && state.responseSession.session_id) {
      request("/api/v1/response/auth/lock", "POST", { session_id: state.responseSession.session_id })
        .catch(function () {});
    }
    state.responseSession = null;
    ephemeralResponseKey = null;
    updateResponseButton();
    toast("Response authority locked.", "info");
    if (state.section === "response") renderBody();
  }

  function openResponseControllerSheet() {
    if (!state.responseSession) return;
    var sess = state.responseSession;
    var keyFp = ephemeralResponseKey ? ephemeralResponseKey.publicKeyHex.slice(0, 16) + "\u2026" : "active";

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row" },
        chip("ok", "Session Active"),
        h("span", { cls: "dim-2", text: "Session ID: " + (sess.session_id ? sess.session_id.slice(0, 16) + "\u2026" : "") })
      ),
      h("dl", { cls: "kv" },
        h("dt", { text: "Operator" }), h("dd", {}, h("b", { text: sess.operator_id || OPERATOR || "admin" })),
        h("dt", { text: "Tenant" }), h("dd", { text: sess.tenant_id || "default" }),
        h("dt", { text: "Auth Method" }), h("dd", { text: sess.auth_method || "totp" }),
        h("dt", { text: "Browser Key" }), h("dd", { cls: "ip", text: keyFp }),
        h("dt", { text: "Absolute Expiry" }), h("dd", { text: sess.expires_at ? new Date(sess.expires_at).toLocaleTimeString() : "8h" }),
        h("dt", { text: "Idle Expiry" }), h("dd", { text: sess.idle_expires_at ? new Date(sess.idle_expires_at).toLocaleTimeString() : "30m" })
      ),
      h("p", { cls: "pending", text: "Locking the session immediately revokes the browser signing key and drops active response authority." })
    );

    var lockBtn = h("button", {
      cls: "btn btn-crit",
      type: "button",
      text: "Lock Response Authority",
      /* confirmLockResponseSession, not lockResponseSession - see there. */
      on: {
        click: function () {
          closeSheet();
          confirmLockResponseSession();
        }
      }
    });

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      lockBtn
    ];

    openSheet("Response Authority Controller", body, foot);
  }

  function openUnlockResponseSheet(onSuccess) {
    if (!hasWebCrypto()) {
      openSheet("Secure Context Required",
        h("div", { cls: "card-body stack" },
          h("div", { cls: "st-banner", "data-state": "crit", text: "WebCrypto & Secure Context Unavailable" }),
          h("p", { cls: "pending", text: "Response authority operations require an ephemeral in-memory Ed25519 browser key signed via the WebCrypto API. Browsers disable WebCrypto on unencrypted or non-secure origins." }),
          h("p", { text: "To unlock response sessions, connect over HTTPS with a trusted certificate (such as the hub's dedicated console TLS listener)." })
        ),
        [h("button", { cls: "btn", type: "button", text: "Dismiss", on: { click: closeSheet } })]
      );
      return;
    }

    var op = state.you || OPERATOR || "admin";
    var tenant = "default";
    if (state.hierarchy && state.hierarchy.length && state.hierarchy[0].tenant) {
      tenant = state.hierarchy[0].tenant.id || "default";
    }

    var errBox = h("div", { cls: "note note-crit", role: "alert", hidden: true });
    var codeInput = h("input", {
      type: "text",
      id: "unlock-totp-code",
      cls: "input-code",
      placeholder: "000000",
      maxlength: "8",
      pattern: "[0-9]*",
      autocomplete: "one-time-code",
      autofocus: true
    });

    var submitBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Unlock Response Session",
      on: {
        click: function () {
          var code = (codeInput.value || "").trim().replace(/\s+/g, "");
          if (code.length < 6) {
            errBox.textContent = "Please enter a valid 6-digit TOTP code.";
            errBox.removeAttribute("hidden");
            codeInput.focus();
            return;
          }

          submitBtn.disabled = true;
          submitBtn.textContent = "Generating Key & Unlocking\u2026";
          errBox.setAttribute("hidden", "");

          var browserSessionId = "sess-browser-" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

          window.crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
            .then(function (keyPair) {
              return window.crypto.subtle.exportKey("raw", keyPair.publicKey)
                .then(function (rawPub) {
                  var pubHex = bufToHex(rawPub);
                  return request("/api/v1/response/auth/unlock", "POST", {
                    operator_id: op,
                    browser_session_id: browserSessionId,
                    browser_public_key: pubHex,
                    totp_code: code
                  }).then(function (session) {
                    state.responseSession = session;
                    ephemeralResponseKey = {
                      keyPair: keyPair,
                      privateKey: keyPair.privateKey,
                      publicKeyHex: pubHex,
                      browserSessionId: browserSessionId
                    };
                    closeSheet();
                    updateResponseButton();
                    toast("Response authority unlocked for 8 hours (30m idle).", "ok");
                    if (state.section === "response") renderBody();
                    if (typeof onSuccess === "function") onSuccess(session);
                  });
                });
            })
            .catch(function (err) {
              submitBtn.disabled = false;
              submitBtn.textContent = "Unlock Response Session";
              errBox.textContent = err.message || "Failed to unlock response session.";
              errBox.removeAttribute("hidden");
              codeInput.focus();
            });
        }
      }
    });

    codeInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        submitBtn.click();
      }
    });

    var enrollBox = h("div", { cls: "totp-enroll-box stack-s u-mt2", hidden: true });
    var enrollBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Setup / Reset Authenticator (TOTP)",
      on: {
        click: function () {
          enrollBtn.disabled = true;
          enrollBtn.textContent = "Generating Secret…";
          request("/api/v1/response/auth/totp/enroll", "POST", { operator_id: op })
            .then(function (res) {
              enrollBtn.style.display = "none";
              enrollBox.style.display = "block";
              enrollBox.innerHTML = "";
              var keyRow = h("div", { cls: "stack-s totp-key-row" },
                h("div", { cls: "label-meta", text: "Manual Entry Secret Key (Base32):" }),
                h("div", { cls: "row-acts uf uf-g3" },
                  h("code", { cls: "cmd u-strong u-break", text: res.secret }),
                  h("button", {
                    cls: "btn mini",
                    type: "button",
                    text: "Copy Key",
                    on: {
                      click: function () { copyText(res.secret, "TOTP Secret Key"); }
                    }
                  })
                ),
                h("div", { cls: "why u-mt1" },
                  h("span", { text: "Add this key into your authenticator app (Google Authenticator, 1Password, Aegis, Bitwarden, etc.). " }),
                  res.otpauth_url ? h("a", { href: res.otpauth_url, target: "_blank", rel: "noopener", text: "Open in Authenticator App" }) : null
                )
              );
              enrollBox.appendChild(keyRow);
              toast("Authenticator enrolled. Enter the generated 6-digit code above.", "ok");
              codeInput.focus();
            })
            .catch(function (err) {
              enrollBtn.disabled = false;
              enrollBtn.textContent = "Setup / Reset Authenticator (TOTP)";
              errBox.textContent = "Enrollment failed: " + (err.message || err);
              errBox.removeAttribute("hidden");
            });
        }
      }
    });

    var body = h("div", { cls: "card-body stack" },
      h("p", { cls: "pending", text: "Response authority operations require multi-factor proof and an ephemeral in-memory Ed25519 keypair. Your private key remains exclusively in browser memory and is never written to disk." }),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Operator: " }), h("b", { text: op }),
        h("span", { cls: "dim-2", text: " \u00b7 Tenant: " }), h("b", { text: tenant })
      ),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "unlock-totp-code", text: "Enter 6-Digit Authenticator Code (TOTP):" }),
        codeInput
      ),
      h("div", { cls: "form-row u-mt1" }, enrollBtn),
      enrollBox,
      errBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      submitBtn
    ];

    openSheet("Unlock Response Authority", body, foot);
    setTimeout(function () { codeInput.focus(); }, 100);
  }

  function launchTerminalShell(asset) {
    if (!asset || !asset.endpoint) {
      toast("Cannot open terminal: host does not have an enrolled agent.", "crit");
      return;
    }

    if (!state.responseSession || !ephemeralResponseKey) {
      openUnlockResponseSheet(function () {
        launchTerminalShell(asset);
      });
      return;
    }

    var ep = asset.endpoint;
    var isWindows = (ep.os || "").toLowerCase().indexOf("windows") >= 0;

    var progSel = h("select", { id: "shell-prog-select" });
    if (isWindows) {
      progSel.appendChild(h("option", { value: "powershell.exe", text: "powershell.exe (Windows PowerShell)" }));
      progSel.appendChild(h("option", { value: "cmd.exe", text: "cmd.exe (Windows Command Prompt)" }));
      progSel.appendChild(h("option", { value: "pwsh.exe", text: "pwsh.exe (PowerShell Core, if installed)" }));
    } else {
      progSel.appendChild(h("option", { value: "/bin/bash", text: "/bin/bash (Interactive Shell)" }));
      progSel.appendChild(h("option", { value: "/bin/sh", text: "/bin/sh (POSIX Shell)" }));
    }

    var errBox = h("div", { cls: "note note-crit", role: "alert", hidden: true });

    var launchBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Launch Terminal Shell",
      on: {
        click: function () {
          var prog = progSel.value;
          launchBtn.disabled = true;
          launchBtn.textContent = "Signing Proof & Dispatching\u2026";
          errBox.setAttribute("hidden", "");

          var payload = { program: prog };
          var payloadStr = JSON.stringify(payload);

          digestSHA256(payloadStr)
            .then(function (digestHex) {
              return signActionProof("terminal_session", digestHex, [ep.id])
                .then(function (proof) {
                  return request("/api/v1/terminal/sessions", "POST", {
                    endpoint_id: ep.id,
                    program: prog,
                    session_id: state.responseSession.session_id,
                    action_digest: digestHex,
                    proof: proof
                  });
                });
            })
            .then(function (sessionSummary) {
              closeSheet();
              toast("Terminal shell session created (" + sessionSummary.session_id.slice(0, 8) + "\u2026). Connecting emulator.", "ok");
              /* Stay where the operator is. This forced `go("response")`,
                 and go() closes the sheet, the route panel and the drawer -
                 so launching a shell from an asset's route panel silently
                 destroyed the panel they were working in. The emulator is a
                 sheet; it does not need a section behind it. */
              openTerminalEmulator(sessionSummary);
            })
            .catch(function (err) {
              launchBtn.disabled = false;
              launchBtn.textContent = "Launch Terminal Shell";
              errBox.textContent = err.message || "Failed to launch terminal shell.";
              errBox.removeAttribute("hidden");
            });
        }
      }
    });

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Target Host: " }), h("b", { text: asset.name || asset.ip }),
        h("span", { cls: "dim-2", text: " \u00b7 Endpoint ID: " }), h("span", { cls: "ip", text: ep.id })
      ),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Platform: " }), h("b", { text: ep.os || "Linux" }),
        h("span", { cls: "dim-2", text: " \u00b7 Privilege Identity: " }), h("b", { cls: "st", "data-state": "crit", text: isWindows ? "LocalSystem" : "root" })
      ),
      h("p", { cls: "pending", text: "Terminal sessions run with full host supervisor identity. Your browser will sign a typed ActionProof V2 bound specifically to this endpoint and program choice. All input, output, and resize frames are encrypted and audited." }),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "shell-prog-select", text: "Select Executable Allowlist Program:" }),
        progSel
      ),
      errBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      launchBtn
    ];

    openSheet("Launch Remote Pseudoterminal", body, foot);
  }

  function openLaunchEndpointShellPicker() {
    var managed = (state.assets || []).filter(function (a) { return a.endpoint; });
    if (!managed.length) {
      toast("No agent-managed endpoints online.", "warn");
      return;
    }

    var sel = h("select", { id: "shell-target-picker" });
    managed.forEach(function (a) {
      sel.appendChild(h("option", { value: a.key, text: (a.name || a.ip) + " (" + (a.endpoint.os || "Linux") + ") - " + a.endpoint.id }));
    });

    var body = h("div", { cls: "card-body stack" },
      h("p", { cls: "pending", text: "Select an enrolled endpoint to open an interactive remote pseudoterminal session:" }),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "shell-target-picker", text: "Target Endpoint:" }),
        sel
      )
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-primary", type: "button", text: "Next \u2192",
        on: {
          click: function () {
            var asset = state.assetByKey[sel.value];
            closeSheet();
            if (asset) launchTerminalShell(asset);
          }
        }
      })
    ];

    openSheet("Select Target Endpoint for Shell", body, foot);
  }

  /* The one live-session lookup, and the one reattach path. The Response page
     row, the Assets banner and the Assets context menu all route through
     reattachTerminal so there is a single implementation of "come back to a
     shell" rather than three that drift. */
  /* Set by an open terminal sheet so the fleet poll can hand it the hub's own
     view of its session. Cleared when the sheet closes. */
  var terminalMetaSubscriber = null;
  var terminalMetaSessionID = "";

  function liveTerminalFor(ep) {
    if (!ep || !ep.id) return null;
    var sessions = arrayOf(state.terminalSessions);
    for (var i = 0; i < sessions.length; i++) {
      var t = sessions[i];
      if (!t || t.endpoint_id !== ep.id) continue;
      if (t.state === "active" || t.state === "detached" || t.state === "connecting" || t.state === "waiting") return t;
    }
    return null;
  }

  function terminalSessionIsLive(t) {
    return !!t && (t.state === "active" || t.state === "detached" || t.state === "connecting" || t.state === "waiting");
  }

  /* Reattaching needs a live response session but no fresh TOTP proof: the
     ActionProof V2 on creation authorised *spawning* a root shell, and coming
     back to one this operator already spawned is not a second privileged
     action. A lapsed response session falls through to the unlock sheet with
     a resume callback, the pattern launchTerminalShell already uses. */
  function reattachTerminal(sessionSummary) {
    if (!sessionSummary || !sessionSummary.session_id) return;
    if (!terminalSessionIsLive(sessionSummary)) {
      toast("That session is no longer live \u2014 nothing to reattach to.", "warn");
      return;
    }
    if (!state.responseSession || !ephemeralResponseKey) {
      openUnlockResponseSheet(function () { reattachTerminal(sessionSummary); });
      return;
    }
    request("/api/v1/terminal/sessions/attach", "POST", { session_id: sessionSummary.session_id })
      .then(function (sum) {
        openTerminalEmulator(sum || sessionSummary, true);
      })
      .catch(function (e) {
        toast("Reattach refused: " + e.message, "crit");
        refresh();
      });
  }

  /* How the agent actually ends the session, per platform. Both sentences said
     "SIGTERM and then SIGKILL", which is the Linux path only: the Windows agent
     holds the shell and everything it started in a job object and ends the lot
     with TerminateJobObject. Naming the wrong mechanism in a confirmation is
     the same defect as naming the wrong blast radius - an operator reads it to
     decide whether to press the button. */
  function terminateMechanism(program) {
    /* The program is what the session was launched with and it is on every
       summary the hub serves; the session summary carries no OS field, so
       reaching for one would have read undefined and quietly picked the Linux
       sentence for every host. */
    return /\.exe$|^pwsh$|^powershell$|^cmd$/i.test(String(program || ""))
      ? "ended together through the job object the agent holds them in"
      : "killed with SIGTERM and then SIGKILL";
  }

  function terminateTerminalSession(sessionSummary, hostLabel) {
    if (!sessionSummary || !sessionSummary.session_id) return;
    var host = hostLabel || sessionSummary.endpoint_id || "this host";
    var act = function () { closeTerminalSession(sessionSummary.session_id); };
    if (!state.responseSession || !ephemeralResponseKey) {
      openUnlockResponseSheet(function () { terminateTerminalSession(sessionSummary, hostLabel); });
      return;
    }
    confirmSheet({
      title: "Terminate terminal session",
      consequence: "Every process started by that shell on " + host + " is " +
        terminateMechanism(sessionSummary && sessionSummary.program) +
        ". Unsaved work in editors on that host is lost, and the session recording is sealed into evidence and cannot be resumed.",
      detail: (sessionSummary.program || "shell") + " \u00b7 session " + String(sessionSummary.session_id).slice(0, 8) + "\u2026",
      confirmLabel: "Terminate session",
      onConfirm: act
    });
  }

  function closeTerminalSession(sessionId) {
    request("/api/v1/terminal/sessions?id=" + encodeURIComponent(sessionId), "DELETE")
      .then(function () {
        toast("Terminal session closed.", "ok");
        refresh();
      })
      .catch(function (e) {
        toast("Failed to close terminal session: " + e.message, "crit");
      });
  }

  /* xterm's own scrollback, and the cap on how much recording is replayed
     into it: writing more than the buffer holds costs time and shows the same
     last N lines. */
  var TERM_SCROLLBACK = 5000;
  /* Six attempts over ~12s of backoff. Enough for a Wi-Fi blip or a proxy
     recycling; short enough that a session that is genuinely gone stops being
     retried and says so. */
  var TERM_MAX_RECONNECT = 6;

  function openTerminalEmulator(session, reattaching) {
    if (!session || !session.session_id) return;

    var epId = session.endpoint_id || "unknown";
    var asset = assetForEndpoint(epId);
    var hostName = asset ? (asset.name || asset.ip || epId) : epId;
    var epOs = (asset && asset.endpoint && asset.endpoint.os) || "Linux";
    var isWindows = epOs.indexOf("Windows") !== -1;
    var identity = isWindows ? "LocalSystem" : "root";
    var prog = session.program || (isWindows ? "powershell.exe" : "/bin/bash");

    var activeSessionsCount = (state.terminalSessions || []).filter(function (s) {
      return s.state === "active" || s.state === "connecting" || s.state === "waiting";
    }).length;

    // Terminal Emulator & WebSocket State
    var term = null;
    var fitAddon = null;
    var ws = null;
    var resizeObserver = null;
    var frameCount = session.frame_count || 0;
    var encLabel = session.encryption || (session.bundle_id ? "AES-256-GCM Evidence" : "AES-256-GCM");
    var termContainer = h("div", { cls: "terminal-container", id: "active-terminal-container" });

    // Status elements
    /* setChip rewrites this in place as the relay connects, drops, retries and
       reattaches. Without a live region none of that is announced, and the
       terminal is the one place where "it stopped working" has to be heard. */
    var statusBadge = chip(session.state === "active" ? "ok" : "warn",
      session.state === "active" ? "Agent Connected" : "Connecting to Relay\u2026");
    statusBadge.setAttribute("role", "status");
    statusBadge.setAttribute("aria-live", "polite");
    var frameCountEl = h("span", { cls: "dim-2" });
    /* recording_bytes and max_recording_bytes ride on every poll and were both
       unused, so the cap announced itself only by appearing mid-scrollback as
       "[Recording limit reached]". Saying how much of it is spent, while it is
       being spent, is the difference between a surprise and a deadline. */
    var recordedBytes = Number(session && session.recording_bytes) || 0;
    var recordedCap = Number(session && session.max_recording_bytes) || 0;
    var recordingBounded = !!(session && session.recording_state === "bounded");
    /* Only the hub knows how many bytes it recorded. Counting them on this end
       instead - adding each frame's length as it arrived off the socket - read
       "13.9 MB of 10.0 MB recorded" on a live session, because a viewer sees
       three things the recording does not: the scrollback replayed to it on
       every reattach, the frames the hub declined to record once the cap was
       reached, and the JSON envelope around each one. A number about evidence
       retention that drifts past its own limit is worse than one that only
       moves when the five-second poll lands. */
    var updateFrames = function (sum) {
      if (sum) {
        if (sum.recording_bytes !== undefined) recordedBytes = Number(sum.recording_bytes) || 0;
        if (sum.max_recording_bytes) recordedCap = Number(sum.max_recording_bytes) || 0;
        if (sum.recording_state === "bounded") recordingBounded = true;
      }
      var text = "Frames: " + frameCount + " (" + encLabel + ")";
      if (recordingBounded) {
        /* The session is still live and still audited; it is the *recording*
           that stopped. An operator who is about to do something they will
           later need to prove has to be told which of those two it is. */
        text += " \u00b7 recording stopped at " + bytes(recordedCap || recordedBytes);
      } else if (recordedCap > 0) {
        text += " \u00b7 " + bytes(Math.min(recordedBytes, recordedCap)) + " of " + bytes(recordedCap) + " recorded";
      } else if (recordedBytes > 0) {
        text += " \u00b7 " + bytes(recordedBytes) + " recorded";
      }
      frameCountEl.textContent = text;
      frameCountEl.setAttribute("data-near-cap",
        recordingBounded || (recordedCap > 0 && recordedBytes / recordedCap >= 0.9) ? "true" : "false");
      frameCountEl.setAttribute("title", recordingBounded
        ? "The recording reached its " + bytes(recordedCap || recordedBytes) + " cap and stopped. The session is still live and still audited, but nothing from here on is sealed into evidence."
        : recordedCap > 0
          ? "The session recording is sealed into evidence. Output past " + bytes(recordedCap) + " is not recorded."
          : "No recording cap reported by the hub.");
    };
    updateFrames(session);
    /* The summary rides the five-second fleet poll that Assets already runs,
       so the figure moves on its own while the operator watches it. */
    terminalMetaSubscriber = function (sum) { updateFrames(sum); };
    terminalMetaSessionID = (session && session.session_id) || "";
    /* The hub sends expires_at and idle_expires_at on every poll. This was a
       hardcoded "Duration: 60m · Idle: 15m", which is a promise the console
       cannot keep - it is whatever --terminal-max-duration and
       --terminal-idle-timeout say on the hub, and the string would have lied
       the moment either changed. */
    var limitsEl = h("span", { cls: "dim-3" });
    var updateLimits = function (sum) {
      var expires = parseTime(sum && sum.expires_at);
      var idle = parseTime(sum && sum.idle_expires_at);
      var parts = [];
      parts.push(expires ? "Ends " + stampText(expires) : "Ends \u2014");
      parts.push(idle ? "Idle out " + stampText(idle) : "Idle out \u2014");
      parts.push("Tenant slots: " + activeSessionsCount + "/4");
      limitsEl.textContent = parts.join(" \u00b7 ");
      limitsEl.setAttribute("title",
        (expires ? "Maximum duration reached at " + expires.toString() : "No maximum duration reported") + "\n" +
        (idle ? "Idle timeout at " + idle.toString() + " unless you type" : "No idle deadline reported"));
    };
    updateLimits(session);

    var overlayMsg = h("div", { cls: "terminal-overlay-msg" },
      h("div", { cls: "spin" }),
      h("b", { text: "Establishing Encrypted Terminal Relay\u2026" }),
      h("span", { cls: "dim-2", text: "Waiting for agent on " + hostName + " (" + epId + ") to connect via loopback WSS." }),
      h("span", { cls: "dim-3", text: "Terminal supervisor process will spawn as " + identity + " with " + prog })
    );
    termContainer.appendChild(overlayMsg);

    // Meta bar
    var metaBar = h("div", { cls: "terminal-meta-bar" },
      h("div", { cls: "terminal-meta-left" },
        statusBadge,
        h("span", { cls: "dim", text: "Endpoint: " }), h("b", { text: hostName }),
        h("span", { cls: "dim-2", text: "(" + epId + ")" }),
        chip("idle", identity),
        h("span", { cls: "ip", text: prog })
      ),
      h("div", { cls: "terminal-meta-right" },
        frameCountEl,
        limitsEl
      )
    );

    /* Set while the operator is deliberately leaving, so ws.onclose knows the
       difference between "I detached" and "the network dropped" - the first
       is done, the second gets a reconnect. */
    var leaving = false;
    var terminated = false;
    var reconnectAttempt = 0;
    var reconnectTimer = null;

    function cleanup() {
      leaving = true;
      /* The poll outlives this sheet; leaving the closure subscribed would
         keep writing into a detached element for the life of the page. */
      terminalMetaSubscriber = null;
      terminalMetaSessionID = "";
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      if (resizeObserver) {
        try { resizeObserver.disconnect(); } catch (e) {}
        resizeObserver = null;
      }
      if (ws) {
        try {
          ws.onclose = null;
          ws.onerror = null;
          ws.onmessage = null;
          /* No close frame. Closing the socket is now a detach on the hub
             side: the process tree keeps running and the session moves to
             `detached`. Sending {type:"close"} is the explicit terminate and
             belongs only to the Terminate button. */
          ws.close();
        } catch (e) {}
        ws = null;
      }
      if (term) {
        try { term.dispose(); } catch (e) {}
        term = null;
      }
      if (liveTerminal) liveTerminal = null;
    }

    // Foot controls
    var sendCtrlCBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Ctrl+C",
      title: "Send Interrupt (SIGINT)",
      on: {
        click: function () {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "stdin", data: btoa("\x03") }));
          }
          if (term) term.focus();
        }
      }
    });

    var sendCtrlDBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Ctrl+D",
      title: "Send EOF",
      on: {
        click: function () {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "stdin", data: btoa("\x04") }));
          }
          if (term) term.focus();
        }
      }
    });

    var clearBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Clear",
      title: "Clear Terminal Screen",
      on: {
        click: function () {
          if (term) term.clear();
        }
      }
    });

    var terminateNow = function () {
      terminated = true;
      leaving = true;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "close" }));
      }
      closeTerminalSession(session.session_id);
      closeSheet();
    };

    var closeSessBtn = h("button", {
      cls: "btn btn-crit",
      type: "button",
      /* Renamed from "Close Session". "Close" is what the ✕ does to a window;
         this kills a process tree on a live host. */
      text: "Terminate Session",
      title: "Kill the remote shell session and seal the recording",
      on: {
        click: function () {
          /* This was the file's only window.confirm(), in a console with a
             purpose-built sheet system - and it named no host and stated no
             consequence beyond one line of browser chrome. */
          confirmSheet({
            title: "Terminate terminal session",
            consequence: "Every process started by that shell on " + hostName + " (" + epId + ") is " +
              terminateMechanism(prog || session.program) +
              ". Unsaved work in editors on that host is lost, and the session recording is sealed into evidence and cannot be resumed.",
            detail: prog + " running as " + identity + " \u00b7 session " + session.session_id.slice(0, 8) + "\u2026",
            confirmLabel: "Terminate session",
            stack: true,
            onConfirm: terminateNow
          });
        }
      }
    });

    var detachBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Detach Viewer",
      title: "Close this viewer and leave the remote session running",
      on: {
        click: function () {
          /* This used to be `closeSheet(); refresh();` - and closeSheet ran
             the cleanup that closed the WebSocket, which the hub answered by
             closing the whole relay, which sent the agent a close frame,
             which made the agent SIGTERM/SIGKILL the remote shell session.
             The button labelled "Detach Viewer", whose tooltip said it would
             not terminate the session, terminated the session. It works now
             because the hub treats an operator socket closing as a detach. */
          leaving = true;
          closeSheet();
          toast("Session detached \u2014 still running on " + hostName + ". Reattach from the asset row.", "ok");
          refresh();
        }
      }
    });

    var foot = [
      h("div", { cls: "terminal-foot-actions" },
        h("div", { cls: "terminal-actions-group" },
          sendCtrlCBtn,
          sendCtrlDBtn,
          clearBtn
        ),
        h("div", { cls: "terminal-actions-group" },
          detachBtn,
          closeSessBtn
        )
      )
    ];

    var body = h("div", { cls: "sheet-terminal-wrapper" },
      metaBar,
      termContainer
    );

    openSheet("Pseudoterminal \u2014 " + hostName + " (" + session.session_id.slice(0, 8) + "\u2026)", body, foot, "sheet-terminal",
      { initialFocus: false });
    if (sheetEl) {
      sheetEl._cleanup = cleanup;
      sheetEl._isTerminal = true;
      /* A stray click on the scrim used to kill a root shell. It detaches
         now, so the question is only whether they meant to leave - and the
         answer is stated rather than implied. */
      sheetEl._confirmClose = function () {
        if (terminated || !ws || ws.readyState !== WebSocket.OPEN) return true;
        leaving = true;
        toast("Session detached \u2014 still running on " + hostName + ". Reattach from the asset row.", "ok");
        return true;
      };
    }

    // Check if xterm is available
    if (!window.Terminal) {
      overlayMsg.innerHTML = "";
      overlayMsg.appendChild(h("div", { cls: "st-banner", "data-state": "crit", text: "Vendored Terminal Emulator Unavailable" }));
      overlayMsg.appendChild(h("p", { text: "The xterm.js terminal engine could not be loaded from /vendor/xterm.js." }));
      return;
    }

    // Initialize xterm with full 16-color ANSI palette and opaque background
    term = new window.Terminal({
      cursorBlink: true,
      cursorStyle: "block",
      convertEol: true,
      /* JetBrains Mono, Fira Code and Cascadia were requested and none of them
         ship with the hub - an airgapped fleet has no CDN to fetch them from,
         so this fell all the way through to Menlo/Consolas. IBM Plex Mono is
         the face the console actually bundles, and --f-mono names it. */
      fontFamily: cssVar("--f-mono", "ui-monospace, Menlo, Consolas, monospace"),
      fontSize: 13,
      lineHeight: 1.25,
      letterSpacing: 0.5,
      allowTransparency: false,
      theme: terminalTheme(),
      allowProposedApi: false,
      scrollback: TERM_SCROLLBACK
    });
    liveTerminal = term;

    if (window.FitAddon && window.FitAddon.FitAddon) {
      fitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(fitAddon);
    }

    term.open(termContainer);
    if (fitAddon) {
      try { fitAddon.fit(); } catch (e) {}
    }
    term.focus();

    // ------------------------------------------------- scrollback replay
    //
    // Reattaching to a session that has been running without a viewer means
    // the output produced meanwhile is in the recording and not on this
    // screen. GET /api/v1/terminal/frames answers with the *live* in-memory
    // frames for an unsealed session, so no new backend was needed for this.
    //
    // Live frames that arrive while the replay is still being fetched are
    // buffered, not written: interleaving them would put the last second of
    // output in the middle of the last ten minutes of it.
    var replaying = false;
    var liveBuffer = [];

    function writeFrameData(b64) {
      if (!b64 || !term) return;
      var bin = atob(b64);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      term.write(bytes);
    }

    function flushLiveBuffer() {
      replaying = false;
      while (liveBuffer.length) writeFrameData(liveBuffer.shift());
    }

    function replayScrollback() {
      replaying = true;
      return request("/api/v1/terminal/frames?session_id=" + encodeURIComponent(session.session_id))
        .then(function (d) {
          var frames = arrayOf(d && d.frames).filter(function (f) { return f && f.type === "stdout"; });
          if (!frames.length) return;
          /* Bounded by xterm's own scrollback: replaying 10 MiB of recording
             into a 5000-line buffer costs the time and shows the last 5000
             lines either way. */
          var tail = frames.length > TERM_SCROLLBACK ? frames.slice(frames.length - TERM_SCROLLBACK) : frames;
          if (tail.length < frames.length) {
            term.write("\r\n\x1b[2m\u2500\u2500 earlier output trimmed (" + (frames.length - tail.length) + " frames) \u2500\u2500\x1b[0m\r\n");
          }
          tail.forEach(function (f) { writeFrameData(f.data); });
          term.write("\r\n\x1b[2m\u2500\u2500 replayed " + tail.length + " frame(s) \u00b7 live from here \u2500\u2500\x1b[0m\r\n");
        })
        .catch(function () { /* replay is a convenience; live I/O still works */ })
        .then(flushLiveBuffer);
    }

    // ------------------------------------------------------- the socket
    var wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    var wsUrl = wsProto + "//" + window.location.host + "/api/v1/terminal/ws/operator?session_id=" + encodeURIComponent(session.session_id);

    function connect(isReconnect) {
      try {
        ws = new WebSocket(wsUrl);
      } catch (e) {
        setChip(statusBadge, "crit", "Connection failed");
        term.write("\r\n[Failed to open WebSocket: " + e.message + "]\r\n");
        return;
      }

      ws.onopen = function () {
        reconnectAttempt = 0;
        setChip(statusBadge, "info", "Attached \u00b7 awaiting agent");
        ws.send(JSON.stringify({ type: "resize", rows: term.rows, cols: term.cols }));
        if (isReconnect || session.state === "detached" || (session.frame_count || 0) > 0) {
          replayScrollback();
        }
      };

      ws.onmessage = function (event) {
        try {
          var frame = JSON.parse(event.data);
          frameCount++;
          updateFrames(null);

          if (frame.type === "stdout") {
            if (overlayMsg.parentNode) overlayMsg.parentNode.removeChild(overlayMsg);
            setChip(statusBadge, "ok", "Attached (Live)");
            if (replaying) liveBuffer.push(frame.data);
            else writeFrameData(frame.data);
          } else if (frame.type === "bounded") {
            setChip(statusBadge, "warn", "Recording bounded");
            /* Through updateFrames, not by writing the element directly: the
               next frame off the socket rebuilt this line and erased it. */
            recordingBounded = true;
            updateFrames(null);
            term.write("\r\n\x1b[33m[Session recording bounded: 10MB limit reached]\x1b[0m\r\n");
          } else if (frame.type === "close") {
            terminated = true;
            leaving = true;
            setChip(statusBadge, "idle", "Terminated");
            term.write("\r\n\r\n[Remote session terminated by agent]\r\n");
          }
        } catch (e) {
          console.error("Failed to parse incoming terminal frame:", e);
        }
      };

      ws.onerror = function () {
        if (!leaving) setChip(statusBadge, "crit", "Relay error");
      };

      ws.onclose = function (e) {
        if (leaving || terminated) {
          setChip(statusBadge, "idle", terminated ? "Terminated" : "Detached (running in background)");
          return;
        }
        /* Not a deliberate detach: a Wi-Fi blip, a proxy timeout, a laptop
           lid. The hub has moved the session to `detached` and the shell is
           still there, so come back rather than stranding the operator on a
           dead rectangle. Bounded, because a session that is genuinely gone
           must stop being retried. */
        if (reconnectAttempt >= TERM_MAX_RECONNECT) {
          setChip(statusBadge, "crit", "Disconnected (code " + e.code + ")");
          term.write("\r\n[Terminal relay disconnected and could not be reattached. Reattach from the asset row.]\r\n");
          return;
        }
        reconnectAttempt++;
        var delay = Math.min(8000, 400 * Math.pow(2, reconnectAttempt - 1));
        setChip(statusBadge, "warn", "Reconnecting\u2026 (" + reconnectAttempt + "/" + TERM_MAX_RECONNECT + ")");
        reconnectTimer = setTimeout(function () {
          reconnectTimer = null;
          if (leaving || terminated) return;
          /* The connect token is single-attach, so a reconnect has to mint a
             fresh one. That POST also re-sets the HttpOnly cookie the
             WebSocket upgrade carries. */
          request("/api/v1/terminal/sessions/attach", "POST", { session_id: session.session_id })
            .then(function (sum) {
              if (sum) { session = sum; updateLimits(sum); updateFrames(sum); }
              if (!leaving && !terminated) connect(true);
            })
            .catch(function (err) {
              setChip(statusBadge, "crit", "Reattach refused");
              term.write("\r\n[Reattach refused: " + (err && err.message ? err.message : "unknown") + "]\r\n");
            });
        }, delay);
      };
    }

    connect(!!reattaching);

    // Terminal keyboard input
    term.onData(function (data) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        var bytes = new TextEncoder().encode(data);
        var bin = "";
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        ws.send(JSON.stringify({ type: "stdin", data: btoa(bin) }));
      }
    });

    // Resize handling
    if (window.ResizeObserver) {
      resizeObserver = new ResizeObserver(function () {
        if (fitAddon) {
          try {
            fitAddon.fit();
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: "resize", rows: term.rows, cols: term.cols }));
            }
          } catch (e) {}
        }
      });
      resizeObserver.observe(termContainer);
    }
  }

  function renderResponse() {
    var view = $("view");
    clear(view);

    var auth = state.responseAuthStatus || { active_sessions: 0 };
    var isUnlocked = !!state.responseSession;

    var authActions = isUnlocked
      ? [
          h("button", { cls: "btn btn-crit", type: "button", text: "Lock Response Authority", on: { click: confirmLockResponseSession } }),
          h("button", { cls: "btn", type: "button", text: "Session Details", on: { click: openResponseControllerSheet } })
        ]
      : [
          h("button", { cls: "btn btn-primary", type: "button", text: "Unlock Response Session", on: { click: function () { openUnlockResponseSheet(); } } })
        ];

    var authCard = card("Response Authority (Ring-0/Proof)", h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row" },
        chip(isUnlocked ? "ok" : "warn", isUnlocked ? "Response Unlocked" : "Response Locked"),
        h("span", { cls: "dim-2", text: "Active Operator Sessions: " + (auth.active_sessions || 0) + " | Key ID: " + (auth.signer_key_id ? auth.signer_key_id.slice(0, 16) + "..." : "configured") })
      ),
      isUnlocked
        ? h("p", { cls: "pending", text: "Response authority is currently unlocked. You may launch forensic collections, interactive pseudoterminals, and execute immutable scripts under signed ActionProof V2. An ephemeral browser key signed with TOTP is active in memory." })
        : h("p", { cls: "pending", text: "Autonomous threat nullification, script execution, and endpoint response actions require ephemeral operator proof signed by an authenticated response session. Unlock with TOTP/Passkey to issue commands." }),
      h("div", { cls: "form-row" }, authActions)
    ));

    // Remote Terminal Sessions Card
    var termSessions = state.terminalSessions || [];
    var termRows = termSessions.map(function (ts) {
      var live = terminalSessionIsLive(ts);
      /* The session-id link used to call openTerminalEmulator unconditionally
         for every row - only the row's *button* was gated on state - so
         clicking a closed session opened an emulator against a dead session
         that could never connect. A closed session's id is a label. */
      var idCell = live
        ? h("a", {
            cls: "ip", href: "#",
            title: "Reattach to this session",
            text: ts.session_id ? ts.session_id.slice(0, 8) + "\u2026" : "",
            on: { click: function (e) { e.preventDefault(); reattachTerminal(ts); } }
          })
        : h("span", {
            cls: "ip dim-2",
            title: "Session " + (ts.close_reason || "closed") + " \u2014 inspect its recording in Forensics",
            text: ts.session_id ? ts.session_id.slice(0, 8) + "\u2026" : ""
          });

      return [
        idCell,
        h("span", { text: ts.endpoint_id || "" }),
        h("span", { text: ts.program || "" }),
        chip(terminalStateTone(ts.state), ts.state || "unknown"),
        h("span", { cls: "dim-2", text: (ts.recording_state || (ts.closed_at ? "sealed" : "recording")) + (ts.frame_count !== undefined ? " (" + ts.frame_count + " frames)" : "") }),
        h("span", { cls: "dim", text: ts.operator_id || "" }),
        stamp(parseTime(ts.created_at)),
        h("div", { cls: "row-actions" },
          live
            ? [
                /* One reattach implementation, shared with the Assets banner
                   and the context menu, so the token rotation and the replay
                   cannot drift between three copies. */
                h("button", { cls: "btn mini", type: "button", text: ts.state === "detached" ? "Reattach" : "Open Console", on: { click: function () { reattachTerminal(ts); } } }),
                h("button", { cls: "btn mini", "data-danger": "true", type: "button", text: "Terminate", on: { click: function () { terminateTerminalSession(ts, ts.endpoint_id); } } })
              ]
            : h("span", { cls: "dim-3", text: ts.close_reason || "closed" })
        )
      ];
    });

    var termCardHead = h("div", { cls: "card-header-actions" },
      h("button", {
        cls: "btn btn-primary",
        type: "button",
        text: "Launch Endpoint Shell",
        on: {
          click: function () {
            openLaunchEndpointShellPicker();
          }
        }
      })
    );

    var termCard = card("Remote Terminal Sessions (ConPTY / forkpty)",
      termRows.length ? simpleTable(["Session ID", "Endpoint", "Program", "State", "Recording", "Operator", "Created", "Action"], termRows) : h("div", { cls: "card-body", text: "No active terminal sessions. Click 'Launch Endpoint Shell' to open a session." }),
      [termCardHead]
    );

    var jobRows = (state.responseJobs || []).map(function (j) {
      return [
        h("a", {
          cls: "ip mono",
          href: "#",
          text: j.id ? j.id.slice(0, 8) + "..." : "",
          on: {
            click: function (e) {
              e.preventDefault();
              openJobOutputModal(j.id);
            }
          }
        }),
        h("span", { text: j.endpoint_id || "" }),
        h("span", { text: j.action_kind || j.kind || "" }),
        /* A failed job's error_code is the difference between "it failed" and
           "the grant had expired", and it was fetched and dropped. */
        h("div", { cls: "uf-col" },
          chip(j.state === "succeeded" ? "ok" : (j.state === "failed" || j.state === "timed_out" ? "crit" : "warn"), j.state || "queued"),
          j.error_code ? h("span", { cls: "dim-3 u-t1", text: j.error_code }) : null,
          (j.attempt || 0) > 1 ? h("span", { cls: "dim-3 u-t1", text: "attempt " + j.attempt }) : null),
        /* The job carries requested_by. The console read operator_id, which no
           response job has ever had, so the Operator column was blank for every
           row on the page - and "who ran this" is the first question asked of
           any response job. */
        h("span", { cls: "dim", text: j.requested_by || j.operator_id || "\u2014" }),
        stamp(parseTime(j.requested_at || j.created_at)),
        /* lease_expires_at says when the agent's claim on this job lapses,
           which is the difference between "still running" and "stuck". */
        h("div", { cls: "row-actions" },
          h("button", {
            cls: "btn mini",
            type: "button",
            text: "Inspect",
            on: {
              click: function () {
                openJobOutputModal(j.id);
              }
            }
          }),
          /* The hub has always served a cancel route and the console never
             called it, so a job dispatched by mistake could only be waited
             out. Only a job that has not finished can be cancelled. */
          responseJobIsOpen(j)
            ? h("button", {
                cls: "btn mini", type: "button", "data-danger": "true", text: "Cancel",
                title: j.lease_expires_at
                  ? "Agent lease runs to " + stampTitle(parseTime(j.lease_expires_at))
                  : "This job has not been leased by an agent yet",
                on: { click: function () { confirmCancelResponseJob(j); } }
              })
            : null
        )
      ];
    });

    var jobsCard = card("Active Response Jobs",
      jobRows.length ? simpleTable(["Job ID", "Endpoint", "Action", "State", "Operator", "Created", "Output"], jobRows) : h("div", { cls: "card-body", text: "No active response jobs in queue." })
    );

    var scriptRows = (state.scripts || []).map(function (sc) {
      return [
        h("b", { text: sc.name || "" }),
        h("span", { cls: "mono", text: sc.interpreter || "" }),
        h("span", { text: "v" + (sc.latest_version || 1) }),
        h("span", { cls: "dim-2", text: sc.description || "" }),
        chip(sc.retired ? "crit" : "ok", sc.retired ? "Retired" : "Active"),
        stamp(parseTime(sc.updated_at)),
        h("div", { cls: "row-actions" },
          !sc.retired ? h("button", {
            cls: "btn mini",
            type: "button",
            text: "Run",
            on: {
              click: function () {
                openScriptRunSheet(sc);
              }
            }
          }) : null,
          h("button", {
            cls: "btn mini",
            type: "button",
            text: "Versions",
            on: {
              click: function () {
                openScriptVersionsSheet(sc);
              }
            }
          }),
          !sc.retired ? h("button", {
            cls: "btn mini", "data-danger": "true",
            type: "button",
            text: "Retire",
            on: {
              click: function () {
                retireScriptConfirm(sc);
              }
            }
          }) : null
        )
      ];
    });

    var scriptCardHead = h("div", { cls: "card-header-actions" },
      h("button", {
        cls: "btn btn-primary",
        type: "button",
        text: "New Script",
        on: {
          click: function () {
            openCreateScriptSheet();
          }
        }
      })
    );

    var scriptsCard = card("Immutable Script Library",
      scriptRows.length ? simpleTable(["Script", "Interpreter", "Version", "Description", "Status", "Updated", "Actions"], scriptRows) : h("div", { cls: "card-body", text: "No registered response scripts. Click 'New Script' to register a script." }),
      [scriptCardHead]
    );

    var schedRows = (state.scriptSchedules || []).map(function (sched) {
      var targetCount = (sched.target_endpoints || []).length;
      var targetPreview = targetCount === 1 ? sched.target_endpoints[0] : targetCount + " endpoints";
      var isCancelled = sched.status === "cancelled";
      return [
        h("span", { cls: "ip mono", text: sched.id ? sched.id.slice(0, 12) + "..." : "" }),
        h("span", { text: (sched.script_id || "").slice(0, 8) + "... v" + sched.version }),
        h("span", { cls: "mono dim-2", text: (sched.script_digest || "").slice(0, 12) + "..." }),
        chip("idle", sched.recurrence || "daily"),
        h("span", { title: (sched.target_endpoints || []).join(", "), text: targetPreview }),
        h("span", { cls: "dim-2", text: (sched.runs_count || 0) + " / " + (sched.max_runs > 0 ? sched.max_runs : "indefinite") }),
        chip(isCancelled ? "crit" : "ok", sched.status || "active"),
        stamp(parseTime(sched.created_at)),
        h("div", { cls: "row-actions" },
          !isCancelled ? h("button", {
            cls: "btn mini", "data-danger": "true",
            type: "button",
            text: "Cancel",
            on: {
              click: function () {
                cancelScriptScheduleConfirm(sched.id);
              }
            }
          }) : h("span", { cls: "dim-3", text: "cancelled" })
        )
      ];
    });

    var schedulesCard = card("Frozen Script Schedules",
      schedRows.length ? simpleTable(["Schedule ID", "Script", "Frozen Digest", "Recurrence", "Target Snapshot", "Runs", "Status", "Created", "Action"], schedRows) : h("div", { cls: "card-body", text: "No scheduled script executions." })
    );

    view.appendChild(h("div", { cls: "pad stack" }, authCard, termCard, jobsCard, scriptsCard, schedulesCard));
  }

  function openJobOutputModal(jobId) {
    if (!jobId) return;

    var headTitle = "Response Job: " + (jobId.length > 16 ? jobId.slice(0, 16) + "..." : jobId);
    var statusBadge = chip("warn", "Loading...");
    statusBadge.setAttribute("aria-live", "polite");
    var metaGrid = h("div", { cls: "alert-exp-grid" });
    var stdoutBox = h("pre", { cls: "job-output-console", text: "Fetching output..." });
    var stderrBox = h("pre", { cls: "job-output-console stderr", hidden: true });
    var truncNotice = h("div", { cls: "st-banner", "data-state": "warn", hidden: true, text: "Output exceeded maximum buffer size and was truncated by endpoint worker." });
    var errBox = h("div", { cls: "note note-crit", role: "alert", hidden: true });

    var copyStdoutBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Copy stdout",
      on: {
        click: function () {
          copyText(stdoutBox.textContent, "stdout");
        }
      }
    });

    var copyStderrBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Copy stderr",
      hidden: true,
      on: {
        click: function () {
          copyText(stderrBox.textContent, "stderr");
        }
      }
    });

    var stdoutHeader = h("div", { cls: "form-row uf uf-between" },
      h("label", { cls: "u-strong", text: "Standard Output (stdout):" }),
      copyStdoutBtn
    );

    var stderrHeader = h("div", { cls: "form-row uf uf-between", hidden: true },
      h("label", { cls: "u-strong", text: "Standard Error (stderr):" }),
      copyStderrBtn
    );

    function renderJobData(job) {
      if (!job) return;
      var isSucceeded = job.state === "succeeded";
      var isFailed = job.state === "failed" || job.state === "timed_out";
      setChip(statusBadge, isSucceeded ? "ok" : (isFailed ? "crit" : "warn"));
      statusBadge.textContent = (job.state || "queued").toUpperCase();

      clear(metaGrid);
      function addMeta(label, val) {
        metaGrid.appendChild(h("div", { cls: "alert-exp-box" },
          h("div", { cls: "alert-exp-label", text: label }),
          h("div", { cls: "alert-exp-val", text: val || "—" })
        ));
      }

      addMeta("Endpoint", job.endpoint_id);
      addMeta("Action Kind", job.action_kind || job.kind);
      addMeta("Operator", job.requested_by || job.operator_id);
      addMeta("Grant", job.authorization_grant_id);
      if (job.error_code) addMeta("Error code", job.error_code);
      if (job.attempt) addMeta("Attempt", String(job.attempt));
      if (job.lease_expires_at) addMeta("Lease expires", job.lease_expires_at);
      addMeta("Dispatched", job.created_at ? new Date(job.created_at).toLocaleString() : "—");

      var res = null;
      if (job.result_json) {
        try { res = JSON.parse(job.result_json); } catch (e) { res = null; }
      }

      if (res) {
        addMeta("Exit Code", res.exit_code !== undefined ? String(res.exit_code) : (isSucceeded ? "0" : "—"));
        addMeta("Duration", res.duration_ms !== undefined ? res.duration_ms + " ms" : "—");
        if (res.error_code) addMeta("Error Code", res.error_code);

        stdoutBox.textContent = res.stdout || "(no standard output produced)";
        if (res.stderr && res.stderr.trim()) {
          stderrBox.textContent = res.stderr;
          stderrBox.removeAttribute("hidden");
          stderrHeader.removeAttribute("hidden");
          copyStderrBtn.removeAttribute("hidden");
        } else {
          stderrBox.setAttribute("hidden", "");
          stderrHeader.setAttribute("hidden", "");
          copyStderrBtn.setAttribute("hidden", "");
        }

        if (res.truncated) {
          truncNotice.removeAttribute("hidden");
        } else {
          truncNotice.setAttribute("hidden", "");
        }
      } else {
        addMeta("Status Detail", job.state === "queued" ? "Queued in hub dispatch queue" : "Running on endpoint worker");
        stdoutBox.textContent = "Job is currently " + (job.state || "queued") + ".\nWaiting for endpoint execution and telemetry return...";
        stderrBox.setAttribute("hidden", "");
        stderrHeader.setAttribute("hidden", "");
        copyStderrBtn.setAttribute("hidden", "");
        truncNotice.setAttribute("hidden", "");
      }
    }

    var pollTimer = null;
    function poll() {
      request("/api/v1/response/jobs?id=" + encodeURIComponent(jobId))
        .then(function (job) {
          errBox.setAttribute("hidden", "");
          renderJobData(job);
          if (job && (job.state === "succeeded" || job.state === "failed" || job.state === "timed_out")) {
            if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
          }
        })
        .catch(function (err) {
          errBox.textContent = err.message || "Failed to load job details.";
          errBox.removeAttribute("hidden");
        });
    }

    poll();
    pollTimer = setInterval(poll, 2000);

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row uf uf-between" },
        h("div", { cls: "form-row" },
          statusBadge,
          h("span", { cls: "ip mono dim-2", text: jobId })
        ),
        h("button", { cls: "btn mini", type: "button", text: "Refresh", on: { click: poll } })
      ),
      metaGrid,
      truncNotice,
      errBox,
      stdoutHeader,
      stdoutBox,
      stderrHeader,
      stderrBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } })
    ];

    openSheet(headTitle, body, foot, "sheet-wide");
    if (sheetEl) {
      sheetEl._cleanup = function () {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      };
    }
  }

  function openCreateScriptSheet() {
    var nameInput = h("input", { id: "create-script-name", type: "text", placeholder: "e.g. check_disk_usage.sh" });
    var descInput = h("input", { id: "create-script-desc", type: "text", placeholder: "e.g. Check disk usage thresholds and mount points" });

    var interpSel = h("select", { id: "create-script-interp" });
    [
      { val: "/bin/bash", label: "/bin/bash (GNU Bourne-Again Shell - Linux)" },
      { val: "/bin/sh", label: "/bin/sh (POSIX Shell - Linux)" },
      { val: "powershell.exe", label: "powershell.exe (Windows PowerShell 5.1+)" },
      { val: "cmd.exe", label: "cmd.exe (Windows Command Prompt)" },
      { val: "pwsh.exe", label: "pwsh.exe (PowerShell Core)" }
    ].forEach(function (opt) {
      interpSel.appendChild(h("option", { value: opt.val, text: opt.label }));
    });

    var sourceEditor = h("textarea", {
      id: "create-script-source",
      cls: "code-editor",
      rows: "10",
      placeholder: "#!/bin/bash\n# Script source executed verbatim without textual template injection\necho \"Starting audit on $(hostname)\"\n"
    });

    var schemaEditor = h("textarea", {
      id: "create-script-schema",
      cls: "code-editor",
      rows: "6",
      placeholder: "Optional JSON parameter schema (leave empty if script requires no parameters)"
    });

    var insertTemplateBtn = h("button", {
      cls: "btn mini",
      type: "button",
      text: "Insert Schema Template",
      on: {
        click: function () {
          schemaEditor.value = JSON.stringify({
            parameters: [
              { name: "threshold_pct", type: "number", required: true, "default": "80", description: "Alert threshold percentage" },
              { name: "mount_point", type: "string", required: false, "default": "/", description: "Mount point to check" },
              { name: "notify_level", type: "enum", "enum": ["info", "warning", "critical"], required: false, "default": "warning", description: "Severity tag" }
            ]
          }, null, 2);
        }
      }
    });

    var errBox = h("div", { id: "create-script-err", cls: "note note-crit", role: "alert", hidden: true });

    var submitBtn = h("button", {
      id: "create-script-submit",
      cls: "btn btn-primary",
      type: "button",
      text: "Register Script",
      on: {
        click: function () {
          var name = (nameInput.value || "").trim();
          var desc = (descInput.value || "").trim();
          var interp = interpSel.value;
          var src = sourceEditor.value;
          var schemaText = (schemaEditor.value || "").trim();

          if (!name) {
            errBox.textContent = "Please enter a script name.";
            errBox.removeAttribute("hidden");
            nameInput.focus();
            return;
          }
          if (!src || !src.trim()) {
            errBox.textContent = "Please provide script source code.";
            errBox.removeAttribute("hidden");
            sourceEditor.focus();
            return;
          }
          if (schemaText) {
            try {
              JSON.parse(schemaText);
            } catch (e) {
              errBox.textContent = "Invalid Parameter Schema JSON: " + e.message;
              errBox.removeAttribute("hidden");
              schemaEditor.focus();
              return;
            }
          }

          submitBtn.disabled = true;
          submitBtn.textContent = "Registering...";
          errBox.setAttribute("hidden", "");

          request("/api/v1/scripts", "POST", {
            name: name,
            description: desc,
            interpreter: interp,
            source: src,
            parameter_schema_json: schemaText
          })
            .then(function (res) {
              closeSheet();
              toast("Script '" + name + "' registered as v1.", "ok");
              return request("/api/v1/scripts").then(function (d) {
                state.scripts = arrayOf(d && d.scripts || d);
                if (state.section === "response") renderBody();
              });
            })
            .catch(function (err) {
              submitBtn.disabled = false;
              submitBtn.textContent = "Register Script";
              errBox.textContent = err.message || "Failed to register script.";
              errBox.removeAttribute("hidden");
            });
        }
      }
    });

    var body = h("div", { cls: "card-body stack" },
      h("p", { cls: "pending", text: "Register an immutable script in the Ominull script library. Scripts are hashed with SHA-256 upon registration. Modifying a script creates a new immutable version." }),
      h("div", { cls: "form-row stack-s" },
        labelFor("Script Name:", nameInput),
        nameInput
      ),
      h("div", { cls: "form-row stack-s" },
        labelFor("Description:", descInput),
        descInput
      ),
      h("div", { cls: "form-row stack-s" },
        labelFor("Interpreter:", interpSel),
        interpSel
      ),
      h("div", { cls: "form-row stack-s" },
        labelFor("Source Code (verbatim execution):", sourceEditor),
        sourceEditor
      ),
      h("div", { cls: "form-row stack-s" },
        h("div", { cls: "form-row uf uf-between" },
          labelFor("Parameter Schema JSON (optional):", schemaEditor),
          insertTemplateBtn
        ),
        schemaEditor
      ),
      errBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      submitBtn
    ];

    openSheet("Register Immutable Script", body, foot, "sheet-wide");
  }

  function openScriptVersionsSheet(script) {
    if (!script) return;

    var headTitle = "Script Versions: " + (script.name || script.id);
    var versionSelect = h("select", {});
    for (var v = script.latest_version || 1; v >= 1; v--) {
      versionSelect.appendChild(h("option", { value: String(v), text: "Version " + v + (v === script.latest_version ? " (Latest)" : "") }));
    }

    var digestSpan = h("span", { cls: "mono dim", text: "Loading..." });
    var createdSpan = h("span", { cls: "dim-2", text: "—" });
    var sourceBox = h("pre", { cls: "script-source-preview", text: "Loading version..." });
    var schemaBox = h("pre", { cls: "script-source-preview", text: "—", hidden: true });
    var schemaLabel = h("label", { cls: "u-strong", text: "Parameter Schema:", hidden: true });
    var errBox = h("div", { cls: "note note-crit", role: "alert", hidden: true });

    function loadVersion(verNum) {
      request("/api/v1/scripts?id=" + encodeURIComponent(script.id) + "&version=" + verNum)
        .then(function (ver) {
          errBox.setAttribute("hidden", "");
          digestSpan.textContent = ver.digest_sha256 || "—";
          createdSpan.textContent = (ver.created_by || "operator") + " · " + (ver.created_at ? new Date(ver.created_at).toLocaleString() : "");
          sourceBox.textContent = ver.source || "";
          if (ver.parameter_schema_json && ver.parameter_schema_json.trim()) {
            try {
              schemaBox.textContent = JSON.stringify(JSON.parse(ver.parameter_schema_json), null, 2);
            } catch (e) {
              schemaBox.textContent = ver.parameter_schema_json;
            }
            schemaBox.removeAttribute("hidden");
            schemaLabel.removeAttribute("hidden");
          } else {
            schemaBox.setAttribute("hidden", "");
            schemaLabel.setAttribute("hidden", "");
          }
        })
        .catch(function (err) {
          errBox.textContent = err.message || "Failed to load version.";
          errBox.removeAttribute("hidden");
        });
    }

    versionSelect.addEventListener("change", function () {
      loadVersion(parseInt(versionSelect.value, 10));
    });

    loadVersion(script.latest_version || 1);

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row uf uf-between" },
        h("div", { cls: "form-row" },
          labelFor("Select Version:", versionSelect),
          versionSelect
        ),
        chip(script.retired ? "crit" : "ok", script.retired ? "Retired" : "Active")
      ),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "SHA-256 Digest: " }),
        digestSpan
      ),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Created: " }),
        createdSpan
      ),
      errBox,
      h("label", { cls: "u-strong", text: "Script Source Code:" }),
      sourceBox,
      schemaLabel,
      schemaBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } })
    ];

    openSheet(headTitle, body, foot, "sheet-wide");
  }

  function openScriptRunSheet(script, initialVersion) {
    if (!script) return;
    if (script.retired) {
      toast("Cannot execute retired script.", "crit");
      return;
    }

    var ver = initialVersion || script.latest_version || 1;
    var headTitle = "Run Script: " + (script.name || script.id);

    var verSelect = h("select", {});
    for (var v = script.latest_version || 1; v >= 1; v--) {
      verSelect.appendChild(h("option", { value: String(v), text: "v" + v + (v === script.latest_version ? " (Latest)" : "") }));
    }
    verSelect.value = String(ver);

    var digestBadge = h("span", { cls: "mono dim", text: "Loading digest..." });
    var paramFormContainer = h("div", { cls: "script-param-group stack-s" });
    var errBox = h("div", { id: "run-script-err", cls: "note note-crit", role: "alert", hidden: true });

    // Mode Toggle: One-off vs Scheduled
    var modeRunNow = h("input", { type: "radio", name: "script-mode", id: "mode-run-now", checked: true });
    var modeSchedule = h("input", { type: "radio", name: "script-mode", id: "mode-schedule" });

    var modeToggleRow = h("div", { cls: "form-row uf-g4 u-mb2" },
      h("label", { cls: "form-check-label", "for": "mode-run-now" }, modeRunNow, h("span", { text: " Run Now (One-Off)" })),
      h("label", { cls: "form-check-label", "for": "mode-schedule" }, modeSchedule, h("span", { text: " Schedule Execution (Frozen Snapshot)" }))
    );

    // Endpoints for Run Now (single select)
    var singleEndpointSel = h("select", { id: "script-single-endpoint" });
    // Endpoints for Schedule (checkbox list)
    var scheduleTargetsContainer = h("div", { cls: "target-endpoints-list stack-s", hidden: true });

    var assetsWithEndpoints = (state.assets || []).filter(function (a) { return !!a.endpoint; });
    if (!assetsWithEndpoints.length && state.endpoints && state.endpoints.length) {
      assetsWithEndpoints = state.endpoints.map(function (ep) { return { endpoint: ep, name: ep.hostname, ip: ep.ip }; });
    }

    var targetCheckboxes = [];
    assetsWithEndpoints.forEach(function (a) {
      var ep = a.endpoint;
      var label = (ep.hostname || a.name || ep.id) + " (" + (ep.ip || a.ip || "unknown") + " · " + (ep.os || "OS") + ")";
      singleEndpointSel.appendChild(h("option", { value: ep.id, text: label }));

      var cb = h("input", { type: "checkbox", value: ep.id, id: "sched-target-" + ep.id });
      targetCheckboxes.push(cb);
      scheduleTargetsContainer.appendChild(h("div", { cls: "form-row uf" },
        cb,
        h("label", { "for": "sched-target-" + ep.id, text: " " + label })
      ));
    });

    // Execution Bounds
    var timeoutInput = h("input", { id: "run-script-timeout", type: "number", min: "1", max: "300", value: "60" });
    var maxOutputSel = h("select", { id: "run-script-max-output" });
    [
      { val: "1048576", label: "1 MiB (Default)" },
      { val: "524288", label: "512 KiB" },
      { val: "2097152", label: "2 MiB" },
      { val: "5242880", label: "5 MiB (Maximum)" }
    ].forEach(function (opt) {
      maxOutputSel.appendChild(h("option", { value: opt.val, text: opt.label }));
    });

    // Schedule-specific fields
    var schedSection = h("div", { cls: "stack-s", hidden: true });
    var recurrenceSel = h("select", {});
    ["hourly", "daily", "weekly"].forEach(function (r) {
      recurrenceSel.appendChild(h("option", { value: r, text: r.charAt(0).toUpperCase() + r.slice(1) }));
    });
    recurrenceSel.value = "daily";

    var maxRunsInput = h("input", { type: "number", min: "0", value: "0", placeholder: "0 = indefinite" });
    var nowIso = new Date(Date.now() + 60000).toISOString().slice(0, 16);
    var startTimeInput = h("input", { type: "datetime-local", value: nowIso });

    schedSection.appendChild(h("div", { cls: "form-row stack-s" },
      labelFor("Recurrence Schedule:", recurrenceSel),
      recurrenceSel
    ));
    schedSection.appendChild(h("div", { cls: "form-row stack-s" },
      labelFor("Start Time (Local):", startTimeInput),
      startTimeInput
    ));
    schedSection.appendChild(h("div", { cls: "form-row stack-s" },
      labelFor("Max Runs (0 for unlimited):", maxRunsInput),
      maxRunsInput
    ));

    var singleTargetRow = h("div", { cls: "form-row stack-s" },
      labelFor("Target Endpoint:", singleEndpointSel),
      singleEndpointSel
    );

    var scheduleTargetRow = h("div", { cls: "form-row stack-s", hidden: true },
      labelFor("Target Endpoints Snapshot (Explicit endpoints to freeze):", scheduleTargetsContainer),
      scheduleTargetsContainer
    );

    var actionBtn = h("button", {
      id: "run-script-action-btn",
      cls: "btn btn-primary",
      type: "button",
      text: "Sign & Execute Script"
    });

    function updateMode() {
      var isSched = modeSchedule.checked;
      singleTargetRow.hidden = isSched;
      scheduleTargetRow.hidden = !isSched;
      scheduleTargetsContainer.hidden = !isSched;
      schedSection.hidden = !isSched;
      actionBtn.textContent = isSched ? "Freeze & Schedule Execution" : "Sign & Execute Script";
    }

    modeRunNow.addEventListener("change", updateMode);
    modeSchedule.addEventListener("change", updateMode);

    var currentVersionData = null;
    var paramInputMap = {};

    function loadVersionSchema(vNum) {
      clear(paramFormContainer);
      paramInputMap = {};
      digestBadge.textContent = "Loading digest...";

      request("/api/v1/scripts?id=" + encodeURIComponent(script.id) + "&version=" + vNum)
        .then(function (sv) {
          currentVersionData = sv;
          digestBadge.textContent = sv.digest_sha256 || "—";

          if (sv.parameter_schema_json && sv.parameter_schema_json.trim()) {
            var schema = null;
            try { schema = JSON.parse(sv.parameter_schema_json); } catch (e) { schema = null; }
            if (schema && Array.isArray(schema.parameters) && schema.parameters.length) {
              schema.parameters.forEach(function (p) {
                var fieldEl = null;
                if (p.type === "enum" && Array.isArray(p.enum)) {
                  fieldEl = h("select", {});
                  p.enum.forEach(function (optVal) {
                    fieldEl.appendChild(h("option", { value: optVal, text: optVal }));
                  });
                  if (p.default !== undefined) fieldEl.value = String(p.default);
                } else if (p.type === "boolean") {
                  fieldEl = h("select", {});
                  fieldEl.appendChild(h("option", { value: "true", text: "true" }));
                  fieldEl.appendChild(h("option", { value: "false", text: "false" }));
                  if (p.default !== undefined) fieldEl.value = String(p.default);
                } else if (p.type === "number") {
                  fieldEl = h("input", { type: "number", step: "any", value: p.default !== undefined ? String(p.default) : "" });
                } else {
                  fieldEl = h("input", { type: "text", value: p.default !== undefined ? String(p.default) : "", placeholder: p.type === "ipv4" ? "10.0.0.1" : (p.type === "cidr" ? "10.0.0.0/24" : "") });
                }

                paramInputMap[p.name] = { param: p, input: fieldEl };

                paramFormContainer.appendChild(h("div", { cls: "form-row stack-s" },
                  h("div", { cls: "form-row uf uf-g1" },
                    h("label", { cls: "u-strong", text: p.name }),
                    p.required ? chip("crit", "required") : h("span", { cls: "dim-3", text: "(optional)" }),
                    h("span", { cls: "mono dim-2", text: "[" + p.type + "]" })
                  ),
                  p.description ? h("span", { cls: "dim-2", text: p.description }) : null,
                  fieldEl
                ));
              });
            } else {
              paramFormContainer.appendChild(h("p", { cls: "dim-2", text: "No input parameters required for this script." }));
            }
          } else {
            paramFormContainer.appendChild(h("p", { cls: "dim-2", text: "No input parameters required for this script." }));
          }
        })
        .catch(function (err) {
          errBox.textContent = err.message || "Failed to load script version.";
          errBox.removeAttribute("hidden");
        });
    }

    verSelect.addEventListener("change", function () {
      loadVersionSchema(parseInt(verSelect.value, 10));
    });
    loadVersionSchema(ver);

    actionBtn.addEventListener("click", function () {
      var vNum = parseInt(verSelect.value, 10);
      var toSec = parseInt(timeoutInput.value, 10) || 60;
      var maxB = parseInt(maxOutputSel.value, 10) || 1048576;
      var isSched = modeSchedule.checked;

      // Collect typed parameters
      var collectedParams = {};
      var keys = Object.keys(paramInputMap);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var item = paramInputMap[k];
        var val = (item.input.value !== undefined ? String(item.input.value) : "").trim();
        if (item.param.required && !val) {
          errBox.textContent = "Required parameter '" + k + "' cannot be empty.";
          errBox.removeAttribute("hidden");
          item.input.focus();
          return;
        }
        if (val !== "") {
          collectedParams[k] = val;
        }
      }

      if (!state.responseSession || !ephemeralResponseKey) {
        openUnlockResponseSheet(function () {
          openScriptRunSheet(script, vNum);
        });
        return;
      }

      errBox.setAttribute("hidden", "");

      if (!isSched) {
        // One-off Run Now
        var epId = singleEndpointSel.value;
        if (!epId) {
          errBox.textContent = "Please select a target endpoint.";
          errBox.removeAttribute("hidden");
          return;
        }

        actionBtn.disabled = true;
        actionBtn.textContent = "Signing Proof & Dispatching...";

        // Request canonical action digest
        request("/api/v1/scripts/digest", "POST", {
          script_id: script.id,
          version: vNum,
          parameters: collectedParams,
          timeout_seconds: toSec,
          max_output_bytes: maxB
        })
          .then(function (res) {
            return signActionProof("script_exec", res.action_digest, [epId])
              .then(function (proof) {
                return request("/api/v1/scripts/run", "POST", {
                  script_id: script.id,
                  version: vNum,
                  endpoint_id: epId,
                  parameters: collectedParams,
                  timeout_seconds: toSec,
                  max_output_bytes: maxB,
                  session_id: state.responseSession.session_id,
                  action_digest: res.action_digest,
                  proof: proof
                });
              });
          })
          .then(function (job) {
            closeSheet();
            toast("Script execution job dispatched (" + (job.id ? job.id.slice(0, 8) : "") + "...) Target: " + epId, "ok");
            request("/api/v1/response/jobs?limit=50").then(function (d) {
              state.responseJobs = arrayOf(d && d.jobs || d);
              if (state.section === "response") renderBody();
            });
            openJobOutputModal(job.id);
          })
          .catch(function (err) {
            actionBtn.disabled = false;
            actionBtn.textContent = "Sign & Execute Script";
            errBox.textContent = err.message || "Failed to dispatch script execution.";
            errBox.removeAttribute("hidden");
          });
      } else {
        // Schedule Execution
        var selectedTargets = [];
        targetCheckboxes.forEach(function (cb) {
          if (cb.checked) selectedTargets.push(cb.value);
        });
        if (!selectedTargets.length) {
          errBox.textContent = "Please select at least one target endpoint to freeze into the schedule snapshot.";
          errBox.removeAttribute("hidden");
          return;
        }

        var rec = recurrenceSel.value;
        var maxR = parseInt(maxRunsInput.value, 10) || 0;
        var startVal = startTimeInput.value ? new Date(startTimeInput.value).toISOString() : new Date().toISOString();

        actionBtn.disabled = true;
        actionBtn.textContent = "Freezing Schedule...";

        request("/api/v1/scripts/schedules", "POST", {
          script_id: script.id,
          version: vNum,
          target_endpoints: selectedTargets,
          parameters: collectedParams,
          recurrence: rec,
          start_time: startVal,
          max_runs: maxR,
          timeout_seconds: toSec,
          max_output_bytes: maxB,
          session_id: state.responseSession.session_id
        })
          .then(function (sched) {
            closeSheet();
            toast("Frozen schedule created for " + selectedTargets.length + " endpoint(s).", "ok");
            return request("/api/v1/scripts/schedules").then(function (d) {
              state.scriptSchedules = arrayOf(d && d.schedules || d);
              if (state.section === "response") renderBody();
            });
          })
          .catch(function (err) {
            actionBtn.disabled = false;
            actionBtn.textContent = "Freeze & Schedule Execution";
            errBox.textContent = err.message || "Failed to create schedule.";
            errBox.removeAttribute("hidden");
          });
      }
    });

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row uf uf-between" },
        h("div", { cls: "form-row" },
          labelFor("Script Version:", verSelect),
          verSelect
        ),
        h("div", { cls: "form-row uf-g1" },
          h("span", { cls: "dim-2", text: "Digest: " }),
          digestBadge
        )
      ),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Interpreter: " }),
        h("span", { cls: "mono u-strong", text: script.interpreter || "/bin/bash" })
      ),
      h("hr", { cls: "line" }),
      modeToggleRow,
      singleTargetRow,
      scheduleTargetRow,
      schedSection,
      h("label", { cls: "u-strong", text: "Script Parameters:" }),
      paramFormContainer,
      h("hr", { cls: "line" }),
      h("div", { cls: "form-row stack-s" },
        labelFor("Execution Timeout (seconds, 1-300):", timeoutInput),
        timeoutInput
      ),
      h("div", { cls: "form-row stack-s" },
        labelFor("Output Buffer Bound:", maxOutputSel),
        maxOutputSel
      ),
      errBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      actionBtn
    ];

    openSheet(headTitle, body, foot, "sheet-wide");
  }

  function retireScriptConfirm(script) {
    if (!script) return;
    openSheet("Retire Script: " + script.name,
      h("div", { cls: "card-body stack" },
        h("div", { cls: "st-banner", "data-state": "crit", text: "Permanent Script Retirement" }),
        h("p", { cls: "pending", text: "Retiring script '" + script.name + "' permanently disables all future executions and schedules for all versions of this script. Completed jobs and historical telemetry are preserved." }),
        h("p", { text: "Are you sure you wish to retire this script?" })
      ),
      [
        h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
        h("button", {
          cls: "btn btn-crit",
          type: "button",
          text: "Retire Script",
          on: {
            click: function () {
              request("/api/v1/scripts?id=" + encodeURIComponent(script.id), "DELETE")
                .then(function () {
                  closeSheet();
                  toast("Script '" + script.name + "' retired.", "ok");
                  return request("/api/v1/scripts").then(function (d) {
                    state.scripts = arrayOf(d && d.scripts || d);
                    if (state.section === "response") renderBody();
                  });
                })
                .catch(function (err) {
                  toast(err.message || "Failed to retire script.", "crit");
                });
            }
          }
        })
      ]
    );
  }

  function cancelScriptScheduleConfirm(schedId) {
    if (!schedId) return;
    openSheet("Cancel Frozen Schedule",
      h("div", { cls: "card-body stack" },
        h("p", { cls: "pending", text: "Are you sure you want to cancel schedule " + schedId + "? No further runs will be dispatched for this schedule." })
      ),
      [
        h("button", { cls: "btn", type: "button", text: "Keep Schedule", on: { click: closeSheet } }),
        h("button", {
          cls: "btn btn-crit",
          type: "button",
          text: "Cancel Schedule",
          on: {
            click: function () {
              request("/api/v1/scripts/schedules?id=" + encodeURIComponent(schedId), "DELETE")
                .then(function () {
                  closeSheet();
                  toast("Schedule " + schedId + " cancelled.", "ok");
                  return request("/api/v1/scripts/schedules").then(function (d) {
                    state.scriptSchedules = arrayOf(d && d.schedules || d);
                    if (state.section === "response") renderBody();
                  });
                })
                .catch(function (err) {
                  toast(err.message || "Failed to cancel schedule.", "crit");
                });
            }
          }
        })
      ]
    );
  }

  function launchForensicsSheet(asset) {
    if (!asset || !asset.endpoint) {
      toast("Cannot collect forensics: host does not have an enrolled agent.", "crit");
      return;
    }

    if (!state.responseSession || !ephemeralResponseKey) {
      openUnlockResponseSheet(function () {
        launchForensicsSheet(asset);
      });
      return;
    }

    var ep = asset.endpoint;

    var profileSel = h("select", { id: "forensics-profile-select" });
    profileSel.appendChild(h("option", { value: "diagnostic", text: "Diagnostic (8 artifacts: OS, Net, Routes, DNS, Resources, Services, Logs, Diag)" }));
    profileSel.appendChild(h("option", { value: "live_volatile", text: "Live Volatile (14 artifacts: Diagnostic + Processes, Sockets, Sessions, Neighbors, Firewall, Modules)" }));
    profileSel.appendChild(h("option", { value: "ir_standard", text: "IR Standard (18 artifacts: Full Triage + Persistence, Tasks, Security Logs, Shell History)" }));
    profileSel.value = "ir_standard";

    var profileDesc = h("p", { cls: "pending", text: "IR Standard Profile: Comprehensive endpoint triage collecting all 18 artifacts across diagnostic, volatile memory/network state, autoruns/persistence, cron/scheduled tasks, authentication/security logs, and user shell history. Cryptographically signed with Ed25519." });

    profileSel.addEventListener("change", function () {
      if (profileSel.value === "diagnostic") {
        profileDesc.textContent = "Diagnostic Profile: Standard baseline telemetry (8 artifacts) including OS build, network interfaces, routing tables, DNS resolution, system resources, service manager state, syslog tail, and agent diagnostics.";
      } else if (profileSel.value === "live_volatile") {
        profileDesc.textContent = "Live Volatile Profile: Real-time volatile system state (14 artifacts) including process tree, active socket-to-PID mappings, logged-in sessions, ARP/NDP neighbors, host firewall rules, and loaded kernel/driver modules.";
      } else {
        profileDesc.textContent = "IR Standard Profile: Comprehensive endpoint triage collecting all 18 artifacts across diagnostic, volatile memory/network state, autoruns/persistence, cron/scheduled tasks, authentication/security logs, and user shell history. Cryptographically signed with Ed25519.";
      }
    });

    var maxBytesSel = h("select", { id: "forensics-maxbytes-select" });
    maxBytesSel.appendChild(h("option", { value: "524288", text: "512 KiB per artifact (10 MiB bundle cap - Recommended)" }));
    maxBytesSel.appendChild(h("option", { value: "262144", text: "256 KiB per artifact" }));
    maxBytesSel.appendChild(h("option", { value: "1048576", text: "1024 KiB per artifact" }));

    var timeoutSel = h("select", { id: "forensics-timeout-select" });
    timeoutSel.appendChild(h("option", { value: "120", text: "120 seconds (Recommended for IR Standard / Volatile)" }));
    timeoutSel.appendChild(h("option", { value: "60", text: "60 seconds (Standard for Diagnostic)" }));
    timeoutSel.appendChild(h("option", { value: "300", text: "300 seconds (High Latency / Deep Inspection)" }));

    var errBox = h("div", { cls: "note note-crit", role: "alert", hidden: true });

    var launchBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Dispatch Forensic Collection",
      on: {
        click: function () {
          var prof = profileSel.value;
          var maxB = parseInt(maxBytesSel.value, 10) || 524288;
          var toSec = parseInt(timeoutSel.value, 10) || 120;

          launchBtn.disabled = true;
          launchBtn.textContent = "Signing Proof & Dispatching\u2026";
          errBox.setAttribute("hidden", "");

          var payload = {
            profile: prof,
            max_bytes: maxB,
            timeout_seconds: toSec
          };
          var payloadStr = JSON.stringify(payload);

          digestSHA256(payloadStr)
            .then(function (digestHex) {
              return signActionProof("forensic_collection", digestHex, [ep.id])
                .then(function (proof) {
                  return request("/api/v1/response/jobs", "POST", {
                    endpoint_id: ep.id,
                    kind: "forensic_collection",
                    payload_json: payloadStr,
                    session_id: state.responseSession.session_id,
                    action_digest: digestHex,
                    proof: proof
                  });
                });
            })
            .then(function (job) {
              closeSheet();
              /* Same hijack as the shell launch: go() would close the route
                 panel the operator dispatched this from. The toast carries
                 the job id and Forensics is one click away. */
              toast("Forensic collection dispatched (" + (job.id ? job.id.slice(0, 8) + "\u2026" : "") + ") on " + (asset.name || asset.ip) + " \u2014 see Forensics", "ok");
              refresh();
            })
            .catch(function (err) {
              launchBtn.disabled = false;
              launchBtn.textContent = "Dispatch Forensic Collection";
              errBox.textContent = err.message || "Failed to dispatch forensic collection.";
              errBox.removeAttribute("hidden");
            });
        }
      }
    });

    var body = h("div", { cls: "card-body stack" },
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Target Host: " }), h("b", { text: asset.name || asset.ip }),
        h("span", { cls: "dim-2", text: " \u00b7 Endpoint ID: " }), h("span", { cls: "ip", text: ep.id })
      ),
      h("div", { cls: "form-row" },
        h("span", { cls: "dim-2", text: "Platform: " }), h("b", { text: ep.os || "Linux" }),
        h("span", { cls: "dim-2", text: " \u00b7 Isolation: " }), chip(asset.isolated ? "crit" : "ok", asset.isolated ? "ISOLATED" : "Online")
      ),
      h("p", { cls: "pending", text: "Forensic collections run under the response authority with signed ActionProof V2. The agent collects forensic telemetry in-process, validates size bounds, computes SHA-256 digests, and generates an Ed25519-signed canonical manifest." }),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "forensics-profile-select", text: "Select Collection Profile:" }),
        profileSel
      ),
      profileDesc,
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "forensics-maxbytes-select", text: "Artifact Size Bound:" }),
        maxBytesSel
      ),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "forensics-timeout-select", text: "Execution Timeout:" }),
        timeoutSel
      ),
      errBox
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      launchBtn
    ];

    openSheet("Dispatch Forensic Collection", body, foot);
  }

  function openLaunchForensicsPicker() {
    var managed = (state.assets || []).filter(function (a) { return a.endpoint; });
    if (!managed.length) {
      toast("No agent-managed endpoints online.", "warn");
      return;
    }

    var sel = h("select", { id: "forensics-target-picker" });
    managed.forEach(function (a) {
      sel.appendChild(h("option", { value: a.key, text: (a.name || a.ip) + " (" + (a.endpoint.os || "Linux") + ") - " + a.endpoint.id }));
    });

    var body = h("div", { cls: "card-body stack" },
      h("p", { cls: "pending", text: "Select an enrolled endpoint to dispatch an authenticated forensic collection job:" }),
      h("div", { cls: "form-row stack-s" },
        h("label", { "for": "forensics-target-picker", text: "Target Endpoint:" }),
        sel
      )
    );

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Cancel", on: { click: closeSheet } }),
      h("button", {
        cls: "btn btn-primary", type: "button", text: "Next \u2192",
        on: {
          click: function () {
            var asset = state.assetByKey[sel.value];
            closeSheet();
            if (asset) launchForensicsSheet(asset);
          }
        }
      })
    ];

    openSheet("Select Target Endpoint for Forensics", body, foot);
  }

  function toggleBundleHold(bundleId, currentHold) {
    /* Releasing a legal hold makes the bundle eligible for retention deletion
       again, and the retention sweeper does not ask a second time. Applying
       one is safe and stays a single click. */
    if (currentHold) {
      confirmSheet({
        title: "Release legal hold",
        consequence: "Bundle " + (bundleId ? bundleId.slice(0, 8) + "\u2026" : "") + " becomes subject to the normal retention policy again and can be deleted by the next retention sweep. Released evidence cannot be recovered.",
        detail: "The release is recorded in the audit log against your operator id.",
        confirmLabel: "Release hold",
        onConfirm: function () { sendBundleHold(bundleId, false); }
      });
      return;
    }
    sendBundleHold(bundleId, true);
  }

  function sendBundleHold(bundleId, newHold) {
    var reason = newHold ? "Compliance legal hold applied by operator" : "Compliance legal hold released by operator";
    request("/api/v1/evidence/bundles/hold", "POST", {
      bundle_id: bundleId,
      hold: newHold,
      reason: reason
    })
      .then(function () {
        toast(newHold ? "Legal hold locked on bundle " + (bundleId ? bundleId.slice(0, 8) : "") + "\u2026" : "Legal hold released on bundle " + (bundleId ? bundleId.slice(0, 8) : "") + "\u2026", "ok");
        refresh();
      })
      .catch(function (err) {
        toast("Failed to update legal hold: " + (err.message || err), "crit");
      });
  }

  function inspectBundle(bundleId) {
    var b = (state.evidenceBundles || []).find(function (x) { return x.id === bundleId; });
    var loadingEl = h("div", { cls: "card-body", text: "Loading bundle items\u2026" });
    var body = h("div", { cls: "stack" }, loadingEl);

    var foot = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      h("a", {
        cls: "btn btn-primary",
        href: "/api/v1/evidence/export?id=" + encodeURIComponent(bundleId),
        text: "Export Archive (.tar.gz)"
      })
    ];

    openSheet("Inspect Evidence Bundle \u2014 " + (bundleId ? bundleId.slice(0, 8) + "\u2026" : ""), body, foot);

    request("/api/v1/evidence/items?bundle_id=" + encodeURIComponent(bundleId))
      .then(function (resp) {
        clear(body);
        var metaRows = [
          [h("span", { cls: "dim-2", text: "Bundle ID:" }), h("span", { cls: "ip", text: bundleId })],
          [h("span", { cls: "dim-2", text: "Endpoint:" }), h("span", { text: (b && b.endpoint_id) || "Unknown" })],
          [h("span", { cls: "dim-2", text: "Profile:" }), chip("idle", (b && b.profile) || "Unknown")],
          [h("span", { cls: "dim-2", text: "Status:" }), chip(b && b.status === "completed" ? "ok" : "warn", (b && b.status) || "pending")],
          [h("span", { cls: "dim-2", text: "Legal Hold:" }), b && b.legal_hold
            ? h("span", { cls: "uf uf-g2" },
                chip("crit", "LOCKED (HOLD)"),
                h("span", { cls: "dim-3", text: (b.legal_hold_actor || "unknown actor") + (b.legal_hold_reason ? " \u00b7 " + b.legal_hold_reason : "") }))
            : h("span", { cls: "dim-3", text: "Normal" })],
          [h("span", { cls: "dim-2", text: "Collected:" }), stamp(parseTime(b && b.created_at))],
          /* Chain of custody. The hub hashes the manifest and signs a receipt
             over it on every finalised bundle, and the word "receipt" did not
             appear in the console once - so the one artefact that makes an
             exported bundle defensible was invisible to the person exporting
             it. */
          [h("span", { cls: "dim-2", text: "Size:" }), h("span", { text: (b && b.total_bytes ? bytes(b.total_bytes) : "\u2014") + (b && b.item_count ? " \u00b7 " + b.item_count + " item" + (b.item_count === 1 ? "" : "s") : "") })],
          [h("span", { cls: "dim-2", text: "Manifest SHA-256:" }), h("span", { cls: "ip u-break", text: (b && b.manifest_sha256) || "not sealed" })],
          [h("span", { cls: "dim-2", text: "Signed receipt:" }), (b && b.receipt_sha256)
            ? h("span", { cls: "ip u-break", text: b.receipt_sha256 })
            : h("span", { cls: "dim-3", text: "no receipt \u2014 this bundle is not yet sealed" })],
          [h("span", { cls: "dim-2", text: "Retention expires:" }), b && b.legal_hold
            ? h("span", { cls: "dim-3", text: "held indefinitely" })
            : stamp(parseTime(b && b.retention_expires_at))]
        ];

        var summaryCard = h("div", { cls: "card-body stack-s" },
          simpleTable(["Field", "Value"], metaRows)
        );

        var items = (resp && resp.items) || [];
        var itemRows = items.map(function (it) {
          var statusTone = "idle";
          if (it.collector_status === "collected") statusTone = "ok";
          else if (it.collector_status === "empty" || it.collector_status === "truncated") statusTone = "warn";
          else if (it.collector_status === "permission_denied" || it.collector_status === "failed") statusTone = "crit";

          var shortSha = it.sha256 ? it.sha256.slice(0, 12) + "\u2026" : "\u2014";
          return [
            h("b", { text: it.name || "" }),
            chip(statusTone, it.collector_status || "unknown"),
            h("span", { text: bytes(it.size_bytes) }),
            h("span", { cls: "dim-3", text: it.content_type || "application/octet-stream" }),
            h("span", { cls: "ip", title: it.sha256 || "", text: shortSha })
          ];
        });

        var itemsTable = items.length
          ? simpleTable(["Artifact Name", "Status", "Size", "Content Type", "SHA-256"], itemRows)
          : h("div", { cls: "card-body", text: "No individual artifacts registered in this bundle." });

        body.appendChild(summaryCard);
        body.appendChild(h("h3", { cls: "section-head", text: "Manifest Artifacts (" + items.length + ")" }));
        body.appendChild(itemsTable);
      })
      .catch(function (err) {
        clear(body);
        body.appendChild(h("div", { cls: "note note-crit", role: "alert", text: "Failed to load bundle artifacts: " + (err.message || err) }));
      });
  }

  /* ------------------------------------------------- Software & Vulnerabilities */

  function vulnStatusBadge(status) {
    var st = status || "insufficient_data";
    var label = st;
    if (st === "matched") label = "Affected";
    else if (st === "not_affected") label = "Not Affected";
    else if (st === "possible") label = "Possible";
    else if (st === "insufficient_data") label = "Inconclusive";
    return h("span", { cls: "vuln-match-badge", "data-status": st, text: label });
  }

  function priorityScoreBadge(score) {
    var num = typeof score === "number" ? score : parseFloat(score) || 0;
    var cls = "priority-badge";
    if (num >= 70) cls += " priority-crit";
    else if (num >= 40) cls += " priority-high";
    return h("span", { cls: cls, text: num.toFixed(1) });
  }

  function cisaKevBadge() {
    return h("span", { cls: "cisa-kev-badge", title: "CISA Known Exploited Vulnerabilities Catalog" },
      icon("i-alert", true),
      h("span", { text: "CISA KEV" })
    );
  }

  function epssBadge(score) {
    var num = typeof score === "number" ? score : parseFloat(score) || 0;
    if (num <= 0) return null;
    var pct = (num * 100).toFixed(1) + "%";
    return h("span", { cls: "epss-badge", title: "EPSS Exploit Prediction: " + pct },
      h("span", { text: "EPSS " + pct })
    );
  }

  function softwareSourceBadge(source) {
    return h("span", { cls: "sw-source-badge", text: source || "unknown" });
  }

  function softwareScopeBadge(scope) {
    if (!scope) return null;
    return h("span", { cls: "sw-scope-badge", text: scope });
  }

  function openMatchEvidenceSheet(v) {
    var ev = null;
    if (v.evidence) {
      try {
        ev = typeof v.evidence === "string" ? JSON.parse(v.evidence) : v.evidence;
      } catch (e) {}
    }

    var sevTone = (v.severity === "CRITICAL" || v.severity === "HIGH") ? "crit" : (v.severity === "MEDIUM" ? "warn" : "idle");

    var flags = [];
    if (v.is_kev) flags.push(cisaKevBadge());
    if (v.epss && v.epss > 0) flags.push(epssBadge(v.epss));

    var kvRows = [
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Correlation Verdict" }),
        vulnStatusBadge(v.status)
      ),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "CVE & Severity" }),
        h("div", { cls: "uf uf-g3" },
          h("b", { text: v.cve_id || "—" }),
          chip(sevTone, (v.severity || "MEDIUM") + (v.cvss ? " " + v.cvss.toFixed(1) : ""))
        )
      ),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Priority Score" }),
        h("div", { cls: "uf uf-g3" },
          priorityScoreBadge(v.priority_score),
          h("span", { cls: "dim-3 u-t2", text: "(CVSS × 6.0 + KEV × 25.0 + EPSS × 15.0) × confidence" })
        )
      )
    ];

    if (flags.length) {
      kvRows.push(h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Threat Intelligence" }),
        h("div", { cls: "uf uf-g2" }, flags)
      ));
    }

    kvRows.push(
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Target Endpoint" }),
        h("span", { cls: "mono", text: v.endpoint_id || "—" })
      ),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Detected Package" }),
        h("div", {},
          h("b", { text: (ev && ev.product) || v.product_name || "—" }),
          h("span", { text: " version " }),
          h("span", { cls: "mono", text: (ev && ev.version) || v.version || "—" })
        )
      )
    );

    if (ev && ev.raw_version && ev.raw_version !== ((ev && ev.version) || v.version)) {
      kvRows.push(h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Raw Installed Version" }),
        h("span", { cls: "mono dim-2", text: ev.raw_version })
      ));
    }

    if (ev && ev.source) {
      kvRows.push(h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Package Source" }),
        softwareSourceBadge(ev.source)
      ));
    }

    var snapID = (ev && ev.snapshot_id) || v.feed_snapshot_id;
    if (snapID) {
      kvRows.push(h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Feed Snapshot ID" }),
        h("span", { cls: "mono dim-2", text: snapID })
      ));
    }

    var criteriaCard = card("Matching Criteria & Version Boundaries", h("div", { cls: "card-body stack" },
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "CPE Criteria Pattern" }),
        h("code", { cls: "mono u-t2 u-break", text: (ev && ev.cpe) || "—" })
      ),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Vulnerable Version Range" }),
        h("code", { cls: "mono u-t2", text: (ev && ev.vulnerable_range) || "—" })
      ),
      h("div", { cls: "drawer-kv-row" },
        h("span", { cls: "drawer-kv-label", text: "Comparison Verdict" }),
        h("div", {
          cls: "note u-t3 u-m0 " + (v.status === "matched" ? "note-crit" : (v.status === "not_affected" ? "note-ok" : "note-warn")),
          text: (ev && ev.version_comparison) || v.match_reason || "—"
        })
      )
    ));

    var auditEvidenceBox = h("pre", {
      cls: "evidence-detail-box",
      text: JSON.stringify(ev || v, null, 2)
    });

    var rawCard = card("Explainable Audit Evidence (Raw Structured Record)", h("div", { cls: "card-body" }, auditEvidenceBox));

    var body = h("div", { cls: "stack" },
      h("div", { cls: "drawer-kv-group" }, kvRows),
      criteriaCard,
      rawCard
    );

    var foot = [
      h("button", {
        cls: "btn btn-primary",
        type: "button",
        text: "Close",
        on: { click: closeSheet }
      })
    ];

    openSheet("Vulnerability Correlation Evidence — " + (v.cve_id || "CVE"), body, foot, "sheet-wide");
  }

  function openSyncFeedModal() {
    var onlineCheck = h("input", { type: "checkbox", checked: true, id: "sync-online-check" });
    var nvdUrlInput = h("input", { type: "text", placeholder: "Default (official NVD 2.0 API)", value: "" });
    var kevUrlInput = h("input", { type: "text", placeholder: "Default (official CISA KEV JSON)", value: "" });
    var epssUrlInput = h("input", { type: "text", placeholder: "Default (official FIRST EPSS JSON)", value: "" });
    var maxResultsInput = h("input", { type: "number", value: "2000", min: "100", max: "50000" });
    var statusText = h("div", { cls: "note dim-3", text: "Sync will fetch feeds in the background, validate schema boundaries, and atomically promote into the active snapshot." });

    var body = h("div", { cls: "stack" },
      h("p", { text: "Synchronize local vulnerability correlation database with authoritative upstream intelligence feeds." }),
      h("label", { cls: "form-row uf uf-g3 u-pointer" },
        onlineCheck,
        h("span", {}, h("b", { text: "Online Feed Fetch" }), h("span", { cls: "dim-3", text: " (Query NVD, CISA KEV, and EPSS directly)" }))
      ),
      h("label", { cls: "lbl" }, "Max NVD Results", maxResultsInput),
      h("label", { cls: "lbl" }, "Custom NVD URL (Optional)", nvdUrlInput),
      h("label", { cls: "lbl" }, "Custom CISA KEV URL (Optional)", kevUrlInput),
      h("label", { cls: "lbl" }, "Custom EPSS URL (Optional)", epssUrlInput),
      statusText
    );

    var startBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Start Feed Sync",
      on: {
        click: function () {
          startBtn.disabled = true;
          startBtn.textContent = "Syncing feeds…";
          statusText.className = "note note-warn";
          statusText.textContent = "Connecting to feeds, ingesting CVE catalog and computing correlation…";

          var payload = {
            online: onlineCheck.checked,
            max_nvd_results: parseInt(maxResultsInput.value, 10) || 2000
          };
          if (nvdUrlInput.value.trim()) payload.nvd_url = nvdUrlInput.value.trim();
          if (kevUrlInput.value.trim()) payload.cisa_kev_url = kevUrlInput.value.trim();
          if (epssUrlInput.value.trim()) payload.epss_url = epssUrlInput.value.trim();

          /* request() is (path, method, body). This passed a fetch-shaped
             options object as `method`, so `opts.method` stringified to
             "[object Object]" and the payload was never sent: both "Sync
             Feeds…" buttons issued a request the hub could not act on. */
          request("/api/v1/vulnerabilities/sync", "POST", payload).then(function (res) {
            statusText.className = "note note-ok";
            var msg = "Feed synchronization complete: Snapshot " + (res.snapshot_id || "") + " activated with " +
              (res.nvd_count || 0) + " CVEs, " + (res.cisa_kev_count || 0) + " KEV items, " + (res.epss_count || 0) + " EPSS scores.";
            statusText.textContent = msg;
            startBtn.disabled = false;
            startBtn.textContent = "Sync Complete";
            toast("Vulnerability feeds synchronized", "ok");
            refresh();
          }).catch(function (err) {
            statusText.className = "note note-crit";
            statusText.textContent = "Sync failed: " + (err && err.message ? err.message : String(err));
            startBtn.disabled = false;
            startBtn.textContent = "Retry Sync";
          });
        }
      }
    });

    var actions = [
      h("button", { cls: "btn", type: "button", text: "Close", on: { click: closeSheet } }),
      startBtn
    ];

    openSheet("Vulnerability Feed Synchronization", body, actions);
  }

  function softwareInventoryCard(asset) {
    var epID = asset.endpoint.id;
    var pkgs = state.softwareByEndpoint[epID];
    if (!pkgs) {
      return card("Installed Software Inventory", emptyBox("Reading installed software inventory…"), null, true);
    }
    if (!pkgs.length) {
      return card("Installed Software Inventory", emptyBox("No installed software packages recorded for this host."), null, true);
    }

    var q = (state.softwareSearchQuery || "").toLowerCase().trim();
    var filtered = q ? pkgs.filter(function (p) {
      var prod = (p.product || "").toLowerCase();
      var rawProd = (p.raw_product || "").toLowerCase();
      var vendor = (p.vendor || "").toLowerCase();
      var rawVendor = (p.raw_vendor || "").toLowerCase();
      var ver = (p.version || "").toLowerCase();
      var src = (p.source || "").toLowerCase();
      return prod.indexOf(q) !== -1 || rawProd.indexOf(q) !== -1 ||
             vendor.indexOf(q) !== -1 || rawVendor.indexOf(q) !== -1 ||
             ver.indexOf(q) !== -1 || src.indexOf(q) !== -1;
    }) : pkgs;

    /* Same defect as the Alerts search: the handler called renderRoute(),
       which rebuilds the panel and with it this field. Cache the node. */
    if (!softwareSearchInput) {
      softwareSearchInput = h("input", {
        type: "search",
        cls: "u-narrow u-t3",
        placeholder: "Filter software…",
        "aria-label": "Filter software inventory"
      });
      softwareSearchInput.value = state.softwareSearchQuery || "";
      softwareSearchInput.addEventListener("input", function () {
        state.softwareSearchQuery = softwareSearchInput.value;
        renderRoute();
      });
    } else if (document.activeElement !== softwareSearchInput) {
      softwareSearchInput.value = state.softwareSearchQuery || "";
    }
    var searchInput = softwareSearchInput;

    var countBadge = chip("idle", (q ? filtered.length + " of " : "") + pkgs.length + " packages");

    var headControls = h("div", {
      cls: "uf uf-between uf-g3 uf-wrap u-mb2"
    },
      h("div", { cls: "uf uf-g3" },
        countBadge,
        q ? h("button", {
          cls: "btn mini",
          type: "button",
          text: "Clear",
          on: { click: function () { state.softwareSearchQuery = ""; renderRoute(); } }
        }) : null
      ),
      searchInput
    );

    var displayLimit = 100;
    var displayed = filtered.slice(0, displayLimit);

    var rows = displayed.map(function (p) {
      var prodNode = h("div", {},
        h("b", { text: p.product || p.raw_product || "—" }),
        (p.raw_product && p.raw_product !== p.product) ? h("div", { cls: "dim-3 u-t2", text: p.raw_product }) : null,
        (p.vendor || p.raw_vendor) ? h("div", { cls: "dim-3 u-t2", text: p.vendor || p.raw_vendor }) : null
      );

      var verNode = h("div", {},
        h("span", { cls: "mono", text: p.version || "—" }),
        (p.raw_version && p.raw_version !== p.version) ? h("div", { cls: "dim-3 mono u-t1", text: p.raw_version }) : null
      );

      var confBadge = chip(p.confidence === "authoritative" ? "ok" : "warn", p.confidence || "inferred");

      return [
        prodNode,
        verNode,
        softwareSourceBadge(p.source),
        h("span", { cls: "mono dim-2", text: p.architecture || "—" }),
        softwareScopeBadge(p.install_scope) || h("span", { cls: "dim-3", text: "—" }),
        confBadge,
        stamp(parseTime(p.observed_at))
      ];
    });

    var body = h("div", { cls: "card-body stack" },
      headControls,
      simpleTable(["Package / Product", "Version", "Source", "Arch", "Scope", "Confidence", "Observed"], rows),
      (filtered.length > displayLimit) ? h("div", { cls: "dim-3 u-center u-t3 u-mt1", text: "Showing first " + displayLimit + " of " + filtered.length + " matching packages. Use the filter to narrow results." }) : null
    );

    return card("Installed Software Inventory", body, null, true);
  }

  function renderForensics() {
    var view = $("view");
    clear(view);

    var collectBtn = h("button", {
      cls: "btn btn-primary",
      type: "button",
      text: "Collect Forensics\u2026",
      on: { click: openLaunchForensicsPicker }
    });

    var bundleRows = (state.evidenceBundles || []).map(function (b) {
      var actCell = h("div", { cls: "form-row" },
        h("button", {
          cls: "btn",
          type: "button",
          text: "Inspect",
          on: { click: function () { inspectBundle(b.id); } }
        }),
        h("a", {
          cls: "btn",
          href: "/api/v1/evidence/export?id=" + encodeURIComponent(b.id),
          text: "Export"
        }),
        h("button", {
          cls: b.legal_hold ? "btn btn-crit" : "btn",
          type: "button",
          text: b.legal_hold ? "Release Hold" : "Lock Hold",
          on: { click: function () { toggleBundleHold(b.id, b.legal_hold); } }
        })
      );

      return [
        h("span", { cls: "ip", text: b.id ? b.id.slice(0, 8) + "\u2026" : "" }),
        h("span", { text: b.endpoint_id || "" }),
        chip("idle", b.profile || ""),
        chip(b.status === "completed" ? "ok" : "warn", b.status || ""),
        h("span", { text: b.item_count ? String(b.item_count) : "0" }),
        b.legal_hold ? chip("crit", "LOCKED (HOLD)") : h("span", { cls: "dim-3", text: "Normal" }),
        stamp(parseTime(b.created_at)),
        actCell
      ];
    });

    var evidenceCard = card("Forensic Evidence Bundles (AES-256-GCM Encrypted)",
      bundleRows.length ? simpleTable(["Bundle ID", "Endpoint", "Profile", "Status", "Items", "Hold", "Collected", "Actions"], bundleRows) : h("div", { cls: "card-body", text: "No forensic collections recorded yet." }),
      [collectBtn],
      true
    );

    // Active Feed Snapshot Meta Strip
    var snap = state.activeSnapshot;
    var snapStrip = h("div", { cls: "snapshot-meta-strip" },
      snap ? [
        chip("ok", "Feed: " + (snap.id || "Active")),
        h("span", {}, h("b", { text: String(snap.nvd_count || 0) }), " CVEs (NVD 2.0)"),
        h("span", {}, h("b", { text: String(snap.cisa_kev_count || 0) }), " KEV Exploits"),
        h("span", {}, h("b", { text: String(snap.epss_count || 0) }), " EPSS Scores"),
        h("span", { cls: "dim-3" }, "Activated " + (snap.activated_at ? new Date(snap.activated_at).toLocaleDateString() : "recently")),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn mini", type: "button", text: "Sync Feeds…", on: { click: openSyncFeedModal } })
      ] : [
        chip("warn", "No Active Feed Snapshot"),
        h("span", { cls: "dim-3", text: "Vulnerability correlation requires active NVD 2.0 / CISA KEV feeds." }),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn mini btn-primary", type: "button", text: "Sync Feeds…", on: { click: openSyncFeedModal } })
      ]
    );

    // Filter Buttons
    var filterBtns = h("div", { cls: "uf uf-g3 uf-wrap u-mt2 u-mb2" },
      h("button", {
        cls: !state.vulnFilterStatus ? "btn btn-primary mini" : "btn mini",
        type: "button",
        "aria-pressed": !state.vulnFilterStatus ? "true" : "false",
        text: "All Verdicts",
        on: { click: function () { state.vulnFilterStatus = ""; refresh(); } }
      }),
      h("button", {
        cls: state.vulnFilterStatus === "matched" ? "btn btn-primary mini" : "btn mini",
        type: "button",
        "aria-pressed": state.vulnFilterStatus === "matched" ? "true" : "false",
        text: "Affected Only",
        on: { click: function () { state.vulnFilterStatus = "matched"; refresh(); } }
      }),
      h("button", {
        cls: state.vulnFilterStatus === "possible" ? "btn btn-primary mini" : "btn mini",
        type: "button",
        "aria-pressed": state.vulnFilterStatus === "possible" ? "true" : "false",
        text: "Possible",
        on: { click: function () { state.vulnFilterStatus = "possible"; refresh(); } }
      }),
      h("button", {
        cls: state.vulnFilterStatus === "not_affected" ? "btn btn-primary mini" : "btn mini",
        type: "button",
        "aria-pressed": state.vulnFilterStatus === "not_affected" ? "true" : "false",
        text: "Not Affected",
        on: { click: function () { state.vulnFilterStatus = "not_affected"; refresh(); } }
      }),
      h("span", { cls: "dim-3 u-t2 u-ml3", text: (state.vulnerabilities || []).length + " correlated records" })
    );

    var vulRows = (state.vulnerabilities || []).map(function (v) {
      var flags = [];
      if (v.is_kev) flags.push(cisaKevBadge());
      if (v.epss && v.epss > 0) flags.push(epssBadge(v.epss));

      var flagsNode = flags.length
        ? h("div", { cls: "uf uf-g1 uf-wrap" }, flags)
        : h("span", { cls: "dim-3", text: "—" });

      var sevTone = (v.severity === "CRITICAL" || v.severity === "HIGH") ? "crit" : (v.severity === "MEDIUM" ? "warn" : "idle");

      var explainBtn = h("button", {
        cls: "btn mini",
        type: "button",
        text: "Explain",
        on: {
          click: function (ev) {
            ev.stopPropagation();
            openMatchEvidenceSheet(v);
          }
        }
      });

      return [
        h("b", { text: v.cve_id || "" }),
        chip(sevTone, (v.severity || "MEDIUM") + (v.cvss ? " " + v.cvss.toFixed(1) : "")),
        priorityScoreBadge(v.priority_score),
        flagsNode,
        vulnStatusBadge(v.status),
        h("span", { text: v.product_name || "—" }),
        h("span", { cls: "mono dim", text: v.version || "—" }),
        h("span", { cls: "dim-3", text: v.match_reason || "—" }),
        explainBtn
      ];
    });

    var vulCardBody = h("div", { cls: "card-body stack" },
      snapStrip,
      filterBtns,
      vulRows.length
        ? simpleTable(["CVE", "Severity", "Priority", "Catalog / Flags", "Verdict", "Product", "Version", "Match Reason", "Actions"], vulRows)
        : h("div", { cls: "empty", text: state.vulnFilterStatus ? "No vulnerabilities match the current filter (" + state.vulnFilterStatus + ")." : "No correlated vulnerabilities found." })
    );

    var vulCard = card("Vulnerability Correlation (NVD 2.0 / CISA KEV / EPSS)", vulCardBody);

    view.appendChild(h("div", { cls: "pad stack" }, evidenceCard, vulCard));
  }

  /* Roles, in the words an operator uses about people rather than the words the
     hub uses about routes. */
  var ROLE_LABELS = {
    admin: "Administrator",
    analyst: "Analyst",
    auditor: "Auditor"
  };
  var ROLE_NOTES = {
    admin: "Runs the fleet. Isolates hosts, pushes agents, and manages this list.",
    analyst: "Investigates and responds. Isolates hosts and works alerts, but cannot change who signs in.",
    auditor: "Reads everything, changes nothing. Every request that is not a read is refused."
  };

  function roleName(r) { return ROLE_LABELS[r] || r || "\u2014"; }

  /* The grant form is built once and reused, like the row filter above it:
     render() runs on every five-second poll, and a form rebuilt underneath
     someone loses whatever they had typed into it - mid-address, with no sign
     of why. */
  var opEmailInput = null;
  var opRoleSel = null;
  var opRoleNote = null;
  var opGrantCard = null;

  function buildGrantCard() {
    opEmailInput = h("input", {
      type: "text", id: "op-email", placeholder: "name@example.com",
      autocomplete: "off", spellcheck: "false"
    });
    opRoleSel = h("select", { id: "op-role" });
    state.operatorRoles.forEach(function (r) {
      opRoleSel.appendChild(h("option", { value: r, text: roleName(r) }));
    });
    opRoleSel.value = "analyst";

    opRoleNote = h("p", { cls: "pending", text: ROLE_NOTES[opRoleSel.value] || "" });
    opRoleSel.addEventListener("change", function () {
      opRoleNote.textContent = ROLE_NOTES[opRoleSel.value] || "";
    });

    opEmailInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); grantOperator(); }
    });

    opGrantCard = card("Grant access",
      h("div", { cls: "card-body" },
        h("div", { cls: "form-row" },
          h("label", { cls: "field" }, h("span", { text: "Email" }), opEmailInput),
          h("label", { cls: "field" }, h("span", { text: "Role" }), opRoleSel),
          h("button", { cls: "btn btn-primary", type: "button", id: "op-grant", text: "Grant",
            on: { click: grantOperator } })),
        opRoleNote,
        h("p", { cls: "pending", text: "The address must match the one the identity provider returns. Granting a role here does not admit anyone on its own: Cloudflare Access still decides who reaches this hub, and this list decides what they are once they do." })));
  }

  function grantOperator() {
    var email = (opEmailInput.value || "").trim();
    var role = opRoleSel.value;
    if (!email) { toast("An operator is identified by an email address", "warn"); return; }
    request("/api/v1/operators", "POST", { email: email, role: role })
      .then(function () {
        toast(email + " is now " + roleName(role).toLowerCase(), "ok");
        opEmailInput.value = "";
        refresh();
      })
      .catch(function (e) { toast("Could not grant access: " + e.message, "crit"); });
  }

  function renderAccess() {
    var view = $("view");

    /* A five-second poll must not yank an open dropdown out from under a click.
       Nothing in this section changes on its own - operators change when an
       administrator changes them - so skipping the rebuild while the focus is
       inside it costs nothing and keeps the section usable.
       It must not skip the *first* build, though: arriving from a section whose
       filter box still held focus left the previous section's table on screen
       under an Access breadcrumb, with no error and nothing to click. */
    if (view.dataset.section === "access" && view.firstChild && view.contains(document.activeElement)) return;

    clear(view);

    /* Defence in depth for a section the rail only offers to administrators:
       the hub refuses these routes to anyone else, and an operator who arrives
       here anyway should be told why rather than shown a table that fails to
       load. */
    if (!IS_ADMIN) {
      view.appendChild(h("div", { cls: "pad stack" },
        card("Access", h("div", { cls: "card-body" },
          h("div", { cls: "empty", text: "Only an administrator can see or change who signs in to this console. You are signed in as " + (OPERATOR || "an operator") + " with the " + roleName(ROLE).toLowerCase() + " role." })))));
      return;
    }

    if (!opGrantCard) buildGrantCard();

    var rows = state.operators.map(function (op) {
      var isYou = op.email === state.you;

      var sel = h("select", { "aria-label": "Role for " + op.email });
      state.operatorRoles.forEach(function (r) {
        sel.appendChild(h("option", { value: r, text: roleName(r) }));
      });
      sel.value = op.role;
      sel.addEventListener("change", function () {
        var next = sel.value;
        request("/api/v1/operators", "POST", { email: op.email, role: next })
          .then(function () { toast(op.email + " is now " + roleName(next).toLowerCase(), "ok"); refresh(); })
          .catch(function (e) {
            sel.value = op.role;
            toast("Could not change the role: " + e.message, "crit");
          });
      });

      return [
        /* "you" belongs against the name, not in the Granted by column - that
           column answers who granted the role, and overwriting it lost the
           answer for whoever happened to be reading their own row. */
        h("span", { cls: "ip" },
          document.createTextNode(op.email),
          isYou ? h("span", { cls: "dim-3", text: "  you" }) : document.createTextNode("")),
        sel,
        h("span", { cls: "dim-3", text: op.created_by || "\u2014" }),
        stamp(parseTime(op.created_at)),
        h("button", {
          cls: "mini", "data-danger": "true", type: "button", text: "Remove",
          title: isYou ? "Remove your own access to this hub" : "Remove " + op.email,
          on: {
            click: function () {
              /* A single unconfirmed click, one row away from a role dropdown,
                 and on your own row it removed your own access. If you are the
                 last administrator nobody can put it back from the console. */
              confirmSheet({
                title: isYou ? "Remove your own access" : "Remove " + op.email,
                consequence: isYou
                  ? "You lose access to this hub immediately. If you are the last administrator, nobody can restore it from the console - it has to be done on the hub host."
                  : op.email + " loses access to this hub immediately. Any console session they have open stops working on its next request.",
                detail: roleName(op.role) + " \u00b7 granted by " + (op.created_by || "unknown"),
                confirmLabel: isYou ? "Remove my access" : "Remove operator",
                requireText: isYou ? "REMOVE MY ACCESS" : null,
                onConfirm: function () {
                  request("/api/v1/operators/remove", "POST", { email: op.email })
                    .then(function () {
                      toast("Removed " + op.email + (isYou ? " \u2014 that was your own access" : ""), isYou ? "warn" : "ok");
                      refresh();
                    })
                    .catch(function (e) { toast("Could not remove: " + e.message, "crit"); });
                }
              });
            }
          }
        })
      ];
    });

    var listCard = card("Operators",
      simpleTable(["Email", "Role", "Granted by", "Added", ""], rows));

    view.appendChild(h("div", { cls: "pad stack" }, listCard, opGrantCard, deviceCredentialCard()));
  }

  function confirmRevokeDeviceCredential(cr) {
    var who = cr.endpoint_id || "this endpoint";
    confirmSheet({
      title: "Revoke device credential",
      consequence: "The agent on " + who + " stops being able to authenticate to this hub. It will not report flows, will not receive policy, and cannot be given a terminal session until somebody re-enrols it on the host itself.",
      detail: "Credential " + (cr.id || "") + " \u00b7 issued " + stampTitle(parseTime(cr.created_at)),
      confirmLabel: "Revoke credential",
      onConfirm: function () {
        request("/api/v1/device-auth/credentials?endpoint_id=" + encodeURIComponent(cr.endpoint_id), "DELETE")
          .then(function () { toast("Device credential revoked for " + who, "warn"); refresh(); })
          .catch(function (e) { toast("Could not revoke the credential: " + e.message, "crit"); });
      }
    });
  }

  /* The machine half of "who may talk to this hub". Operators were listed and
     agents were not, so a revoked-in-theory endpoint had no screen anywhere in
     the console. The credential string itself is never shown: the hub returns
     it exactly once, at enrolment. */
  function deviceCredentialCard() {
    var creds = state.deviceCredentials;
    if (!creds.length) {
      return card("Enrolled device credentials",
        h("div", { cls: "card-body" },
          emptyBox("No device credential has been issued. Agents are still authenticating with the shared tenant key.")));
    }

    var rows = creds.map(function (cr) {
      var revoked = !!cr.revoked_at;
      var actions = h("div", { cls: "row-actions" });
      if (!revoked) {
        actions.appendChild(h("button", {
          cls: "btn mini", type: "button", text: "Revoke", "data-danger": "true",
          title: "Stop this machine authenticating to the hub",
          on: { click: function () { confirmRevokeDeviceCredential(cr); } }
        }));
      }
      return [
        h("b", { text: cr.endpoint_id || "\u2014" }),
        h("span", { cls: "dim", text: cr.id || "\u2014" }),
        revoked
          ? h("span", { cls: "st", "data-state": "crit" }, h("span", { text: "revoked" }))
          : h("span", { cls: "st", "data-state": "ok" }, h("span", { text: "active" })),
        stamp(parseTime(cr.created_at)),
        cr.last_used_at ? stamp(parseTime(cr.last_used_at)) : h("span", { cls: "dim", text: "never used" }),
        cr.revoked_at ? stamp(parseTime(cr.revoked_at)) : h("span", { cls: "dim", text: "\u2014" }),
        actions
      ];
    });

    return card("Enrolled device credentials",
      simpleTable(["Endpoint", "Credential", "State", "Issued", "Last used", "Revoked", ""], rows));
  }

  /* --------------------------------------------------------- full route */

  var routeEl = null;
  var routeOpener = null;
  var drawerOpener = null;

  function closeRoute() {
    var wasOpen = !!routeEl;
    var opener = routeOpener;
    if (routeEl) {
      if (routeEl._trap) document.removeEventListener("keydown", routeEl._trap, true);
      if (routeEl.parentNode) routeEl.parentNode.removeChild(routeEl);
    }
    routeEl = null;
    routeOpener = null;
    if (wasOpen) restoreFocus(opener);
    state.routeKey = "";
    /* Only when a route was actually on screen: go() closes the route before
       it pushes its own entry, and two entries for one navigation makes Back
       feel broken. */
    if (wasOpen) syncURL(true);
  }

  function openRoute(key) {
    /* Whatever the operator was on when the full view opened, so Escape puts
       them back there instead of at the top of the document. Recorded before
       closeRoute clears it, and only when the route was not already open. */
    var opener = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    if (state.routeKey !== key) closeRoute();
    if (!routeOpener) routeOpener = opener;
    state.routeKey = key;
    syncURL(true);
    renderRoute();
    /* The full view shows this asset's recent flows, which only the Traffic and
       Audit sections load; fetch them on demand so the panel is never empty. */
    if (!state.events.length) {
      request("/api/v1/events").then(function (d) {
        state.events = arrayOf(d);
        if (state.routeKey) renderRoute();
      }).catch(function () { /* the panel degrades to "nothing recorded" */ });
    }
    /* Same for the baseline. Waiting for the next refresh tick left "what
       happens if I isolate this host" reading "Reading the baseline" for five
       seconds, which is long enough for someone to act without it. */
    var asset = state.assetByKey[key];
    if (asset && asset.endpoint) {
      var epID = asset.endpoint.id;
      request("/api/v1/software?endpoint_id=" + encodeURIComponent(epID)).then(function (d) {
        state.softwareByEndpoint[epID] = (d && d.packages) || [];
        if (state.routeKey) renderRoute();
      }).catch(function () {});
      request("/api/v1/network-profiles?level=endpoint&id=" + encodeURIComponent(epID)).then(function (d) {
        state.profilesByEndpoint[epID] = arrayOf(d);
        if (state.routeKey) renderRoute();
      }).catch(function () { /* the card degrades to "nothing recorded yet" */ });
      request("/api/v1/baseline/endpoint?endpoint_id=" + encodeURIComponent(epID)).then(function (d) {
        state.baselineByEndpoint[epID] = d || {};
        if (state.routeKey) renderRoute();
      }).catch(function () { /* the card degrades to the loading line */ });
      if (!state.baselineServices.length) {
        request("/api/v1/baseline/catalogue").then(function (d) {
          state.baselineServices = arrayOf(d && d.services);
        }).catch(function () { /* the editor falls back to the built-in list */ });
      }
    }
  }

  /* Why the console thinks a host is what it says it is. The scanner used to
     print "Ubuntu Linux" over a regex that had matched the word OpenSSH, and
     there was no way to see that from the screen - which is the same as there
     being no way to correct it. */
  var IDENT_METHODS = {
    "agent": "the agent installed on it",
    "ssh-banner": "the SSH server's own version string",
    "mdns-device-info": "the host's own mDNS device-info record",
    "mdns-services": "the services it publishes over mDNS",
    "http-server": "the web server's Server header",
    "ssdp": "its UPnP announcement",
    "netbios": "its NetBIOS name table",
    "snmp-sysdescr": "its SNMP system description",
    "signature": "a weighted match against the signature catalogue"
  };

  function identityWhyCard(asset) {
    var sc = asset.scan;
    var method = (sc && sc.identity_method) || (asset.endpoint ? "agent" : "");
    var why = arrayOf(sc && sc.identity_why);
    if (!method && !why.length) return null;

    var body = h("div", { cls: "card-body stack" },
      h("dl", { cls: "kv" },
        h("dt", { text: "Reads as" }), h("dd", {}, h("b", { text: (sc && sc.os_guess) || asset.identity || "\u2014" })),
        h("dt", { text: "Decided by" }), h("dd", { text: IDENT_METHODS[method] || method || "\u2014" }),
        h("dt", { text: "Confidence" }),
        h("dd", { text: sc && sc.confidence ? Math.round(sc.confidence * 100) + "%" : "\u2014" }),
        h("dt", { text: "Hop limit" }),
        h("dd", { text: sc && sc.ttl ? String(sc.ttl) : "not measured" })));

    if (why.length) {
      var list = h("div", { cls: "why" });
      why.forEach(function (w) { list.appendChild(h("div", { cls: "whyline", text: w })); });
      body.appendChild(list);
    }
    if (method === "signature") {
      body.appendChild(h("p", { cls: "pending", text: "Nothing on this host named itself, so this is a weighted guess rather than an answer. Correct it on the Evidence card and the correction wins from then on." }));
    }
    return card("How this was identified", body);
  }

  /* The rolling profile the hub builds from every flow it has seen for this
     host: one row per process/destination/port conversation, with how often
     and how much. Raw flow rows answer "what happened at 14:03"; this answers
     "is this normal for this machine", which is the question an operator
     actually has in front of an alert. */
  function commProfileCard(asset) {
    var epID = asset.endpoint.id;
    var profiles = state.profilesByEndpoint[epID];
    if (!profiles) return card("What this host talks to", emptyBox("Reading this host's communication profile\u2026"), null, true);
    if (!profiles.length) {
      return card("What this host talks to",
        emptyBox("No conversation has been profiled for this host yet. The profile is built from the flows the agent reports, so a freshly enrolled host is empty until it talks."), null, true);
    }

    var shown = profiles.slice(0, 30);
    var rows = shown.map(function (pr) {
      var moved = (Number(pr.total_bytes_in) || 0) + (Number(pr.total_bytes_out) || 0);
      return [
        h("span", { cls: "dim", text: pr.process_name || pr.process_path || "\u2014" }),
        h("span", { cls: "ip", text: (pr.dst_ip || "\u2014") + ":" + (pr.dst_port || 0) }),
        (pr.protocol || "\u2014") + (pr.direction ? " " + pr.direction : ""),
        pr.country || "\u2014",
        String(Number(pr.event_count) || 0),
        bytes(moved),
        /* Baseline here means the hub accepted this conversation as normal for
           the host. Anything unmarked is traffic nobody has vouched for. */
        pr.is_baseline
          ? h("span", { cls: "st", "data-state": "ok" }, h("span", { text: "baseline" }))
          : h("span", { cls: "st", "data-state": "idle" }, h("span", { text: "unvouched" })),
        stamp(parseTime(pr.last_seen))
      ];
    });

    var body = h("div", { cls: "stack" },
      simpleTable(["Process", "Destination", "Protocol", "Country", "Conversations", "Moved", "Baseline", "Last seen"], rows));
    if (profiles.length > shown.length) {
      body.appendChild(h("p", { cls: "pending", text: "Showing the " + shown.length + " busiest of " + profiles.length + " profiled conversations." }));
    }
    return card("What this host talks to", body, null, true);
  }

  function renderRoute() {
    var previousScrollTop = 0;
    if (routeEl) {
      var prevBody = routeEl.querySelector(".route-body");
      if (prevBody) previousScrollTop = prevBody.scrollTop;
      if (routeEl.parentNode) routeEl.parentNode.removeChild(routeEl);
    }
    routeEl = null;
    if (!state.routeKey) return;

    var asset = state.assetByKey[state.routeKey];
    if (!asset) { state.routeKey = ""; return; }

    var ep = asset.endpoint;
    var sc = asset.scan;

    var idCard = card("Identity", h("div", { cls: "card-body" },
      h("dl", { cls: "kv" },
        h("dt", { text: "Asset" }), h("dd", {}, h("b", { text: asset.name })),
        h("dt", { text: "Address" }), h("dd", {}, h("b", { text: asset.ip || "\u2014" })),
        h("dt", { text: "MAC" }), h("dd", { text: asset.mac || "\u2014" }),
        h("dt", { text: "Vendor" }), h("dd", { text: asset.vendor || "\u2014" }),
        h("dt", { text: "Role" }), h("dd", {}, h("b", { text: asset.role && asset.role !== "unknown" ? roleLabel(asset.role) : "\u2014" })),
        h("dt", { text: "Identity" }), h("dd", { text: asset.identity }),
        h("dt", { text: "Client" }), h("dd", { text: asset.tenantName }),
        h("dt", { text: "Location" }), h("dd", { text: asset.locationName }),
        h("dt", { text: "Subnet" }), h("dd", { text: asset.subnet || "\u2014" }),
        h("dt", { text: "Last seen" }), h("dd", {}, stamp(asset.lastSeen)))));

    var agentCard = card("Agent", h("div", { cls: "card-body" },
      ep
        ? h("dl", { cls: "kv" },
            h("dt", { text: "Endpoint id" }), h("dd", {}, h("b", { text: ep.id })),
            h("dt", { text: "Version" }), h("dd", { text: shortVersion(ep.driver_version) + (asset.stale ? " \u2014 outdated" : "") }),
            h("dt", { text: "Collector" }), h("dd", { text: engineOf(ep.driver_version) || "\u2014" }),
            h("dt", { text: "OS" }), h("dd", { text: ep.os || "\u2014" }),
            h("dt", { text: "Role" }), h("dd", { text: ep.role_tag || "\u2014" }),
            h("dt", { text: "Software" }), h("dd", { text: ep.installed_software || "\u2014" }),
            h("dt", { text: "Registered" }), h("dd", {}, stamp(parseTime(ep.created_at))))
        : emptyBox("No agent on this asset. It is on the deployment worklist.")));

    var portsBody = h("div", { cls: "card-body" });
    if (asset.ports.length) {
      var pl = h("div", { cls: "portlist" });
      asset.ports.slice().sort(function (a, b) { return (a.port || 0) - (b.port || 0); }).forEach(function (p) {
        pl.appendChild(h("span", { cls: "port", "data-risk": p.risk_level || "LOW", text: p.port + (p.service ? " " + p.service : "") }));
      });
      portsBody.appendChild(pl);
    } else {
      portsBody.appendChild(h("div", { cls: "empty", text: sc ? "No open ports observed." : "Not scanned." }));
    }
    var weak = sc ? arrayOf(sc.weakpoints) : [];
    if (weak.length) {
      var wl = h("div", { cls: "why" });
      weak.forEach(function (w) { wl.appendChild(h("div", { text: "\u00b7 " + w })); });
      portsBody.appendChild(wl);
    }

    var evBody = h("div", { cls: "card-body" });
    evBody.appendChild(claimsPanel(asset));
    evBody.appendChild(h("p", { cls: "pending", text: "Highest confidence wins per field, never per record. Losing scan claims stay on the row so an operator can see how the identity was formed." }));

    var flows = state.events.filter(function (e) {
      return (ep && e.endpoint_id === ep.id) || (asset.ip && (e.src_ip === asset.ip || e.dst_ip === asset.ip));
    }).slice(0, 25);
    var flowCard = card("Recent flows", simpleTable(["Time", "Action", "Source", "Destination", "Process", "Forensics"],
      flows.map(function (e) {
        var procNode = [h("span", { cls: "dim", text: e.process_path || e.domain || "—" })];
        if (e.attribution_status && e.attribution_status !== "unknown") {
          procNode.push(h("span", { cls: "u-ml2" }, processAttributionBadge(e.attribution_status)));
        }
        var forensicsBtn = h("button", {
          cls: "btn mini", type: "button", text: "Inspect",
          on: { click: function (ev) { ev.stopPropagation(); openEventInspectionSheet(e); } }
        });
        return [
          stamp(parseTime(e.timestamp)),
          h("span", { cls: "st", "data-state": e.action === "BLOCK" ? "crit" : "ok" },
            icon(e.action === "BLOCK" ? "g-quarantine" : "g-online", true),
            h("span", { text: e.action || "" })),
          h("span", { cls: "ip", text: (e.src_ip || "") + ":" + (e.src_port || 0) }),
          h("span", { cls: "ip", text: (e.dst_ip || "") + ":" + (e.dst_port || 0) }),
          h("div", { cls: "uf uf-wrap uf-g1" }, procNode),
          forensicsBtn
        ];
      })), null, true);

    var alerts = state.anomalies.filter(function (a) { return (ep && a.endpoint_id === ep.id) || (asset.ip && a.dst_ip === asset.ip); });
    var alertCard = card("Open alerts", alerts.length
      ? h("div", {}, alerts.map(function (a) { return alertCardNode(a, true); }))
      : emptyBox("No open alert on this asset."), null, true);

    var routeBody = h("div", { cls: "route-body" }, idCard, identityWhyCard(asset), agentCard, card("Observed exposure", portsBody),
      ep ? baselineEndpointCard(asset) : null,
      ep ? commProfileCard(asset) : null,
      ep ? softwareInventoryCard(asset) : null,
      card("Evidence", evBody), flowCard, alertCard);

    routeEl = h("div", {
      cls: "route", role: "dialog", "aria-modal": "true", tabindex: "-1",
      "aria-label": "Asset " + asset.name
    },
      h("div", { cls: "route-head" },
        h("button", { cls: "btn btn-icon", type: "button", "aria-label": "Back", on: { click: closeRoute } }, icon("i-close")),
        h("h2", { text: asset.name }),
        stateBadge(asset.state),
        evidenceStrip(asset),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn", type: "button", text: "Copy address", on: { click: function () { copyAddress(asset); } } }),
        h("button", {
          cls: "btn", type: "button", text: "Actions",
          on: {
            click: function (e) {
              var r = e.currentTarget.getBoundingClientRect();
              openAssetMenu(asset, r.left - 60, r.bottom + 4, null);
            }
          }
        })),
      routeBody);

    document.body.appendChild(routeEl);
    if (previousScrollTop > 0) {
      routeBody.scrollTop = previousScrollTop;
    }
    /* A dialog nobody focused is a dialog a keyboard operator cannot reach:
       Tab carried on through the table behind it. Focus moves in on the first
       build only, so a five-second repaint does not yank the caret back to the
       top of the panel while somebody is reading it. */
    routeEl._trap = trapFocus(routeEl);
    document.addEventListener("keydown", routeEl._trap, true);
    if (!routeEl.contains(document.activeElement)) {
      try { routeEl.focus(); } catch (e) { /* not focusable in every engine */ }
    }
  }

  /* -------------------------------------------------------------- drawers */

  var drawerEl = null;
  var scrimEl = null;
  var openDrawer = "";

  function closeDrawer() {
    var opener = drawerOpener;
    var wasOpen = !!drawerEl;
    if (drawerEl) {
      if (drawerEl._trap) document.removeEventListener("keydown", drawerEl._trap, true);
      if (drawerEl.parentNode) drawerEl.parentNode.removeChild(drawerEl);
    }
    if (scrimEl && scrimEl.parentNode) scrimEl.parentNode.removeChild(scrimEl);
    drawerEl = null;
    scrimEl = null;
    drawerOpener = null;
    openDrawer = "";
    if (wasOpen) restoreFocus(opener);
  }

  function showDrawer(kind) {
    if (kind !== "alerts") return;
    if (openDrawer === kind) { closeDrawer(); return; }
    var opener = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    closeDrawer();
    drawerOpener = opener;
    openDrawer = kind;
    scrimEl = h("div", { cls: "scrim", on: { click: closeDrawer } });
    document.body.appendChild(scrimEl);
    drawerEl = h("aside", {
      cls: "drawer", role: "dialog", "aria-modal": "true", tabindex: "-1",
      "aria-label": "Alerts"
    });
    document.body.appendChild(drawerEl);
    renderDrawer();
    drawerEl._trap = trapFocus(drawerEl);
    document.addEventListener("keydown", drawerEl._trap, true);
    if (!drawerEl.contains(document.activeElement)) {
      try { drawerEl.focus(); } catch (e) { /* not focusable in every engine */ }
    }
  }

  /* The detector's own numbers, when it recorded any.
     A beacon verdict used to arrive as one sentence of prose, so "score 0.82"
     and "threshold 0.70" were something an operator had to read out of a
     paragraph and compare in their head. The hub has always computed both. */
  function evidencePanel(a) {
    if (!a.evidence) return null;
    var ev;
    try { ev = JSON.parse(a.evidence); } catch (e) { return null; }
    if (!ev || ev.kind !== "beacon") return null;

    var score = Number(ev.score) || 0;
    var threshold = Number(ev.threshold) || 0;
    var over = threshold > 0 ? score / threshold : 0;

    function pct(v) { return v === undefined || v === null ? "\u2014" : (Number(v) * 100).toFixed(0) + "%"; }
    function secs(v) { return v === undefined || v === null ? "\u2014" : Number(v).toFixed(1) + "s"; }

    var facts = [
      ["Beacon score", score.toFixed(2) + " of " + threshold.toFixed(2) + " needed"],
      ["Regularity", pct(ev.regularity)],
      ["Consistency", pct(ev.consistency)],
      ["Uniformity", pct(ev.uniformity)],
      ["Mean interval", secs(ev.mean_interval)],
      ["Jitter", secs(ev.std_dev) + " (" + pct(ev.coef_variation) + ")"],
      ["Check-ins", String(ev.samples || 0) + " over " + Math.round(Number(ev.span_minutes) || 0) + " min"],
      ["Payload variation", ev.size_variation === undefined ? "not reported by the agent" : pct(ev.size_variation)]
    ];

    return h("div", { cls: "stack-s" },
      h("div", { cls: "card-sub" },
        document.createTextNode("Detector evidence "),
        chip(over >= 1.2 ? "crit" : over >= 1 ? "warn" : "idle",
          over >= 1 ? (over).toFixed(2) + "\u00d7 threshold" : "below threshold")),
      h("div", { cls: "alert-exp-grid" },
        facts.map(function (f) {
          return h("div", { cls: "alert-exp-box" },
            h("div", { cls: "alert-exp-label", text: f[0] }),
            h("div", { cls: "alert-exp-val", text: f[1] }));
        })));
  }

  function alertCardNode(a, compact) {
    var node = h("div", { cls: "alert", "data-sev": a.severity || "LOW" },
      h("div", { cls: "sev" }),
      h("div", {},
        h("div", { cls: "sev-word", text: (a.severity || "LOW") + " \u00b7 " + (a.anomaly_type || "ANOMALY") }),
        h("div", { cls: "ttl", text: a.title || "Anomaly" }),
        h("div", { cls: "meta" },
          document.createTextNode((a.hostname || a.endpoint_id || "\u2014") + " \u00b7 "),
          stamp(parseTime(a.timestamp))),
        h("div", { cls: "desc", text: a.description || "" }),
        a.details ? h("div", { cls: "meta", text: a.details }) : null,
        compact ? null : evidencePanel(a),
        compact ? null : h("div", { cls: "acts" },
          h("button", {
            cls: "mini", type: "button", text: "Open asset",
            on: {
              click: function () {
                var asset = assetForAlert(a);
                if (asset) { closeDrawer(); openRoute(asset.key); }
                else toast("No asset row for " + (a.hostname || a.endpoint_id), "warn");
              }
            }
          }),
          h("button", {
            cls: "mini", type: "button", "data-danger": "true", text: "Isolate host",
            on: {
              click: function () {
                var asset = assetForAlert(a);
                if (asset) setIsolation(asset, true);
                else toast("No agented asset for " + (a.hostname || a.endpoint_id), "warn");
              }
            }
          }),
          h("button", {
            cls: "mini", type: "button", text: "Acknowledge",
            on: {
              click: function () {
                request("/api/v1/anomalies/acknowledge", "POST", { id: a.id })
                  .then(function () { toast("Acknowledged", "ok"); refresh(); })
                  .catch(function (e) { toast("Acknowledge failed: " + e.message, "crit"); });
              }
            }
          }))));
    return node;
  }

  function renderDrawer() {
    if (!drawerEl) return;
    var previousScrollTop = 0;
    if (openDrawer === "alerts") {
      var prevBody = drawerEl.querySelector(".drawer-body");
      if (prevBody) previousScrollTop = prevBody.scrollTop;
    }
    clear(drawerEl);

    if (openDrawer === "alerts") {
      drawerEl.appendChild(h("div", { cls: "drawer-head" },
        icon("i-alert"),
        h("h2", { text: "Alerts" }),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn btn-icon", type: "button", "aria-label": "Close", on: { click: closeDrawer } }, icon("i-close"))));
      var body = h("div", { cls: "drawer-body" });
      if (!state.anomalies.length) {
        body.appendChild(emptyBox("No open anomalies."));
      } else {
        state.anomalies.forEach(function (a) { body.appendChild(alertCardNode(a, false)); });
      }
      drawerEl.appendChild(body);
      if (previousScrollTop > 0) {
        body.scrollTop = previousScrollTop;
      }
      return;
    }
  }

  /* ------------------------------------------------------ command palette */

  var paletteEl = null;
  var paletteItems = [];
  var paletteCursor = 0;
  var paletteOpener = null;

  function closePalette() {
    if (paletteEl) {
      if (paletteEl._trap) document.removeEventListener("keydown", paletteEl._trap, true);
      if (paletteEl.parentNode) paletteEl.parentNode.removeChild(paletteEl);
    }
    paletteEl = null;
    /* The palette is opened from the keyboard more often than anything else in
       the console, and it dropped focus on <body> when it closed - so Escape
       sent a keyboard operator back to the top of the document instead of to
       whatever they were on. Running an item is different: that item moves
       focus itself. */
    var opener = paletteOpener;
    paletteOpener = null;
    return opener;
  }

  function paletteSource() {
    var items = [];

    SECTIONS.forEach(function (sec) {
      items.push({
        group: "Go", label: "Go to " + sec.label, iconId: "i-" + sec.id,
        hint: "section", run: function () { go(sec.id); }
      });
    });

    state.assets.forEach(function (a) {
      items.push({
        group: "Assets", label: a.name, mono: true,
        iconId: a.evidence.agent ? "i-assets" : "i-discovery",
        hint: (a.ip || "") + " \u00b7 " + a.state.word,
        extra: a.searchText,
        run: function () {
          state.filters = {};
          state.query = "";
          state.expandedKey = a.key;
          state.cursorKey = a.key;
          go("assets");
          openRoute(a.key);
        }
      });
    });

    var seenGroups = {};
    state.assets.forEach(function (a) {
      if (seenGroups[a.groupKey]) return;
      seenGroups[a.groupKey] = true;
      items.push({
        group: "Scope", label: a.groupKey, iconId: "i-tag", hint: "filter",
        run: function () {
          state.filters = {};
          state.query = a.locationName;
          go("assets");
        }
      });
    });

    Object.keys(FILTERS).forEach(function (k) {
      items.push({
        group: "Filter", label: "Filter: " + FILTERS[k].label, iconId: "i-search", hint: "assets",
        run: function () { state.filters = {}; state.filters[k] = true; go("assets"); }
      });
    });

    items.push({ group: "Act", label: "Isolate selected hosts", iconId: "i-lock", hint: "bulk", run: function () { bulkIsolate(true); } });
    items.push({ group: "Act", label: "Release selected hosts", iconId: "i-unlock", hint: "bulk", run: function () { bulkIsolate(false); } });
    items.push({ group: "Act", label: "Push agent updates to the fleet", iconId: "i-download", hint: "agents", run: pushAgentUpdates });
    items.push({ group: "Act", label: "Sync threat-intel feeds", iconId: "i-refresh", hint: "policy", run: function () {
      request("/api/v1/threatintel/sync", "POST").then(function () { toast("Feeds synced", "ok"); refresh(); })
        .catch(function (e) { toast("Sync failed: " + e.message, "crit"); });
    } });
    items.push({ group: "Act", label: "Refresh now", iconId: "i-refresh", hint: "", run: refresh });
    items.push({ group: "Act", label: "Open alerts drawer", iconId: "i-alert", hint: "", run: function () { showDrawer("alerts"); } });

    THEMES.forEach(function (t) {
      items.push({
        group: "Theme", label: "Theme: " + THEME_NAMES[t], iconId: "i-theme", hint: t,
        run: function () { applyTheme(t, true); toast("Theme: " + THEME_NAMES[t], "ok"); }
      });
    });

    items.push({
      group: "Theme", label: state.demo ? "Leave demo mode" : "Enter demo mode", iconId: "i-tag",
      hint: "synthetic fleet",
      run: function () {
        state.demo = !state.demo;
        writeStore("ominull.demo", state.demo ? "true" : "false");
        toast(state.demo ? "Demo mode on \u2014 synthetic fleet" : "Demo mode off", "warn");
        refresh();
      }
    });

    return items;
  }

  function scoreItem(item, q) {
    if (!q) return 1;
    var hay = (item.label + " " + (item.hint || "") + " " + (item.extra || "")).toLowerCase();
    var idx = hay.indexOf(q);
    if (idx < 0) {
      /* Subsequence fallback so "wexec" still reaches "corp-win11-exec". */
      var j = 0;
      for (var i = 0; i < hay.length && j < q.length; i++) {
        if (hay[i] === q[j]) j++;
      }
      return j === q.length ? 0.2 : 0;
    }
    return idx === 0 ? 3 : 2;
  }

  function renderPaletteList(query) {
    var q = query.trim().toLowerCase();
    var all = paletteSource();
    var scored = [];
    all.forEach(function (it) {
      var sc = scoreItem(it, q);
      if (sc > 0) scored.push({ it: it, score: sc });
    });
    scored.sort(function (a, b) { return b.score - a.score; });
    paletteItems = scored.slice(0, 60).map(function (x) { return x.it; });
    if (paletteCursor >= paletteItems.length) paletteCursor = 0;

    var list = paletteEl.querySelector(".palette-list");
    clear(list);
    var lastGroup = "";
    paletteItems.forEach(function (it, i) {
      if (it.group !== lastGroup) {
        lastGroup = it.group;
        list.appendChild(h("div", { cls: "lbl", text: it.group }));
      }
      list.appendChild(h("button", {
        cls: "pi", type: "button", id: "pi-" + i, role: "option",
        "aria-selected": i === paletteCursor ? "true" : "false",
        "data-cursor": i === paletteCursor ? "true" : "false",
        on: {
          click: function () { restoreFocus(closePalette()); it.run(); },
          mouseenter: function () {
            paletteCursor = i;
            Array.prototype.forEach.call(list.querySelectorAll(".pi"), function (b, bi) {
              b.setAttribute("data-cursor", bi === i ? "true" : "false");
              b.setAttribute("aria-selected", bi === i ? "true" : "false");
            });
            syncPaletteActiveDescendant();
          }
        }
      },
        icon(it.iconId),
        h("span", { cls: it.mono ? "t t-mono" : "t", text: it.label }),
        it.hint ? h("span", { cls: "s", text: it.hint }) : null));
    });

    if (!paletteItems.length) {
      list.appendChild(emptyBox("Nothing matches."));
    }
    syncPaletteActiveDescendant();
  }

  /* The palette had no ARIA at all - a combobox with a filtered list of
     options, announced as a text field beside a pile of buttons. It ranks
     "Isolate selected hosts" with the same scorer as "Go to Assets", so which
     row is armed has to be something a screen reader can report. */
  function syncPaletteActiveDescendant() {
    if (!paletteEl) return;
    var input = paletteEl.querySelector("input");
    if (!input) return;
    if (paletteItems.length) input.setAttribute("aria-activedescendant", "pi-" + paletteCursor);
    else input.removeAttribute("aria-activedescendant");
  }

  function openPalette() {
    if (paletteEl) return;
    paletteCursor = 0;
    paletteOpener = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    var input = h("input", {
      type: "text", placeholder: "Jump to a host, an address, a section, or an action\u2026",
      "aria-label": "Command palette", role: "combobox", "aria-expanded": "true",
      "aria-controls": "palette-list", "aria-autocomplete": "list", autocomplete: "off"
    });
    paletteEl = h("div", {
      cls: "palette-wrap",
      on: {
        click: function (e) { if (e.target === paletteEl) restoreFocus(closePalette()); }
      }
    },
      h("div", { cls: "palette", role: "dialog", "aria-modal": "true", "aria-label": "Command palette" },
        input,
        h("div", { cls: "palette-list", id: "palette-list", role: "listbox", "aria-label": "Results" }),
        h("div", { cls: "palette-foot" },
          h("span", { text: "enter run" }),
          h("span", { text: "up/down move" }),
          h("span", { text: "esc close" }))));
    document.body.appendChild(paletteEl);
    paletteEl._trap = trapFocus(paletteEl);
    document.addEventListener("keydown", paletteEl._trap, true);
    renderPaletteList("");

    input.addEventListener("input", function () {
      paletteCursor = 0;
      renderPaletteList(input.value);
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown" || (e.key === "n" && e.ctrlKey)) {
        e.preventDefault();
        paletteCursor = Math.min(paletteItems.length - 1, paletteCursor + 1);
        renderPaletteList(input.value);
        var cur = paletteEl.querySelector('.pi[data-cursor="true"]');
        if (cur) cur.scrollIntoView({ block: "nearest" });
      } else if (e.key === "ArrowUp" || (e.key === "p" && e.ctrlKey)) {
        e.preventDefault();
        paletteCursor = Math.max(0, paletteCursor - 1);
        renderPaletteList(input.value);
        var cur2 = paletteEl.querySelector('.pi[data-cursor="true"]');
        if (cur2) cur2.scrollIntoView({ block: "nearest" });
      } else if (e.key === "Enter") {
        e.preventDefault();
        var it = paletteItems[paletteCursor];
        /* Focus goes back to whatever opened the palette before the item runs,
           so an action that opens an overlay of its own records a live opener
           rather than the palette input it is about to remove. */
        if (it) { restoreFocus(closePalette()); it.run(); }
      } else if (e.key === "Escape") {
        e.preventDefault();
        restoreFocus(closePalette());
      }
    });
    input.focus();
  }

  /* ------------------------------------------------------------ keyboard */

  function cursorIndex(rows) {
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].key === state.cursorKey) return i;
    }
    return -1;
  }

  function moveCursor(delta) {
    var rows = visibleAssets().filter(function (r) { return !state.collapsedGroups[r.groupKey]; });
    if (!rows.length) return;
    var i = cursorIndex(rows);
    i = i < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, i + delta));
    state.cursorKey = rows[i].key;
    render();
    var el = document.querySelector('tr.row[data-key="' + cssEscape(state.cursorKey) + '"]');
    if (el) el.scrollIntoView({ block: "nearest" });
  }

  function cssEscape(v) {
    return String(v).replace(/["\\]/g, "\\$&");
  }

  function cursorAsset() {
    return state.cursorKey ? state.assetByKey[state.cursorKey] : null;
  }

  function typingInField(e) {
    var t = e.target;
    if (!t) return false;
    var tag = (t.tagName || "").toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select" || t.isContentEditable;
  }

  /* Is the terminal sheet open and holding focus? Both branches below run
     *before* the typingInField guard, which is why they used to fire while a
     shell had focus: Escape closed the sheet - and closing the sheet used to
     kill the process, so pressing Escape inside vim killed vim and everything
     under it - and Ctrl+K opened the command palette instead of reaching
     readline's kill-line. Single-letter shortcuts were already safe: xterm
     focuses a hidden <textarea> and typingInField catches it. */
  function terminalHasFocus() {
    return !!(sheetEl && sheetEl._isTerminal && sheetEl.contains(document.activeElement));
  }

  document.addEventListener("keydown", function (e) {
    var inTerminal = terminalHasFocus();

    var mod = IS_MAC ? e.metaKey : e.ctrlKey;
    if (mod && (e.key === "k" || e.key === "K")) {
      if (inTerminal) return; // kill-line belongs to the shell
      e.preventDefault();
      openPalette();
      return;
    }

    if (e.key === "Escape") {
      /* Escape belongs to whatever is running in the shell. Dismiss the
         terminal with the header ✕ or Detach Viewer. */
      if (inTerminal) return;
      if (sheetEl) { requestCloseSheet(); return; }
      if (paletteEl) { restoreFocus(closePalette()); return; }
      if (ctxMenu) { closeCtx(); return; }
      if (accountPop) { closeAccountPop(); return; }
      if (routeEl) { closeRoute(); return; }
      if (openDrawer) { closeDrawer(); return; }
      if (state.query) { state.query = ""; render(); return; }
      return;
    }

    if (paletteEl || typingInField(e) || e.ctrlKey || e.metaKey || e.altKey) return;

    /* Row operations. Terminal muscle memory, no mouse round-trip. */
    if (state.section !== "assets" || routeEl) {
      if (e.key === "/") { e.preventDefault(); go("assets"); focusFilter(); }
      return;
    }

    var a;
    switch (e.key) {
      case "j":
        e.preventDefault(); moveCursor(1); break;
      case "k":
        e.preventDefault(); moveCursor(-1); break;
      case "x":
        a = cursorAsset();
        if (a) {
          e.preventDefault();
          if (state.selected[a.key]) delete state.selected[a.key];
          else state.selected[a.key] = true;
          render();
        }
        break;
      case "i":
        a = cursorAsset();
        if (a) { e.preventDefault(); setIsolation(a, !a.isolated); }
        break;
      case "r":
        a = cursorAsset();
        if (a) { e.preventDefault(); rescan(a); }
        break;
      case "y":
        a = cursorAsset();
        if (a) { e.preventDefault(); copyAddress(a); }
        break;
      case "d":
        a = cursorAsset();
        if (a && !a.evidence.agent) { e.preventDefault(); installAgent(a); }
        break;
      case "Enter":
        a = cursorAsset();
        if (a) { e.preventDefault(); openRoute(a.key); }
        break;
      case "/":
        e.preventDefault(); focusFilter(); break;
      default:
        break;
    }
  });

  function focusFilter() {
    var input = $("filter-input");
    if (input) { input.focus(); input.select(); }
  }

  document.addEventListener("click", function (e) {
    if (ctxMenu && !ctxMenu.contains(e.target) && !e.target.closest(".menu-btn")) closeCtx();
    if (accountPop && !accountPop.contains(e.target) && !e.target.closest("#user-avatar-btn")) closeAccountPop();
  });

  window.addEventListener("resize", function () {
    closeCtx();
    closeAccountPop();
  });

  /* ------------------------------------------------------------- topbar */

  var filterInput = null;
  /* Long-lived input nodes. See renderAlerts / softwareInventoryCard: a render
     that clears its own view destroys any field inside it, so the field has to
     outlive the render. */
  var alertsSearchInput = null;
  var softwareSearchInput = null;

  function updateCrumb() {
    var sec = SECTIONS.filter(function (x) { return x.id === state.section; })[0];
    $("crumb-main").textContent = sec ? sec.label : "";

    var sub = "";
    if (state.section === "assets") {
      var stats = assetStats();
      var active = activeFilters();
      sub = "/ " + stats.total + " known \u00b7 " + stats.agented + " agented";
      if (active.length) {
        sub += " \u00b7 filtered: " + active.map(function (k) { return FILTERS[k].label.toLowerCase(); }).join(", ");
      }
      if (state.query) sub += " \u00b7 \u201c" + state.query + "\u201d";
    } else if (state.section === "alerts") {
      var unack = state.unackAlertsTotal !== undefined ? state.unackAlertsTotal : state.anomalies.filter(function (a) { return !a.acknowledged; }).length;
      var total = state.alertsData ? state.alertsData.total : state.anomalies.length;
      sub = "/ " + total + " total \u00b7 " + unack + " open";
    } else if (state.section === "topology") {
      sub = "/ " + state.topoWindow + " window";
    } else if (state.demo) {
      sub = "/ demo";
    }
    if (state.demo && state.section === "assets") sub += " \u00b7 demo";
    $("crumb-sub").textContent = sub;

    var badge = $("rail-alert-badge");
    if (badge) {
      var count = state.unackAlertsTotal !== undefined ? state.unackAlertsTotal : state.anomalies.filter(function (a) { return !a.acknowledged; }).length;
      badge.textContent = String(count);
      badge.setAttribute("data-n", String(count));
    }

    var health = $("health");
    var hstate = state.lastError ? "down" : (assetStats().offline > 0 ? "degraded" : "ok");
    health.setAttribute("data-state", hstate);
    health.setAttribute("data-stale", state.viewStale ? "true" : "false");
    var title = state.lastError
      ? "Hub unreachable: " + state.lastError
      : (hstate === "degraded" ? "Hub healthy \u00b7 some endpoints offline" : "Hub healthy");
    if (state.viewStale) title += " \u00b7 view paused while you are typing";
    health.setAttribute("title", title);
    $("health-word").textContent = title;
  }

  /* Says out loud that the view is not being repainted, so a paused console is
     distinguishable from a hub that has stopped answering. */
  function setStale(on) {
    if (state.viewStale === !!on) return;
    state.viewStale = !!on;
    var health = $("health");
    if (health) health.setAttribute("data-stale", state.viewStale ? "true" : "false");
  }

  function renderTopbar() {
    updateCrumb();

    var sweepDot = $("sweep-pulse-dot");
    var sweepLabel = $("sweep-label-text");
    var isScanning = !!(state.scanStatus && state.scanStatus.active);
    if (sweepDot) {
      if (isScanning) sweepDot.classList.add("scanning");
      else sweepDot.classList.remove("scanning");
    }
    if (sweepLabel) {
      sweepLabel.textContent = isScanning ? "Scanning LAN (" + (state.scanStatus.progress || 0) + "%)" : "Subnet Sweep";
    }

    var actions = $("topbar-actions");

    if (state.section === "assets") {
      /* The filter field is reused rather than rebuilt to preserve focus and caret */
      if (!filterInput) {
        filterInput = h("input", {
          type: "search", id: "filter-input", placeholder: "Filter rows", "aria-label": "Filter rows"
        });
        filterInput.value = state.query;
        filterInput.addEventListener("input", function () {
          state.query = filterInput.value;
          state.cursorKey = "";
          syncURL(false);
          renderBody();
          renderStrip();
          updateCrumb();
        });
      } else if (document.activeElement !== filterInput) {
        filterInput.value = state.query;
      }
      if (actions && actions.firstElementChild !== filterInput) {
        clear(actions);
        actions.appendChild(filterInput);
      }
    } else if (actions) {
      clear(actions);
      if (state.section === "topology") {
        ["1h", "6h", "24h", "7d"].forEach(function (w) {
          actions.appendChild(h("button", {
            cls: state.topoWindow === w ? "btn btn-primary" : "btn", type: "button", text: w,
            "aria-pressed": state.topoWindow === w ? "true" : "false",
            on: {
              click: function () {
                state.topoWindow = w;
                loadTopology().then(render);
              }
            }
          }));
        });
      }
    }
  }

  /* --------------------------------------------------------------- render */

  function renderBody() {
    var view = $("view");
    var scrollTop = view.scrollTop;
    var scrollLeft = view.scrollLeft;
    var tblWrap = view.querySelector(".tblwrap");
    var tblScrollLeft = tblWrap ? tblWrap.scrollLeft : 0;

    /* Several sections reuse their filter input across rebuilds precisely so
       typing survives, but clear(view) detaches it and re-appends it, and
       detaching a focused element blurs it - the caret was kept and the focus
       was not, so the next keystroke went to the document instead of the box
       the operator was typing in. Reinstating focus on the same node
       afterwards is the whole fix. */
    var focused = document.activeElement;
    var refocus = focused && focused !== document.body && view.contains(focused) ? focused : null;
    var selStart = null, selEnd = null;
    if (refocus && typeof refocus.selectionStart === "number") {
      try { selStart = refocus.selectionStart; selEnd = refocus.selectionEnd; } catch (e) { selStart = null; }
    }

    if (state.section === "assets") renderAssets();
    else if (state.section === "topology") renderTopology();
    else if (state.section === "traffic") renderTraffic();
    else if (state.section === "policy") renderPolicy();
    else if (state.section === "alerts") renderAlerts();
    else if (state.section === "response") renderResponse();
    else if (state.section === "forensics") renderForensics();
    else if (state.section === "audit") renderAudit();
    else if (state.section === "access") renderAccess();
    else renderAssets();

    /* What the view now holds, so a guard that skips a redundant rebuild can
       tell "the poll came round again" from "the operator navigated here". */
    view.dataset.section = state.section;

    view.scrollTop = scrollTop;
    view.scrollLeft = scrollLeft;
    if (tblScrollLeft > 0) {
      var newTbl = view.querySelector(".tblwrap");
      if (newTbl) newTbl.scrollLeft = tblScrollLeft;
    }

    if (refocus && view.contains(refocus) && document.activeElement !== refocus) {
      try {
        refocus.focus();
        if (selStart !== null) refocus.setSelectionRange(selStart, selEnd);
      } catch (e) { /* not every focusable element has a selection */ }
    }

    Array.prototype.forEach.call(document.querySelectorAll(".rail-btn"), function (b) {
      b.setAttribute("aria-current", b.getAttribute("data-section") === state.section ? "true" : "false");
    });
  }

  function render() {
    renderTopbar();
    renderStrip();
    renderBody();
    if (routeEl) renderRoute();
    if (drawerEl) renderDrawer();
  }

  function go(section) {
    if (section === "discovery") section = "assets";
    state.section = section;
    closeAllSheets();
    closeRoute();
    closeDrawer();
    syncURL(true);
    render();
    refresh();
  }

  /* ----------------------------------------------------------------- load */

  function loadTopology() {
    return request("/api/v1/topology/graph?window=" + encodeURIComponent(state.topoWindow))
      .then(function (d) { state.topology = d || null; })
      .catch(function () { state.topology = null; });
  }

  function refresh() {
    if (state.refreshing) {
      state.queuedRefresh = true;
      return Promise.resolve();
    }
    state.refreshing = true;
    state.queuedRefresh = false;

    var af = state.alertsFilter || { page: 1, limit: 50 };
    var offset = (af.page - 1) * af.limit;
    var aParams = "?limit=" + af.limit + "&offset=" + offset;
    if (af.unacknowledged_only) aParams += "&unacknowledged_only=true";
    if (af.severity) aParams += "&severity=" + encodeURIComponent(af.severity);
    if (af.search) aParams += "&search=" + encodeURIComponent(af.search);
    if (af.type) aParams += "&type=" + encodeURIComponent(af.type);
    if (af.endpoint_id) aParams += "&endpoint_id=" + encodeURIComponent(af.endpoint_id);
    /* The Held tab. A learning window records findings without raising them,
       and a console that never showed them would be quiet for a reason the
       operator could not see. */
    if (af.held) aParams += "&held=true";

    var jobs = [
      request("/api/v1/hierarchy").then(function (d) { state.hierarchy = arrayOf(d); }),
      request("/api/v1/endpoints").then(function (d) { state.endpoints = arrayOf(d); }),
      request("/api/v1/assets").then(function (d) { state.assetGraph = arrayOf(d); }),
      request("/api/v1/scanner/results").then(function (d) { state.scanAssets = arrayOf(d); }),
      request("/api/v1/scanner/coverage").then(function (d) { state.coverage = d || null; }),
      request("/api/v1/locations").then(function (d) { state.locations = arrayOf(d); }),
      request("/api/v1/learning/windows").then(function (d) { state.learningWindows = arrayOf(d && d.windows); }).catch(function () { state.learningWindows = []; }),
      request("/api/v1/anomalies" + aParams).then(function (d) {
        if (d && Array.isArray(d.alerts)) {
          var lastPage = Math.max(1, Math.ceil((Number(d.total) || 0) / af.limit));
          if (af.page > lastPage) {
            af.page = lastPage;
            state.queuedRefresh = true;
          }
          state.alertsData = d;
          state.anomalies = d.alerts;
          state.unackAlertsTotal = Number(d.unacknowledged_total) || 0;
          state.heldAlertsTotal = Number(d.held_total) || 0;
        } else {
          var page = arrayOf(d);
          state.anomalies = page;
          state.unackAlertsTotal = page.filter(function (a) { return !a.acknowledged; }).length;
        }
      }),
      request("/api/v1/agents/update-status").then(function (d) { state.updateStatus = d || null; }),
      request("/api/v1/mesh/quarantined").then(function (d) { state.meshPeers = arrayOf(d); })
    ];

    if (state.section === "policy") {
      jobs.push(request("/api/v1/baseline/policies").then(function (d) {
        state.baselinePolicies = arrayOf(d && d.policies);
        state.baselineServices = arrayOf(d && d.services);
      }));
      jobs.push(request("/api/v1/detection/tuning").then(function (d) { state.tuning = d || null; }));
      jobs.push(request("/api/v1/exclusions").then(function (d) { state.exclusions = arrayOf(d); }));
      jobs.push(request("/api/v1/threatintel/iocs").then(function (d) { state.iocs = arrayOf(d); }));
    }
    /* The section id is "access" (SECTIONS, above). This read "operators"
       and `state.section` is never that, so the fetch never fired: the table
       always rendered simpleTable's generic empty string and `state.you`
       stayed "" so the "you" marker never appeared. */
    if (state.section === "access") {
      jobs.push(request("/api/v1/operators").then(function (d) {
        state.operators = arrayOf(d && d.operators);
        if (d && Array.isArray(d.roles) && d.roles.length) state.operatorRoles = d.roles;
        state.you = (d && d.you) || "";
      }));
      /* Device credentials are the other half of "who may talk to this hub",
         and the console never asked for them: an operator could see every
         human sign-in and nothing at all about the machines. Admin-only at
         the hub, and Access is already admin-only. */
      jobs.push(request("/api/v1/device-auth/credentials").then(function (d) {
        state.deviceCredentials = arrayOf(d && d.credentials);
      }).catch(function () { /* the card says the list could not be read */ }));
    }
    /* Terminal sessions are fleet state, not Response-page state. This fetch
       sat inside the `section === "response"` block, so an operator on Assets
       could not be told that a root shell was open on a host in front of them
       - the data existed and was simply not asked for unless they happened to
       be on the right page. It is cheap (one row per live session, capped at
       four per tenant) and it is what the Assets banner reads. */
    jobs.push(request("/api/v1/terminal/sessions")
      .then(function (d) {
        state.terminalSessions = arrayOf(d && d.sessions || d);
        state.terminalAvailable = true;
        if (terminalMetaSubscriber && terminalMetaSessionID) {
          for (var ti = 0; ti < state.terminalSessions.length; ti++) {
            var ts = state.terminalSessions[ti];
            if (ts && ts.session_id === terminalMetaSessionID) { terminalMetaSubscriber(ts); break; }
          }
        }
      })
      .catch(function () {
        /* responseGate answers 404 when the response feature is off, and the
           auditor role is refused outright. Either way there is nothing to
           show and nothing to report: the banner simply does not render. */
        state.terminalSessions = [];
        state.terminalAvailable = false;
      }));
    if (state.section === "response") {
      jobs.push(request("/api/v1/response/auth/status").then(function (d) { state.responseAuthStatus = d || null; }).catch(function () {}));
      jobs.push(request("/api/v1/response/jobs?limit=50").then(function (d) { state.responseJobs = arrayOf(d && d.jobs || d); }).catch(function () {}));
      jobs.push(request("/api/v1/scripts").then(function (d) { state.scripts = arrayOf(d && d.scripts || d); }).catch(function () {}));
      jobs.push(request("/api/v1/scripts/schedules").then(function (d) { state.scriptSchedules = arrayOf(d && d.schedules || d); }).catch(function () {}));
    }
    if (state.section === "forensics") {
      jobs.push(request("/api/v1/evidence/bundles").then(function (d) { state.evidenceBundles = arrayOf(d && d.bundles || d); }).catch(function () {}));
      var vulnUrl = "/api/v1/vulnerabilities";
      if (state.vulnFilterStatus) vulnUrl += "?status=" + encodeURIComponent(state.vulnFilterStatus);
      jobs.push(request(vulnUrl).then(function (d) { state.vulnerabilities = arrayOf(d && d.vulnerabilities || d); }).catch(function () {}));
      jobs.push(request("/api/v1/vulnerabilities/snapshots/active").then(function (d) { state.activeSnapshot = (d && d.snapshot) || null; }).catch(function () { state.activeSnapshot = null; }));
    }
    if (state.section === "audit") {
      jobs.push(request("/api/v1/audit/logs").then(function (d) { state.audit = arrayOf(d); }));
      jobs.push(request("/api/v1/events?limit=200").then(function (d) { state.events = arrayOf(d); }));
    }
    if (state.section === "traffic") {
      var tf = state.trafficFilter || { range: "1h" };
      var qs = "?range=" + encodeURIComponent(tf.range || "1h");
      if (tf.endpoint_id) qs += "&endpoint_id=" + encodeURIComponent(tf.endpoint_id);
      if (tf.src_ip) qs += "&src_ip=" + encodeURIComponent(tf.src_ip);
      if (tf.dst_ip) qs += "&dst_ip=" + encodeURIComponent(tf.dst_ip);
      if (tf.process) qs += "&process=" + encodeURIComponent(tf.process);
      if (tf.domain) qs += "&domain=" + encodeURIComponent(tf.domain);
      if (tf.country) qs += "&country=" + encodeURIComponent(tf.country);
      if (tf.protocol) qs += "&protocol=" + encodeURIComponent(tf.protocol);
      if (tf.port) qs += "&port=" + encodeURIComponent(tf.port);
      if (tf.direction) qs += "&direction=" + encodeURIComponent(tf.direction);
      if (tf.action) qs += "&action=" + encodeURIComponent(tf.action);
      if (tf.hash) qs += "&hash=" + encodeURIComponent(tf.hash);
      if (tf.user) qs += "&user=" + encodeURIComponent(tf.user);
      if (tf.attribution) qs += "&attribution=" + encodeURIComponent(tf.attribution);
      if (tf.measured_only) qs += "&measured_only=true";
      if (tf.cursor) qs += "&cursor=" + encodeURIComponent(tf.cursor);

      jobs.push(request("/api/v1/traffic/overview" + qs).then(function (d) { state.trafficOverview = d || null; }));
      jobs.push(request("/api/v1/traffic/flows" + qs).then(function (d) { state.trafficFlows = d || null; }));
      jobs.push(request("/api/v1/dns/status").then(function (d) { state.dnsStatus = d || null; }));
      jobs.push(request("/api/v1/dns/events?limit=40").then(function (d) { state.dnsEvents = arrayOf(d && d.events); }));
      /* The sinkhole's own rules, beside the queries they decided. This was
         guarded on `state.section === "dns"`, and there is no dns section, so
         the hub's rule list was fetched by nobody and rendered by nobody. */
      jobs.push(request("/api/v1/dns/policy").then(function (d) { state.dnsPolicy = arrayOf(d && d.rules); }).catch(function () {}));
      /* The whole analytics summary existed in this file only as a demo
         fixture: the hub computes a diurnal baseline, a live diurnal curve,
         the top talkers by volume and a per-country breakdown with threat
         counts, and the console read one field of it - total_blocks - from a
         state slot nothing ever filled. */
      jobs.push(request("/api/v1/analytics/summary").then(function (d) { state.analytics = d || null; }).catch(function () {}));
    }
    if (state.section === "topology") jobs.push(loadTopology());

    if (state.routeKey && state.assetByKey[state.routeKey] && state.assetByKey[state.routeKey].endpoint) {
      var openEp = state.assetByKey[state.routeKey].endpoint.id;
      jobs.push(request("/api/v1/baseline/endpoint?endpoint_id=" + encodeURIComponent(openEp))
        .then(function (d) { state.baselineByEndpoint[openEp] = d || {}; }));
      if (!state.baselineServices.length) {
        jobs.push(request("/api/v1/baseline/catalogue").then(function (d) { state.baselineServices = arrayOf(d && d.services); }));
      }
    }

    /* One failure among fourteen concurrent requests used to pin the health
       pip to "Hub unreachable" for the life of the page: `lastError` was set
       here and cleared nowhere. A cycle in which nothing failed is the
       evidence that the hub is reachable, so that is what clears it. */
    var cycleError = "";
    return Promise.all(jobs.map(function (p) {
      return p.catch(function (e) {
        cycleError = (e && e.message) || String(e);
        return null;
      });
    })).then(function () {
      state.lastError = cycleError;
      state.loading = false;
      buildAssets();
      pushHistory(Object.assign({ total: state.assets.length }, assetStats()));
      Object.keys(state.selected).forEach(function (k) {
        if (!state.assetByKey[k]) delete state.selected[k];
      });
      if (state.expandedKey && !state.assetByKey[state.expandedKey]) state.expandedKey = "";
      if (state.cursorKey && !state.assetByKey[state.cursorKey]) state.cursorKey = "";
      if (state.routeKey && !state.assetByKey[state.routeKey]) closeRoute();

      /* Do not rebuild the view out from under someone who is typing or has
         text selected - but do keep saying that the data behind it is moving.
         The old guard returned here with no indication at all, so a console
         with an open terminal (xterm focuses a hidden <textarea>, which this
         sees as an input) froze silently for as long as the shell was open
         and looked like a hub that had stopped answering. */
      var sel = window.getSelection ? window.getSelection() : null;
      var hasActiveTextSelection = sel && !sel.isCollapsed && sel.toString().length > 0;
      var ae = document.activeElement;
      var isInputFocused = ae && (
        ae.tagName === "INPUT" ||
        ae.tagName === "TEXTAREA" ||
        ae.isContentEditable ||
        ae.tagName === "SELECT" // an open <select> is destroyed by a rebuild too
      );
      var dragging = !!state.pointerDragging;
      if (hasActiveTextSelection || isInputFocused || dragging) {
        updateCrumb();
        renderStrip();
        var alertBadge = $("rail-alert-badge");
        if (alertBadge) alertBadge.textContent = state.unackAlertsTotal || 0;
        setStale(true);
        return;
      }

      setStale(false);
      render();
    }).finally(function () {
      state.refreshing = false;
      if (state.queuedRefresh) {
        state.queuedRefresh = false;
        refresh();
      }
    });
  }

  /* ------------------------------------------------------------------ init */

  function init() {
    var params = new URLSearchParams(window.location.search);
    state.demo = params.get("demo") === "true" ||
      window.location.hash === "#demo" ||
      readStore("ominull.demo", "false") === "true";

    applyTheme(readStore("ominull.theme", DEFAULT_THEME), false);

    $("omni-kbd").textContent = MOD_LABEL;
    $("omni").addEventListener("click", openPalette);

    var sweepBtn = $("topbar-sweep-btn");
    if (sweepBtn) sweepBtn.addEventListener("click", openSweepModal);

    var installBtn = $("topbar-install-btn");
    if (installBtn) installBtn.addEventListener("click", function () { openInstallerSheet({ platform: "linux" }); });

    var avatarBtn = $("user-avatar-btn");
    if (avatarBtn) {
      var opName = state.you || OPERATOR || "admin";
      var initial = (opName[0] || "A").toUpperCase();
      var avInit = $("avatar-initial");
      if (avInit) avInit.textContent = initial;

      avatarBtn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (accountPop) closeAccountPop();
        else openAccountPop();
      });
    }

    if (IS_ADMIN) $("rail-access").removeAttribute("hidden");

    Array.prototype.forEach.call(document.querySelectorAll(".rail-btn"), function (b) {
      b.addEventListener("click", function () { go(b.getAttribute("data-section")); });
    });

    if (state.demo) toast("Demo mode \u2014 synthetic fleet, no live hub data", "warn");
    if (READ_ONLY) toast("Read-only role \u2014 the hub refuses any action taken from this console", "warn");

    var respBtn = $("topbar-response-btn");
    if (respBtn) {
      respBtn.addEventListener("click", function () {
        if (state.responseSession) {
          openResponseControllerSheet();
        } else {
          openUnlockResponseSheet();
        }
      });
      updateResponseButton();
    }
    setInterval(updateResponseTimer, 1000);

    /* Twenty-five window.__* handles used to ship to production, among them
       __responseCrypto.signActionProof - the primitive that mints response
       authorisations. Anything that got script execution in this page was
       handed a signing oracle and a direct call into every destructive sheet.
       Nothing in the console reads them; they were a debugging convenience. */

    if ("serviceWorker" in navigator && !state.demo) {
      window.addEventListener("load", function () {
        navigator.serviceWorker.register("/sw.js").catch(function () {});
      });
    }

    /* A hidden tab is nine unconditional requests every five seconds against
       a hub that nobody is looking at. Pause while hidden and refresh once on
       return, so coming back shows current data rather than whatever was on
       screen when the tab was backgrounded. */
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") refresh();
    });

    /* A topology node drag lasting longer than the poll interval was destroyed
       mid-gesture by the rebuild. The guard in refresh() knows about this. */
    document.addEventListener("pointerdown", function () { state.pointerDragging = true; }, true);
    document.addEventListener("pointerup", function () { state.pointerDragging = false; }, true);
    document.addEventListener("pointercancel", function () { state.pointerDragging = false; }, true);

    /* Address first, then paint: restoreView decides which section render()
       is about to draw, so doing it afterwards would flash Assets. */
    suppressHistory = true;
    restoreView();
    suppressHistory = false;
    syncURL(false);

    window.addEventListener("popstate", function (e) {
      /* Back and Forward move the console, not the browser off it. */
      suppressHistory = true;
      closeAllSheets();
      closeDrawer();
      applyURLState(e.state || decodeURLState(location.hash) || { section: "assets" });
      suppressHistory = false;
      render();
      if (state.routeKey) renderRoute();
      refresh();
    });

    render();
    refresh();
    setInterval(function () {
      if (document.visibilityState === "hidden") return;
      refresh();
    }, 5000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
