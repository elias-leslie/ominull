/* Ominull console.
 *
 * Invariants this file exists to hold:
 *   - No inline style attributes. Anything data-driven is SVG geometry or a
 *     data-* attribute the stylesheet selects on. A `style=` here would be a
 *     colour that the theme switcher cannot reach.
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
    { id: "discovery", label: "Discovery" },
    { id: "topology", label: "Topology" },
    { id: "traffic", label: "Traffic" },
    { id: "policy", label: "Policy" },
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

  /* Engine label from the decorated driver version an agent reports, e.g.
     "1.1.0 (WFP Callout)" -> "WFP Callout". */
  function engineOf(v) {
    var m = /\(([^)]+)\)/.exec(String(v || ""));
    return m ? m[1] : "";
  }

  function osFamily(os) {
    var l = String(os || "").toLowerCase();
    if (l.indexOf("windows") >= 0) return "windows";
    if (l.indexOf("mac") >= 0 || l.indexOf("darwin") >= 0) return "macos";
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
    inference: null,
    coverage: null,
    anomalies: [],
    // True when the last fetch came back a full page, so the count on the
    // badge is a floor rather than a total.
    anomaliesCapped: false,
    updateStatus: null,
    meshPeers: [],
    policyGroups: [],
    exclusions: [],
    iocs: [],
    audit: [],
    operators: [],
    operatorRoles: ["admin", "analyst", "auditor"],
    you: "",
    events: [],
    analytics: null,
    topology: null,
    topoWindow: "24h",

    assets: [],
    assetByKey: {},

    filters: {},
    query: "",
    selected: {},
    cursorKey: "",
    expandedKey: "",
    collapsedGroups: {},
    routeKey: "",

    topoSelected: "",
    topoEdgeSelected: "",
    chat: [],
    chatBusy: false,
    statHistory: {},
    scanJob: null
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
          var msg = "";
          try { msg = (JSON.parse(t) || {}).error || ""; } catch (e) { msg = ""; }
          if (!msg) msg = (t || "").slice(0, 200);
          throw new Error(msg || "HTTP " + res.status);
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
  function demoData() {
    var now = new Date().toISOString();
    var mins = function (m) { return new Date(Date.now() - m * 60000).toISOString(); };

    var endpoints = [
      { id: "win11-corp-exec", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "corp-win11-exec", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.15", mac: "00:1A:2B:3C:4D:5E", role_tag: "workstation", installed_software: "Ominull WFP Agent v1.1.0, PowerShell 7.4", driver_version: "1.1.0 (WFP Callout)", status: "online", is_isolated: true, last_seen_at: now, created_at: "2026-08-20T10:00:00Z" },
      { id: "mac-eng-lead", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "mac-eng-lead", os: "macOS Sonoma 14.8 (x86_64)", ip: "10.0.4.88", mac: "3C:22:FB:11:22:33", role_tag: "workstation", installed_software: "Ominull PF Engine v1.1.0, Zsh 5.9", driver_version: "1.1.0 (PF)", status: "online", is_isolated: false, last_seen_at: mins(0.1), created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-dmz-web-01", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "dmz-web-01", os: "Debian 12 Bookworm (x86_64)", ip: "10.0.4.20", mac: "00:50:56:A1:B2:C3", role_tag: "web-server", installed_software: "Ominull eBPF Daemon v1.1.0, Nginx 1.26", driver_version: "1.1.0 (eBPF/TC)", status: "online", is_isolated: false, last_seen_at: mins(0.2), created_at: "2026-08-20T10:00:00Z" },
      { id: "win11-fin-11", tenant_id: "corp-default", location_id: "loc-hq", location_name: "Corporate HQ LAN", hostname: "corp-win11-fin", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.31", mac: "00:1A:2B:99:88:77", role_tag: "workstation", installed_software: "Ominull WFP Agent v1.0.0", driver_version: "1.0.0 (WFP Callout)", status: "offline", is_isolated: false, last_seen_at: mins(134), created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-prod-db-01", tenant_id: "corp-default", location_id: "loc-cloud", location_name: "AWS Production VPC", hostname: "prod-db-01", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.4", mac: "02:42:AC:11:00:02", role_tag: "db-server", installed_software: "Ominull eBPF Daemon v1.0.0, PostgreSQL 16", driver_version: "1.0.0 (eBPF/TC)", status: "online", is_isolated: false, last_seen_at: mins(0.05), created_at: "2026-08-20T10:00:00Z" },
      { id: "linux-prod-api-02", tenant_id: "corp-default", location_id: "loc-cloud", location_name: "AWS Production VPC", hostname: "prod-api-02", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.9", mac: "02:42:AC:11:00:09", role_tag: "app-server", installed_software: "Ominull eBPF Daemon v1.1.0", driver_version: "1.1.0 (eBPF/TC)", status: "online", is_isolated: false, last_seen_at: mins(0.15), created_at: "2026-08-21T10:00:00Z" },
      { id: "win11-branch-kiosk", tenant_id: "harbour-health", location_id: "loc-branch", location_name: "Branch Clinic", hostname: "branch-kiosk-19", os: "Windows 11 IoT Enterprise (x86_64)", ip: "10.0.4.44", mac: "00:1A:2B:44:44:44", role_tag: "kiosk", installed_software: "Ominull WFP Agent v1.1.0", driver_version: "1.1.0 (WFP Callout)", status: "online", is_isolated: false, last_seen_at: mins(0.3), created_at: "2026-08-22T10:00:00Z" },
      { id: "linux-branch-nvr", tenant_id: "harbour-health", location_id: "loc-branch", location_name: "Branch Clinic", hostname: "branch-nvr-01", os: "Debian 12 Bookworm (aarch64)", ip: "10.0.4.46", mac: "00:50:56:46:46:46", role_tag: "recorder", installed_software: "Ominull eBPF Daemon v1.0.0", driver_version: "1.0.0 (eBPF/TC)", status: "online", is_isolated: false, last_seen_at: mins(0.4), created_at: "2026-08-22T10:00:00Z" }
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
      { ip: "10.0.4.1", mac: "00:00:0C:9F:F0:01", vendor: "Cisco Systems", hostname: "core-gateway", os_guess: "Cisco IOS-XE Gateway", category: "Router / Firewall", confidence: 0.95, ttl: 255, app_delta_ms: 0.8, is_managed: false, agent_endpoint_id: "", risk_score: "LOW", weakpoints: [], last_seen: mins(2), open_ports: [{ port: 22, protocol: "tcp", service: "ssh", risk_level: "LOW" }, { port: 443, protocol: "tcp", service: "https", risk_level: "LOW" }] },
      { ip: "10.0.4.10", mac: "00:1A:2B:0A:0A:0A", vendor: "Dell Inc.", hostname: "", os_guess: "Windows Server", category: "Server", confidence: 0.71, ttl: 128, app_delta_ms: 1.0, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["RDP reachable from three subnets"], last_seen: mins(0.2), open_ports: [{ port: 53, protocol: "tcp", service: "dns", risk_level: "LOW" }, { port: 88, protocol: "tcp", service: "kerberos", risk_level: "LOW" }, { port: 135, protocol: "tcp", service: "rpc", risk_level: "LOW" }, { port: 389, protocol: "tcp", service: "ldap", risk_level: "LOW" }, { port: 445, protocol: "tcp", service: "smb", risk_level: "HIGH" }, { port: 636, protocol: "tcp", service: "ldaps", risk_level: "LOW" }, { port: 3389, protocol: "tcp", service: "rdp", risk_level: "HIGH" }] },
      { ip: "10.0.4.15", mac: "00:1A:2B:3C:4D:5E", vendor: "Dell Inc.", hostname: "corp-win11-exec", os_guess: "Windows 11 Enterprise (x86_64)", category: "Workstation", confidence: 0.98, ttl: 128, app_delta_ms: 1.1, is_managed: true, agent_endpoint_id: "win11-corp-exec", risk_score: "LOW", weakpoints: [], last_seen: mins(1), open_ports: [{ port: 135, protocol: "tcp", service: "epmap", risk_level: "LOW" }, { port: 445, protocol: "tcp", service: "microsoft-ds", risk_level: "LOW" }] },
      { ip: "10.0.4.20", mac: "00:50:56:A1:B2:C3", vendor: "VMware, Inc.", hostname: "dmz-web-01", os_guess: "Linux (generic)", category: "Server", confidence: 0.62, ttl: 64, app_delta_ms: 1.2, is_managed: true, agent_endpoint_id: "linux-dmz-web-01", risk_score: "LOW", weakpoints: [], last_seen: mins(1), open_ports: [{ port: 80, protocol: "tcp", service: "http", risk_level: "MEDIUM" }, { port: 443, protocol: "tcp", service: "https", risk_level: "LOW" }] },
      { ip: "10.0.4.55", mac: "00:11:32:44:55:66", vendor: "Synology Inc.", hostname: "unmanaged-nas", os_guess: "Synology DiskStation DSM 7.2", category: "Storage / NAS", confidence: 0.92, ttl: 64, app_delta_ms: 1.4, is_managed: false, agent_endpoint_id: "", risk_score: "HIGH", weakpoints: ["Unencrypted HTTP administrative console (port 5000)", "SMBv1 legacy dialect enabled"], last_seen: mins(3), open_ports: [{ port: 445, protocol: "tcp", service: "smb", risk_level: "HIGH" }, { port: 5000, protocol: "tcp", service: "http", risk_level: "HIGH" }, { port: 5001, protocol: "tcp", service: "https", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.71", mac: "00:1B:A9:71:71:71", vendor: "Brother Industries", hostname: "", os_guess: "Embedded print controller", category: "Printer", confidence: 0.44, ttl: 64, app_delta_ms: 2.6, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["Unauthenticated raw print queue on 9100"], last_seen: mins(4), open_ports: [{ port: 631, protocol: "tcp", service: "ipp", risk_level: "LOW" }, { port: 9100, protocol: "tcp", service: "jetdirect", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.88", mac: "3C:22:FB:11:22:33", vendor: "Apple, Inc.", hostname: "mac-eng-lead", os_guess: "macOS", category: "Workstation", confidence: 0.81, ttl: 64, app_delta_ms: 1.0, is_managed: true, agent_endpoint_id: "mac-eng-lead", risk_score: "LOW", weakpoints: [], last_seen: mins(1), open_ports: [{ port: 22, protocol: "tcp", service: "ssh", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.99", mac: "B8:27:EB:12:34:56", vendor: "Raspberry Pi Foundation", hostname: "rogue-dev-kali", os_guess: "Kali Linux Rolling (ARM64)", category: "Shadow IT / Pentest", confidence: 0.89, ttl: 64, app_delta_ms: 2.1, is_managed: false, agent_endpoint_id: "", risk_score: "CRITICAL", weakpoints: ["Unauthorized Metasploit payload listener on port 4444", "Unmanaged shadow IT device"], last_seen: mins(0.5), open_ports: [{ port: 22, protocol: "tcp", service: "ssh", risk_level: "MEDIUM" }, { port: 4444, protocol: "tcp", service: "metasploit", risk_level: "CRITICAL" }] },
      { ip: "10.0.4.120", mac: "50:02:91:AA:BB:CC", vendor: "Samsung Electronics", hostname: "lobby-display", os_guess: "Samsung Tizen Smart Display", category: "IoT / Display", confidence: 0.88, ttl: 64, app_delta_ms: 1.9, is_managed: false, agent_endpoint_id: "", risk_score: "MEDIUM", weakpoints: ["Unauthenticated smart-display remote API on LAN"], last_seen: mins(9), open_ports: [{ port: 8001, protocol: "tcp", service: "smarttv-api", risk_level: "MEDIUM" }] },
      { ip: "10.0.4.201", mac: "", vendor: "", hostname: "", os_guess: "", category: "", confidence: 0.12, ttl: 0, app_delta_ms: 0, is_managed: false, agent_endpoint_id: "", risk_score: "LOW", weakpoints: [], last_seen: mins(62), open_ports: [] }
    ];

    var anomalies = [
      { id: "alert-dga-01", tenant_id: "corp-default", location_id: "loc-hq", endpoint_id: "win11-corp-exec", hostname: "corp-win11-exec", anomaly_type: "DGA_BEACONING", severity: "CRITICAL", title: "Suspicious DGA / high-entropy domain", description: "Process powershell.exe queried 142 high-entropy domains in 60s; 138 returned NXDOMAIN.", details: "Shannon entropy 4.02 bits/byte | destination xj829vbnpqlmz019.xyz:443", process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", dst_ip: "198.51.100.22", dst_port: 443, timestamp: mins(4), acknowledged: false },
      { id: "alert-offhours-02", tenant_id: "corp-default", location_id: "loc-hq", endpoint_id: "win11-corp-exec", hostname: "corp-win11-exec", anomaly_type: "NOVEL_PROCESS_EGRESS", severity: "HIGH", title: "Off-hours interactive shell egress", description: "Interactive shell opened an external session at 02:14 UTC.", details: "explorer.exe -> powershell.exe -> 198.51.100.22:8443", process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", dst_ip: "198.51.100.22", dst_port: 8443, timestamp: mins(38), acknowledged: false },
      { id: "alert-fanout-03", tenant_id: "corp-default", location_id: "loc-hq", endpoint_id: "mac-eng-lead", hostname: "mac-eng-lead", anomaly_type: "UNUSUAL_PORT", severity: "HIGH", title: "Internal subnet fan-out / port sweep", description: "Host probed 8 distinct internal addresses within a 60s window.", details: "Probed 445, 3389 across 10.0.4.0/24", process_path: "/usr/bin/nmap", dst_ip: "10.0.4.0/24", dst_port: 445, timestamp: mins(51), acknowledged: false },
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

    /* What a flow-inference pass concludes over this fixture. Each rationale
       states only what the traffic actually shows: how many endpoints, from
       which processes, on which ports, and what is absent. */
    var DEMO_INFERENCES = [
      {
        ip: "10.0.4.10", role: "domain-controller", label: "Domain controller", confidence: 0.86,
        rationale: "6 agented endpoints across 2 locations, from lsass.exe and svchost.exe, on 389/88/445/135; fan-in without any fan-out; nothing else on 10.0.4.0/24 answers 88."
      },
      {
        ip: "10.0.4.12", role: "domain-controller", label: "Domain controller", confidence: 0.86,
        rationale: "5 agented endpoints across 2 locations, from lsass.exe and svchost.exe, on 88/389/135; fan-in without any fan-out; no probe has ever reached this address and no agent reports from it."
      },
      {
        ip: "10.0.4.55", role: "file-server", label: "File server", confidence: 0.74,
        rationale: "4 agented endpoints, on 445; fan-in without any fan-out; 620.0 MB across 3120 flows."
      },
      {
        ip: "10.0.4.71", role: "print-server", label: "Print server", confidence: 0.65,
        rationale: "3 agented endpoints, on 9100/631; nothing else on 10.0.4.0/24 answers 9100."
      }
    ];

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
    topoNodes.push({ id: "10.0.4.10", label: "10.0.4.10", type: "unmanaged", ip: "10.0.4.10", os: "Windows Server", role: "domain-controller", risk: "MEDIUM", is_isolated: false, group: "Server", evidence: ["scan", "inferred"], confidence: 0.86, rationale: DEMO_INFERENCES[0].rationale, quiet: false });
    topoNodes.push({ id: "10.0.4.12", label: "10.0.4.12", type: "unmanaged", ip: "10.0.4.12", os: "", role: "domain-controller", risk: "MEDIUM", is_isolated: false, group: "Seen in traffic only", evidence: ["inferred"], confidence: 0.86, rationale: DEMO_INFERENCES[1].rationale, quiet: false });
    topoNodes.push({ id: "10.0.4.55", label: "unmanaged-nas", type: "unmanaged", ip: "10.0.4.55", os: "Synology DiskStation DSM 7.2", role: "file-server", risk: "HIGH", is_isolated: false, group: "Storage / NAS", evidence: ["scan", "inferred"], confidence: 0.74, rationale: DEMO_INFERENCES[2].rationale, quiet: false });
    topoNodes.push({ id: "10.0.4.71", label: "10.0.4.71", type: "unmanaged", ip: "10.0.4.71", os: "Embedded print controller", role: "print-server", risk: "MEDIUM", is_isolated: false, group: "Printer", evidence: ["scan", "inferred"], confidence: 0.65, rationale: DEMO_INFERENCES[3].rationale, quiet: true });
    topoNodes.push({ id: "10.0.4.99", label: "rogue-dev-kali", type: "unmanaged", ip: "10.0.4.99", os: "Kali Linux Rolling (ARM64)", role: "Shadow IT / Pentest", risk: "CRITICAL", is_isolated: false, group: "Shadow IT / Pentest", evidence: ["scan"], quiet: false });
    topoNodes.push({ id: "10.0.4.120", label: "lobby-display", type: "unmanaged", ip: "10.0.4.120", os: "Samsung Tizen Smart Display", role: "IoT / Display", risk: "MEDIUM", is_isolated: false, group: "IoT / Display", evidence: ["scan"], quiet: true });
    topoNodes.push({ id: "198.51.100.22", label: "198.51.100.22", type: "threat", ip: "198.51.100.22", os: "", role: "unknown", risk: "CRITICAL", is_isolated: false, group: "Blocked destination", evidence: [], quiet: false });

    /* The demo asset graph is generated from the same two fixtures the live
       hub merges, plus the inferences flow alone supports. 10.0.4.12 exists
       in no scan and runs no agent: it is named entirely by the shape of the
       traffic other hosts send it. */
    function demoClaim(field, source, value, confidence, rationale, seen) {
      return { field: field, source: source, value: value, confidence: confidence, rationale: rationale || "", observed_at: seen, winner: false };
    }

    /* Same rule as the hub: highest confidence wins per field, operator and
       agent claims outrank scan and inference outright. */
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

      /* A host with no agent and no scan, named from flow alone. */
      out.push(demoMergeAsset({
        id: "asset-ip-10-0-4-12-10-0-4-0-24", identity_kind: "ip", identity_value: "10.0.4.12|10.0.4.0/24",
        agent_endpoint_id: "", tenant_id: "default", location_id: "",
        ip: "10.0.4.12", mac: "", subnet: "10.0.4.0/24",
        first_seen_at: mins(300), last_seen_at: mins(0.4), ports: [],
        claims: [demoClaim("role", "inferred", "domain-controller", 0.86, DEMO_INFERENCES[1].rationale, mins(0.4))]
      }));

      out.forEach(function (a) {
        DEMO_INFERENCES.forEach(function (inf) {
          if (a.ip !== inf.ip) return;
          if (a.claims.some(function (c) { return c.source === "inferred" && c.field === "role"; })) return;
          a.claims.push(demoClaim("role", "inferred", inf.role, inf.confidence, inf.rationale, a.last_seen_at));
          demoMergeAsset(a);
        });
      });
      return out;
    }

    var topoEdges = [
      { id: "e1", source: "10.0.4.15", target: "10.0.4.10", protocol: "tcp", port: 389, flow_count: 2140, total_bytes: 42000000, verdict: "clean", last_seen: now },
      { id: "e2", source: "10.0.4.88", target: "10.0.4.10", protocol: "tcp", port: 88, flow_count: 980, total_bytes: 12000000, verdict: "clean", last_seen: now },
      { id: "e3", source: "10.0.4.20", target: "10.0.4.1", protocol: "tcp", port: 443, flow_count: 18200, total_bytes: 1420000000, verdict: "clean", last_seen: now },
      { id: "e4", source: "10.0.4.44", target: "10.0.4.10", protocol: "tcp", port: 445, flow_count: 640, total_bytes: 8100000, verdict: "clean", last_seen: now },
      { id: "e5", source: "10.0.4.46", target: "10.0.4.55", protocol: "tcp", port: 445, flow_count: 3120, total_bytes: 620000000, verdict: "clean", last_seen: now },
      { id: "e6", source: "10.0.4.15", target: "198.51.100.22", protocol: "tcp", port: 443, flow_count: 142, total_bytes: 810000, verdict: "blocked", last_seen: now },
      { id: "e7", source: "10.0.4.88", target: "10.0.4.99", protocol: "tcp", port: 4444, flow_count: 61, total_bytes: 190000, verdict: "anomalous", last_seen: now },
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
      e.ports = [{ port: e.port, protocol: (e.protocol || "tcp").toUpperCase(), flow_count: e.flow_count, total_bytes: e.total_bytes, verdict: e.verdict }];
    });
    topoEdges[0].ports.push({ port: 445, protocol: "TCP", flow_count: 610, total_bytes: 7400000, verdict: "clean" });
    topoEdges[0].ports.push({ port: 135, protocol: "TCP", flow_count: 240, total_bytes: 1100000, verdict: "clean" });
    topoEdges[0].ports.push({ port: 88, protocol: "TCP", flow_count: 1290, total_bytes: 6800000, verdict: "clean" });

    return {
      "/api/v1/hierarchy": hierarchy,
      "/api/v1/endpoints": endpoints,
      "/api/v1/assets": demoAssetGraph(),
      "/api/v1/inference/status": {
        last_run: mins(1), inferred_count: DEMO_INFERENCES.length, window: "24h0m0s",
        interval: "5m0s", last_error: "", max_confidence: 0.9, results: DEMO_INFERENCES
      },
      "/api/v1/scanner/results": scan,
      "/api/v1/scanner/coverage": {
        total_discovered: scan.length, total_managed: 4, total_unmanaged: scan.length - 4,
        coverage_percent: Math.round((4 / scan.length) * 1000) / 10, critical_risks: 1, high_risks: 1
      },
      "/api/v1/anomalies": anomalies,
      "/api/v1/agents/update-status": {
        latest_version: "1.1.0",
        outdated: [
          { endpoint_id: "linux-prod-db-01", hostname: "prod-db-01", os: "Linux 6.8.0-40-generic (x86_64)", ip: "172.16.10.4", driver_version: "1.0.0 (eBPF/TC)" },
          { endpoint_id: "win11-fin-11", hostname: "corp-win11-fin", os: "Windows 11 Enterprise (x86_64)", ip: "10.0.4.31", driver_version: "1.0.0 (WFP Callout)" },
          { endpoint_id: "linux-branch-nvr", hostname: "branch-nvr-01", os: "Debian 12 Bookworm (aarch64)", ip: "10.0.4.46", driver_version: "1.0.0 (eBPF/TC)" }
        ],
        pending: []
      },
      "/api/v1/mesh/quarantined": [
        { id: "mq-01", target_ip: "10.0.4.99", target_mac: "B8:27:EB:12:34:56", subnet: "10.0.4.0/24", reason: "Metasploit listener on 4444", active: true, created_at: mins(22) }
      ],
      "/api/v1/policy-groups": [
        { id: "pg-default-zt", tenant_id: "corp-default", scope: "global", scope_value: "", name: "Corporate zero-trust default", description: "Baseline egress control for every managed endpoint", schedule: "all", criteria: "{}", action: "BLOCK", rule_type: "port", rule_value: "", port: 445, protocol: "tcp", active: true, created_at: "2026-08-20T10:00:00Z" },
        { id: "pg-quarantine-drop", tenant_id: "corp-default", scope: "global", scope_value: "", name: "Emergency lateral quarantine", description: "Drops peer-to-peer traffic for quarantined hosts", schedule: "all", criteria: "{}", action: "ISOLATE", rule_type: "cidr", rule_value: "10.0.4.0/24", port: 0, protocol: "any", active: true, created_at: "2026-08-21T10:00:00Z" },
        { id: "pg-offhours", tenant_id: "corp-default", scope: "client", scope_value: "corp-default", name: "Off-hours shell egress alert", description: "Alerts on interactive shells opening external sessions outside business hours", schedule: "off_hours", criteria: "{\"process\":\"powershell\"}", action: "ALERT", rule_type: "process", rule_value: "powershell.exe", port: 0, protocol: "tcp", active: false, created_at: "2026-08-23T10:00:00Z" }
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
        { id: "a-1", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "ISOLATE_HOST", resource: "win11-corp-exec", details: "Auto-isolated by detector: DGA beaconing", ip_address: "10.0.4.58", timestamp: mins(4) },
        { id: "a-2", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "MESH_QUARANTINE", resource: "10.0.4.99", details: "Metasploit listener on 4444", ip_address: "10.0.4.58", timestamp: mins(22) },
        { id: "a-3", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "SYNC_TI", resource: "threatintel", details: "4 indicators refreshed from 3 feeds", ip_address: "10.0.4.58", timestamp: mins(60) },
        { id: "a-4", tenant_id: "corp-default", user_id: "u-admin", username: "admin", action: "ADD_RULE", resource: "pg-offhours", details: "Off-hours shell egress alert created", ip_address: "10.0.4.58", timestamp: mins(180) }
      ],
      "/api/v1/events": [
        { id: 9001, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(4), layer: "ALE_AUTH_CONNECT", action: "BLOCK", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "198.51.100.22", src_port: 52140, dst_port: 443, bytes_in: 0, bytes_out: 1240, country: "NL", process_path: "powershell.exe", process_id: 4812, domain: "xj829vbnpqlmz019.xyz" },
        { id: 9002, tenant_id: "corp-default", endpoint_id: "mac-eng-lead", timestamp: mins(51), layer: "PF_OUT", action: "BLOCK", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.88", dst_ip: "10.0.4.99", src_port: 61022, dst_port: 4444, bytes_in: 0, bytes_out: 480, country: "", process_path: "/usr/bin/nmap", process_id: 9911 },
        { id: 9003, tenant_id: "corp-default", endpoint_id: "linux-dmz-web-01", timestamp: mins(2), layer: "TC_EGRESS", action: "PERMIT", direction: "INBOUND", protocol: 6, src_ip: "203.0.113.9", dst_ip: "10.0.4.20", src_port: 44120, dst_port: 443, bytes_in: 8400, bytes_out: 142000, country: "DE", process_path: "/usr/sbin/nginx", process_id: 1220 },
        { id: 9004, tenant_id: "corp-default", endpoint_id: "linux-prod-db-01", timestamp: mins(96), layer: "TC_EGRESS", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "172.16.10.4", dst_ip: "203.0.113.51", src_port: 40122, dst_port: 5432, bytes_in: 210000, bytes_out: 4200000000, country: "US", process_path: "/usr/lib/postgresql/16/bin/postgres", process_id: 780 },
        /* Fan-in to 10.0.4.10 from several agented endpoints on directory
           ports. This is the shape Pass 2 reads as "domain controller"; in
           Pass 1 it is visible as flow, not yet as an inference. */
        { id: 9005, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.10", src_port: 49812, dst_port: 389, bytes_in: 21400, bytes_out: 9200, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9006, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1.2), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.10", src_port: 49813, dst_port: 88, bytes_in: 4100, bytes_out: 2600, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9007, tenant_id: "corp-default", endpoint_id: "win11-branch-kiosk", timestamp: mins(2), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.44", dst_ip: "10.0.4.10", src_port: 51002, dst_port: 445, bytes_in: 812000, bytes_out: 44000, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 1044 },
        { id: 9008, tenant_id: "corp-default", endpoint_id: "win11-fin-11", timestamp: mins(140), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.31", dst_ip: "10.0.4.10", src_port: 50221, dst_port: 135, bytes_in: 9400, bytes_out: 3100, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 998 },
        { id: 9009, tenant_id: "corp-default", endpoint_id: "mac-eng-lead", timestamp: mins(3), layer: "PF_OUT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.88", dst_ip: "10.0.4.10", src_port: 61140, dst_port: 389, bytes_in: 15200, bytes_out: 6100, country: "", process_path: "/usr/libexec/opendirectoryd", process_id: 221 },
        { id: 9010, tenant_id: "corp-default", endpoint_id: "win11-corp-exec", timestamp: mins(1.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.15", dst_ip: "10.0.4.12", src_port: 49901, dst_port: 88, bytes_in: 8400, bytes_out: 3100, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 712 },
        { id: 9011, tenant_id: "corp-default", endpoint_id: "win11-fin-11", timestamp: mins(2.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.31", dst_ip: "10.0.4.12", src_port: 50120, dst_port: 389, bytes_in: 6200, bytes_out: 2400, country: "", process_path: "C:\\Windows\\System32\\lsass.exe", process_id: 704 },
        { id: 9012, tenant_id: "corp-default", endpoint_id: "win11-branch-kiosk", timestamp: mins(4.5), layer: "ALE_AUTH_CONNECT", action: "PERMIT", direction: "OUTBOUND", protocol: 6, src_ip: "10.0.4.44", dst_ip: "10.0.4.12", src_port: 51002, dst_port: 135, bytes_in: 3100, bytes_out: 1400, country: "", process_path: "C:\\Windows\\System32\\svchost.exe", process_id: 988 }
      ],
      "/api/v1/analytics/summary": {
        total_bytes_in: 3120000000, total_bytes_out: 7480000000, total_events: 48210,
        total_blocks: 318, total_permits: 47892,
        countries: { US: 31200, DE: 4210, NL: 980, SG: 640, GB: 410 },
        top_processes: {},
        severity_counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 0 },
        enforcement_counts: { "WFP Callout": 3, "eBPF/TC": 4, PF: 1 },
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
          inferred_nodes_count: topoNodes.filter(function (n) { return (n.evidence || []).indexOf("inferred") >= 0; }).length,
          window_label: "24h"
        }
      },
      "/api/v1/copilot/config": { provider: "ollama", ollama_model: "llama3.2" }
    };
  }

  var DEMO_CACHE = null;

  /* The same merge rule the hub applies, so a demo correction visibly wins
     the field the way a live one would. */
  function DEMO_REMERGE(a) {
    var rank = { operator: 3, agent: 2, scan: 1, inferred: 1 };
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
        var hit = DEMO_CACHE[base];
        if (hit !== undefined) {
          resolve(hit);
          return;
        }
        resolve(base.indexOf("/coverage") >= 0 || base.indexOf("/summary") >= 0 ? {} : []);
      }, 40);
    });
  }

  /* Demo writes mutate the fixture so an isolate or an acknowledge visibly
     lands, the same way it would against a live hub. */
  function demoMutate(base, body) {
    var eps = DEMO_CACHE["/api/v1/endpoints"];
    var setIso = function (id, on) {
      eps.forEach(function (e) { if (e.id === id) e.is_isolated = on; });
      DEMO_CACHE["/api/v1/hierarchy"] = demoRebuildHierarchy();
    };
    if (base === "/api/v1/endpoints/isolate") { setIso(body && body.endpoint_id, true); return { status: "isolated" }; }
    if (base === "/api/v1/endpoints/unisolate") { setIso(body && body.endpoint_id, false); return { status: "released" }; }
    if (base === "/api/v1/endpoints/isolate-bulk") { arrayOf(body && body.endpoint_ids).forEach(function (id) { setIso(id, true); }); return { status: "isolated" }; }
    if (base === "/api/v1/endpoints/unisolate-bulk") { arrayOf(body && body.endpoint_ids).forEach(function (id) { setIso(id, false); }); return { status: "released" }; }
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
    if (base === "/api/v1/copilot/chat") {
      return {
        reply: "Severity: HIGH.\n\nThe fan-in shape on 10.0.4.10 (389/88/135/445 from lsass.exe and svchost.exe, in bursts at logon) reads as a directory server, not a workstation. corp-win11-exec is the host to look at first: it is the only endpoint with both a blocked external session and an unusual internal sweep in the same hour.\n\nRecommended order:\n  1. Keep corp-win11-exec isolated; capture the socket table before release.\n  2. Confirm 10.0.4.99 stays mesh-quarantined - the 4444 listener is still up.\n  3. Deploy an agent to 10.0.4.10 so the directory server stops being inferred.",
        timestamp: new Date().toISOString(), model: "llama3.2 (demo)", provider: "ollama"
      };
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
    if (base === "/api/v1/inference/run") {
      var st = DEMO_CACHE["/api/v1/inference/status"];
      st.last_run = new Date().toISOString();
      return { status: "completed", inferred_count: arrayOf(st.results).length, detail: st };
    }
    if (base === "/api/v1/scanner/scan") return { scan_id: "scan-demo", status: "running" };
    if (base === "/api/v1/agents/update") {
      return { desired_version: "1.1.0", scheduled: [{ endpoint_id: "linux-prod-db-01", hostname: "prod-db-01", from: "1.0.0", to: "1.1.0" }], unsupported: [{ endpoint_id: "win11-fin-11", hostname: "corp-win11-fin", os: "Windows", reason: "self-update not supported on this platform yet; use the SSH/WinRM push-deployer" }] };
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
    var slots = ["theme-sw-1", "theme-sw-2", "theme-sw-3", "theme-sw-4"];
    var roles = ["ground", "ink", "ok", "crit"];
    slots.forEach(function (id, i) {
      $(id).className = "sw sw-" + roles[i] + "-" + name;
    });
    $("theme-btn").setAttribute("title", "Theme: " + THEME_NAMES[name]);
  }

  var themePop = null;

  function closeThemePop() {
    if (themePop && themePop.parentNode) themePop.parentNode.removeChild(themePop);
    themePop = null;
    $("theme-btn").setAttribute("aria-expanded", "false");
  }

  function openThemePop() {
    closeThemePop();
    var btn = $("theme-btn");
    var pop = h("div", { cls: "theme-pop", role: "radiogroup", "aria-label": "Theme" },
      h("div", { cls: "lbl", text: "Palette" }));

    THEMES.forEach(function (t) {
      var chips = h("span", { cls: "chips" });
      ["ground", "ink", "brand", "ok", "warn", "crit"].forEach(function (role) {
        chips.appendChild(h("i", { cls: "sw-" + role + "-" + t }));
      });
      pop.appendChild(h("button", {
        cls: "theme-opt", type: "button", role: "radio",
        "aria-checked": state.theme === t ? "true" : "false",
        on: {
          click: function () {
            applyTheme(t, true);
            closeThemePop();
            toast("Theme: " + THEME_NAMES[t], "ok");
          }
        }
      }, h("span", { text: THEME_NAMES[t] }), chips));
    });

    document.body.appendChild(pop);
    var r = btn.getBoundingClientRect();
    var pr = pop.getBoundingClientRect();
    placeOverlay(pop, r.right + 8, Math.min(r.bottom - pr.height, window.innerHeight - pr.height - 8));
    themePop = pop;
    btn.setAttribute("aria-expanded", "true");
  }

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
    var inferredClaim = null;
    arrayOf(a.claims).forEach(function (c) {
      if (c.source === "scan" && (!scanClaim || (c.confidence || 0) > (scanClaim.confidence || 0))) scanClaim = c;
      if (c.source === "inferred" && (!inferredClaim || (c.confidence || 0) > (inferredClaim.confidence || 0))) inferredClaim = c;
    });
    return {
      agent: !!a.agent_endpoint_id,
      scan: claimGrade(scanClaim),
      inferred: claimGrade(inferredClaim),
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
      var inferredRole = bestClaim(a, "role", "inferred");
      var identityBits = [a.os || "Unidentified"];
      var descriptor = a.category || a.role;
      if (descriptor) identityBits.push(descriptor);

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
          : "Discovered \u2014 no client assigned",
        subnet: a.subnet || (loc ? loc.subnet_cidr : ""),
        evidence: ev,
        endpoint: ep,
        scan: scanByIP[a.ip] || null,
        claims: arrayOf(a.claims),
        role: a.role || "",
        roleConf: Number(a.role_confidence) || 0,
        rationale: a.rationale || "",
        inferredRole: inferredRole,
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
      /* An agented asset reporting under the tenant API key alone cannot be
         told from any other endpoint holding the same key. This is the number
         that has to reach zero before --client-certs required is safe. */
      keyOnly: count(function (x) { return x.evidence.agent && !(x.endpoint && x.endpoint.cert_cn); })
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
      { id: "keyonly", label: "Key only, no cert", value: stats.keyOnly, tone: stats.keyOnly ? "warn" : "" },
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

  function inferredCount() {
    return state.assets.filter(function (a) { return !!a.evidence.inferred; }).length;
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
        { label: "Coverage", value: covered ? (cov.coverage_percent || 0) + "%" : "\u2014" },
        { label: "Deduced from flow", value: String(inferredCount()) },
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
        { label: "Anomalous edges", value: String(m.anomalous_edge_count || 0), tone: m.anomalous_edge_count ? "warn" : "" }
      ];
    }
    if (state.section === "traffic") {
      var an = state.analytics || {};
      return [
        { label: "Events", value: String(an.total_events || 0) },
        { label: "Blocked", value: String(an.total_blocks || 0), tone: an.total_blocks ? "crit" : "" },
        { label: "Permitted", value: String(an.total_permits || 0) },
        { label: "Bytes in", value: bytes(an.total_bytes_in) },
        { label: "Bytes out", value: bytes(an.total_bytes_out) },
        { label: "Countries", value: String(arrayOf(an.geo_stats).length) }
      ];
    }
    if (state.section === "policy") {
      return [
        { label: "Policy groups", value: String(state.policyGroups.length) },
        { label: "Active", value: String(state.policyGroups.filter(function (g) { return g.active; }).length) },
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
    if (ctxMenu && ctxMenu.parentNode) ctxMenu.parentNode.removeChild(ctxMenu);
    ctxMenu = null;
    Array.prototype.forEach.call(document.querySelectorAll('.menu-btn[aria-expanded="true"]'), function (b) {
      b.setAttribute("aria-expanded", "false");
    });
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

  /* Actions live in a menu rather than a row of buttons because a menu grows
     with capability and a button row does not. */
  function openAssetMenu(asset, x, y, anchorBtn) {
    closeCtx();
    var agent = asset.evidence.agent;
    var menu = h("div", { cls: "ctx", role: "menu" });

    menu.appendChild(h("div", { cls: "lbl", text: "Asset" }));
    menu.appendChild(menuItem("Open full view", "i-external", "\u21b5", function () { openRoute(asset.key); }));
    menu.appendChild(menuItem("Show in topology", "i-topology", "g t", function () {
      state.topoSelected = asset.evidence.agent ? asset.key : asset.ip;
      go("topology");
    }));
    menu.appendChild(menuItem("Copy address", "i-copy", "y", function () { copyAddress(asset); }));

    menu.appendChild(h("div", { cls: "sep" }));
    menu.appendChild(h("div", { cls: "lbl", text: "Discovery" }));
    menu.appendChild(menuItem("Rescan this host", "i-refresh", "r", function () { rescan(asset); }));
    menu.appendChild(menuItem("Correct fingerprint\u2026", "i-tag", null, function () { correctFingerprint(asset); },
      { disabled: !asset.scan, why: "Needs a scan result to correct" }));

    var inferred = asset.inferredRole;
    var corrected = bestClaim({ claims: asset.claims }, "role", "operator");
    if (corrected) {
      menu.appendChild(menuItem("Withdraw role correction", "i-refresh", null, function () {
        correctAsset(asset, "role", "", "", true);
      }));
    } else if (inferred) {
      menu.appendChild(menuItem("Confirm " + roleLabel(inferred.value).toLowerCase(), "i-check", null, function () {
        correctAsset(asset, "role", inferred.value, "operator confirmed the flow inference", false);
      }));
      menu.appendChild(menuItem("Not a " + roleLabel(inferred.value).toLowerCase(), "i-close", null, function () {
        correctAsset(asset, "role", "unknown", "operator rejected the flow inference", false);
      }, { danger: true }));
    }

    menu.appendChild(h("div", { cls: "sep" }));
    menu.appendChild(h("div", { cls: "lbl", text: "Act" }));
    menu.appendChild(menuItem("Deploy agent", "i-download", "d", function () { deployAgent(asset); },
      { disabled: agent, why: "This host already runs an agent" }));

    if (agent && asset.isolated) {
      menu.appendChild(menuItem("Release host", "i-unlock", null, function () { setIsolation(asset, false); }));
    } else {
      menu.appendChild(menuItem("Isolate host", "i-lock", "i", function () { setIsolation(asset, true); },
        { danger: true, disabled: !agent, why: "Ring-0 isolation needs an agent; use mesh quarantine instead" }));
    }

    if (asset.meshed) {
      menu.appendChild(menuItem("Release from peer mesh", "i-unlock", null, function () { setMesh(asset, false); }));
    } else {
      menu.appendChild(menuItem("Quarantine via peer mesh", "i-lock", null, function () { setMesh(asset, true); },
        { danger: true, disabled: !asset.ip, why: "Needs an address" }));
    }

    document.body.appendChild(menu);
    var r = menu.getBoundingClientRect();
    placeOverlay(menu, Math.min(x, window.innerWidth - r.width - 8), Math.min(y, window.innerHeight - r.height - 8));
    ctxMenu = menu;
    if (anchorBtn) anchorBtn.setAttribute("aria-expanded", "true");
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
    var path = on ? "/api/v1/endpoints/isolate" : "/api/v1/endpoints/unisolate";
    var body = { endpoint_id: asset.endpoint.id };
    if (on) body.allow_ips = [];
    request(path, "POST", body).then(function () {
      toast((on ? "Isolated " : "Released ") + asset.name, on ? "crit" : "ok");
      refresh();
    }).catch(function (e) { toast("Isolation failed: " + e.message, "crit"); });
  }

  function setMesh(asset, on) {
    if (!asset.ip) { toast("No address for " + asset.name, "warn"); return; }
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
    var actual = window.prompt("Actual device for " + asset.ip + ":", asset.scan ? asset.scan.os_guess : "");
    if (!actual) return;
    request("/api/v1/scanner/feedback", "POST", {
      ip: asset.ip, actual_device: actual,
      vendor: asset.scan ? asset.scan.vendor : "",
      category: asset.scan ? asset.scan.category : ""
    }).then(function () {
      toast("Signature trained for " + asset.ip, "ok");
      refresh();
    }).catch(function (e) { toast("Training failed: " + e.message, "crit"); });
  }

  function deployAgent(asset) {
    if (asset.evidence.agent) { toast(asset.name + " already runs an agent", "warn"); return; }
    var user = window.prompt("SSH user for " + asset.ip + ":", "");
    if (!user) return;
    var family = osFamily(asset.scan ? asset.scan.os_guess : "") || "linux";
    request("/api/v1/deployer/push", "POST", {
      target_ip: asset.ip, username: user, os: family,
      protocol: family === "windows" ? "winrm" : "ssh"
    }).then(function (job) {
      toast("Deployment queued for " + asset.ip + (job && job.job_id ? " (" + job.job_id + ")" : ""), "ok");
    }).catch(function (e) { toast("Deploy failed: " + e.message, "crit"); });
  }

  function bulkIsolate(on) {
    var keys = selectedKeys();
    var ids = keys.map(function (k) { return state.assetByKey[k]; })
      .filter(function (a) { return a && a.endpoint; })
      .map(function (a) { return a.endpoint.id; });
    if (!ids.length) { toast("Select agented hosts first", "warn"); return; }
    var path = on ? "/api/v1/endpoints/isolate-bulk" : "/api/v1/endpoints/unisolate-bulk";
    var body = { endpoint_ids: ids };
    if (on) body.allow_ips = [];
    request(path, "POST", body).then(function () {
      toast((on ? "Isolated " : "Released ") + ids.length + " host" + (ids.length === 1 ? "" : "s"), on ? "crit" : "ok");
      refresh();
    }).catch(function (e) { toast("Bulk action failed: " + e.message, "crit"); });
  }

  function pushAgentUpdates() {
    request("/api/v1/agents/update", "POST", { all: true }).then(function (res) {
      var n = arrayOf(res && res.scheduled).length;
      var u = arrayOf(res && res.unsupported).length;
      toast("Queued " + n + " self-update" + (n === 1 ? "" : "s") +
        (u ? "; " + u + " need the push-deployer" : ""), n ? "ok" : "warn");
      refresh();
    }).catch(function (e) { toast("Update push failed: " + e.message, "crit"); });
  }

  /* ---------------------------------------------------------- assets view */

  function evidenceStrip(asset) {
    var wrap = h("span", {
      cls: "ev",
      title: "Known by \u2014 agent: " + (asset.evidence.agent ? "yes" : "no") +
        ", scan: " + (asset.evidence.scan || "no") +
        ", inferred: " + (asset.evidence.inferred || "no")
    });
    wrap.appendChild(h("i", { "data-on": asset.evidence.agent ? "agent" : null }));
    wrap.appendChild(h("i", { "data-on": asset.evidence.scan ? "scan" : null }));
    wrap.appendChild(h("i", { "data-on": asset.evidence.inferred ? "inferred" : null }));
    return wrap;
  }

  function stateBadge(st) {
    return h("span", { cls: "st", "data-state": st.tone }, icon(st.glyph, true), h("span", { text: st.word }));
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

  /* The inference panel: what was deduced, why, and the two buttons that end
     the argument. Confirm pins the deduction; Reject withdraws it and leaves
     the row unclaimed rather than substituting another guess. */
  function inferencePanel(asset) {
    var wrap = h("div", {});
    var inferred = asset.inferredRole;
    var operator = bestClaim({ claims: asset.claims }, "role", "operator");

    if (!inferred && !operator) return null;

    if (inferred) {
      wrap.appendChild(h("p", { cls: "why" },
        h("b", { text: "Flow inference: " + roleLabel(inferred.value) + "." }),
        document.createTextNode(" " + (inferred.rationale || ""))));
      wrap.appendChild(h("div", { cls: "detail-acts" }, meter(Number(inferred.confidence) || 0)));
    }

    if (operator) {
      wrap.appendChild(h("p", { cls: "why" },
        h("b", { text: "Operator correction: " + roleLabel(operator.value) + "." }),
        document.createTextNode(" " + (operator.rationale || "") +
          " This outranks the inference and every scan.")));
      wrap.appendChild(h("div", { cls: "detail-acts" },
        h("button", {
          cls: "mini", type: "button", text: "Withdraw correction",
          on: {
            click: function (e) {
              e.stopPropagation();
              correctAsset(asset, "role", "", "", true);
            }
          }
        })));
      return wrap;
    }

    var acts = h("div", { cls: "detail-acts" });
    acts.appendChild(h("button", {
      cls: "mini", type: "button", text: "Confirm " + roleLabel(inferred.value).toLowerCase(),
      on: {
        click: function (e) {
          e.stopPropagation();
          correctAsset(asset, "role", inferred.value, "operator confirmed the flow inference", false);
        }
      }
    }));
    acts.appendChild(h("button", {
      cls: "mini", type: "button", text: "Not a " + roleLabel(inferred.value).toLowerCase(),
      "data-danger": "true",
      on: {
        click: function (e) {
          e.stopPropagation();
          correctAsset(asset, "role", "unknown", "operator rejected the flow inference", false);
        }
      }
    }));
    wrap.appendChild(acts);
    return wrap;
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
    var inference = inferencePanel(asset);
    if (inference) {
      whyCol.appendChild(inference);
    } else if (ep && asset.evidence.scan) {
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

    var td = h("td", { colspan: String(colspan) }, h("div", { cls: "detail" }, identityCol, exposureCol, whyCol));
    return h("tr", { cls: "exp" }, td);
  }

  function assetRow(asset, colspan) {
    var selected = !!state.selected[asset.key];
    var isCursor = state.cursorKey === asset.key;

    var check = h("input", {
      type: "checkbox", "aria-label": "Select " + asset.name,
      on: {
        click: function (e) { e.stopPropagation(); },
        change: function (e) {
          state.selected[asset.key] = e.target.checked;
          if (!e.target.checked) delete state.selected[asset.key];
          render();
        }
      }
    });
    check.checked = selected;

    var menuBtn = h("button", {
      cls: "menu-btn", type: "button", "aria-haspopup": "true", "aria-expanded": "false",
      "aria-label": "Actions for " + asset.name,
      on: {
        click: function (e) {
          e.stopPropagation();
          var r = e.currentTarget.getBoundingClientRect();
          openAssetMenu(asset, r.left - 170, r.bottom + 2, e.currentTarget);
        }
      }
    }, icon("i-dots"));

    var nameCell = h("td", {}, h("span", { cls: "host", text: asset.name }));
    /* Annotate only when the name is a bare address: the Identity column
       already carries the category, so repeating it on a named host is noise. */
    if (asset.name === asset.ip && asset.scan && asset.scan.category) {
      nameCell.appendChild(document.createTextNode(" "));
      nameCell.appendChild(h("span", { cls: "dim-3", text: "\u2192 likely " + asset.scan.category.toLowerCase() }));
    }

    var agentCell;
    if (asset.endpoint) {
      agentCell = h("span", { cls: "ver", "data-stale": asset.stale ? "true" : "false", text: shortVersion(asset.endpoint.driver_version) });
    } else {
      agentCell = h("span", { cls: "dim-3", text: "\u2014" });
    }

    var exposure = asset.ports.length
      ? h("span", { cls: "ago", text: asset.ports.length + (asset.riskyPorts ? " \u00b7 " + asset.riskyPorts + " risky" : "") })
      : h("span", { cls: "dim-3", text: asset.scan ? "0" : "\u2014" });

    /* The Identity column says what the host is; for an agented one it also has
       to say who the hub believes it is. An endpoint reporting under the tenant
       key alone is indistinguishable from any other holding that key, and an
       operator has no other place to see that before turning
       --client-certs required on. */
    var identityCell = h("td", { cls: "dim" }, h("span", { text: asset.identity }));
    if (asset.endpoint) {
      var cn = asset.endpoint.cert_cn || "";
      identityCell.appendChild(document.createTextNode(" "));
      identityCell.appendChild(h("span", {
        cls: "auth", "data-bound": cn ? "true" : "false",
        title: cn
          ? "Last reported under client certificate \u201c" + cn + "\u201d"
          : "Reports under the tenant API key alone. Any agent holding that key can report as this endpoint.",
        text: cn ? "\u00b7 cert" : "\u00b7 key only"
      }));
    }

    /* Cell order must match the header in renderAssets():
       select \u00b7 Asset \u00b7 Address \u00b7 Identity \u00b7 Known by \u00b7 State \u00b7 Exposure \u00b7
       Agent \u00b7 Last seen \u00b7 menu */
    return h("tr", {
      cls: "row",
      "data-selected": selected ? "true" : "false",
      "data-cursor": isCursor ? "true" : "false",
      "data-key": asset.key,
      on: {
        click: function () {
          state.cursorKey = asset.key;
          state.expandedKey = state.expandedKey === asset.key ? "" : asset.key;
          render();
        },
        contextmenu: function (e) {
          e.preventDefault();
          state.cursorKey = asset.key;
          openAssetMenu(asset, e.clientX, e.clientY, null);
        }
      }
    },
      h("td", {}, check),
      nameCell,
      h("td", {}, h("span", { cls: "ip", text: asset.ip || "\u2014" })),
      identityCell,
      h("td", {}, evidenceStrip(asset)),
      h("td", {}, stateBadge(asset.state)),
      h("td", {}, exposure),
      h("td", {}, agentCell),
      h("td", {}, h("span", { cls: "ago", text: ago(asset.lastSeen) })),
      h("td", {}, menuBtn));
  }

  function renderAssets() {
    var view = $("view");
    var rows = visibleAssets();
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
      h("th", { text: "Asset" }),
      h("th", { text: "Address" }),
      h("th", { text: "Identity" }),
      h("th", { title: "agent \u00b7 scan \u00b7 inferred", text: "Known by" }),
      h("th", { text: "State" }),
      h("th", { text: "Exposure" }),
      h("th", { text: "Agent" }),
      h("th", { text: "Last seen" }),
      h("th", { cls: "c-menu" }));

    var tbody = h("tbody");
    var currentGroup = null;
    var groupCounts = {};
    rows.forEach(function (r) {
      if (!groupCounts[r.groupKey]) groupCounts[r.groupKey] = { n: 0, q: 0, noagent: 0 };
      groupCounts[r.groupKey].n++;
      if (r.isolated || r.meshed) groupCounts[r.groupKey].q++;
      if (!r.evidence.agent) groupCounts[r.groupKey].noagent++;
    });

    rows.forEach(function (r) {
      if (r.groupKey !== currentGroup) {
        currentGroup = r.groupKey;
        var g = groupCounts[currentGroup];
        var collapsed = !!state.collapsedGroups[currentGroup];
        var meta = g.n + " asset" + (g.n === 1 ? "" : "s") +
          (g.noagent ? " \u00b7 " + g.noagent + " without an agent" : "") +
          (g.q ? " \u00b7 " + g.q + " quarantined" : "");
        (function (key) {
          tbody.appendChild(h("tr", {
            cls: "grp", "aria-expanded": collapsed ? "false" : "true",
            on: {
              click: function () {
                if (state.collapsedGroups[key]) delete state.collapsedGroups[key];
                else state.collapsedGroups[key] = true;
                render();
              }
            }
          }, h("td", { colspan: String(cols) },
            h("span", { cls: "tw" },
              (function () { var i = icon("i-twist", true); i.classList.add("ic-twist"); return i; })(),
              h("span", { text: key }),
              h("span", { cls: "cnt", text: "\u2014 " + meta })))));
        })(currentGroup);
      }
      if (state.collapsedGroups[currentGroup]) return;
      tbody.appendChild(assetRow(r, cols));
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
      h("span", {}, h("i", { "data-on": "inferred" }), h("span", { text: "inferred \u2014 deduced from flow (Pass 2)" })),
      h("span", {}, h("i", { "data-on": "none" }), h("span", { text: "nothing yet" })),
      h("span", { text: "j/k move \u00b7 x select \u00b7 i isolate \u00b7 r rescan \u00b7 y copy \u00b7 / filter \u00b7 enter open" }));

    clear(view);
    view.appendChild(wrap);
    view.appendChild(key);
  }

  /* ------------------------------------------------------- other sections */

  function card(title, body, actions, wide) {
    var head = h("h3", {}, h("span", { cls: "fill", text: title }));
    if (actions) actions.forEach(function (a) { head.appendChild(a); });
    return h("section", { cls: wide ? "card card-wide" : "card" }, head, body);
  }

  function simpleTable(headers, rows) {
    var thead = h("tr");
    headers.forEach(function (t) { thead.appendChild(h("th", { text: t })); });
    var tbody = h("tbody");
    if (!rows.length) {
      tbody.appendChild(h("tr", {}, h("td", { colspan: String(headers.length) },
        h("div", { cls: "empty", text: "Nothing recorded." }))));
    }
    rows.forEach(function (cells) {
      var tr = h("tr", { cls: "row" });
      cells.forEach(function (c) {
        tr.appendChild(h("td", {}, typeof c === "string" ? document.createTextNode(c) : c));
      });
      tbody.appendChild(tr);
    });
    return h("div", { cls: "tblwrap" }, h("table", {}, h("thead", {}, thead), tbody));
  }

  function renderDiscovery() {
    var view = $("view");
    var cov = state.coverage || {};

    /* The hub knows the network it is on - the location carries a CIDR and
       every managed endpoint carries an address. Defaulting the field to a
       demo subnet meant the first scan an operator ran on a real deployment
       swept a network that does not exist and reported nothing found. */
    var defaultSubnet = suggestedSubnet();
    var subnetInput = h("input", { type: "text", id: "scan-subnet", value: defaultSubnet, placeholder: defaultSubnet });
    var profileSel = h("select", { id: "scan-profile" },
      h("option", { value: "quick", text: "Quick" }),
      h("option", { value: "standard", text: "Standard" }),
      h("option", { value: "deep", text: "Deep" }));
    profileSel.value = "standard";

    var launch = card("Subnet sweep",
      h("div", { cls: "card-body" },
        h("div", { cls: "form-row" },
          h("label", { cls: "field" }, h("span", { text: "Subnet" }), subnetInput),
          h("label", { cls: "field" }, h("span", { text: "Profile" }), profileSel),
          h("button", {
            cls: "btn btn-primary", type: "button", text: "Start scan",
            on: {
              click: function () {
                request("/api/v1/scanner/scan", "POST", { subnet: subnetInput.value, profile: profileSel.value })
                  .then(function (res) {
                    state.scanJob = res && res.scan_id ? res.scan_id : "running";
                    toast("Scan started on " + subnetInput.value, "ok");
                    setTimeout(refresh, 3000);
                  })
                  .catch(function (e) { toast("Scan failed: " + e.message, "crit"); });
              }
            }
          })),
        h("p", { cls: "pending", text: state.scanJob
          ? "Last job: " + state.scanJob
          : "Discovered assets are written to the asset graph as they are found, so they survive a hub restart and an agent installed later enriches the same row." })));

    var unmanaged = state.assets.filter(function (a) { return !a.evidence.agent; });
    var worklist = card("Deployment worklist \u2014 seen, but not covered",
      simpleTable(["Address", "Identity", "Vendor", "Exposure", "Risk", "Last seen", ""],
        unmanaged.map(function (a) {
          return [
            h("span", { cls: "ip", text: a.ip || "\u2014" }),
            h("span", { cls: "dim", text: a.identity }),
            h("span", { cls: "dim-3", text: (a.scan && a.scan.vendor) || "\u2014" }),
            h("span", { cls: "ago", text: String(a.ports.length) }),
            h("span", { cls: "st", "data-state": a.riskyPorts ? "warn" : "idle" },
              icon(a.riskyPorts ? "g-watch" : "g-offline", true),
              h("span", { text: a.risk || "LOW" })),
            h("span", { cls: "ago", text: ago(a.lastSeen) }),
            h("button", { cls: "mini", type: "button", text: "Deploy agent", on: { click: function () { deployAgent(a); } } })
          ];
        })));

    /* Coverage is a ratio over what the sweep found, so before any sweep it is
       not zero - there is nothing to take a ratio of. Printing "Managed 0" and
       "0% covered" next to an Assets view reporting four managed endpoints made
       the two screens contradict each other over the same fleet. */
    var discovered = cov.total_discovered !== undefined ? cov.total_discovered : state.scanAssets.length;
    var swept = discovered > 0;

    var covBody = h("div", { cls: "card-body" },
      swept
        ? h("dl", { cls: "kv" },
            h("dt", { text: "Discovered" }), h("dd", {}, h("b", { text: String(discovered) })),
            h("dt", { text: "Managed" }), h("dd", { text: String(cov.total_managed || 0) }),
            h("dt", { text: "Unmanaged" }), h("dd", { text: String(cov.total_unmanaged || 0) }),
            h("dt", { text: "Coverage" }), h("dd", {}, h("b", { text: (cov.coverage_percent || 0) + "%" })),
            h("dt", { text: "Critical" }), h("dd", { text: String(cov.critical_risks || 0) }),
            h("dt", { text: "High" }), h("dd", { text: String(cov.high_risks || 0) }),
            h("dt", { text: "Named by flow" }), h("dd", {}, h("b", { text: String(inferredCount()) })))
        : h("div", { cls: "empty", text: "No sweep has run, so there is nothing to measure coverage against. " +
            "The fleet's agented hosts are on the Assets view; a sweep is what finds the ones without an agent." }));

    var inf = state.inference || {};
    var infBody = h("div", { cls: "card-body" });
    var infRows = arrayOf(inf.results);
    if (infRows.length) {
      infBody.appendChild(simpleTable(["Address", "Deduced role", "Confidence", "Why"],
        infRows.map(function (r) {
          var asset = state.assets.filter(function (a) { return a.ip === r.ip; })[0];
          return [
            h("span", { cls: "ip", text: r.ip }),
            h("span", {}, h("b", { text: r.label || roleLabel(r.role) })),
            h("span", { cls: "ago", text: (Number(r.confidence) || 0).toFixed(2) }),
            h("span", { cls: "dim",
              on: asset ? { click: function () { state.expandedKey = asset.key; state.cursorKey = asset.key; go("assets"); } } : null,
              text: r.rationale || "" })
          ];
        })));
    } else {
      infBody.appendChild(h("div", { cls: "empty", text: "No role deduced from flow in the current window." }));
    }
    infBody.appendChild(h("p", { cls: "pending", text: "Inference runs every " + (inf.interval || "5m") +
      " over a " + (inf.window || "24h") + " window of traffic. It never outranks an agent, a scan or an operator correction." }));

    clear(view);
    view.appendChild(h("div", { cls: "pad stack" },
      h("div", { cls: "cols" }, launch, card("Coverage", covBody)),
      card("Deduced from flow \u2014 hosts nothing probed and nothing runs on", infBody, [
        h("button", {
          cls: "mini", type: "button", text: "Run inference now",
          on: {
            click: function () {
              request("/api/v1/inference/run", "POST").then(function (res) {
                toast("Inference pass complete: " + ((res && res.inferred_count) || 0) + " role(s)", "ok");
                refresh();
              }).catch(function (e) { toast("Inference failed: " + e.message, "crit"); });
            }
          }
        })
      ], true),
      worklist));
  }

  /* Radial layout: highest-degree node in the centre, its neighbours on the
     inner ring, everything else outside. Deterministic in node id so the graph
     does not jump between five-second refreshes. */
  function layoutTopology(nodes, edges) {
    var degree = {};
    nodes.forEach(function (n) { degree[n.id] = 0; });
    edges.forEach(function (e) {
      if (degree[e.source] !== undefined) degree[e.source]++;
      if (degree[e.target] !== undefined) degree[e.target]++;
    });
    var ordered = nodes.slice().sort(function (a, b) {
      if (degree[b.id] !== degree[a.id]) return degree[b.id] - degree[a.id];
      return a.id < b.id ? -1 : 1;
    });
    if (!ordered.length) return {};

    var hub = ordered[0];

    var neighbours = [];
    var outer = [];
    ordered.slice(1).forEach(function (n) {
      var touches = edges.some(function (e) {
        return (e.source === hub.id && e.target === n.id) || (e.target === hub.id && e.source === n.id);
      });
      (touches ? neighbours : outer).push(n);
    });

    /* Rings have to be sized and, past a point, multiplied. Fixed radii put 120
       nodes of diameter 18 onto a circle giving each 8 units of arc, so they
       overlapped into a solid band that could be neither read nor clicked.
       Growing one ring instead just shrinks every node when the whole thing is
       scaled to fit, so the outer nodes spill onto further rings once the
       current one is full - the box grows slowly, and the nodes stay big enough
       to aim at.

       ELLIPSE_RATIO is matched to the panel the graph is drawn in, which is
       roughly twice as wide as it is tall. Round rings in a wide box are fitted
       by height and leave the width empty, and everything is scaled down to
       suit the dimension that ran out first - which is how a graph ends up
       correct, uncrowded and still unreadable. PERIMETER_K, sqrt((1+r^2)/2), is
       the factor between an ellipse's semi-major axis and the radius of a
       circle with the same perimeter, so ring capacity stays honest when the
       ratio changes. */
    var ELLIPSE_RATIO = 0.58;
    var PERIMETER_K = Math.sqrt((1 + ELLIPSE_RATIO * ELLIPSE_RATIO) / 2);
    var ringCapacity = function (a, nodeR) {
      return Math.max(1, Math.floor((2 * Math.PI * PERIMETER_K * a) / (nodeR * 2 + 4)));
    };

    var innerA = 150;
    while (neighbours.length > ringCapacity(innerA, 9)) innerA += 40;

    /* Each outer ring starts far enough out to clear the one inside it. */
    var rings = [];
    var remaining = outer.length;
    var a = Math.max(340, innerA + 150);
    while (remaining > 0) {
      var cap = Math.min(remaining, ringCapacity(a, 8));
      rings.push({ a: a, take: cap });
      remaining -= cap;
      a += 120;
    }
    var maxA = rings.length ? rings[rings.length - 1].a : innerA;

    var W = Math.round(2 * (maxA + 90));
    var H = Math.round(2 * (maxA * ELLIPSE_RATIO + 75));
    var cx = W / 2, cy = H / 2;
    var pos = {};
    pos[hub.id] = { x: cx, y: cy, r: 13 };

    /* Equal arc, not equal angle. Stepping the parametric angle evenly around a
       flattened ellipse bunches nodes at the left and right ends, where the
       curve is tightest - the same crowding the ring sizing above exists to
       prevent, reintroduced by the placement. Walking a sampled arc-length
       table spaces them by the distance actually between them. */
    var place = function (list, radiusX, radiusY, phase, r) {
      var n = list.length;
      if (!n) return;

      var SAMPLES = 720;
      var cum = [0];
      var px = radiusX, py = 0;
      for (var k = 1; k <= SAMPLES; k++) {
        var t = (k / SAMPLES) * Math.PI * 2;
        var qx = Math.cos(t) * radiusX, qy = Math.sin(t) * radiusY;
        cum.push(cum[k - 1] + Math.hypot(qx - px, qy - py));
        px = qx; py = qy;
      }
      var total = cum[SAMPLES];

      var at = 0;
      list.forEach(function (node, i) {
        var want = (i / n) * total;
        while (at < SAMPLES && cum[at + 1] < want) at++;
        var ang = phase + ((at / SAMPLES) * Math.PI * 2);
        pos[node.id] = { x: cx + Math.cos(ang) * radiusX, y: cy + Math.sin(ang) * radiusY, r: r };
      });
    };
    place(neighbours, innerA, innerA * ELLIPSE_RATIO, -Math.PI / 2, 9);

    var cursor = 0;
    rings.forEach(function (ring, idx) {
      /* Each ring is offset a little so nodes do not line up into spokes. */
      place(outer.slice(cursor, cursor + ring.take), ring.a, ring.a * ELLIPSE_RATIO,
            -Math.PI / 2 + 0.35 + idx * 0.4, 8);
      cursor += ring.take;
    });
    return { pos: pos, width: W, height: H };
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

  function renderTopology() {
    var view = $("view");
    var data = state.topology;
    clear(view);

    if (!data || !arrayOf(data.nodes).length) {
      view.appendChild(h("div", { cls: "empty", text: state.loading ? "Loading graph\u2026" : "No flow recorded in this window." }));
      return;
    }

    var nodes = arrayOf(data.nodes);
    var edges = arrayOf(data.edges);
    var layout = layoutTopology(nodes, edges);
    var pos = layout.pos;

    var maxFlow = Math.max.apply(null, edges.map(function (e) { return Number(e.flow_count) || 1; }).concat([1]));

    var svg = s("svg", { viewBox: "0 0 " + layout.width + " " + layout.height, preserveAspectRatio: "xMidYMid meet", role: "img", "aria-label": "Communications topology" });

    /* Aggregate to asset-pair edges and label only the heaviest port per pair;
       labelling every 5-tuple is what makes these graphs unreadable. */
    var pairs = {};
    edges.forEach(function (e) {
      var a = e.source < e.target ? e.source : e.target;
      var b = e.source < e.target ? e.target : e.source;
      var id = a + "\u0000" + b;
      var p = pairs[id];
      if (!p) {
        p = pairs[id] = { id: id, source: a, target: b, flow: 0, bytes: 0, verdict: "clean", topPort: e.port, topFlow: 0, ports: {} };
      }
      p.flow += Number(e.flow_count) || 0;
      p.bytes += Number(e.total_bytes) || 0;
      if (e.verdict === "blocked") p.verdict = "blocked";
      else if (e.verdict === "anomalous" && p.verdict !== "blocked") p.verdict = "anomalous";
      if ((Number(e.flow_count) || 0) >= p.topFlow) { p.topFlow = Number(e.flow_count) || 0; p.topPort = e.port; }

      /* The hub aggregates to the asset pair and hands the ports over with
         it, so the graph can stay one line per pair and still answer "which
         ports" without another round trip. */
      arrayOf(e.ports).forEach(function (ps) {
        var k = (ps.protocol || "TCP") + "/" + ps.port;
        var slot = p.ports[k] || (p.ports[k] = { port: ps.port, protocol: ps.protocol || "TCP", flow: 0, bytes: 0, verdict: "clean" });
        slot.flow += Number(ps.flow_count) || 0;
        slot.bytes += Number(ps.total_bytes) || 0;
        if (ps.verdict && ps.verdict !== "clean") slot.verdict = ps.verdict;
      });
    });

    var edgeLayer = s("g");
    var labelLayer = s("g");

    /* Where the node circles and their captions will land. A port label that
       falls on top of a hostname is worse than no port label at all: the two
       strings interleave and neither can be read. The selected-link panel is
       the authoritative port list, so the label is a convenience we drop
       rather than draw illegibly. Node captions sit centred below the circle
       at pt.y + pt.r + 11; the half-width is estimated from the monospace
       advance, which is close enough for an overlap test. */
    var occupied = [];
    nodes.forEach(function (n) {
      var pt = pos[n.id];
      if (pt) occupied.push({ x0: pt.x - pt.r, x1: pt.x + pt.r, y0: pt.y - pt.r, y1: pt.y + pt.r });
    });

    /* Node captions get the same treatment as the port labels below: drawn
       only where they can be read. A subnet sweep puts a couple of hundred
       nodes on this graph, and captioning all of them turned the ring into a
       band of overlapping text with no readable name anywhere in it - the
       managed hosts, which are the point of the view, buried among addresses.
       Nothing is lost by dropping one: every node keeps its hover title and
       the side panel names whatever is selected.

       Order decides who keeps a caption when two collide, so it runs from most
       to least worth naming: the selection, then the hosts the fleet actually
       manages, then the busiest. */
    var captionOrder = nodes.slice().sort(function (a, b) {
      var sa = a.id === state.topoSelected ? 0 : 1;
      var sb = b.id === state.topoSelected ? 0 : 1;
      if (sa !== sb) return sa - sb;
      // Anything the fleet knows by name outranks a bare address.
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

    /* The flow an edge has to carry before it is worth naming: the 24th
       heaviest, so a small graph labels everything and a large one labels the
       traffic that matters. */
    var pairFlows = Object.keys(pairs).map(function (k) { return pairs[k].flow; }).sort(function (x, y) { return y - x; });
    var labelFloor = pairFlows.length > 24 ? pairFlows[23] : 0;

    Object.keys(pairs).sort().forEach(function (id) {
      var p = pairs[id];
      var a = pos[p.source], b = pos[p.target];
      if (!a || !b) return;
      var w = 0.8 + (p.flow / maxFlow) * 2.6;
      edgeLayer.appendChild(s("line", {
        "class": "edge", "data-verdict": p.verdict,
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
      }));
      var lx = (a.x + b.x) / 2, ly = (a.y + b.y) / 2 - 3;
      /* Two rules, and the graph needs both. Only edges that carry enough flow
         to be worth naming get a label at all - 241 of them, most reading
         "443", is not information. And a label that is drawn has to claim the
         space it occupies, or the next one lands on top of it; testing a bare
         midpoint against other labels' boxes let every one of them through. */
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

    var nodeLayer = s("g");
    nodes.forEach(function (n) {
      var pt = pos[n.id];
      if (!pt) return;
      var circle = s("circle", {
        "class": "node", "data-kind": nodeKind(n),
        "data-selected": state.topoSelected === n.id ? "true" : "false",
        /* A known asset that was quiet in the window is dimmed, never
           omitted: absence is information on a security graph. */
        "data-quiet": n.quiet ? "true" : "false",
        cx: pt.x, cy: pt.y, r: pt.r,
        on: {
          click: function () { state.topoSelected = n.id; state.topoEdgeSelected = ""; render(); }
        }
      });
      circle.appendChild(s("title", {
        text: (n.label || n.id) + " \u00b7 " + (n.ip || "") +
          (n.role && n.role !== "unknown" ? " \u00b7 " + n.role : "") +
          (n.quiet ? " \u00b7 quiet in this window" : "")
      }));
      nodeLayer.appendChild(circle);
      if (showCaption[n.id]) {
        labelLayer.appendChild(s("text", {
          "class": "nlabel", x: pt.x, y: pt.y + pt.r + 11, "text-anchor": "middle",
          text: n.label || n.id
        }));
      }
    });

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
        h("dt", { text: "Volume" }), h("dd", { text: bytes(selEdge.bytes) }),
        h("dt", { text: "Verdict" }), h("dd", { text: selEdge.verdict })));

      var portKeys = Object.keys(selEdge.ports).sort(function (a, b) {
        return selEdge.ports[b].bytes - selEdge.ports[a].bytes;
      });
      if (portKeys.length) {
        side.appendChild(h("h4", { text: "Ports on this link" }));
        var plist = h("div", { cls: "portlist" });
        portKeys.forEach(function (k) {
          var ps = selEdge.ports[k];
          plist.appendChild(h("span", {
            cls: "port", "data-risk": ps.verdict === "blocked" ? "CRITICAL" : "LOW",
            text: ps.port + " " + ps.protocol + " \u00b7 " + bytes(ps.bytes)
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
      side.appendChild(h("p", { cls: "pending", text: "Click a node, or a link to see its ports. Selection is shared with the Assets table \u2014 the graph is a lens, not a destination." }));
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
        h("dt", { text: "Volume" }), h("dd", { text: bytes(linked.reduce(function (t, p) { return t + p.bytes; }, 0)) }));
      side.appendChild(kv);
      if (sel.rationale) {
        side.appendChild(h("p", { cls: "why" },
          h("b", { text: "Deduced from flow." }),
          document.createTextNode(" " + sel.rationale)));
      }

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
    legend.appendChild(h("span", { text: "edge width = flow volume \u00b7 dashed = blocked \u00b7 label = heaviest port per pair \u00b7 hollow = quiet in this window" }));

    view.appendChild(h("div", { cls: "topo" }, h("div", { cls: "topo-canvas" }, svg), side));
    view.appendChild(legend);
  }

  function barList(items, valueFn, labelFn, textFn) {
    var max = Math.max.apply(null, items.map(valueFn).concat([1]));
    var list = h("div", { cls: "barlist" });
    items.forEach(function (it) {
      var frac = Math.max(0, Math.min(1, valueFn(it) / max));
      var svg = s("svg", { viewBox: "0 0 118 8", preserveAspectRatio: "none", "aria-hidden": "true" });
      svg.appendChild(s("rect", { "class": "track", x: 0, y: 2, width: 118, height: 4, rx: 2 }));
      svg.appendChild(s("rect", { "class": "fill", x: 0, y: 2, width: (frac * 118).toFixed(1), height: 4, rx: 2 }));
      list.appendChild(h("div", { cls: "barrow" },
        h("span", { cls: "n", text: labelFn(it), title: labelFn(it) }),
        svg,
        h("span", { cls: "v", text: textFn(it) })));
    });
    return list;
  }

  function renderTraffic() {
    var view = $("view");
    var an = state.analytics || {};
    clear(view);

    var timeline = arrayOf(an.bandwidth_timeline);
    var chartCard;
    if (timeline.length) {
      var maxB = Math.max.apply(null, timeline.map(function (p) {
        return Math.max(Number(p.bytes_in) || 0, Number(p.bytes_out) || 0);
      }).concat([1]));
      var n = timeline.length;
      /* The bars are laid out across a fixed 100-unit width and scaled to the
         bucket count, rather than eight units per bucket. With the six buckets
         the hub returns, the old form stretched each three-unit bar across a
         quarter of the card - a chart of six blocks, unreadable as a series. */
      var W = 100;
      var slot = W / n;
      var barW = slot * 0.3;
      var maxBlocks = Math.max.apply(null, timeline.map(function (p) { return Number(p.blocks) || 0; }).concat([1]));
      var svg = s("svg", { "class": "chart", viewBox: "0 0 " + W + " 132", preserveAspectRatio: "none", role: "img", "aria-label": "Bandwidth and blocked flows over time" });
      timeline.forEach(function (p, i) {
        var bin = Number(p.bytes_in) || 0;
        var bout = Number(p.bytes_out) || 0;
        /* A bucket with no traffic draws nothing. The one-pixel floor the old
           chart used drew a bar for silence, which is the state most worth
           being able to see. */
        var hi = bin ? Math.max(1, Math.round((bin / maxB) * 60)) : 0;
        var ho = bout ? Math.max(1, Math.round((bout / maxB) * 60)) : 0;
        var x0 = i * slot + slot * 0.15;
        if (hi) svg.appendChild(s("rect", { "class": "series-in", x: x0, y: 62 - hi, width: barW, height: hi }));
        if (ho) svg.appendChild(s("rect", { "class": "series-out", x: x0 + barW + slot * 0.1, y: 62 - ho, width: barW, height: ho }));
        var blocks = Number(p.blocks) || 0;
        // Scaled against the busiest bucket, not a fixed four units per block,
        // which flattened anything past fifteen into the same full-height bar.
        if (blocks) {
          var hb = Math.max(2, Math.round((blocks / maxBlocks) * 55));
          svg.appendChild(s("rect", { "class": "series-block", x: x0, y: 66, width: barW * 2 + slot * 0.1, height: hb }));
        }
      });
      svg.appendChild(s("line", { "class": "axis", x1: 0, y1: 63, x2: W, y2: 63 }));

      /* Bucket times as HTML under the chart rather than SVG text: the chart is
         drawn with preserveAspectRatio="none" so it can fill the card, and any
         text inside it would be stretched with the bars. Without these the
         series had no time axis at all. */
      var ticks = h("div", { cls: "chart-ticks" });
      timeline.forEach(function (p) {
        ticks.appendChild(h("span", { text: String(p.timestamp || "") }));
      });

      chartCard = card("Bandwidth and blocks",
        h("div", { cls: "card-body" }, svg, ticks,
          h("div", { cls: "legend" },
            h("span", { text: "above the axis: bytes in / bytes out" }),
            h("span", { text: "below: blocked flows" }),
            h("span", { text: "ten-minute buckets, last hour" }))));
    } else {
      chartCard = card("Bandwidth and blocks", h("div", { cls: "empty", text: "No timeline in this window." }));
    }

    var talkers = arrayOf(an.top_talkers);
    var talkerCard = card("Top talkers",
      h("div", { cls: "card-body" },
        talkers.length
          ? barList(talkers, function (t) { return Number(t.total_bytes) || 0; },
              function (t) { return (t.process || "\u2014") + " \u00b7 " + (Number(t.flow_count) || 0) + " flows"; },
              function (t) { return bytes(t.total_bytes); })
          : h("div", { cls: "empty", text: "No process attribution yet." })));

    var geo = arrayOf(an.geo_stats);
    var geoCard = card("Destinations by country",
      h("div", { cls: "card-body" },
        geo.length
          ? barList(geo, function (g) { return Number(g.total_bytes) || 0; },
              function (g) { return (g.country_name || g.country) + " \u00b7 " + (Number(g.flow_count) || 0) + " flows" + (g.threat_count ? " \u00b7 " + g.threat_count + " flagged" : ""); },
              function (g) { return bytes(g.total_bytes); })
          : h("div", { cls: "empty", text: "No geo data." })));

    var evRows = state.events.slice(0, 60).map(function (e) {
      return [
        h("span", { cls: "ago", text: ago(parseTime(e.timestamp)) }),
        h("span", { cls: "st", "data-state": e.action === "BLOCK" ? "crit" : "ok" },
          icon(e.action === "BLOCK" ? "g-quarantine" : "g-online", true),
          h("span", { text: e.action || "\u2014" })),
        h("span", { cls: "dim-3", text: e.direction || "" }),
        h("span", { cls: "ip", text: (e.src_ip || "") + ":" + (e.src_port || 0) }),
        h("span", { cls: "ip", text: (e.dst_ip || "") + ":" + (e.dst_port || 0) }),
        h("span", { cls: "dim", text: e.process_path || e.domain || "\u2014" }),
        h("span", { cls: "ago", text: bytes((Number(e.bytes_in) || 0) + (Number(e.bytes_out) || 0)) })
      ];
    });

    view.appendChild(h("div", { cls: "pad stack" },
      chartCard,
      h("div", { cls: "cols" }, talkerCard, geoCard),
      card("Recent flows", simpleTable(["Age", "Action", "Dir", "Source", "Destination", "Process", "Bytes"], evRows))));
  }

  function renderPolicy() {
    var view = $("view");
    clear(view);

    var groups = simpleTable(["Name", "Scope", "Action", "Match", "Schedule", "State", ""],
      state.policyGroups.map(function (g) {
        return [
          h("span", { text: g.name || g.id }),
          h("span", { cls: "dim-3", text: g.scope + (g.scope_value ? " \u00b7 " + g.scope_value : "") }),
          h("span", { cls: "dim", text: g.action || "\u2014" }),
          h("span", { cls: "ip", text: (g.rule_type || "") + " " + (g.rule_value || (g.port ? String(g.port) : "")) }),
          h("span", { cls: "dim-3", text: g.schedule || "all" }),
          h("span", { cls: "st", "data-state": g.active ? "ok" : "idle" },
            icon(g.active ? "g-online" : "g-offline", true),
            h("span", { text: g.active ? "Active" : "Paused" })),
          h("button", {
            cls: "mini", type: "button", text: g.active ? "Pause" : "Activate",
            on: {
              click: function () {
                request("/api/v1/policy-groups/toggle", "POST", { id: g.id, active: !g.active })
                  .then(function () { toast((g.active ? "Paused " : "Activated ") + (g.name || g.id), "ok"); refresh(); })
                  .catch(function (e) { toast("Toggle failed: " + e.message, "crit"); });
              }
            }
          })
        ];
      }));

    var excl = simpleTable(["Name", "Scope", "Process", "Destination", "Port", "State"],
      state.exclusions.map(function (x) {
        return [
          h("span", { text: x.name || x.id }),
          h("span", { cls: "dim-3", text: x.scope + (x.scope_value ? " \u00b7 " + x.scope_value : "") }),
          h("span", { cls: "dim", text: x.process_path || "any" }),
          h("span", { cls: "ip", text: x.dst_ip_range || "any" }),
          h("span", { cls: "ip", text: (x.port ? String(x.port) : "any") + "/" + (x.protocol || "any") }),
          h("span", { cls: "st", "data-state": x.active ? "ok" : "idle" },
            icon(x.active ? "g-online" : "g-offline", true),
            h("span", { text: x.active ? "Active" : "Off" }))
        ];
      }));

    var iocs = simpleTable(["Indicator", "Type", "Threat", "Source", "Confidence", "Last seen"],
      state.iocs.map(function (i) {
        return [
          h("span", { cls: "ip", text: i.value || i.indicator || "\u2014" }),
          h("span", { cls: "dim-3", text: i.type || "" }),
          h("span", { cls: "dim", text: i.threat_type || i.threat_name || "" }),
          h("span", { cls: "dim-3", text: i.source || "" }),
          h("span", { cls: "ago", text: String(i.confidence !== undefined ? i.confidence : "") }),
          h("span", { cls: "ago", text: ago(parseTime(i.last_seen_at || i.created_at)) })
        ];
      }));

    var mesh = simpleTable(["Address", "MAC", "Subnet", "Reason", "Since", ""],
      state.meshPeers.map(function (p) {
        return [
          h("span", { cls: "ip", text: p.target_ip }),
          h("span", { cls: "ip", text: p.target_mac || "\u2014" }),
          h("span", { cls: "ip", text: p.subnet || "\u2014" }),
          h("span", { cls: "dim", text: p.reason || "" }),
          h("span", { cls: "ago", text: ago(parseTime(p.created_at)) }),
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

    view.appendChild(h("div", { cls: "pad stack" },
      card("Policy groups", groups),
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
      card("Peer-mesh quarantine", mesh)));
  }

  function renderAudit() {
    var view = $("view");
    clear(view);

    var rows = state.audit.map(function (a) {
      return [
        h("span", { cls: "ago", text: ago(parseTime(a.timestamp)) }),
        h("span", { cls: "dim", text: a.username || a.user_id || "\u2014" }),
        h("span", { text: a.action || "" }),
        h("span", { cls: "ip", text: a.resource || "" }),
        h("span", { cls: "dim-3", text: a.details || "" }),
        h("span", { cls: "ip", text: a.ip_address || "" })
      ];
    });

    view.appendChild(h("div", { cls: "pad stack" },
      card("Audit trail", simpleTable(["Age", "Actor", "Action", "Resource", "Details", "From"], rows))));
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
       inside it costs nothing and keeps the section usable. */
    if (view.firstChild && view.contains(document.activeElement)) return;

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
        h("span", { cls: "ago", text: op.created_at ? ago(parseTime(op.created_at)) : "\u2014" }),
        h("button", {
          cls: "mini", type: "button", text: "Remove",
          on: {
            click: function () {
              request("/api/v1/operators/remove", "POST", { email: op.email })
                .then(function () {
                  toast("Removed " + op.email + (isYou ? " \u2014 that was your own access" : ""), isYou ? "warn" : "ok");
                  refresh();
                })
                .catch(function (e) { toast("Could not remove: " + e.message, "crit"); });
            }
          }
        })
      ];
    });

    var listCard = card("Operators",
      simpleTable(["Email", "Role", "Granted by", "Added", ""], rows));

    view.appendChild(h("div", { cls: "pad stack" }, listCard, opGrantCard));
  }

  /* --------------------------------------------------------- full route */

  var routeEl = null;

  function closeRoute() {
    if (routeEl && routeEl.parentNode) routeEl.parentNode.removeChild(routeEl);
    routeEl = null;
    state.routeKey = "";
  }

  function openRoute(key) {
    state.routeKey = key;
    renderRoute();
    /* The full view shows this asset's recent flows, which only the Traffic and
       Audit sections load; fetch them on demand so the panel is never empty. */
    if (!state.events.length) {
      request("/api/v1/events").then(function (d) {
        state.events = arrayOf(d);
        if (state.routeKey) renderRoute();
      }).catch(function () { /* the panel degrades to "nothing recorded" */ });
    }
  }

  function renderRoute() {
    if (routeEl && routeEl.parentNode) routeEl.parentNode.removeChild(routeEl);
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
        h("dt", { text: "Last seen" }), h("dd", { text: ago(asset.lastSeen) + " ago" }))));

    var agentCard = card("Agent", h("div", { cls: "card-body" },
      ep
        ? h("dl", { cls: "kv" },
            h("dt", { text: "Endpoint id" }), h("dd", {}, h("b", { text: ep.id })),
            h("dt", { text: "Version" }), h("dd", { text: shortVersion(ep.driver_version) + (asset.stale ? " \u2014 outdated" : "") }),
            h("dt", { text: "Engine" }), h("dd", { text: engineOf(ep.driver_version) || "\u2014" }),
            h("dt", { text: "OS" }), h("dd", { text: ep.os || "\u2014" }),
            h("dt", { text: "Role" }), h("dd", { text: ep.role_tag || "\u2014" }),
            h("dt", { text: "Software" }), h("dd", { text: ep.installed_software || "\u2014" }),
            h("dt", { text: "Registered" }), h("dd", { text: ago(parseTime(ep.created_at)) + " ago" }))
        : h("div", { cls: "empty", text: "No agent on this asset. It is on the deployment worklist." })));

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
    var routeInference = inferencePanel(asset);
    if (routeInference) evBody.appendChild(routeInference);
    evBody.appendChild(h("p", { cls: "pending", text: "Highest confidence wins per field, never per record. Losing claims stay on the row so an operator can see that the scanner said one thing and the agent another." }));

    var flows = state.events.filter(function (e) {
      return (ep && e.endpoint_id === ep.id) || (asset.ip && (e.src_ip === asset.ip || e.dst_ip === asset.ip));
    }).slice(0, 25);
    var flowCard = card("Recent flows", simpleTable(["Age", "Action", "Source", "Destination", "Process"],
      flows.map(function (e) {
        return [
          h("span", { cls: "ago", text: ago(parseTime(e.timestamp)) }),
          h("span", { cls: "st", "data-state": e.action === "BLOCK" ? "crit" : "ok" },
            icon(e.action === "BLOCK" ? "g-quarantine" : "g-online", true),
            h("span", { text: e.action || "" })),
          h("span", { cls: "ip", text: (e.src_ip || "") + ":" + (e.src_port || 0) }),
          h("span", { cls: "ip", text: (e.dst_ip || "") + ":" + (e.dst_port || 0) }),
          h("span", { cls: "dim", text: e.process_path || e.domain || "\u2014" })
        ];
      })), null, true);

    var alerts = state.anomalies.filter(function (a) { return (ep && a.endpoint_id === ep.id) || (asset.ip && a.dst_ip === asset.ip); });
    var alertCard = card("Open alerts", alerts.length
      ? h("div", {}, alerts.map(function (a) { return alertCardNode(a, true); }))
      : h("div", { cls: "empty", text: "No open alert on this asset." }), null, true);

    routeEl = h("div", { cls: "route", role: "dialog", "aria-label": "Asset " + asset.name },
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
      h("div", { cls: "route-body" }, idCard, agentCard, card("Observed exposure", portsBody),
        card("Evidence", evBody), flowCard, alertCard));

    document.body.appendChild(routeEl);
  }

  /* -------------------------------------------------------------- drawers */

  var drawerEl = null;
  var scrimEl = null;
  var openDrawer = "";
  var chatInput = null;

  function closeDrawer() {
    if (drawerEl && drawerEl.parentNode) drawerEl.parentNode.removeChild(drawerEl);
    if (scrimEl && scrimEl.parentNode) scrimEl.parentNode.removeChild(scrimEl);
    drawerEl = null;
    scrimEl = null;
    openDrawer = "";
    $("btn-alerts").setAttribute("aria-expanded", "false");
    $("btn-copilot").setAttribute("aria-expanded", "false");
  }

  function showDrawer(kind) {
    if (openDrawer === kind) { closeDrawer(); return; }
    closeDrawer();
    openDrawer = kind;
    scrimEl = h("div", { cls: "scrim", on: { click: closeDrawer } });
    document.body.appendChild(scrimEl);
    drawerEl = h("aside", { cls: "drawer", role: "dialog", "aria-label": kind === "alerts" ? "Alerts" : "Copilot" });
    document.body.appendChild(drawerEl);
    $(kind === "alerts" ? "btn-alerts" : "btn-copilot").setAttribute("aria-expanded", "true");
    renderDrawer();
  }

  function alertCardNode(a, compact) {
    var node = h("div", { cls: "alert", "data-sev": a.severity || "LOW" },
      h("div", { cls: "sev" }),
      h("div", {},
        h("div", { cls: "sev-word", text: (a.severity || "LOW") + " \u00b7 " + (a.anomaly_type || "ANOMALY") }),
        h("div", { cls: "ttl", text: a.title || "Anomaly" }),
        h("div", { cls: "meta", text: (a.hostname || a.endpoint_id || "\u2014") + " \u00b7 " + ago(parseTime(a.timestamp)) + " ago" }),
        h("div", { cls: "desc", text: a.description || "" }),
        a.details ? h("div", { cls: "meta", text: a.details }) : null,
        compact ? null : h("div", { cls: "acts" },
          h("button", {
            cls: "mini", type: "button", text: "Ask Copilot",
            on: { click: function () { askAboutAlert(a); } }
          }),
          h("button", {
            cls: "mini", type: "button", text: "Open asset",
            on: {
              click: function () {
                var asset = state.assetByKey[a.endpoint_id];
                if (asset) { closeDrawer(); openRoute(asset.key); }
                else toast("No asset row for " + a.endpoint_id, "warn");
              }
            }
          }),
          h("button", {
            cls: "mini", type: "button", "data-danger": "true", text: "Isolate host",
            on: {
              click: function () {
                var asset = state.assetByKey[a.endpoint_id];
                if (asset) setIsolation(asset, true);
                else toast("No agented asset for " + a.endpoint_id, "warn");
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
    var wasOpen = drawerEl.childNodes.length > 0;
    clear(drawerEl);

    if (openDrawer === "alerts") {
      drawerEl.appendChild(h("div", { cls: "drawer-head" },
        icon("i-alert"),
        h("h2", { text: "Alerts" }),
        h("span", { cls: "fill" }),
        h("button", { cls: "btn btn-icon", type: "button", "aria-label": "Close", on: { click: closeDrawer } }, icon("i-close"))));
      var body = h("div", { cls: "drawer-body" });
      if (!state.anomalies.length) {
        body.appendChild(h("div", { cls: "empty", text: "No open anomalies." }));
      } else {
        state.anomalies.forEach(function (a) { body.appendChild(alertCardNode(a, false)); });
      }
      drawerEl.appendChild(body);
      return;
    }

    drawerEl.appendChild(h("div", { cls: "drawer-head" },
      icon("i-copilot"),
      h("h2", { text: "Copilot" }),
      h("span", { cls: "fill" }),
      h("button", { cls: "btn btn-icon", type: "button", "aria-label": "Close", on: { click: closeDrawer } }, icon("i-close"))));

    var chat = h("div", { cls: "chat" });
    if (!state.chat.length) {
      chat.appendChild(h("div", { cls: "empty", text: "Ask about a host, an alert, or the fleet. The drawer stays open over whatever you are looking at." }));
    }
    state.chat.forEach(function (m) {
      var node = h("div", { cls: "msg", "data-who": m.who },
        h("div", { cls: "who", text: m.who === "you" ? "You" : "Copilot" }),
        h("pre", { text: m.text }));
      /* Say who wrote it. A degraded answer comes from the built-in rule set and
         reads exactly like a model's, so the reply alone cannot be trusted to
         mean the configured provider was reached. */
      if (m.who === "copilot" && (m.source || m.notice)) {
        node.appendChild(h("div", { cls: "msg-src", "data-degraded": m.degraded ? "true" : "false" },
          h("span", { text: m.source || "" }),
          m.notice ? h("span", { text: m.notice }) : null));
      }
      chat.appendChild(node);
    });
    if (state.chatBusy) chat.appendChild(h("div", { cls: "empty", text: "Thinking\u2026" }));
    drawerEl.appendChild(h("div", { cls: "drawer-body" }, chat));

    /* The composer node survives re-renders so a five-second poll cannot wipe
       a half-typed question or yank focus back mid-sentence. */
    if (!chatInput) {
      chatInput = h("textarea", { placeholder: "Ask the Copilot\u2026", "aria-label": "Message" });
      chatInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submitChat(); }
      });
    }
    drawerEl.appendChild(h("div", { cls: "drawer-foot" }, chatInput,
      h("button", { cls: "btn btn-primary", type: "button", text: "Send", on: { click: submitChat } })));
    if (!wasOpen) chatInput.focus();
    chat.scrollTop = chat.scrollHeight;
  }

  /* "ollama \u00b7 llama3.2", or "built-in rules" when the configured provider
     could not be reached. The hub already reports both; the console used to
     drop them and show the answer as though it had come from the model. */
  function copilotSource(res) {
    if (!res) return "";
    if (res.degraded) return "built-in rules";
    var parts = [];
    if (res.provider) parts.push(res.provider);
    if (res.model) parts.push(res.model);
    return parts.join(" \u00b7 ");
  }

  function submitChat() {
    if (!chatInput) return;
    var text = chatInput.value.trim();
    if (!text) return;
    chatInput.value = "";
    sendChat(text);
  }

  function sendChat(text) {
    state.chat.push({ who: "you", text: text });
    state.chatBusy = true;
    renderDrawer();
    request("/api/v1/copilot/chat", "POST", { message: text }).then(function (res) {
      state.chatBusy = false;
      state.chat.push({
        who: "copilot",
        text: (res && res.reply) || "(no reply)",
        source: copilotSource(res),
        notice: (res && res.notice) || "",
        degraded: !!(res && res.degraded)
      });
      renderDrawer();
    }).catch(function (e) {
      state.chatBusy = false;
      state.chat.push({ who: "copilot", text: "Copilot unavailable: " + e.message });
      renderDrawer();
    });
  }

  function askAboutAlert(a) {
    showDrawerIfNeeded("copilot");
    var q = "Investigate alert " + a.id + ": " + (a.title || "") + " on " + (a.hostname || a.endpoint_id) +
      ". " + (a.description || "") + " " + (a.details || "");
    sendChat(q.trim());
  }

  function showDrawerIfNeeded(kind) {
    if (openDrawer !== kind) showDrawer(kind);
  }

  /* ------------------------------------------------------ command palette */

  var paletteEl = null;
  var paletteItems = [];
  var paletteCursor = 0;

  function closePalette() {
    if (paletteEl && paletteEl.parentNode) paletteEl.parentNode.removeChild(paletteEl);
    paletteEl = null;
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
    items.push({ group: "Act", label: "Open Copilot drawer", iconId: "i-copilot", hint: "", run: function () { showDrawer("copilot"); } });

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
        cls: "pi", type: "button", "data-cursor": i === paletteCursor ? "true" : "false",
        on: {
          click: function () { closePalette(); it.run(); },
          mouseenter: function () {
            paletteCursor = i;
            Array.prototype.forEach.call(list.querySelectorAll(".pi"), function (b, bi) {
              b.setAttribute("data-cursor", bi === i ? "true" : "false");
            });
          }
        }
      },
        icon(it.iconId),
        h("span", { cls: it.mono ? "t t-mono" : "t", text: it.label }),
        it.hint ? h("span", { cls: "s", text: it.hint }) : null));
    });

    if (!paletteItems.length) {
      list.appendChild(h("div", { cls: "empty", text: "Nothing matches." }));
    }
  }

  function openPalette() {
    if (paletteEl) return;
    paletteCursor = 0;
    var input = h("input", { type: "text", placeholder: "Jump to a host, an address, a section, or an action\u2026", "aria-label": "Command palette" });
    paletteEl = h("div", {
      cls: "palette-wrap",
      on: {
        click: function (e) { if (e.target === paletteEl) closePalette(); }
      }
    },
      h("div", { cls: "palette" },
        input,
        h("div", { cls: "palette-list" }),
        h("div", { cls: "palette-foot" },
          h("span", { text: "enter run" }),
          h("span", { text: "up/down move" }),
          h("span", { text: "esc close" }))));
    document.body.appendChild(paletteEl);
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
        if (it) { closePalette(); it.run(); }
      } else if (e.key === "Escape") {
        e.preventDefault();
        closePalette();
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

  document.addEventListener("keydown", function (e) {
    var mod = IS_MAC ? e.metaKey : e.ctrlKey;
    if (mod && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      openPalette();
      return;
    }

    if (e.key === "Escape") {
      if (paletteEl) { closePalette(); return; }
      if (ctxMenu) { closeCtx(); return; }
      if (themePop) { closeThemePop(); return; }
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
        if (a && !a.evidence.agent) { e.preventDefault(); deployAgent(a); }
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
    if (ctxMenu && !ctxMenu.contains(e.target)) closeCtx();
    if (themePop && !themePop.contains(e.target) && e.target !== $("theme-btn") && !$("theme-btn").contains(e.target)) closeThemePop();
  }, true);

  window.addEventListener("resize", function () {
    closeCtx();
    closeThemePop();
  });

  /* ------------------------------------------------------------- topbar */

  var filterInput = null;

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
    } else if (state.section === "discovery") {
      var cov = state.coverage || {};
      sub = (cov.total_discovered || state.scanAssets.length)
        ? "/ " + (cov.coverage_percent || 0) + "% covered"
        : "/ no sweep yet";
    } else if (state.section === "topology") {
      sub = "/ " + state.topoWindow + " window";
    } else if (state.demo) {
      sub = "/ demo";
    }
    if (state.demo && state.section === "assets") sub += " \u00b7 demo";
    $("crumb-sub").textContent = sub;

    $("hub-version").textContent = HUB_VERSION ? "hub " + HUB_VERSION : "";

    /* The hub returns at most ANOMALY_PAGE unacknowledged anomalies, so a full
       page is a floor and not a count. Printing it as one turned "at least a
       hundred open" into a confident "100", which is the number an operator
       then reasons about. */
    var pip = $("alert-count");
    var open = state.anomalies.length;
    var capped = !!state.anomaliesCapped;
    pip.textContent = capped ? open + "+" : String(open);
    pip.setAttribute("data-n", String(open));
    pip.setAttribute("title", capped
      ? "At least " + open + " open anomalies; the hub returns one page at a time."
      : open + " open " + (open === 1 ? "anomaly" : "anomalies"));

    var health = $("health");
    var hstate = state.lastError ? "down" : (assetStats().offline > 0 ? "degraded" : "ok");
    health.setAttribute("data-state", hstate);
    health.setAttribute("title", state.lastError
      ? "Hub unreachable: " + state.lastError
      : (hstate === "degraded" ? "Hub healthy \u00b7 some endpoints offline" : "Hub healthy"));
    $("health-word").textContent = health.getAttribute("title");
  }

  function renderTopbar() {
    updateCrumb();

    var actions = $("topbar-actions");
    clear(actions);

    if (state.section === "assets") {
      /* The filter field is reused rather than rebuilt: render() runs on every
         five-second poll, and a fresh input would drop the caret mid-word. */
      var input = filterInput;
      if (!input) {
        input = filterInput = h("input", {
          type: "search", id: "filter-input", placeholder: "Filter rows", "aria-label": "Filter rows"
        });
        input.value = state.query;
        input.addEventListener("input", function () {
          state.query = input.value;
          state.cursorKey = "";
          renderBody();
          renderStrip();
          updateCrumb();
        });
      } else if (document.activeElement !== input) {
        input.value = state.query;
      }
      actions.appendChild(input);

      var sel = selectedKeys().length;
      if (sel) {
        actions.appendChild(h("button", {
          cls: "btn", type: "button", text: "Release " + sel,
          on: { click: function () { bulkIsolate(false); } }
        }));
        actions.appendChild(h("button", {
          cls: "btn", type: "button", text: "Isolate " + sel,
          on: { click: function () { bulkIsolate(true); } }
        }));
      }
      if (assetStats().outdated) {
        actions.appendChild(h("button", {
          cls: "btn btn-primary", type: "button", text: "Update agents",
          on: { click: pushAgentUpdates }
        }));
      }
    } else if (state.section === "topology") {
      ["1h", "6h", "24h", "7d"].forEach(function (w) {
        actions.appendChild(h("button", {
          cls: state.topoWindow === w ? "btn btn-primary" : "btn", type: "button", text: w,
          on: {
            click: function () {
              state.topoWindow = w;
              loadTopology().then(render);
            }
          }
        }));
      });
    } else if (state.section === "discovery") {
      actions.appendChild(h("button", {
        cls: "btn", type: "button", text: "Refresh",
        on: { click: refresh }
      }));
    }
  }

  /* --------------------------------------------------------------- render */

  function renderBody() {
    var view = $("view");
    var scrollTop = view.scrollTop;

    if (state.section === "assets") renderAssets();
    else if (state.section === "discovery") renderDiscovery();
    else if (state.section === "topology") renderTopology();
    else if (state.section === "traffic") renderTraffic();
    else if (state.section === "policy") renderPolicy();
    else if (state.section === "audit") renderAudit();
    else if (state.section === "access") renderAccess();

    view.scrollTop = scrollTop;

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
    state.section = section;
    closeRoute();
    closeDrawer();
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
    var jobs = [
      request("/api/v1/hierarchy").then(function (d) { state.hierarchy = arrayOf(d); }),
      request("/api/v1/endpoints").then(function (d) { state.endpoints = arrayOf(d); }),
      request("/api/v1/assets").then(function (d) { state.assetGraph = arrayOf(d); }),
      request("/api/v1/scanner/results").then(function (d) { state.scanAssets = arrayOf(d); }),
      request("/api/v1/scanner/coverage").then(function (d) { state.coverage = d || null; }),
      /* Only used to seed the discovery scan field, but it is the hub's own
         answer to "what network is this", which beats guessing from an
         address. */
      request("/api/v1/locations").then(function (d) { state.locations = arrayOf(d); }),
      request("/api/v1/anomalies").then(function (d) {
        var page = arrayOf(d);
        /* Recorded before the acknowledged ones are filtered out: a full page
           means the hub had more to give, whatever survives the filter. */
        state.anomaliesCapped = page.length >= ANOMALY_PAGE;
        state.anomalies = page.filter(function (a) { return !a.acknowledged; });
      }),
      request("/api/v1/agents/update-status").then(function (d) { state.updateStatus = d || null; }),
      request("/api/v1/mesh/quarantined").then(function (d) { state.meshPeers = arrayOf(d); })
    ];

    if (state.section === "policy") {
      jobs.push(request("/api/v1/policy-groups").then(function (d) { state.policyGroups = arrayOf(d); }));
      jobs.push(request("/api/v1/exclusions").then(function (d) { state.exclusions = arrayOf(d); }));
      jobs.push(request("/api/v1/threatintel/iocs").then(function (d) { state.iocs = arrayOf(d); }));
    }
    if (state.section === "access" && IS_ADMIN) {
      jobs.push(request("/api/v1/operators").then(function (d) {
        state.operators = arrayOf(d && d.operators);
        if (d && Array.isArray(d.roles) && d.roles.length) state.operatorRoles = d.roles;
        state.you = (d && d.you) || "";
      }));
    }
    if (state.section === "audit") {
      jobs.push(request("/api/v1/audit/logs").then(function (d) { state.audit = arrayOf(d); }));
      jobs.push(request("/api/v1/events").then(function (d) { state.events = arrayOf(d); }));
    }
    if (state.section === "traffic" || state.routeKey) {
      jobs.push(request("/api/v1/analytics/summary").then(function (d) { state.analytics = d || null; }));
      jobs.push(request("/api/v1/events").then(function (d) { state.events = arrayOf(d); }));
    }
    if (state.section === "topology") jobs.push(loadTopology());
    if (state.section === "discovery" || state.section === "topology" || state.expandedKey || state.routeKey) {
      jobs.push(request("/api/v1/inference/status").then(function (d) { state.inference = d || null; }));
    }

    return Promise.all(jobs.map(function (p) {
      return p.catch(function (e) {
        state.lastError = e.message;
        return null;
      });
    })).then(function () {
      state.loading = false;
      buildAssets();
      pushHistory(Object.assign({ total: state.assets.length }, assetStats()));
      /* Drop selections for assets that no longer exist, but keep every other
         selection so a five-second refresh never clears the operator's work. */
      Object.keys(state.selected).forEach(function (k) {
        if (!state.assetByKey[k]) delete state.selected[k];
      });
      if (state.expandedKey && !state.assetByKey[state.expandedKey]) state.expandedKey = "";
      if (state.cursorKey && !state.assetByKey[state.cursorKey]) state.cursorKey = "";
      if (state.routeKey && !state.assetByKey[state.routeKey]) closeRoute();
      render();
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
    $("btn-alerts").addEventListener("click", function () { showDrawer("alerts"); });
    $("btn-copilot").addEventListener("click", function () { showDrawer("copilot"); });
    $("theme-btn").addEventListener("click", function (e) {
      e.stopPropagation();
      if (themePop) closeThemePop();
      else openThemePop();
    });

    if (IS_ADMIN) $("rail-access").removeAttribute("hidden");

    /* An operator who signed in as themselves should be able to see who the
       console thinks they are without opening a section to find out. */
    if (OPERATOR && OPERATOR !== "admin") {
      $("signed-in").textContent = OPERATOR + (READ_ONLY ? " \u00b7 read only" : "");
      $("signed-in").title = "Signed in as " + OPERATOR + " (" + roleName(ROLE).toLowerCase() + ")";
    }

    Array.prototype.forEach.call(document.querySelectorAll(".rail-btn"), function (b) {
      b.addEventListener("click", function () { go(b.getAttribute("data-section")); });
    });

    if (state.demo) toast("Demo mode \u2014 synthetic fleet, no live hub data", "warn");
    /* Said once, on arrival. The alternative is letting someone select forty
       hosts and click Isolate to find out. */
    if (READ_ONLY) toast("Read-only role \u2014 the hub refuses any action taken from this console", "warn");

    render();
    refresh();
    setInterval(refresh, 5000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
