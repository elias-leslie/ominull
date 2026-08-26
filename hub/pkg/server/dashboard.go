package server

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ominull Enterprise Threat Nullification Command Center</title>
    <style>
        :root {
            --bg-base: #090d16;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --bg-hover: #374151;
            --border-color: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --cyan: #06b6d4;
            --cyan-glow: rgba(6, 182, 212, 0.25);
            --green: #10b981;
            --green-glow: rgba(16, 185, 129, 0.2);
            --red: #ef4444;
            --red-glow: rgba(239, 68, 68, 0.25);
            --amber: #f59e0b;
            --purple: #8b5cf6;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", monospace; }
        body { background: var(--bg-base); color: var(--text-main); padding: 24px 32px; min-height: 100vh; }

        /* Top Header */
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); margin-bottom: 24px; }
        .logo-group { display: flex; align-items: center; gap: 12px; }
        .logo-badge { background: linear-gradient(135deg, #06b6d4, #3b82f6); width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 18px; color: #fff; box-shadow: 0 0 16px var(--cyan-glow); }
        .logo-title { font-size: 20px; font-weight: 800; letter-spacing: 1.5px; color: #fff; }
        .logo-title span { color: var(--cyan); }
        .live-tag { display: inline-flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); color: var(--green); padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .pulse-dot { width: 7px; height: 7px; background: var(--green); border-radius: 50%; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(1.3); } 100% { opacity: 1; transform: scale(1); } }

        /* Metrics Row */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .metric-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 18px 20px; position: relative; overflow: hidden; }
        .metric-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--cyan); opacity: 0.8; }
        .metric-card.red::before { background: var(--red); }
        .metric-card.green::before { background: var(--green); }
        .metric-card.purple::before { background: var(--purple); }
        .metric-card.amber::before { background: var(--amber); }
        .metric-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; margin-bottom: 6px; }
        .metric-val { font-size: 32px; font-weight: 800; color: #fff; line-height: 1.1; }
        .metric-sub { font-size: 11px; color: var(--text-muted); margin-top: 6px; }

        /* Bulk Command Center Bar */
        .bulk-bar { background: #131c2e; border: 1px solid #1e293b; border-left: 4px solid var(--red); border-radius: 10px; padding: 14px 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3); }
        .bulk-title { font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .bulk-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

        /* Section Containers */
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; margin-top: 24px; }
        .section-title { font-size: 16px; font-weight: 700; letter-spacing: 0.5px; color: #fff; display: flex; align-items: center; gap: 8px; }
        .section-actions { display: flex; gap: 8px; align-items: center; }

        /* Inputs & Buttons */
        input[type="text"], input[type="number"], select { background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 7px 12px; border-radius: 6px; font-size: 13px; outline: none; }
        input[type="text"]:focus, select:focus { border-color: var(--cyan); }
        .btn { background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 7px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
        .btn:hover { background: var(--bg-hover); border-color: #6b7280; }
        .btn-cyan { background: rgba(6, 182, 212, 0.15); border-color: var(--cyan); color: var(--cyan); }
        .btn-cyan:hover { background: rgba(6, 182, 212, 0.3); }
        .btn-isolate { background: rgba(239, 68, 68, 0.15); border-color: var(--red); color: #f87171; }
        .btn-isolate:hover { background: rgba(239, 68, 68, 0.35); box-shadow: 0 0 10px var(--red-glow); }
        .btn-unisolate { background: rgba(16, 185, 129, 0.15); border-color: var(--green); color: #34d399; }
        .btn-unisolate:hover { background: rgba(16, 185, 129, 0.35); box-shadow: 0 0 10px var(--green-glow); }
        .btn-bulk-red { background: #7f1d1d; border-color: var(--red); color: #fecaca; font-weight: 700; }
        .btn-bulk-red:hover { background: #991b1b; }
        .btn-bulk-green { background: #064e3b; border-color: var(--green); color: #a7f3d0; font-weight: 700; }
        .btn-bulk-green:hover { background: #065f46; }

        /* Tables */
        .table-wrap { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: #1a2234; padding: 12px 16px; font-size: 11px; font-weight: 700; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.6px; border-bottom: 1px solid var(--border-color); }
        td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid var(--border-color); color: #e5e7eb; vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: rgba(55, 65, 81, 0.4); }

        /* Badges */
        .badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .badge-online { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-offline { background: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.4); }
        .badge-isolated { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.5); }
        .badge-block { background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 800; }
        .badge-permit { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-ti { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.5); }
        .os-tag { background: #1f2937; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #d1d5db; border: 1px solid #374151; font-family: monospace; }

        /* Modals */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; width: 550px; max-width: 90vw; padding: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8); }
        .modal-title { font-size: 18px; font-weight: 800; margin-bottom: 16px; color: #fff; display: flex; justify-content: space-between; align-items: center; }
        .form-group { margin-bottom: 14px; }
        .form-label { display: block; font-size: 12px; color: var(--text-muted); font-weight: 600; margin-bottom: 6px; text-transform: uppercase; }
        .form-control { width: 100%; }
        .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1f2937; font-size: 13px; }
        .detail-label { color: var(--text-muted); font-weight: 600; }
        .detail-value { font-family: monospace; color: #fff; max-width: 320px; word-break: break-all; text-align: right; }
    </style>
</head>
<body>

    <header>
        <div class="logo-group">
            <div class="logo-badge">Ø</div>
            <div>
                <div class="logo-title">OMINULL <span>ENTERPRISE</span></div>
                <div style="font-size: 11px; color: var(--text-muted);">Kernel-Native Cross-Platform Threat Nullification Hub</div>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 16px;">
            <div class="live-tag"><div class="pulse-dot"></div> TI & TELEMETRY STREAM ACTIVE</div>
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); padding: 5px 12px; border-radius: 6px; font-size: 12px;">
                <span style="color: var(--text-muted); margin-right: 6px;">Master Key:</span>
                <code style="color: var(--cyan);">ominull-master-admin-key</code>
            </div>
        </div>
    </header>

    <!-- Metrics Row -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-title">Monitored Endpoints</div>
            <div class="metric-val" id="metric-endpoints">0</div>
            <div class="metric-sub">Deterministic fleet matrix</div>
        </div>
        <div class="metric-card amber">
            <div class="metric-title">Threat Intel (C2 IOCs)</div>
            <div class="metric-val" id="metric-iocs" style="color: var(--amber);">0</div>
            <div class="metric-sub">Abuse.ch & Emerging Threats</div>
        </div>
        <div class="metric-card purple">
            <div class="metric-title">Active Dynamic Rules</div>
            <div class="metric-val" id="metric-rules" style="color: var(--purple);">0</div>
            <div class="metric-sub">Broadcast to kernel callouts</div>
        </div>
        <div class="metric-card red">
            <div class="metric-title">Isolated Hosts (Quarantine)</div>
            <div class="metric-val" id="metric-isolated" style="color: var(--red);">0</div>
            <div class="metric-sub">Default-deny ring-0 active</div>
        </div>
        <div class="metric-card green">
            <div class="metric-title">Telemetry Events</div>
            <div class="metric-val" id="metric-events" style="color: var(--green);">0</div>
            <div class="metric-sub">Real-time stream decisions</div>
        </div>
    </div>

    <!-- Bulk Threat Nullification Command Bar -->
    <div class="bulk-bar">
        <div class="bulk-title">
            <span style="color: var(--red); font-size: 16px;">🛡️</span>
            <span>Bulk Threat Nullification & Fleet Quarantine</span>
        </div>
        <div class="bulk-actions">
            <button class="btn btn-bulk-red" onclick="executeBulkAction('all', '', true)">🔴 ISOLATE ALL FLEET</button>
            <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'windows', true)">Isolate Windows</button>
            <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'linux', true)">Isolate Linux</button>
            <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'darwin', true)">Isolate macOS</button>
            <button class="btn btn-bulk-green" onclick="executeBulkAction('all', '', false)">🟢 UNISOLATE ALL</button>
        </div>
    </div>

    <!-- Enrolled Endpoints Section -->
    <div class="section-header">
        <div class="section-title">
            <span>Enrolled Fleet Matrix</span>
            <span id="endpoint-count-badge" class="badge badge-online">0 ACTIVE</span>
        </div>
        <div class="section-actions">
            <input type="text" id="ep-search" placeholder="Filter by host, IP or OS..." oninput="renderEndpoints()">
            <button class="btn btn-cyan" onclick="refreshData()">Sync Fleet</button>
        </div>
    </div>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th style="width: 36px;"><input type="checkbox" id="select-all-ep" onchange="toggleSelectAll(this)"></th>
                    <th>Status</th>
                    <th>Hostname</th>
                    <th>Platform / Kernel Engine</th>
                    <th>Endpoint IP</th>
                    <th>Driver Release</th>
                    <th>Isolation State</th>
                    <th>Last Heartbeat</th>
                    <th>Active IR Control</th>
                </tr>
            </thead>
            <tbody id="endpoints-body">
                <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">Syncing endpoint fleet...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Dynamic Policy & Rule Management Section -->
    <div class="section-header">
        <div class="section-title">
            <span>Dynamic Kernel Policy & Threat Rules</span>
            <span id="rules-count-badge" class="badge badge-ti">0 ACTIVE RULES</span>
        </div>
        <div class="section-actions">
            <button class="btn" onclick="syncThreatFeeds()">⚡ Sync TI Feeds</button>
            <button class="btn btn-cyan" onclick="openRuleModal()">+ Add Policy Rule</button>
        </div>
    </div>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Rule Name</th>
                    <th>Match Type</th>
                    <th>Target Value</th>
                    <th>Port / Protocol</th>
                    <th>Verdict Action</th>
                    <th>Deployment Scope</th>
                    <th>Active Status</th>
                    <th>Revoke</th>
                </tr>
            </thead>
            <tbody id="rules-body">
                <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No active policy rules defined.</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Live Telemetry Stream Section -->
    <div class="section-header">
        <div class="section-title">
            <span>Real-Time Threat & Kernel Stream Telemetry</span>
        </div>
        <div class="section-actions">
            <select id="event-verdict-filter" onchange="renderEvents()">
                <option value="ALL">All Verdicts</option>
                <option value="BLOCK">Blocked Only</option>
                <option value="PERMIT">Permitted Only</option>
            </select>
            <input type="text" id="event-search" placeholder="Filter by process or IP..." oninput="renderEvents()">
            <button class="btn" onclick="exportEventsCSV()">Export CSV</button>
        </div>
    </div>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Verdict</th>
                    <th>Kernel / Extension Layer</th>
                    <th>Direction</th>
                    <th>Source Tuple</th>
                    <th>Destination Tuple</th>
                    <th>Proto</th>
                    <th>Process Image Path / PID</th>
                    <th>Inspect</th>
                </tr>
            </thead>
            <tbody id="events-body">
                <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">Waiting for telemetry stream...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Rule Authoring Modal -->
    <div id="rule-modal" class="modal-overlay" onclick="closeRuleModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-title">
                <span>Author Dynamic Kernel Rule</span>
                <span style="font-size: 12px; color: var(--cyan);">Ring-0 Callout Broadcast</span>
            </div>
            <div class="form-group">
                <label class="form-label">Rule Name / Description</label>
                <input type="text" id="rule-name" class="form-control" placeholder="e.g. Block CobaltStrike C2 Subnet">
            </div>
            <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div>
                    <label class="form-label">Match Type</label>
                    <select id="rule-type" class="form-control">
                        <option value="cidr">CIDR Subnet (e.g. 198.51.100.0/24)</option>
                        <option value="ip">Single IPv4 (e.g. 185.220.101.5)</option>
                        <option value="domain">Domain / TLS SNI (e.g. evil-c2.net)</option>
                        <option value="port">Port Only (e.g. 4444)</option>
                        <option value="process">Process Path (e.g. powershell.exe)</option>
                    </select>
                </div>
                <div>
                    <label class="form-label">Target Match Value</label>
                    <input type="text" id="rule-value" class="form-control" placeholder="185.220.101.0/24">
                </div>
            </div>
            <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div>
                    <label class="form-label">Port (0 = All Ports)</label>
                    <input type="number" id="rule-port" class="form-control" value="0">
                </div>
                <div>
                    <label class="form-label">Protocol</label>
                    <select id="rule-proto" class="form-control">
                        <option value="any">Any Protocol</option>
                        <option value="tcp">TCP (6)</option>
                        <option value="udp">UDP (17)</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div>
                    <label class="form-label">Verdict Action</label>
                    <select id="rule-action" class="form-control">
                        <option value="BLOCK">🔴 BLOCK (Drop Traffic)</option>
                        <option value="PERMIT">🟢 PERMIT (Allow Traffic)</option>
                    </select>
                </div>
                <div>
                    <label class="form-label">Deployment Scope</label>
                    <select id="rule-scope" class="form-control">
                        <option value="all">Entire Fleet (All Platforms)</option>
                        <option value="platform:windows">Windows Only (WFP)</option>
                        <option value="platform:linux">Linux Only (eBPF)</option>
                        <option value="platform:darwin">macOS Only (NetworkExt)</option>
                    </select>
                </div>
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px;">
                <button class="btn" onclick="closeRuleModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="saveRule()">Save & Deploy Rule</button>
            </div>
        </div>
    </div>

    <!-- Forensic Inspector Modal -->
    <div id="inspector-modal" class="modal-overlay" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-title">Kernel Telemetry Forensic Inspector</div>
            <div id="modal-details"></div>
            <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                <button class="btn btn-cyan" onclick="closeModal()">Close</button>
            </div>
        </div>
    </div>

    <script>
        var ADMIN_KEY = "ominull-master-admin-key";
        var rawEndpoints = [];
        var rawEvents = [];
        var rawRules = [];
        var rawIOCs = [];
        var selectedIDs = {};

        function fetchAPI(endpoint, method, body) {
            method = method || "GET";
            var opts = {
                method: method,
                headers: { "X-API-Key": ADMIN_KEY, "Content-Type": "application/json" }
            };
            if (body) opts.body = JSON.stringify(body);
            return fetch(endpoint, opts).then(function(res) { return res.json(); });
        }

        function refreshData() {
            Promise.all([
                fetchAPI("/api/v1/endpoints"),
                fetchAPI("/api/v1/events"),
                fetchAPI("/api/v1/rules"),
                fetchAPI("/api/v1/threatintel/iocs")
            ]).then(function(results) {
                var newEndpoints = results[0] || [];
                newEndpoints.sort(function(a, b) {
                    return a.hostname.localeCompare(b.hostname) || a.id.localeCompare(b.id);
                });

                rawEndpoints = newEndpoints;
                rawEvents = results[1] || [];
                rawRules = results[2] || [];
                rawIOCs = results[3] || [];

                document.getElementById("metric-endpoints").innerText = rawEndpoints.length;
                document.getElementById("metric-isolated").innerText = rawEndpoints.filter(function(e) { return e.is_isolated; }).length;
                document.getElementById("metric-events").innerText = rawEvents.length;
                document.getElementById("metric-rules").innerText = rawRules.length;
                document.getElementById("metric-iocs").innerText = rawIOCs.length;
                document.getElementById("endpoint-count-badge").innerText = rawEndpoints.length + " ACTIVE";
                document.getElementById("rules-count-badge").innerText = rawRules.length + " ACTIVE RULES";

                renderEndpoints();
                renderRules();
                renderEvents();
            }).catch(function(err) {
                console.error("Sync error:", err);
            });
        }

        function renderEndpoints() {
            var search = (document.getElementById("ep-search").value || "").toLowerCase();
            var filtered = rawEndpoints.filter(function(ep) {
                return ep.hostname.toLowerCase().includes(search) || (ep.ip || "").toLowerCase().includes(search) || ep.os.toLowerCase().includes(search);
            });

            var tbody = document.getElementById("endpoints-body");
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No endpoints matching search query.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(function(ep) {
                var diff = Math.abs(Date.now() - new Date(ep.last_seen_at).getTime());
                var isOnline = diff < 60000;
                var statusBadge = isOnline ? '<span class="badge badge-online">ONLINE</span>' : '<span class="badge badge-offline">OFFLINE</span>';
                var isoBadge = ep.is_isolated ? '<span class="badge badge-isolated">QUARANTINED</span>' : '<span class="badge badge-online">NORMAL</span>';
                var isoBtn = ep.is_isolated
                    ? '<button class="btn btn-unisolate" onclick="unisolateTarget(\'' + ep.id + '\')">UNISOLATE</button>'
                    : '<button class="btn btn-isolate" onclick="isolateTarget(\'' + ep.id + '\')">ISOLATE HOST</button>';

                var isChecked = selectedIDs[ep.id] ? "checked" : "";

                return '<tr id="ep-row-' + ep.id + '">' +
                    '<td><input type="checkbox" ' + isChecked + ' onchange="toggleSelectEp(\'' + ep.id + '\', this)"></td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td><strong style="color:#fff;">' + ep.hostname + '</strong></td>' +
                    '<td><span class="os-tag">' + ep.os + '</span></td>' +
                    '<td><code>' + (ep.ip || "10.0.0.50") + '</code></td>' +
                    '<td>v' + (ep.driver_version || "1.0.0") + '</td>' +
                    '<td>' + isoBadge + '</td>' +
                    '<td>' + new Date(ep.last_seen_at).toLocaleTimeString() + '</td>' +
                    '<td>' + isoBtn + '</td>' +
                '</tr>';
            }).join("");
        }

        function renderRules() {
            var tbody = document.getElementById("rules-body");
            if (rawRules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No active policy rules defined. Click "+ Add Policy Rule" to deploy.</td></tr>';
                return;
            }

            tbody.innerHTML = rawRules.map(function(r) {
                var actionBadge = r.action === "BLOCK" ? '<span class="badge badge-block">BLOCK</span>' : '<span class="badge badge-permit">PERMIT</span>';
                var portText = r.port > 0 ? ":" + r.port : "Any";
                var protoText = (r.protocol || "any").toUpperCase();

                return '<tr>' +
                    '<td><strong style="color:#fff;">' + r.name + '</strong></td>' +
                    '<td><span class="os-tag">' + r.type.toUpperCase() + '</span></td>' +
                    '<td><code>' + r.value + '</code></td>' +
                    '<td>' + portText + ' / ' + protoText + '</td>' +
                    '<td>' + actionBadge + '</td>' +
                    '<td><span class="os-tag">' + (r.scope || "ALL").toUpperCase() + '</span></td>' +
                    '<td><span class="badge badge-online">ACTIVE</span></td>' +
                    '<td><button class="btn btn-isolate" style="padding: 2px 8px; font-size: 11px;" onclick="deleteRule(\'' + r.id + '\')">Revoke</button></td>' +
                '</tr>';
            }).join("");
        }

        function openRuleModal() {
            document.getElementById("rule-modal").style.display = "flex";
        }

        function closeRuleModal() {
            document.getElementById("rule-modal").style.display = "none";
        }

        function saveRule() {
            var name = document.getElementById("rule-name").value.trim();
            var type = document.getElementById("rule-type").value;
            var value = document.getElementById("rule-value").value.trim();
            var port = parseInt(document.getElementById("rule-port").value, 10) || 0;
            var protocol = document.getElementById("rule-proto").value;
            var action = document.getElementById("rule-action").value;
            var scopeSel = document.getElementById("rule-scope").value;

            if (!name || !value) {
                return alert("Please fill in Rule Name and Target Match Value.");
            }

            var scope = "all";
            var scopeVal = "";
            if (scopeSel.startsWith("platform:")) {
                scope = "platform";
                scopeVal = scopeSel.split(":")[1];
            }

            fetchAPI("/api/v1/rules", "POST", {
                name: name,
                type: type,
                value: value,
                port: port,
                protocol: protocol,
                action: action,
                scope: scope,
                scope_value: scopeVal
            }).then(function() {
                closeRuleModal();
                refreshData();
            });
        }

        function deleteRule(id) {
            if (confirm("Revoke dynamic policy rule " + id + "?")) {
                fetchAPI("/api/v1/rules?id=" + id, "DELETE").then(refreshData);
            }
        }

        function syncThreatFeeds() {
            fetchAPI("/api/v1/threatintel/sync", "POST").then(function(res) {
                alert("Threat intelligence feed synchronization initiated in background.");
                setTimeout(refreshData, 2000);
            });
        }

        function renderEvents() {
            var verdict = document.getElementById("event-verdict-filter").value;
            var search = (document.getElementById("event-search").value || "").toLowerCase();

            var filtered = rawEvents.filter(function(ev) {
                if (verdict !== "ALL" && ev.action !== verdict) return false;
                if (search && !ev.process_path.toLowerCase().includes(search) && !ev.src_ip.includes(search) && !ev.dst_ip.includes(search)) return false;
                return true;
            });

            var tbody = document.getElementById("events-body");
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No telemetry events matching filters.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.slice(0, 50).map(function(ev, idx) {
                var actionBadge = ev.action === "BLOCK" ? '<span class="badge badge-block">BLOCK</span>' : '<span class="badge badge-permit">PERMIT</span>';
                var procName = ev.process_path.split('\\').pop().split('/').pop() || ev.process_path;
                var proto = ev.protocol === 6 ? "TCP" : ev.protocol === 17 ? "UDP" : ev.protocol;

                return '<tr>' +
                    '<td>' + new Date(ev.timestamp).toLocaleTimeString() + '</td>' +
                    '<td>' + actionBadge + '</td>' +
                    '<td><code>' + ev.layer + '</code></td>' +
                    '<td>' + ev.direction + '</td>' +
                    '<td>' + ev.src_ip + ':' + ev.src_port + '</td>' +
                    '<td>' + ev.dst_ip + ':' + ev.dst_port + '</td>' +
                    '<td>' + proto + '</td>' +
                    '<td title="' + ev.process_path + '">PID ' + ev.process_id + ' (' + procName + ')</td>' +
                    '<td><button class="btn" style="padding: 2px 8px; font-size: 11px;" onclick="inspectEvent(' + idx + ')">Inspect</button></td>' +
                '</tr>';
            }).join("");
        }

        function inspectEvent(idx) {
            var ev = rawEvents[idx];
            if (!ev) return;
            var proto = ev.protocol === 6 ? "TCP (6)" : ev.protocol === 17 ? "UDP (17)" : ev.protocol;
            var html = '<div class="detail-row"><span class="detail-label">Timestamp</span><span class="detail-value">' + ev.timestamp + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Endpoint ID</span><span class="detail-value">' + ev.endpoint_id + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Action Verdict</span><span class="detail-value">' + ev.action + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Kernel Layer</span><span class="detail-value">' + ev.layer + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Flow Direction</span><span class="detail-value">' + ev.direction + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Source Tuple</span><span class="detail-value">' + ev.src_ip + ':' + ev.src_port + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Destination Tuple</span><span class="detail-value">' + ev.dst_ip + ':' + ev.dst_port + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Transport Protocol</span><span class="detail-value">' + proto + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Process ID (PID)</span><span class="detail-value">' + ev.process_id + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Full Image Path</span><span class="detail-value">' + ev.process_path + '</span></div>';

            document.getElementById("modal-details").innerHTML = html;
            document.getElementById("inspector-modal").style.display = "flex";
        }

        function closeModal() {
            document.getElementById("inspector-modal").style.display = "none";
        }

        function isolateTarget(endpointId) {
            if (confirm("Trigger microsecond kernel isolation for " + endpointId + "?")) {
                fetchAPI("/api/v1/endpoints/isolate", "POST", { endpoint_id: endpointId, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        function unisolateTarget(endpointId) {
            fetchAPI("/api/v1/endpoints/unisolate", "POST", { endpoint_id: endpointId }).then(refreshData);
        }

        function executeBulkAction(scope, value, enable) {
            var actionText = enable ? "ISOLATE (Default-Deny Quarantine)" : "UNISOLATE (Normal)";
            var targetDesc = scope === "all" ? "the ENTIRE fleet" : "all " + value + " endpoints";
            if (confirm("CRITICAL ACTION: Are you sure you want to " + actionText + " " + targetDesc + "?")) {
                var url = enable ? "/api/v1/endpoints/isolate-bulk" : "/api/v1/endpoints/unisolate-bulk";
                fetchAPI(url, "POST", { scope: scope, value: value, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        function exportEventsCSV() {
            if (rawEvents.length === 0) return alert("No events to export.");
            var csv = "Timestamp,EndpointID,Action,Layer,Direction,SrcIP,SrcPort,DstIP,DstPort,Protocol,PID,ProcessPath\n";
            rawEvents.forEach(function(e) {
                csv += [e.timestamp, e.endpoint_id, e.action, e.layer, e.direction, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.protocol, e.process_id, '"' + e.process_path.replace(/"/g, '""') + '"'].join(",") + "\n";
            });
            var blob = new Blob([csv], { type: "text/csv" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "ominull_telemetry_" + Date.now() + ".csv";
            a.click();
        }

        refreshData();
        setInterval(refreshData, 3000);
    </script>
</body>
</html>`
