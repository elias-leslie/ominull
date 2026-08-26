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
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }
        .metric-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 18px 20px; position: relative; overflow: hidden; }
        .metric-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--cyan); opacity: 0.8; }
        .metric-card.red::before { background: var(--red); }
        .metric-card.green::before { background: var(--green); }
        .metric-card.purple::before { background: var(--purple); }
        .metric-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; margin-bottom: 6px; }
        .metric-val { font-size: 32px; font-weight: 800; color: #fff; line-height: 1.1; }
        .metric-sub { font-size: 11px; color: var(--text-muted); margin-top: 6px; }

        /* Section Containers */
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; margin-top: 24px; }
        .section-title { font-size: 16px; font-weight: 700; letter-spacing: 0.5px; color: #fff; display: flex; align-items: center; gap: 8px; }
        .section-actions { display: flex; gap: 8px; align-items: center; }

        /* Inputs & Buttons */
        input[type="text"], select { background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 7px 12px; border-radius: 6px; font-size: 13px; outline: none; }
        input[type="text"]:focus { border-color: var(--cyan); }
        .btn { background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 7px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
        .btn:hover { background: var(--bg-hover); border-color: #6b7280; }
        .btn-cyan { background: rgba(6, 182, 212, 0.15); border-color: var(--cyan); color: var(--cyan); }
        .btn-cyan:hover { background: rgba(6, 182, 212, 0.3); }
        .btn-isolate { background: rgba(239, 68, 68, 0.15); border-color: var(--red); color: #f87171; }
        .btn-isolate:hover { background: rgba(239, 68, 68, 0.35); box-shadow: 0 0 10px var(--red-glow); }
        .btn-unisolate { background: rgba(16, 185, 129, 0.15); border-color: var(--green); color: #34d399; }
        .btn-unisolate:hover { background: rgba(16, 185, 129, 0.35); box-shadow: 0 0 10px var(--green-glow); }

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
        .os-tag { background: #1f2937; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #d1d5db; border: 1px solid #374151; font-family: monospace; }

        /* Jump Kits Grid */
        .jumpkits-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
        .jumpkit-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 16px 20px; }
        .jumpkit-card h4 { font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
        .code-snippet { background: #000; border: 1px solid #374151; border-radius: 6px; padding: 10px 14px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; color: #34d399; display: flex; justify-content: space-between; align-items: center; }
        .copy-btn { background: #1f2937; border: 1px solid #374151; color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 11px; cursor: pointer; }
        .copy-btn:hover { background: var(--cyan); color: #000; }

        /* Modal Inspector */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; width: 550px; max-width: 90vw; padding: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8); }
        .modal-title { font-size: 18px; font-weight: 800; margin-bottom: 16px; color: #fff; }
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
            <div class="live-tag"><div class="pulse-dot"></div> TELEMETRY STREAM ACTIVE</div>
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
            <div class="metric-sub">Active Windows, Linux & macOS nodes</div>
        </div>
        <div class="metric-card red">
            <div class="metric-title">Isolated Hosts (Quarantine)</div>
            <div class="metric-val" id="metric-isolated" style="color: var(--red);">0</div>
            <div class="metric-sub">Kernel default-deny active</div>
        </div>
        <div class="metric-card green">
            <div class="metric-title">Telemetry Events Logged</div>
            <div class="metric-val" id="metric-events" style="color: var(--green);">0</div>
            <div class="metric-sub">Inbound / Outbound flow decisions</div>
        </div>
        <div class="metric-card purple">
            <div class="metric-title">Active Tenants</div>
            <div class="metric-val" id="metric-tenants" style="color: var(--purple);">1</div>
            <div class="metric-sub">Isolated multi-tenant partitions</div>
        </div>
    </div>

    <!-- Enrolled Endpoints Section -->
    <div class="section-header">
        <div class="section-title">
            <span>Enrolled Fleet Matrix</span>
            <span id="endpoint-count-badge" class="badge badge-online">3 ACTIVE</span>
        </div>
        <div class="section-actions">
            <input type="text" id="ep-search" placeholder="Filter by host or IP..." oninput="renderEndpoints()">
            <button class="btn btn-cyan" onclick="refreshData()">Sync Fleet</button>
        </div>
    </div>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
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
                <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Syncing endpoint fleet...</td></tr>
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

    <!-- 1-Line Remote Deployment Jump-Kits -->
    <div class="section-header">
        <div class="section-title">Automated 1-Line Remote Deployment Jump-Kits</div>
    </div>
    <div class="jumpkits-grid">
        <div class="jumpkit-card">
            <h4>
                <span>Windows 11 / Server 2025 (PowerShell / WinRM / EDR)</span>
                <span class="os-tag">WFP KERNEL CALLOUT</span>
            </h4>
            <div class="code-snippet">
                <span id="win-cmd">iwr -useb http://10.0.0.57:9999/bootstrap.ps1 | iex</span>
                <button class="copy-btn" onclick="copyToClipboard('win-cmd', this)">Copy</button>
            </div>
        </div>
        <div class="jumpkit-card">
            <h4>
                <span>Linux (Debian / Ubuntu / RHEL via SSH / Ansible)</span>
                <span class="os-tag">eBPF TC ENGINE</span>
            </h4>
            <div class="code-snippet">
                <span id="linux-cmd">curl -sSL http://10.0.0.57:9999/bootstrap.sh | sudo bash</span>
                <button class="copy-btn" onclick="copyToClipboard('linux-cmd', this)">Copy</button>
            </div>
        </div>
    </div>

    <!-- Modal Event Detail Inspector -->
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
                fetchAPI("/api/v1/tenants")
            ]).then(function(results) {
                rawEndpoints = results[0] || [];
                rawEvents = results[1] || [];
                var tenants = results[2] || [];

                document.getElementById("metric-endpoints").innerText = rawEndpoints.length;
                document.getElementById("metric-isolated").innerText = rawEndpoints.filter(function(e) { return e.is_isolated; }).length;
                document.getElementById("metric-events").innerText = rawEvents.length;
                document.getElementById("metric-tenants").innerText = tenants.length;
                document.getElementById("endpoint-count-badge").innerText = rawEndpoints.length + " ACTIVE";

                renderEndpoints();
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
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No endpoints matching search query.</td></tr>';
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

                return '<tr>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td><strong style="color:#fff;">' + ep.hostname + '</strong></td>' +
                    '<td><span class="os-tag">' + ep.os + '</span></td>' +
                    '<td><code>' + (ep.ip || "10.0.0.110") + '</code></td>' +
                    '<td>v' + (ep.driver_version || "1.0.0") + '</td>' +
                    '<td>' + isoBadge + '</td>' +
                    '<td>' + new Date(ep.last_seen_at).toLocaleTimeString() + '</td>' +
                    '<td>' + isoBtn + '</td>' +
                '</tr>';
            }).join("");
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
            if (confirm("Are you sure you want to trigger microsecond kernel isolation for " + endpointId + "?")) {
                fetchAPI("/api/v1/endpoints/isolate", "POST", { endpoint_id: endpointId, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        function unisolateTarget(endpointId) {
            fetchAPI("/api/v1/endpoints/unisolate", "POST", { endpoint_id: endpointId }).then(refreshData);
        }

        function copyToClipboard(elementId, btn) {
            var text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(function() {
                var orig = btn.innerText;
                btn.innerText = "Copied!";
                btn.style.background = "var(--green)";
                setTimeout(function() {
                    btn.innerText = orig;
                    btn.style.background = "";
                }, 1500);
            });
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
