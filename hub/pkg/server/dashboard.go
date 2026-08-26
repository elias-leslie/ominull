package server

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ominull Unified Threat Nullification Hub</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-bright: #f0f6fc;
            --accent: #58a6ff;
            --green: #2ea043;
            --red: #da3633;
            --yellow: #d29922;
            --purple: #bc8cff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg); color: var(--text); padding: 24px; }
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
        .logo { font-size: 24px; font-weight: bold; color: var(--text-bright); letter-spacing: 2px; }
        .logo span { color: var(--accent); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
        .card h3 { font-size: 13px; color: #8b949e; text-transform: uppercase; margin-bottom: 8px; }
        .card .value { font-size: 28px; font-weight: bold; color: var(--text-bright); }
        .section-title { font-size: 18px; font-weight: 600; color: var(--text-bright); margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
        table { width: 100%; border-collapse: collapse; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 24px; }
        th, td { padding: 12px 16px; text-align: left; font-size: 13px; border-bottom: 1px solid var(--border); }
        th { background: #21262d; color: #8b949e; font-weight: 600; }
        tr:hover { background: #1f242c; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge-online { background: rgba(46, 160, 67, 0.2); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.4); }
        .badge-offline { background: rgba(139, 148, 158, 0.2); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.4); }
        .badge-isolated { background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid rgba(218, 54, 51, 0.4); }
        .badge-block { background: rgba(218, 54, 51, 0.2); color: #f85149; }
        .badge-permit { background: rgba(46, 160, 67, 0.2); color: #3fb950; }
        .btn { padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid var(--border); background: #21262d; color: var(--text-bright); transition: 0.15s ease; }
        .btn:hover { background: #30363d; }
        .btn-isolate { background: rgba(218, 54, 51, 0.2); color: #f85149; border-color: rgba(218, 54, 51, 0.5); }
        .btn-isolate:hover { background: rgba(218, 54, 51, 0.4); }
        .btn-unisolate { background: rgba(46, 160, 67, 0.2); color: #3fb950; border-color: rgba(46, 160, 67, 0.5); }
        .btn-unisolate:hover { background: rgba(46, 160, 67, 0.4); }
        .code-box { background: #000; border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; color: #7ee787; overflow-x: auto; margin-top: 8px; }
    </style>
</head>
<body>
    <header>
        <div class="logo">OMINULL <span>//</span> HUB</div>
        <div>
            <span style="font-size: 12px; color: #8b949e; margin-right: 8px;">Master Key:</span>
            <code style="background: #21262d; padding: 4px 8px; border-radius: 4px; font-size: 12px; color: var(--accent);">ominull-master-admin-key</code>
        </div>
    </header>

    <div class="grid">
        <div class="card">
            <h3>Active Endpoints</h3>
            <div class="value" id="count-endpoints">0</div>
        </div>
        <div class="card">
            <h3>Isolated Targets</h3>
            <div class="value" id="count-isolated" style="color: var(--red);">0</div>
        </div>
        <div class="card">
            <h3>Kernel Events Logged</h3>
            <div class="value" id="count-events" style="color: var(--green);">0</div>
        </div>
        <div class="card">
            <h3>Active Tenants</h3>
            <div class="value" id="count-tenants" style="color: var(--purple);">1</div>
        </div>
    </div>

    <div class="section-title">
        <span>Enrolled Endpoints (Windows / Linux / macOS)</span>
        <button class="btn" onclick="refreshData()">Refresh</button>
    </div>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Hostname</th>
                <th>OS / Platform</th>
                <th>IP Address</th>
                <th>Driver Version</th>
                <th>Isolation State</th>
                <th>Last Seen</th>
                <th>Active IR Controls</th>
            </tr>
        </thead>
        <tbody id="endpoints-body">
            <tr><td colspan="8" style="text-align: center; color: #8b949e;">Loading endpoints...</td></tr>
        </tbody>
    </table>

    <div class="section-title">Real-Time Threat & Kernel Stream Telemetry</div>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Layer</th>
                <th>Direction</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>PID / Process Image Path</th>
            </tr>
        </thead>
        <tbody id="events-body">
            <tr><td colspan="8" style="text-align: center; color: #8b949e;">Listening for live telemetry...</td></tr>
        </tbody>
    </table>

    <div class="section-title">Automated 1-Line Remote Deployment Bootstrappers</div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px;">
        <div class="card">
            <h3>Windows 11 / Server 2025 (PowerShell / WinRM / EDR Live Response)</h3>
            <div class="code-box">iwr -useb http://10.0.0.57:9999/bootstrap.ps1 | iex</div>
        </div>
        <div class="card">
            <h3>Linux (Debian / Ubuntu / RHEL via SSH / Ansible)</h3>
            <div class="code-box">curl -sSL http://10.0.0.57:9999/bootstrap.sh | sudo bash</div>
        </div>
    </div>

    <script>
        var ADMIN_KEY = "ominull-master-admin-key";

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
                var endpoints = results[0] || [];
                var events = results[1] || [];
                var tenants = results[2] || [];

                document.getElementById("count-endpoints").innerText = endpoints.length;
                document.getElementById("count-isolated").innerText = endpoints.filter(function(e) { return e.is_isolated; }).length;
                document.getElementById("count-events").innerText = events.length;
                document.getElementById("count-tenants").innerText = tenants.length;

                var epBody = document.getElementById("endpoints-body");
                if (endpoints.length === 0) {
                    epBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #8b949e;">No active endpoints enrolled yet. Run a 1-line bootstrap script above to enroll an endpoint.</td></tr>';
                } else {
                    epBody.innerHTML = endpoints.map(function(ep) {
                        var statusBadge = ep.status === "online" ? '<span class="badge badge-online">ONLINE</span>' : '<span class="badge badge-offline">OFFLINE</span>';
                        var isoBadge = ep.is_isolated ? '<span class="badge badge-isolated">QUARANTINED</span>' : '<span class="badge badge-online">NORMAL</span>';
                        var isoBtn = ep.is_isolated
                            ? '<button class="btn btn-unisolate" onclick="unisolateTarget(\'' + ep.id + '\')">UNISOLATE</button>'
                            : '<button class="btn btn-isolate" onclick="isolateTarget(\'' + ep.id + '\')">ISOLATE HOST</button>';

                        return '<tr>' +
                            '<td>' + statusBadge + '</td>' +
                            '<td><strong>' + ep.hostname + '</strong></td>' +
                            '<td>' + ep.os + '</td>' +
                            '<td><code>' + (ep.ip || "10.0.0.110") + '</code></td>' +
                            '<td>v' + (ep.driver_version || "1.0.0") + '</td>' +
                            '<td>' + isoBadge + '</td>' +
                            '<td>' + new Date(ep.last_seen_at).toLocaleTimeString() + '</td>' +
                            '<td>' + isoBtn + '</td>' +
                        '</tr>';
                    }).join("");
                }

                var evBody = document.getElementById("events-body");
                if (events.length === 0) {
                    evBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #8b949e;">No events logged yet.</td></tr>';
                } else {
                    evBody.innerHTML = events.slice(0, 50).map(function(ev) {
                        var actionBadge = ev.action === "BLOCK" ? '<span class="badge badge-block">BLOCK</span>' : '<span class="badge badge-permit">PERMIT</span>';
                        var procName = ev.process_path.split('\\').pop() || ev.process_path;
                        return '<tr>' +
                            '<td>' + new Date(ev.timestamp).toLocaleTimeString() + '</td>' +
                            '<td>' + actionBadge + '</td>' +
                            '<td><code>' + ev.layer + '</code></td>' +
                            '<td>' + ev.direction + '</td>' +
                            '<td>' + ev.src_ip + ':' + ev.src_port + '</td>' +
                            '<td>' + ev.dst_ip + ':' + ev.dst_port + '</td>' +
                            '<td>' + (ev.protocol === 6 ? "TCP" : ev.protocol === 17 ? "UDP" : ev.protocol) + '</td>' +
                            '<td title="' + ev.process_path + '">PID ' + ev.process_id + ' (' + procName + ')</td>' +
                        '</tr>';
                    }).join("");
                }
            }).catch(function(err) {
                console.error("Failed to refresh data:", err);
            });
        }

        function isolateTarget(endpointId) {
            if (confirm("Are you sure you want to instantly quarantine endpoint " + endpointId + " at the kernel layer?")) {
                fetchAPI("/api/v1/endpoints/isolate", "POST", { endpoint_id: endpointId, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        function unisolateTarget(endpointId) {
            fetchAPI("/api/v1/endpoints/unisolate", "POST", { endpoint_id: endpointId }).then(refreshData);
        }

        refreshData();
        setInterval(refreshData, 3000);
    </script>
</body>
</html>`
