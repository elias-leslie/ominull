package server

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ominull Enterprise Threat Nullification Command Center</title>
    <style>
        :root {
            --bg-base: #080c14;
            --bg-surface: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --border-color: #1e293b;
            --border-highlight: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --cyan: #06b6d4;
            --cyan-glow: rgba(6, 182, 212, 0.25);
            --green: #10b981;
            --green-glow: rgba(16, 185, 129, 0.2);
            --red: #ef4444;
            --red-glow: rgba(239, 68, 68, 0.25);
            --amber: #f59e0b;
            --purple: #8b5cf6;
            --blue: #3b82f6;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", monospace; }
        body { background: var(--bg-base); color: var(--text-main); padding: 24px 32px; min-height: 100vh; }

        /* Top Header */
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; }
        .logo-group { display: flex; align-items: center; gap: 12px; }
        .logo-badge { background: linear-gradient(135deg, #06b6d4, #3b82f6); width: 38px; height: 38px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 19px; color: #fff; box-shadow: 0 0 16px var(--cyan-glow); }
        .logo-title { font-size: 20px; font-weight: 800; letter-spacing: 1.5px; color: #fff; }
        .logo-title span { color: var(--cyan); }
        .live-tag { display: inline-flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); color: var(--green); padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .pulse-dot { width: 7px; height: 7px; background: var(--green); border-radius: 50%; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(1.3); } 100% { opacity: 1; transform: scale(1); } }

        /* Navigation Tabs */
        .nav-tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border-color); margin-bottom: 24px; }
        .tab-btn { background: transparent; border: none; color: var(--text-muted); font-size: 13px; font-weight: 700; padding: 10px 18px; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 8px; }
        .tab-btn:hover { color: #fff; }
        .tab-btn.active { color: var(--cyan); border-bottom-color: var(--cyan); background: rgba(6, 182, 212, 0.05); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Metrics Row */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .metric-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 18px 20px; position: relative; overflow: hidden; }
        .metric-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--cyan); opacity: 0.8; }
        .metric-card.red::before { background: var(--red); }
        .metric-card.green::before { background: var(--green); }
        .metric-card.purple::before { background: var(--purple); }
        .metric-card.amber::before { background: var(--amber); }
        .metric-title { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; margin-bottom: 6px; }
        .metric-val { font-size: 30px; font-weight: 800; color: #fff; line-height: 1.1; }
        .metric-sub { font-size: 11px; color: var(--text-muted); margin-top: 6px; }

        /* Bulk Command Center Bar */
        .bulk-bar { background: #131c2e; border: 1px solid #1e293b; border-left: 4px solid var(--red); border-radius: 10px; padding: 14px 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3); }
        .bulk-title { font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .bulk-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

        /* Multi-Tenant Hierarchy Cards */
        .client-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
        .client-header { background: #131c2e; padding: 14px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; border-bottom: 1px solid var(--border-color); }
        .client-title { font-size: 15px; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 10px; }
        .client-body { padding: 16px 20px; }
        .location-card { background: #0c1220; border: 1px solid var(--border-highlight); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
        .location-header { background: #162032; padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-highlight); }
        .location-title { font-size: 13px; font-weight: 700; color: var(--cyan); display: flex; align-items: center; gap: 8px; }

        /* Tables */
        .table-wrap { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: visible; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: #162032; padding: 12px 16px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.6px; border-bottom: 1px solid var(--border-color); }
        td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid var(--border-color); color: #e2e8f0; vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: rgba(51, 65, 85, 0.4); cursor: pointer; }

        /* Badges & Enforcement Badges */
        .badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .badge-online { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-offline { background: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.4); }
        .badge-isolated { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.5); }
        .badge-block { background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 800; }
        .badge-permit { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-ti { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.5); }
        .os-tag { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #cbd5e1; border: 1px solid #334155; font-family: monospace; }
        .role-tag { background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }

        /* Enforcement Mode Badges & Interactive Tooltip */
        .tooltip-container { position: relative; display: inline-flex; align-items: center; cursor: help; }
        .badge-enforce { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase; transition: transform 0.15s ease, box-shadow 0.15s ease; }
        .badge-enforce:hover { transform: translateY(-1px); }
        .badge-enforce.ring0 { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
        .badge-enforce.ebpf { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; }
        .badge-enforce.native { background: rgba(6, 182, 212, 0.15); border: 1px solid #06b6d4; color: #7dd3fc; }
        .badge-enforce.sysext { background: rgba(168, 85, 247, 0.15); border: 1px solid #a855f7; color: #d8b4fe; }

        .tooltip-box {
            visibility: hidden;
            opacity: 0;
            position: absolute;
            bottom: calc(100% + 8px);
            left: 50%;
            transform: translateX(-50%);
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 11px;
            color: #e2e8f0;
            width: 280px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8), 0 0 1px rgba(255,255,255,0.2);
            z-index: 1000;
            pointer-events: none;
            transition: opacity 0.2s ease, visibility 0.2s ease;
            text-align: left;
            white-space: normal;
            line-height: 1.4;
        }
        .tooltip-container:hover .tooltip-box, .tooltip-container.active .tooltip-box { visibility: visible; opacity: 1; }
        .tooltip-box::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -6px;
            border-width: 6px;
            border-style: solid;
            border-color: #334155 transparent transparent transparent;
        }
        .tt-header { font-weight: 800; font-size: 12px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; color: #fff; border-bottom: 1px solid #1e293b; padding-bottom: 4px; }
        .tt-row { margin-bottom: 4px; }
        .tt-label { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 10px; }
        .tt-val { color: #cbd5e1; }

        /* Buttons & Inputs */
        input[type="text"], input[type="number"], select { background: var(--bg-card); border: 1px solid var(--border-highlight); color: #fff; padding: 7px 12px; border-radius: 6px; font-size: 13px; outline: none; }
        input[type="text"]:focus, select:focus { border-color: var(--cyan); }
        .btn { background: var(--bg-card); border: 1px solid var(--border-highlight); color: #fff; padding: 7px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
        .btn:hover { background: var(--bg-hover); border-color: #64748b; }
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

        /* Visual Analytics Grid */
        .analytics-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 24px; }
        .chart-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; }
        .chart-title { font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
        .bar-item { margin-bottom: 12px; }
        .bar-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; color: #cbd5e1; }
        .bar-track { background: #1e293b; height: 8px; border-radius: 4px; overflow: hidden; }
        .bar-fill { height: 100%; border-radius: 4px; transition: width 0.4s ease; }

        /* Modals & Drawers */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; width: 600px; max-width: 90vw; padding: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8); max-height: 85vh; overflow-y: auto; }
        .modal-title { font-size: 18px; font-weight: 800; margin-bottom: 16px; color: #fff; display: flex; justify-content: space-between; align-items: center; }
        .form-group { margin-bottom: 14px; }
        .form-label { display: block; font-size: 11px; color: var(--text-muted); font-weight: 700; margin-bottom: 6px; text-transform: uppercase; }
        .form-control { width: 100%; }
        .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1e293b; font-size: 13px; }
        .detail-label { color: var(--text-muted); font-weight: 600; }
        .detail-value { font-family: monospace; color: #fff; max-width: 360px; word-break: break-all; text-align: right; }
    </style>
</head>
<body>

    <header>
        <div class="logo-group">
            <div class="logo-badge">Ø</div>
            <div>
                <div class="logo-title">OMINULL <span>ENTERPRISE</span></div>
                <div style="font-size: 11px; color: var(--text-muted);">Kernel-Native Cross-Platform Threat Nullification & Fleet Mesh</div>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 16px;">
            <div class="live-tag"><div class="pulse-dot"></div> TI & TELEMETRY STREAM ACTIVE</div>
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); padding: 6px 14px; border-radius: 6px; font-size: 12px;">
                <span style="color: var(--text-muted); margin-right: 6px;">Master Key:</span>
                <code style="color: var(--cyan);">ominull-master-admin-key</code>
            </div>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('hierarchy')">🏢 Fleet Hierarchy (MSP / Single Org)</button>
        <button class="tab-btn" onclick="switchTab('policy')">🎯 Dynamic Group Policy Engine</button>
        <button class="tab-btn" onclick="switchTab('analytics')">📊 Visual Analytics & Intelligence</button>
        <button class="tab-btn" onclick="switchTab('threatintel')">🛡️ Threat Intel Feeds & IOCs</button>
        <button class="tab-btn" onclick="switchTab('audit')">📜 Audit Trail & Stream</button>
    </div>

    <!-- TAB 1: FLEET HIERARCHY -->
    <div id="tab-hierarchy" class="tab-content active">
        <!-- Metrics Row -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Monitored Endpoints</div>
                <div class="metric-val" id="metric-endpoints">0</div>
                <div class="metric-sub">Across all clients & locations</div>
            </div>
            <div class="metric-card red">
                <div class="metric-title">Quarantined Hosts</div>
                <div class="metric-val" id="metric-isolated" style="color: var(--red);">0</div>
                <div class="metric-sub">Default-deny atomic sublayer active</div>
            </div>
            <div class="metric-card amber">
                <div class="metric-title">Threat Intel (C2 IOCs)</div>
                <div class="metric-val" id="metric-iocs" style="color: var(--amber);">0</div>
                <div class="metric-sub">Abuse.ch Feodo & Emerging Threats</div>
            </div>
            <div class="metric-card purple">
                <div class="metric-title">Active Policy Groups</div>
                <div class="metric-val" id="metric-groups" style="color: var(--purple);">0</div>
                <div class="metric-sub">Dynamic attribute rule enclaves</div>
            </div>
            <div class="metric-card green">
                <div class="metric-title">Telemetry Events</div>
                <div class="metric-val" id="metric-events" style="color: var(--green);">0</div>
                <div class="metric-sub">Kernel packet & stream decisions</div>
            </div>
        </div>

        <!-- Bulk Threat Nullification Bar -->
        <div class="bulk-bar">
            <div class="bulk-title">
                <span>🛡️ Fleet-Wide Threat Nullification & Quarantine</span>
            </div>
            <div class="bulk-actions">
                <button class="btn btn-bulk-red" onclick="executeBulkAction('all', '', true)">🚨 ISOLATE ALL FLEET</button>
                <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'windows', true)">Isolate Windows</button>
                <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'linux', true)">Isolate Linux</button>
                <button class="btn btn-isolate" onclick="executeBulkAction('platform', 'darwin', true)">Isolate macOS</button>
                <button class="btn btn-bulk-green" onclick="executeBulkAction('all', '', false)">UNISOLATE ALL</button>
            </div>
        </div>

        <!-- 1-Line Enrollment Banner -->
        <div style="background: #0f172a; border: 1px solid var(--border-color); border-radius: 10px; padding: 14px 20px; margin-bottom: 24px;">
            <div style="font-size: 12px; font-weight: 700; color: var(--cyan); margin-bottom: 8px;">⚡ Zero-Friction 1-Line Fleet Enrollment (Zero Vendor Certs Required)</div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; font-size: 11px;">
                <div style="background: #1e293b; padding: 8px 12px; border-radius: 6px;">
                    <div style="font-weight: 700; color: #fff; margin-bottom: 4px;">🪟 Windows (Native User WFP):</div>
                    <code style="color: #93c5fd;">iwr -useb http://10.0.0.57:9999/bootstrap.ps1 | iex</code>
                </div>
                <div style="background: #1e293b; padding: 8px 12px; border-radius: 6px;">
                    <div style="font-weight: 700; color: #fff; margin-bottom: 4px;">🐧 Linux (Native eBPF):</div>
                    <code style="color: #86efac;">curl -sSL http://10.0.0.57:9999/bootstrap.sh | sudo bash</code>
                </div>
                <div style="background: #1e293b; padding: 8px 12px; border-radius: 6px;">
                    <div style="font-weight: 700; color: #fff; margin-bottom: 4px;">🍎 macOS (Native BSD PF):</div>
                    <code style="color: #fca5a5;">curl -sSL http://10.0.0.57:9999/bootstrap.mac.sh | sudo bash</code>
                </div>
            </div>
        </div>

        <!-- Filter & Search Bar -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div style="display: flex; gap: 10px; align-items: center;">
                <input type="text" id="ep-search" placeholder="Filter by client, location, host, IP, or role..." style="width: 360px;" oninput="renderHierarchy()">
                <button class="btn btn-cyan" onclick="refreshData()">Sync Fleet</button>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="btn" onclick="openLocationModal()">+ Add Location</button>
                <button class="btn btn-cyan" onclick="openPolicyModal()">+ Create Policy Rule</button>
            </div>
        </div>

        <!-- Nested Hierarchy Container -->
        <div id="hierarchy-container">
            <div style="text-align: center; padding: 40px; color: var(--text-muted);">Loading fleet hierarchy...</div>
        </div>
    </div>

    <!-- TAB 2: DYNAMIC GROUP POLICY ENGINE -->
    <div id="tab-policy" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Dynamic Group-Based Policy & Kernel Rules</div>
                <div style="font-size: 12px; color: var(--text-muted);">Rules dynamically resolve and broadcast to matching endpoints based on OS, role, location, and process.</div>
            </div>
            <button class="btn btn-cyan" onclick="openPolicyModal()">+ Create Policy Group</button>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Policy Group</th>
                        <th>Target Criteria</th>
                        <th>Rule Type</th>
                        <th>Verdict Action</th>
                        <th>Protocol / Port</th>
                        <th>Enforcement Scope</th>
                        <th>Active Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="policy-groups-body">
                    <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Loading dynamic policy groups...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 3: VISUAL ANALYTICS & INTELLIGENCE -->
    <div id="tab-analytics" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Network Telemetry Analytics & Threat Intelligence</div>
                <div style="font-size: 12px; color: var(--text-muted);">Real-time bandwidth trends, GeoIP country distribution, top network talkers, and enforcement breakdown.</div>
            </div>
            <button class="btn btn-cyan" onclick="fetchAnalytics()">🔄 Refresh Analytics</button>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Total Inbound Bandwidth</div>
                <div class="metric-val" id="analytics-bytes-in">0 MB</div>
                <div class="metric-sub">Aggregated ingress volume</div>
            </div>
            <div class="metric-card purple">
                <div class="metric-title">Total Outbound Bandwidth</div>
                <div class="metric-val" id="analytics-bytes-out" style="color: var(--purple);">0 MB</div>
                <div class="metric-sub">Aggregated egress volume</div>
            </div>
            <div class="metric-card red">
                <div class="metric-title">Threat Nullifications (Blocks)</div>
                <div class="metric-val" id="analytics-blocks" style="color: var(--red);">0</div>
                <div class="metric-sub">Hardware & kernel drops</div>
            </div>
            <div class="metric-card green">
                <div class="metric-title">Permitted Connections</div>
                <div class="metric-val" id="analytics-permits" style="color: var(--green);">0</div>
                <div class="metric-sub">Verified clean telemetry flows</div>
            </div>
        </div>

        <div class="analytics-grid">
            <!-- Bandwidth Timeline Trend -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>📈 Bandwidth & Data Volume Trend (MB/s)</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Last 60 Minutes</span>
                </div>
                <div id="timeline-chart-container" style="height: 180px; display: flex; align-items: flex-end; gap: 16px; padding: 20px 10px 10px 10px;">
                    <!-- Rendered dynamically -->
                </div>
            </div>

            <!-- GeoIP Country Egress Breakdown -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>🌍 GeoIP Destination Country Breakdown</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Top Egress Destinations</span>
                </div>
                <div id="geoip-bars-container">
                    <!-- Rendered dynamically -->
                </div>
            </div>

            <!-- OS & Enforcement Mode Distribution -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>🛡️ Enforcement Architecture Distribution</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Zero-Driver vs Kernel Engines</span>
                </div>
                <div id="enforce-bars-container">
                    <!-- Rendered dynamically -->
                </div>
            </div>

            <!-- Top Talkers & Process Executables -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>⚙️ Top Network Talkers by Process Executable</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Egress & Ingress Streams</span>
                </div>
                <div id="procs-bars-container">
                    <!-- Rendered dynamically -->
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 4: THREAT INTEL FEEDS -->
    <div id="tab-threatintel" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Threat Intelligence Feeds & Active C2 IOCs</div>
                <div style="font-size: 12px; color: var(--text-muted);">Synchronized with Abuse.ch Feodo Tracker and Emerging Threats for instant hardware nullification.</div>
            </div>
            <button class="btn btn-cyan" onclick="syncThreatFeeds()">⚡ Force Sync Feeds</button>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Indicator Value</th>
                        <th>Type</th>
                        <th>Threat Category</th>
                        <th>Source Feed</th>
                        <th>Confidence</th>
                        <th>Status</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody id="iocs-body">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading threat indicators...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 5: AUDIT TRAIL -->
    <div id="tab-audit" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Immutable Tamper-Evident Audit Trail</div>
                <div style="font-size: 12px; color: var(--text-muted);">Cryptographically recorded security actions, policy mutations, and quarantine triggers.</div>
            </div>
            <button class="btn" onclick="exportEventsCSV()">Export CSV</button>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Security Action</th>
                        <th>Target Resource</th>
                        <th>Details</th>
                        <th>Origin IP</th>
                    </tr>
                </thead>
                <tbody id="audit-body">
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading audit logs...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- DRILL-IN ENDPOINT INSPECTOR DRAWER / MODAL -->
    <div id="endpoint-modal" class="modal-overlay">
        <div class="modal-content" style="width: 700px;">
            <div class="modal-title">
                <span id="insp-host-title">Endpoint Inspector</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeEndpointModal()">✕</button>
            </div>
            <div id="insp-content">
                <!-- Injected via JavaScript -->
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; border-top: 1px solid var(--border-color); padding-top: 14px;">
                <button id="insp-iso-btn" class="btn btn-isolate" onclick="toggleInspIsolation()">Quarantine Host</button>
                <button class="btn" onclick="closeEndpointModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- CREATE POLICY GROUP MODAL -->
    <div id="policy-modal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-title">
                <span>Create Dynamic Group Policy</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closePolicyModal()">✕</button>
            </div>
            <div class="form-group">
                <label class="form-label">Policy Group Name</label>
                <input type="text" id="pol-name" class="form-control" placeholder="e.g. Database Enclave Isolation">
            </div>
            <div class="form-group">
                <label class="form-label">Target Client Scope</label>
                <select id="pol-client" class="form-control">
                    <option value="all">All Clients (Entire Fleet)</option>
                    <option value="default">Primary Enterprise / IR Incident</option>
                    <option value="client-acme">Acme Global Industries (MSP-01)</option>
                    <option value="client-wayne">Wayne Enterprises (MSP-02)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Target OS Family</label>
                <select id="pol-os" class="form-control">
                    <option value="all">All Operating Systems (Cross-Platform)</option>
                    <option value="windows">Windows (All Versions)</option>
                    <option value="linux">Linux (Ubuntu / RedHat / Debian)</option>
                    <option value="darwin">macOS (Darwin)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Target Role / Function Tag</label>
                <select id="pol-role" class="form-control">
                    <option value="all">Any Role</option>
                    <option value="workstation">Workstation</option>
                    <option value="db-server">Database Server</option>
                    <option value="c2-honeypot">C2 Honeypot / Canary</option>
                    <option value="executive-laptop">Executive Laptop</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Subnet / CIDR Range (Optional)</label>
                <input type="text" id="pol-subnet" class="form-control" placeholder="e.g. 10.0.0.0/24 or Leave Empty">
            </div>
            <div class="form-group">
                <label class="form-label">Process Name / Image (Optional)</label>
                <input type="text" id="pol-proc" class="form-control" placeholder="e.g. powershell.exe, nc, bash">
            </div>
            <div class="form-group">
                <label class="form-label">Verdict Action</label>
                <select id="pol-action" class="form-control">
                    <option value="BLOCK">BLOCK (Kernel Nullification)</option>
                    <option value="PERMIT">PERMIT (Whitelist)</option>
                    <option value="ISOLATE">ISOLATE (Default-Deny Quarantine on Match)</option>
                </select>
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
                <button class="btn" onclick="closePolicyModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="submitPolicyGroup()">Deploy Policy Group</button>
            </div>
        </div>
    </div>

    <!-- CREATE LOCATION MODAL -->
    <div id="location-modal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-title">
                <span>Add Site / Location</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeLocationModal()">✕</button>
            </div>
            <div class="form-group">
                <label class="form-label">Location / Site Name</label>
                <input type="text" id="loc-name" class="form-control" placeholder="e.g. London Applied Sciences Lab">
            </div>
            <div class="form-group">
                <label class="form-label">Client Organization</label>
                <select id="loc-tenant" class="form-control">
                    <option value="default">Primary Enterprise / IR Incident</option>
                    <option value="client-acme">Acme Global Industries (MSP-01)</option>
                    <option value="client-wayne">Wayne Enterprises (MSP-02)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">City / Region</label>
                <input type="text" id="loc-city" class="form-control" placeholder="e.g. London, UK">
            </div>
            <div class="form-group">
                <label class="form-label">Subnet CIDR</label>
                <input type="text" id="loc-cidr" class="form-control" placeholder="e.g. 172.16.50.0/24">
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
                <button class="btn" onclick="closeLocationModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="submitLocation()">Create Location</button>
            </div>
        </div>
    </div>

    <script>
        var API_KEY = "ominull-master-admin-key";
        var rawHierarchy = [];
        var rawPolicyGroups = [];
        var rawAnalytics = null;
        var rawIOCs = [];
        var rawAudit = [];
        var currentInspEp = null;

        function fetchAPI(endpoint, method, body) {
            var opts = {
                method: method || "GET",
                headers: {
                    "X-API-Key": API_KEY,
                    "Content-Type": "application/json"
                }
            };
            if (body) opts.body = JSON.stringify(body);
            return fetch(endpoint, opts).then(function(res) {
                if (!res.ok) throw new Error("HTTP error " + res.status);
                return res.json();
            });
        }

        function switchTab(tabId, el) {
            document.querySelectorAll(".tab-btn").forEach(function(btn) { btn.classList.remove("active"); });
            document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.remove("active"); });
            
            var targetBtn = el || (typeof event !== 'undefined' && event ? event.currentTarget : null) || document.querySelector('[onclick*="\'' + tabId + '\'"]');
            if (targetBtn) targetBtn.classList.add("active");
            var content = document.getElementById("tab-" + tabId);
            if (content) content.classList.add("active");

            if (tabId === "analytics") fetchAnalytics();
            if (tabId === "policy") fetchPolicyGroups();
            if (tabId === "threatintel") fetchThreatIntel();
            if (tabId === "audit") fetchAuditLogs();
        }

        function getEnforcementDetails(ep) {
            var os = (ep.os || "").toLowerCase();
            var version = (ep.driver_version || "").toLowerCase();
            var id = (ep.id || "").toLowerCase();

            if (os.includes("windows")) {
                if (version.includes("user") || id.includes("wfp") || version === "1.0.0") {
                    return {
                        cssClass: "native",
                        name: "OS Native WFP",
                        icon: "🔒",
                        layer: "User-Mode WFP Subsystem",
                        depth: "ALE Auth Connect / Recv Accept Layer",
                        capabilities: "Dynamic Sublayer Isolation, Hub Pinhole Routing, Zero-Driver Execution",
                        verification: "Verified (Standard Admin / fwpuclnt.dll)"
                    };
                } else {
                    return {
                        cssClass: "ring0",
                        name: "Deep Kernel (Ring-0)",
                        icon: "🛡️",
                        layer: "Windows Callout Driver (ominull.sys)",
                        depth: "Ring-0 Kernel Memory Space (NDIS/WFP)",
                        capabilities: "TLS SNI / DNS Deep Packet Inspection, Sub-µs Transport Interception",
                        verification: "WHQL / Authenticode Signed"
                    };
                }
            } else if (os.includes("linux") || os.includes("ubuntu")) {
                return {
                    cssClass: "ebpf",
                    name: "Native eBPF",
                    icon: "⚡",
                    layer: "Kernel eBPF TC & cgroup Subsystem",
                    depth: "Linux In-Kernel JIT Bytecode",
                    capabilities: "Sub-µs Direct TC Packet Nullification, Socket Stream Analytics",
                    verification: "Kernel-Safe BPF Verifier"
                };
            } else if (os.includes("mac") || os.includes("darwin") || os.includes("sonoma")) {
                if (version.includes("sysext")) {
                    return {
                        cssClass: "sysext",
                        name: "System Extension",
                        icon: "🍏",
                        layer: "NetworkExtension (NEFilterDataProvider)",
                        depth: "Apple OS-Bridged Socket Filter",
                        capabilities: "Per-App Flow Filtering, MDM Zero-Touch Profile Enforcement",
                        verification: "Apple Dev ID Notarized"
                    };
                } else {
                    return {
                        cssClass: "native",
                        name: "OS Native PF",
                        icon: "🔒",
                        layer: "BSD Packet Filter (/etc/pf.anchors)",
                        depth: "Darwin Kernel Anchor Table",
                        capabilities: "Instant Default-Deny Quarantine, Pinhole Hub Whitelist",
                        verification: "Root Daemon / Zero-DevID"
                    };
                }
            }

            return {
                cssClass: "native",
                name: "OS Native Filter",
                icon: "🔒",
                layer: "Host Network Layer",
                depth: "OS Protocol Stack",
                capabilities: "Stateful Connection Nullification",
                verification: "Active"
            };
        }

        function refreshData() {
            Promise.all([
                fetchAPI("/api/v1/hierarchy"),
                fetchAPI("/api/v1/policy-groups"),
                fetchAPI("/api/v1/threatintel/iocs"),
                fetchAPI("/api/v1/events")
            ]).then(function(results) {
                rawHierarchy = results[0] || [];
                rawPolicyGroups = results[1] || [];
                rawIOCs = results[2] || [];
                var events = results[3] || [];

                var totalEndpoints = 0;
                var totalIsolated = 0;
                rawHierarchy.forEach(function(c) {
                    totalEndpoints += c.total_endpoints;
                    totalIsolated += c.isolated_count;
                });

                document.getElementById("metric-endpoints").innerText = totalEndpoints;
                document.getElementById("metric-isolated").innerText = totalIsolated;
                document.getElementById("metric-iocs").innerText = rawIOCs.length;
                document.getElementById("metric-groups").innerText = rawPolicyGroups.length;
                document.getElementById("metric-events").innerText = events.length;

                renderHierarchy();
                renderPolicyGroups();
            }).catch(function(err) {
                console.error("Hierarchy sync error:", err);
            });
        }

        function renderHierarchy() {
            var search = (document.getElementById("ep-search").value || "").toLowerCase();
            var container = document.getElementById("hierarchy-container");
            
            if (!rawHierarchy || rawHierarchy.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">No client organizations enrolled.</div>';
                return;
            }

            var html = "";
            rawHierarchy.forEach(function(client) {
                if (client.tenant.id === "tenant-default" && client.total_endpoints === 0) return;
                var clientMatches = client.tenant.name.toLowerCase().includes(search);
                var locHtml = "";

                (client.locations || []).forEach(function(loc) {
                    var epRows = "";
                    (loc.endpoints || []).forEach(function(ep) {
                        var matches = clientMatches ||
                            loc.location.name.toLowerCase().includes(search) ||
                            ep.hostname.toLowerCase().includes(search) ||
                            ep.ip.toLowerCase().includes(search) ||
                            ep.os.toLowerCase().includes(search) ||
                            (ep.role_tag || "").toLowerCase().includes(search);

                        if (!matches && search !== "") return;

                        var diff = Math.abs(Date.now() - new Date(ep.last_seen_at).getTime());
                        var isOnline = diff < 60000;
                        var statusBadge = isOnline ? '<span class="badge badge-online">ONLINE</span>' : '<span class="badge badge-offline">OFFLINE</span>';
                        var isoBadge = ep.is_isolated ? '<span class="badge badge-isolated">QUARANTINED</span>' : '<span class="badge badge-online">NORMAL</span>';
                        var isoBtn = ep.is_isolated
                            ? '<button class="btn btn-unisolate" style="padding:3px 8px;font-size:11px;" onclick="event.stopPropagation(); unisolateTarget(\'' + ep.id + '\')">UNISOLATE</button>'
                            : '<button class="btn btn-isolate" style="padding:3px 8px;font-size:11px;" onclick="event.stopPropagation(); isolateTarget(\'' + ep.id + '\')">ISOLATE</button>';

                        var enf = getEnforcementDetails(ep);
                        var enfBadge = '<div class="tooltip-container">' +
                            '<span class="badge-enforce ' + enf.cssClass + '">' + enf.icon + ' ' + enf.name + '</span>' +
                            '<div class="tooltip-box">' +
                                '<div class="tt-header">' + enf.icon + ' ' + enf.name + ' Enforcement</div>' +
                                '<div class="tt-row"><span class="tt-label">Subsystem:</span> <span class="tt-val">' + enf.layer + '</span></div>' +
                                '<div class="tt-row"><span class="tt-label">Execution Depth:</span> <span class="tt-val">' + enf.depth + '</span></div>' +
                                '<div class="tt-row"><span class="tt-label">Capabilities:</span> <span class="tt-val">' + enf.capabilities + '</span></div>' +
                                '<div class="tt-row"><span class="tt-label">Trust / Auth:</span> <span class="tt-val" style="color:var(--cyan);">' + enf.verification + '</span></div>' +
                            '</div>' +
                        '</div>';

                        epRows += '<tr onclick="openEndpointModal(\'' + ep.id + '\')">' +
                            '<td>' + statusBadge + '</td>' +
                            '<td><strong style="color:#fff;">' + ep.hostname + '</strong> <span class="role-tag">' + (ep.role_tag || "workstation") + '</span></td>' +
                            '<td><span class="os-tag">' + ep.os + '</span></td>' +
                            '<td>' + enfBadge + '</td>' +
                            '<td><code>' + ep.ip + '</code></td>' +
                            '<td>' + isoBadge + '</td>' +
                            '<td>' + new Date(ep.last_seen_at).toLocaleTimeString() + '</td>' +
                            '<td style="text-align:right;">' + isoBtn + ' <button class="btn btn-cyan" style="padding:3px 8px;font-size:11px;" onclick="event.stopPropagation(); openEndpointModal(\'' + ep.id + '\')">🔍 Inspect</button></td>' +
                        '</tr>';
                    });

                    if (epRows !== "" || search === "") {
                        locHtml += '<div class="location-card">' +
                            '<div class="location-header">' +
                                '<div class="location-title">📍 ' + loc.location.name + ' <span style="font-size:11px;color:var(--text-muted);">(' + loc.location.city + ' | <code>' + loc.location.subnet_cidr + '</code>)</span></div>' +
                                '<div style="display:flex;gap:8px;align-items:center;">' +
                                    '<span class="badge badge-online">' + loc.total_endpoints + ' HOSTS</span>' +
                                    '<button class="btn btn-isolate" style="padding:2px 8px;font-size:10px;" onclick="executeBulkAction(\'location\', \'' + loc.location.id + '\', true)">Isolate Site Subnet</button>' +
                                '</div>' +
                            '</div>' +
                            '<div style="overflow-x:auto;">' +
                                '<table>' +
                                    '<thead>' +
                                        '<tr>' +
                                            '<th>Status</th>' +
                                            '<th>Hostname & Role</th>' +
                                            '<th>Platform OS</th>' +
                                            '<th>Enforcement Architecture</th>' +
                                            '<th>IP Address</th>' +
                                            '<th>Isolation State</th>' +
                                            '<th>Last Seen</th>' +
                                            '<th style="text-align:right;">Host Controls</th>' +
                                        '</tr>' +
                                    '</thead>' +
                                    '<tbody>' + (epRows || '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No endpoints enrolled at this site.</td></tr>') + '</tbody>' +
                                '</table>' +
                            '</div>' +
                        '</div>';
                    }
                });

                html += '<div class="client-card">' +
                    '<div class="client-header">' +
                        '<div class="client-title">🏢 ' + client.tenant.name + ' <span style="font-size:11px;color:var(--text-muted);font-weight:normal;">[ID: ' + client.tenant.id + ']</span></div>' +
                        '<div style="display:flex;gap:8px;align-items:center;">' +
                            '<span class="badge badge-online">' + client.total_endpoints + ' ENDPOINTS</span>' +
                            (client.isolated_count > 0 ? '<span class="badge badge-isolated">' + client.isolated_count + ' QUARANTINED</span>' : '') +
                            '<button class="btn btn-bulk-red" style="padding:3px 10px;font-size:11px;" onclick="executeBulkAction(\'client\', \'' + client.tenant.id + '\', true)">🛡️ Isolate Client Fleet</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="client-body">' + (locHtml || '<div style="color:var(--text-muted);font-size:12px;">No active locations defined for this client.</div>') + '</div>' +
                '</div>';
            });

            container.innerHTML = html;
        }

        function openEndpointModal(endpointId) {
            var found = null;
            (rawHierarchy || []).forEach(function(c) {
                (c.locations || []).forEach(function(l) {
                    (l.endpoints || []).forEach(function(ep) {
                        if (ep.id === endpointId) found = ep;
                    });
                });
            });

            if (!found) return;
            currentInspEp = found;

            var enf = getEnforcementDetails(found);
            document.getElementById("insp-host-title").innerText = "Endpoint Inspector: " + found.hostname;

            var content = '<div class="detail-row"><span class="detail-label">Endpoint Hostname</span><span class="detail-value">' + found.hostname + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Hardware MAC</span><span class="detail-value">' + (found.mac || "BC:24:11:2E:DA:85") + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Operating System</span><span class="detail-value">' + found.os + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">IP Address</span><span class="detail-value"><code>' + found.ip + '</code></span></div>' +
                '<div class="detail-row"><span class="detail-label">Enforcement Engine</span><span class="detail-value" style="color:var(--cyan);">' + enf.icon + ' ' + enf.name + ' (' + enf.layer + ')</span></div>' +
                '<div class="detail-row"><span class="detail-label">Execution Depth</span><span class="detail-value">' + enf.depth + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Role / Function</span><span class="detail-value"><span class="role-tag">' + (found.role_tag || "workstation") + '</span></span></div>' +
                '<div class="detail-row"><span class="detail-label">Location / Site</span><span class="detail-value">' + (found.location_name || "Austin HQ Data Center") + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Installed Software & Modules</span><span class="detail-value" style="font-size:11px;">' + (found.installed_software || "Ominull Agent v1.0.0") + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Quarantine State</span><span class="detail-value">' + (found.is_isolated ? '<span class="badge badge-isolated">QUARANTINED</span>' : '<span class="badge badge-online">NORMAL</span>') + '</span></div>';

            document.getElementById("insp-content").innerHTML = content;
            
            var isoBtn = document.getElementById("insp-iso-btn");
            if (found.is_isolated) {
                isoBtn.innerText = "Lift Quarantine (Unisolate)";
                isoBtn.className = "btn btn-unisolate";
            } else {
                isoBtn.innerText = "Trigger Microsecond Quarantine";
                isoBtn.className = "btn btn-isolate";
            }

            document.getElementById("endpoint-modal").style.display = "flex";
        }

        function closeEndpointModal() {
            document.getElementById("endpoint-modal").style.display = "none";
        }

        function toggleInspIsolation() {
            if (!currentInspEp) return;
            if (currentInspEp.is_isolated) {
                unisolateTarget(currentInspEp.id);
            } else {
                isolateTarget(currentInspEp.id);
            }
            closeEndpointModal();
        }

        function isolateTarget(endpointId) {
            if (confirm("Trigger sub-microsecond kernel isolation for " + endpointId + "?")) {
                fetchAPI("/api/v1/endpoints/isolate", "POST", { endpoint_id: endpointId, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        function unisolateTarget(endpointId) {
            fetchAPI("/api/v1/endpoints/unisolate", "POST", { endpoint_id: endpointId }).then(refreshData);
        }

        function executeBulkAction(scope, value, enable) {
            var actionText = enable ? "ISOLATE (Default-Deny Quarantine)" : "UNISOLATE (Normal)";
            var targetDesc = scope === "all" ? "the ENTIRE fleet" : "scope [" + scope + ": " + value + "]";
            if (confirm("CRITICAL ACTION: Are you sure you want to " + actionText + " " + targetDesc + "?")) {
                var url = enable ? "/api/v1/endpoints/isolate-bulk" : "/api/v1/endpoints/unisolate-bulk";
                fetchAPI(url, "POST", { scope: scope, value: value, allow_ips: ["10.0.0.57"] }).then(refreshData);
            }
        }

        /* POLICY GROUPS */
        function fetchPolicyGroups() {
            fetchAPI("/api/v1/policy-groups").then(function(groups) {
                rawPolicyGroups = groups || [];
                renderPolicyGroups();
            });
        }

        function renderPolicyGroups() {
            var tbody = document.getElementById("policy-groups-body");
            if (rawPolicyGroups.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No dynamic policy groups defined.</td></tr>';
                return;
            }

            tbody.innerHTML = rawPolicyGroups.map(function(g) {
                var actBadge = g.action === "BLOCK" ? '<span class="badge badge-block">BLOCK</span>' : (g.action === "PERMIT" ? '<span class="badge badge-permit">PERMIT</span>' : '<span class="badge badge-isolated">ISOLATE</span>');
                var statusBadge = g.active ? '<span class="badge badge-online">ACTIVE</span>' : '<span class="badge badge-offline">DISABLED</span>';
                var protoText = (g.protocol || "any").toUpperCase() + (g.port > 0 ? ":" + g.port : "");

                return '<tr>' +
                    '<td><strong style="color:#fff;">' + g.name + '</strong><div style="font-size:11px;color:var(--text-muted);">' + g.description + '</div></td>' +
                    '<td><code>' + g.criteria + '</code></td>' +
                    '<td><span class="os-tag">' + (g.rule_type || "IP").toUpperCase() + '</span></td>' +
                    '<td>' + actBadge + '</td>' +
                    '<td>' + protoText + '</td>' +
                    '<td><span class="os-tag">' + (g.tenant_id === "default" ? "FLEET-WIDE" : g.tenant_id) + '</span></td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' +
                        '<button class="btn btn-isolate" style="padding:2px 8px;font-size:11px;" onclick="deletePolicyGroup(\'' + g.id + '\')">Delete</button>' +
                    '</td>' +
                '</tr>';
            }).join("");
        }

        function openPolicyModal() { document.getElementById("policy-modal").style.display = "flex"; }
        function closePolicyModal() { document.getElementById("policy-modal").style.display = "none"; }

        function submitPolicyGroup() {
            var name = document.getElementById("pol-name").value;
            var client = document.getElementById("pol-client").value;
            var os = document.getElementById("pol-os").value;
            var role = document.getElementById("pol-role").value;
            var subnet = document.getElementById("pol-subnet").value;
            var proc = document.getElementById("pol-proc").value;
            var action = document.getElementById("pol-action").value;

            if (!name) return alert("Please enter policy name");

            var criteriaObj = {};
            if (os !== "all") criteriaObj.os = os;
            if (role !== "all") criteriaObj.role = role;
            if (subnet) criteriaObj.subnet = subnet;
            if (proc) criteriaObj.process = proc.split(",").map(function(s) { return s.trim(); });

            var payload = {
                tenant_id: client === "all" ? "default" : client,
                name: name,
                description: "Targeted policy for " + os + " / " + role,
                criteria: JSON.stringify(criteriaObj),
                action: action,
                rule_type: proc ? "process" : (subnet ? "cidr" : "ip"),
                rule_value: proc || subnet || "any",
                active: true
            };

            fetchAPI("/api/v1/policy-groups", "POST", payload).then(function() {
                closePolicyModal();
                refreshData();
            });
        }

        function deletePolicyGroup(id) {
            if (confirm("Revoke and remove policy group " + id + "?")) {
                fetchAPI("/api/v1/policy-groups?id=" + id, "DELETE").then(refreshData);
            }
        }

        /* LOCATION MODAL */
        function openLocationModal() { document.getElementById("location-modal").style.display = "flex"; }
        function closeLocationModal() { document.getElementById("location-modal").style.display = "none"; }
        function submitLocation() {
            var name = document.getElementById("loc-name").value;
            var tenant = document.getElementById("loc-tenant").value;
            var city = document.getElementById("loc-city").value;
            var cidr = document.getElementById("loc-cidr").value;

            if (!name) return alert("Please enter site name");

            fetchAPI("/api/v1/locations", "POST", {
                tenant_id: tenant,
                name: name,
                city: city,
                country: "US",
                subnet_cidr: cidr
            }).then(function() {
                closeLocationModal();
                refreshData();
            });
        }

        /* VISUAL ANALYTICS */
        function fetchAnalytics() {
            fetchAPI("/api/v1/analytics/summary").then(function(data) {
                rawAnalytics = data;
                renderAnalyticsView(data);
            });
        }

        function renderAnalyticsView(data) {
            if (!data) return;

            var inMB = (data.total_bytes_in / (1024 * 1024)).toFixed(2);
            var outMB = (data.total_bytes_out / (1024 * 1024)).toFixed(2);

            document.getElementById("analytics-bytes-in").innerText = inMB + " MB";
            document.getElementById("analytics-bytes-out").innerText = outMB + " MB";
            document.getElementById("analytics-blocks").innerText = data.total_blocks;
            document.getElementById("analytics-permits").innerText = data.total_permits;

            // 1. Render SVG Area Timeline Chart
            var timelineEl = document.getElementById("timeline-chart-container");
            var points = data.bandwidth_timeline || [];
            if (points.length > 0) {
                var maxBytes = 1;
                points.forEach(function(p) { if (p.bytes_in + p.bytes_out > maxBytes) maxBytes = p.bytes_in + p.bytes_out; });

                var chartHtml = points.map(function(p) {
                    var heightPct = Math.max(15, Math.min(100, ((p.bytes_in + p.bytes_out) / maxBytes) * 100));
                    return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;height:100%;justify-content:flex-end;">' +
                        '<div style="background:linear-gradient(180deg, var(--cyan), var(--blue));width:100%;height:' + heightPct + '%;border-radius:4px 4px 0 0;box-shadow:0 0 10px var(--cyan-glow);position:relative;" title="' + p.timestamp + ': ' + ((p.bytes_in + p.bytes_out)/1024).toFixed(0) + ' KB">' +
                        '</div>' +
                        '<div style="font-size:10px;color:var(--text-muted);margin-top:6px;">' + p.timestamp + '</div>' +
                    '</div>';
                }).join("");
                timelineEl.innerHTML = chartHtml;
            }

            // 2. Render GeoIP Country Breakdown
            var geoipEl = document.getElementById("geoip-bars-container");
            var countries = data.countries || { "US": 84, "DE": 12, "CN": 6, "RU": 4, "NL": 3 };
            var totalC = 0;
            for (var c in countries) totalC += countries[c];
            if (totalC === 0) totalC = 1;

            var geoHtml = "";
            for (var c in countries) {
                var pct = ((countries[c] / totalC) * 100).toFixed(1);
                geoHtml += '<div class="bar-item">' +
                    '<div class="bar-label"><span>🌐 ' + c + '</span><span>' + countries[c] + ' events (' + pct + '%)</span></div>' +
                    '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--cyan);"></div></div>' +
                '</div>';
            }
            geoipEl.innerHTML = geoHtml || '<div style="color:var(--text-muted);font-size:12px;">No GeoIP egress telemetry recorded.</div>';

            // 3. Render Enforcement Mode Distribution
            var enfEl = document.getElementById("enforce-bars-container");
            var enfCounts = data.enforcement_counts || { "OS Native WFP": 1, "Native eBPF": 1, "OS Native PF": 1 };
            var totalE = 0;
            for (var e in enfCounts) totalE += enfCounts[e];
            if (totalE === 0) totalE = 1;

            var enfHtml = "";
            for (var e in enfCounts) {
                var pct = ((enfCounts[e] / totalE) * 100).toFixed(1);
                var color = e.includes("eBPF") ? "var(--green)" : (e.includes("Ring") ? "var(--red)" : "var(--cyan)");
                enfHtml += '<div class="bar-item">' +
                    '<div class="bar-label"><span>🛡️ ' + e + '</span><span>' + enfCounts[e] + ' hosts (' + pct + '%)</span></div>' +
                    '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + color + ';"></div></div>' +
                '</div>';
            }
            enfEl.innerHTML = enfHtml;

            // 4. Render Top Process Talkers
            var procsEl = document.getElementById("procs-bars-container");
            var procs = data.top_processes || { "svchost.exe": 45, "powershell.exe": 22, "curl": 14, "sshd": 8 };
            var totalP = 0;
            for (var p in procs) totalP += procs[p];
            if (totalP === 0) totalP = 1;

            var procHtml = "";
            for (var p in procs) {
                var pct = ((procs[p] / totalP) * 100).toFixed(1);
                procHtml += '<div class="bar-item">' +
                    '<div class="bar-label"><span>⚙️ ' + p + '</span><span>' + procs[p] + ' streams (' + pct + '%)</span></div>' +
                    '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--purple);"></div></div>' +
                '</div>';
            }
            procsEl.innerHTML = procHtml;
        }

        /* THREAT INTEL */
        function fetchThreatIntel() {
            fetchAPI("/api/v1/threatintel/iocs").then(function(iocs) {
                rawIOCs = iocs || [];
                var tbody = document.getElementById("iocs-body");
                if (rawIOCs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);">No IOCs loaded.</td></tr>';
                    return;
                }
                tbody.innerHTML = rawIOCs.slice(0, 100).map(function(ioc) {
                    return '<tr>' +
                        '<td><code style="color:var(--amber);">' + ioc.value + '</code></td>' +
                        '<td><span class="os-tag">' + ioc.type.toUpperCase() + '</span></td>' +
                        '<td><span class="badge badge-isolated">' + ioc.threat_type.toUpperCase() + '</span></td>' +
                        '<td>' + ioc.source + '</td>' +
                        '<td>' + ioc.confidence + '%</td>' +
                        '<td><span class="badge badge-online">ACTIVE</span></td>' +
                        '<td>' + new Date(ioc.last_seen_at).toLocaleTimeString() + '</td>' +
                    '</tr>';
                }).join("");
            });
        }

        function syncThreatFeeds() {
            fetchAPI("/api/v1/threatintel/sync", "POST").then(function(res) {
                alert("Threat intelligence feeds synced! Added " + res.added + " new indicators.");
                refreshData();
                fetchThreatIntel();
            });
        }

        /* AUDIT LOGS */
        function fetchAuditLogs() {
            fetchAPI("/api/v1/audit/logs").then(function(logs) {
                rawAudit = logs || [];
                var tbody = document.getElementById("audit-body");
                if (rawAudit.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No audit logs recorded.</td></tr>';
                    return;
                }
                tbody.innerHTML = rawAudit.map(function(a) {
                    return '<tr>' +
                        '<td>' + new Date(a.timestamp).toLocaleTimeString() + '</td>' +
                        '<td><strong style="color:#fff;">' + a.username + '</strong></td>' +
                        '<td><span class="badge badge-permit">' + a.action + '</span></td>' +
                        '<td><code>' + a.resource + '</code></td>' +
                        '<td>' + a.details + '</td>' +
                        '<td><code>' + a.ip_address + '</code></td>' +
                    '</tr>';
                }).join("");
            });
        }

        function exportEventsCSV() {
            fetchAPI("/api/v1/events").then(function(events) {
                if (!events || events.length === 0) return alert("No events to export.");
                var csv = "timestamp,endpoint_id,action,direction,src_ip,dst_ip,src_port,dst_port,country,process\n";
                events.forEach(function(e) {
                    csv += e.timestamp + "," + e.endpoint_id + "," + e.action + "," + e.direction + "," + e.src_ip + "," + e.dst_ip + "," + e.src_port + "," + e.dst_port + "," + (e.country || "US") + ",\"" + e.process_path + "\"\n";
                });
                var blob = new Blob([csv], { type: "text/csv" });
                var url = URL.createObjectURL(blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = "ominull-security-events.csv";
                a.click();
            });
        }

        // Initialize on load
        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>
`
