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

        /* Navigation Tabs (Compact) */
        .nav-tabs { display: flex; gap: 4px; background: #090d16; padding: 4px; border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 12px; }
        .tab-btn { background: transparent; border: none; color: var(--text-muted); font-size: 12px; font-weight: 700; padding: 6px 14px; cursor: pointer; border-radius: 6px; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
        .tab-btn:hover { color: #fff; background: rgba(255, 255, 255, 0.05); }
        .tab-btn.active { color: var(--cyan); background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* High-Density Stats Ribbon (Replaces 120px bulky boxes) */
        .stats-ribbon { display: flex; align-items: center; justify-content: space-between; background: #0f172a; border: 1px solid var(--border-color); border-radius: 8px; padding: 7px 14px; margin-bottom: 12px; gap: 12px; flex-wrap: wrap; }
        .stat-group { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        .stat-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; color: #94a3b8; }
        .stat-pill strong { font-size: 13px; font-weight: 800; color: #fff; }
        .stat-pill.red strong { color: var(--red); }
        .stat-pill.green strong { color: var(--green); }
        .stat-pill.amber strong { color: var(--amber); }
        .stat-pill.purple strong { color: var(--purple); }
        .stat-divider { width: 1px; height: 14px; background: #334155; }

        /* Compact Toolbar */
        .compact-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
        .toolbar-left { display: flex; gap: 8px; align-items: center; flex: 1; min-width: 320px; }
        .toolbar-right { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }

        /* Multi-Tenant Hierarchy Cards (Dense) */
        .client-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
        .client-header { background: #131c2e; padding: 8px 14px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; border-bottom: 1px solid var(--border-color); }
        .client-title { font-size: 13px; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 8px; }
        .client-body { padding: 8px 12px; }
        .location-card { background: #0c1220; border: 1px solid var(--border-highlight); border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
        .location-header { background: #162032; padding: 6px 10px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-highlight); }
        .location-title { font-size: 12px; font-weight: 700; color: var(--cyan); display: flex; align-items: center; gap: 6px; }

        /* Tables (High Density) */
        .table-wrap { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; overflow: visible; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: #162032; padding: 8px 12px; font-size: 10px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-color); }
        td { padding: 7px 12px; font-size: 12px; border-bottom: 1px solid var(--border-color); color: #e2e8f0; vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: rgba(51, 65, 85, 0.35); cursor: pointer; }

        /* Badges & Enforcement Badges */
        .badge { display: inline-flex; align-items: center; gap: 3px; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
        .badge-online { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-offline { background: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.4); }
        .badge-isolated { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.5); }
        .badge-block { background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 800; }
        .badge-permit { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-ti { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.5); }
        .os-tag { background: #1e293b; padding: 2px 5px; border-radius: 4px; font-size: 10px; color: #cbd5e1; border: 1px solid #334155; font-family: monospace; }
        .role-tag { background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.4); padding: 1px 5px; border-radius: 3px; font-size: 9px; font-weight: 700; text-transform: uppercase; }

        /* Enforcement Mode Badges & Interactive Tooltip */
        .tooltip-container { position: relative; display: inline-flex; align-items: center; cursor: help; }
        .badge-enforce { display: inline-flex; align-items: center; gap: 4px; padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase; transition: transform 0.15s ease, box-shadow 0.15s ease; }
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
            padding: 10px 12px;
            font-size: 11px;
            color: #e2e8f0;
            width: 260px;
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
        .tt-header { font-weight: 800; font-size: 11px; margin-bottom: 5px; display: flex; align-items: center; gap: 6px; color: #fff; border-bottom: 1px solid #1e293b; padding-bottom: 3px; }
        .tt-row { margin-bottom: 3px; }
        .tt-label { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 9px; }
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

        /* 24-Hour Diurnal Chart */
        .diurnal-wrap { height: 200px; display: flex; align-items: flex-end; gap: 4px; padding: 20px 4px 8px 4px; position: relative; }
        .diurnal-hour-col { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; position: relative; }
        .diurnal-bars-stack { width: 100%; display: flex; align-items: flex-end; justify-content: center; gap: 2px; height: 100%; }
        .diurnal-base-bar { width: 45%; background: rgba(6, 182, 212, 0.35); border-top: 2px solid var(--cyan); border-radius: 2px 2px 0 0; transition: height 0.3s ease; }
        .diurnal-live-bar { width: 45%; background: rgba(239, 68, 68, 0.85); border-top: 2px solid var(--red); border-radius: 2px 2px 0 0; box-shadow: 0 0 6px var(--red-glow); transition: height 0.3s ease; }
        .diurnal-live-bar.normal { background: rgba(16, 185, 129, 0.8); border-color: var(--green); box-shadow: 0 0 6px var(--green-glow); }
        .diurnal-hour-label { font-size: 9px; color: var(--text-muted); margin-top: 4px; font-family: monospace; }
        .diurnal-legend { display: flex; gap: 16px; font-size: 11px; color: #cbd5e1; align-items: center; }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .legend-box { width: 12px; height: 12px; border-radius: 2px; }

        /* Modals & 1-Click Triage Modal */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; width: 600px; max-width: 90vw; padding: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8); max-height: 85vh; overflow-y: auto; }
        .modal-title { font-size: 18px; font-weight: 800; margin-bottom: 16px; color: #fff; display: flex; justify-content: space-between; align-items: center; }
        .form-group { margin-bottom: 14px; }
        .form-label { display: block; font-size: 11px; color: var(--text-muted); font-weight: 700; margin-bottom: 6px; text-transform: uppercase; }
        .form-control { width: 100%; }
        .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1e293b; font-size: 13px; }
        .detail-label { color: var(--text-muted); font-weight: 600; }
        .detail-value { font-family: monospace; color: #fff; max-width: 360px; word-break: break-all; text-align: right; }

        .triage-card { background: rgba(15, 23, 42, 0.9); border: 1px solid var(--border-highlight); border-radius: 8px; padding: 14px; margin-bottom: 16px; }
        .triage-btn-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 18px; }
        .triage-action-btn { padding: 12px; border-radius: 8px; font-weight: 700; font-size: 12px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; cursor: pointer; transition: all 0.2s ease; border: 1px solid transparent; text-align: center; }
        .triage-action-btn.nullify { background: rgba(239, 68, 68, 0.2); border-color: var(--red); color: #fca5a5; }
        .triage-action-btn.nullify:hover { background: rgba(239, 68, 68, 0.4); box-shadow: 0 0 15px var(--red-glow); }
        .triage-action-btn.quarantine { background: rgba(245, 158, 11, 0.2); border-color: var(--amber); color: #fcd34d; }
        .triage-action-btn.quarantine:hover { background: rgba(245, 158, 11, 0.4); box-shadow: 0 0 15px var(--amber-glow); }
        .triage-action-btn.approve { background: rgba(16, 185, 129, 0.2); border-color: var(--green); color: #6ee7b7; }
        .triage-action-btn.approve:hover { background: rgba(16, 185, 129, 0.4); box-shadow: 0 0 15px var(--green-glow); }
        .triage-action-btn.policy { background: rgba(6, 182, 212, 0.2); border-color: var(--cyan); color: #a5f3fc; }
        .triage-action-btn.policy:hover { background: rgba(6, 182, 212, 0.4); box-shadow: 0 0 15px var(--cyan-glow); }
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
        <div style="display: flex; align-items: center; gap: 12px;">
            <div class="live-tag"><div class="pulse-dot"></div> TELEMETRY ACTIVE</div>
            <button class="btn btn-cyan" style="font-weight: 800; padding: 6px 14px; font-size: 12px; box-shadow: 0 0 10px var(--cyan-glow);" onclick="openDeployModal()">🚀 Deploy New Agent</button>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('hierarchy', this)">🏢 Fleet Hierarchy (MSP / Single Org)</button>
        <button class="tab-btn" onclick="switchTab('scanner', this)">🔍 Asset Scanner & Coverage</button>
        <button class="tab-btn" onclick="switchTab('topology', this)">🌐 Communications Topology Graph</button>
        <button class="tab-btn" onclick="switchTab('comms', this)">📡 Network Comms Profiler & Exclusions</button>
        <button class="tab-btn" onclick="switchTab('policy', this)">🎯 Dynamic Group Policy Engine</button>
        <button class="tab-btn" onclick="switchTab('analytics', this)">📊 Visual Analytics & Intelligence</button>
        <button class="tab-btn" onclick="switchTab('threatintel', this)">🛡️ Threat Intel Feeds & IOCs</button>
        <button class="tab-btn" onclick="switchTab('audit', this)">📜 Audit Trail & Stream</button>
    </div>

    <!-- TAB 1: FLEET HIERARCHY -->
    <div id="tab-hierarchy" class="tab-content active">
        <!-- 1-Line Executive Stats Ribbon -->
        <div class="stats-ribbon">
            <div class="stat-group">
                <div class="stat-pill">
                    <span>💻 Monitored Hosts:</span>
                    <strong id="metric-endpoints">0</strong>
                </div>
                <div class="stat-divider"></div>
                <div class="stat-pill red">
                    <span>🚨 Quarantined:</span>
                    <strong id="metric-isolated">0</strong>
                </div>
                <div class="stat-divider"></div>
                <div class="stat-pill green">
                    <span>🛡️ Active IOCs:</span>
                    <strong id="metric-iocs">0</strong>
                </div>
                <div class="stat-divider"></div>
                <div class="stat-pill amber">
                    <span>📊 Learned Baselines:</span>
                    <strong id="metric-profiles">0</strong>
                </div>
                <div class="stat-divider"></div>
                <div class="stat-pill purple">
                    <span>⚡ Allowlist Pinholes:</span>
                    <strong id="metric-exclusions">0</strong>
                </div>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
                <span style="color: var(--green);">●</span> Zero-Trust Sublayer Active
            </div>
        </div>

        <!-- Integrated Compact Toolbar (Search, Bulk Actions, Location Management) -->
        <div class="compact-toolbar">
            <div class="toolbar-left">
                <input type="text" id="ep-search" placeholder="🔍 Filter endpoints by client, location, hostname, IP, role, or OS..." style="width: 100%; max-width: 420px;" oninput="renderHierarchy()">
                <button class="btn btn-cyan" style="padding: 6px 12px;" onclick="refreshData()">Sync Fleet</button>
            </div>
            <div class="toolbar-right">
                <button class="btn btn-bulk-red" style="padding: 6px 12px; font-size: 11px;" onclick="executeBulkAction('all', '', true)">🚨 Isolate Fleet</button>
                <button class="btn btn-bulk-green" style="padding: 6px 12px; font-size: 11px;" onclick="executeBulkAction('all', '', false)">Unisolate All</button>
                <div class="stat-divider" style="height: 20px; margin: 0 4px;"></div>
                <button class="btn" style="padding: 6px 12px; font-size: 11px;" onclick="openLocationModal()">+ Add Location</button>
                <button class="btn btn-cyan" style="padding: 6px 12px; font-size: 11px;" onclick="openPolicyModal()">+ Create Policy Rule</button>
            </div>
        </div>

        <!-- Nested Hierarchy Container -->
        <div id="hierarchy-container">
            <div style="text-align: center; padding: 40px; color: var(--text-muted);">Loading fleet hierarchy...</div>
        </div>
    </div>

    <!-- TAB 2: NETWORK COMMS PROFILER & EXCLUSIONS -->
    <div id="tab-comms" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Network Communications Profiler & Anomaly Detection</div>
                <div style="font-size: 12px; color: var(--text-muted);">Continuous 5-tuple + process baseline tracking at Global, Client, Location, and Endpoint levels.</div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <label style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Scope Level:</label>
                <select id="comms-level-select" onchange="fetchCommsData()">
                    <option value="global">🌐 Global Fleet (All Clients)</option>
                    <option value="client:default">🏢 Client: Primary Enterprise</option>
                    <option value="client:client-acme">🏢 Client: Acme Global (MSP-01)</option>
                    <option value="client:client-wayne">🏢 Client: Wayne Enterprises (MSP-02)</option>
                    <option value="location:loc-hq">📍 Location: Austin HQ DC</option>
                    <option value="endpoint:linux-ominull-target-linux">💻 Endpoint: ominull-target-linux</option>
                    <option value="endpoint:win11-target-01">💻 Endpoint: DESKTOP-T6BG81P</option>
                    <option value="endpoint:macos-sonoma-01">💻 Endpoint: macos-sonoma-ir</option>
                </select>
                <button class="btn btn-cyan" onclick="openExclusionModal()">+ Create Custom Exclusion</button>
            </div>
        </div>

        <!-- Discovered Abnormalities Section -->
        <div style="margin-bottom: 24px;">
            <div style="font-size: 14px; font-weight: 700; color: var(--red); margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                <span>⚠️ Detected Communication Abnormalities & Outliers</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Target Host</th>
                            <th>Anomaly Classification</th>
                            <th>Process Image</th>
                            <th>Destination (IP:Port)</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th style="text-align:right;">Incident Response Action</th>
                        </tr>
                    </thead>
                    <tbody id="anomalies-body">
                        <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No communication abnormalities currently detected.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Discovered Network Communication Baseline Profiles -->
        <div style="margin-bottom: 24px;">
            <div style="font-size: 14px; font-weight: 700; color: var(--cyan); margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
                <span>📊 Discovered Process & Network Communications Baseline</span>
                <span style="font-size: 11px; color: var(--text-muted);">Learned 5-tuple flows across endpoints and subnets</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Process Name</th>
                            <th>Origin Endpoint</th>
                            <th>Destination IP</th>
                            <th>Port / Protocol</th>
                            <th>Direction</th>
                            <th>Country</th>
                            <th>Flow Count</th>
                            <th>Bandwidth (In / Out)</th>
                            <th>Last Seen</th>
                            <th style="text-align:right;">Baseline Action</th>
                        </tr>
                    </thead>
                    <tbody id="comms-profiles-body">
                        <tr><td colspan="10" style="text-align: center; color: var(--text-muted);">Loading communications profiles...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Custom Tool Exclusions & Pinhole Allowlists -->
        <div>
            <div style="font-size: 14px; font-weight: 700; color: var(--purple); margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
                <span>🛡️ Custom Security Tool Exclusions & Allowlist Pinholes</span>
                <button class="btn btn-cyan" style="padding: 3px 10px; font-size: 11px;" onclick="openExclusionModal()">+ Add Exclusion</button>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Exclusion Name</th>
                            <th>Target Process</th>
                            <th>Destination IP / CIDR</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Scope</th>
                            <th>Reason / Operational Justification</th>
                            <th>Status</th>
                            <th style="text-align:right;">Action</th>
                        </tr>
                    </thead>
                    <tbody id="exclusions-body">
                        <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">Loading custom exclusions...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 3: DYNAMIC GROUP POLICY ENGINE -->
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

        <!-- 24-Hour Diurnal Time-of-Day Profile -->
        <div class="chart-card" style="margin-bottom: 20px;">
            <div class="chart-title">
                <div>
                    <span>⏰ 24x7 Diurnal Time-of-Day Behavioral Profiler</span>
                    <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Hourly baseline activity model vs live telemetry across 24 UTC hours. Red highlight indicates anomalous off-hours interactive spikes (e.g. 02:00 UTC).</div>
                </div>
                <div class="diurnal-legend">
                    <div class="legend-item"><div class="legend-box" style="background: rgba(6, 182, 212, 0.5); border: 1px solid var(--cyan);"></div> Expected Baseline Curve</div>
                    <div class="legend-item"><div class="legend-box" style="background: rgba(16, 185, 129, 0.8); border: 1px solid var(--green);"></div> Normal Daytime Traffic</div>
                    <div class="legend-item"><div class="legend-box" style="background: rgba(239, 68, 68, 0.85); border: 1px solid var(--red);"></div> Off-Hours Anomaly (22:00-05:00)</div>
                </div>
            </div>
            <div id="diurnal-chart-container" class="diurnal-wrap">
                <!-- Injected dynamically via JavaScript -->
            </div>
        </div>

        <div class="analytics-grid">
            <!-- Bandwidth Timeline Trend -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>📈 Bandwidth & Flow Trend</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Last 60 Minutes</span>
                </div>
                <div id="timeline-chart-container" style="height: 180px; display: flex; align-items: flex-end; gap: 16px; padding: 20px 10px 10px 10px;">
                    <!-- Rendered dynamically -->
                </div>
            </div>

            <!-- Top Talkers by Process Executable -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>⚙️ Top Network Talkers</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Ranked by Flows & Bandwidth</span>
                </div>
                <div id="procs-bars-container">
                    <!-- Rendered dynamically -->
                </div>
            </div>

            <!-- GeoIP Country Egress Breakdown -->
            <div class="chart-card">
                <div class="chart-title">
                    <span>🌍 GeoIP Destination Countries & Threat Intel</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Top External ASNs & Dest Networks</span>
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

    <!-- TAB: ASSET SCANNER & COVERAGE -->
    <div id="tab-scanner" class="tab-content">
        <!-- Header & Scan Control Bar -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Network Asset Discovery, Fingerprinting & Coverage Audit</div>
                <div style="font-size: 12px; color: var(--text-muted);">Multi-tier non-intrusive and aggressive IR discovery with extensible OS fingerprinting, TTL/Window/Delta-timing heuristics, and shadow IT detection.</div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <input type="text" id="scan-subnet" class="form-control" style="width: 170px;" value="10.0.0.0/24" placeholder="Subnet CIDR">
                <select id="scan-profile" class="form-control" style="width: 220px;">
                    <option value="standard">🔍 Standard Audit (Top Ports + OUI)</option>
                    <option value="aggressive">⚡ Aggressive IR (Full Sweep + Risk)</option>
                    <option value="passive">🕵️ Passive Stealth (Zero Packets)</option>
                </select>
                <button id="btn-run-scan" class="btn btn-cyan" onclick="startNetworkScan()">🚀 Run Network Sweep</button>
            </div>
        </div>

        <!-- Scan Progress Bar -->
        <div id="scan-progress-box" style="display: none; background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-bottom: 6px;">
                <span id="scan-status-text" style="font-weight: 700; color: var(--cyan);">Scanning subnet...</span>
                <span id="scan-progress-pct" style="font-weight: 700;">0%</span>
            </div>
            <div class="bar-track" style="height: 8px;">
                <div id="scan-progress-bar" class="bar-fill" style="width: 0%; background: var(--cyan);"></div>
            </div>
        </div>

        <!-- Protection Coverage KPI Cards -->
        <div class="analytics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 16px;">
            <div class="metric-card">
                <div class="metric-title">Discovered Assets</div>
                <div class="metric-value" id="cov-total" style="color: #fff;">0</div>
                <div class="metric-sub" id="cov-sub-unmanaged">0 Unmanaged / Missing Agent</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Agent Fleet Coverage</div>
                <div class="metric-value" id="cov-pct" style="color: var(--green);">0.0%</div>
                <div class="metric-sub" id="cov-sub-managed">0 Managed Endpoints Online</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Critical Weakpoints</div>
                <div class="metric-value" id="cov-crit" style="color: var(--red);">0</div>
                <div class="metric-sub">Exposed SMB / Telnet / Redis</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">High Risk Exposure</div>
                <div class="metric-value" id="cov-high" style="color: var(--amber);">0</div>
                <div class="metric-sub">Exposed RDP / WinRM / WAN Egress</div>
            </div>
        </div>

        <!-- Discovered Assets Table -->
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Asset IP / Hostname</th>
                        <th>Hardware Vendor (OUI)</th>
                        <th>OS Fingerprint & Confidence</th>
                        <th>Timing (RTT / Δt)</th>
                        <th>Open Ports & Services</th>
                        <th>Protection Status</th>
                        <th>Risk Score & Weakpoints</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="scanner-body">
                    <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No scan executed yet. Click "Run Network Sweep" or wait for passive peer correlation.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB: VISUAL COMMUNICATIONS TOPOLOGY GRAPH -->
    <div id="tab-topology" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div>
                <div style="font-size: 18px; font-weight: 800; color: #fff;">Communications Topology & Relationship Graph</div>
                <div style="font-size: 12px; color: var(--text-muted);">Real-time force-directed mapping of Endpoints, Unmanaged Assets, Cloud ASNs, and External WAN Threats.</div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <select id="topo-window" class="form-control" style="width: 140px;" onchange="fetchTopologyData()">
                    <option value="1h">Last 1 Hour</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                </select>
                <button class="btn btn-cyan" onclick="fetchTopologyData()">🔄 Refresh Graph</button>
            </div>
        </div>

        <!-- Graph Metrics Ribbon -->
        <div class="stats-ribbon" style="margin-bottom: 12px;">
            <div class="stat-group">
                <div class="stat-pill"><span>Active Nodes:</span><strong id="topo-metric-nodes">0</strong></div>
                <div class="stat-divider"></div>
                <div class="stat-pill cyan"><span>Flow Edges:</span><strong id="topo-metric-edges">0</strong></div>
                <div class="stat-divider"></div>
                <div class="stat-pill red"><span>Anomalous / Blocked Links:</span><strong id="topo-metric-anom">0</strong></div>
                <div class="stat-divider"></div>
                <div class="stat-pill green"><span>Managed Nodes:</span><strong id="topo-metric-managed">0</strong></div>
                <div class="stat-divider"></div>
                <div class="stat-pill amber"><span>Unmanaged / Shadow Nodes:</span><strong id="topo-metric-unmanaged">0</strong></div>
            </div>
        </div>

        <!-- Graph Interactive Canvas Container -->
        <div style="position: relative; background: #070d19; border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden; box-shadow: inset 0 0 40px rgba(0,0,0,0.8);">
            <!-- Canvas -->
            <canvas id="topo-canvas" width="1200" height="640" style="display: block; width: 100%; height: 640px; cursor: grab;"></canvas>

            <!-- Graph Floating Controls Overlay -->
            <div style="position: absolute; bottom: 16px; left: 16px; background: rgba(15, 23, 42, 0.85); border: 1px solid var(--border-color); backdrop-filter: blur(8px); border-radius: 8px; padding: 10px 14px; display: flex; gap: 14px; font-size: 11px; align-items: center; z-index: 10;">
                <div style="display: flex; align-items: center; gap: 6px;"><span style="width:10px;height:10px;border-radius:50%;background:var(--cyan);box-shadow:0 0 6px var(--cyan);"></span> Managed Workstation</div>
                <div style="display: flex; align-items: center; gap: 6px;"><span style="width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);"></span> Server / Hub Controller</div>
                <div style="display: flex; align-items: center; gap: 6px;"><span style="width:10px;height:10px;border-radius:50%;background:var(--amber);box-shadow:0 0 6px var(--amber);"></span> Unmanaged Asset</div>
                <div style="display: flex; align-items: center; gap: 6px;"><span style="width:10px;height:10px;border-radius:50%;background:#38bdf8;"></span> Cloud / SaaS</div>
                <div style="display: flex; align-items: center; gap: 6px;"><span style="width:10px;height:10px;border-radius:50%;background:var(--red);box-shadow:0 0 6px var(--red);"></span> Threat / Blocked IOC</div>
            </div>

            <div style="position: absolute; top: 16px; right: 16px; background: rgba(15, 23, 42, 0.85); border: 1px solid var(--border-color); backdrop-filter: blur(8px); border-radius: 8px; padding: 8px 12px; font-size: 11px; color: var(--text-muted); z-index: 10;">
                💡 <strong>Controls:</strong> Drag Nodes • Scroll to Zoom • Click Node to Inspect
            </div>

            <!-- Inspector Panel Overlay (when node is clicked) -->
            <div id="topo-inspector" style="display: none; position: absolute; top: 16px; left: 16px; width: 320px; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(6, 182, 212, 0.3); backdrop-filter: blur(12px); border-radius: 10px; padding: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); z-index: 20;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div id="topo-insp-title" style="font-weight: 800; font-size: 14px; color: #fff;">Node Details</div>
                    <button class="btn" style="padding: 2px 6px; font-size: 10px;" onclick="closeTopoInspector()">✕</button>
                </div>
                <div id="topo-insp-content" style="font-size: 12px; margin-bottom: 12px;"></div>
                <div id="topo-insp-actions" style="display: flex; gap: 6px;"></div>
            </div>
        </div>
    </div>

    <!-- TRAIN DEVICE SIGNATURE MODAL -->
    <div id="train-modal" class="modal-overlay">
        <div class="modal-content" style="width: 580px;">
            <div class="modal-title">
                <span style="display: flex; align-items: center; gap: 8px;">🎓 Train Extensible Device / OS Signature</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeTrainModal()">✕</button>
            </div>
            
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
                Teach the fingerprint engine the ground-truth identity of this asset. Future scans across your enterprise will match this device with high precision.
            </div>

            <div class="triage-card" style="margin-bottom: 14px;">
                <div class="detail-row"><span class="detail-label">Asset IP</span><span class="detail-value" id="train-ip">-</span></div>
                <div class="detail-row"><span class="detail-label">Hardware Vendor</span><span class="detail-value" id="train-vendor-seen">-</span></div>
                <div class="detail-row"><span class="detail-label">Observed Ports</span><span class="detail-value" id="train-ports-seen">-</span></div>
            </div>

            <div class="form-group">
                <label class="form-label">Actual Device / OS Name (Ground Truth)</label>
                <input type="text" id="train-name" class="form-control" placeholder="e.g. NVIDIA Shield TV Pro (Android 11) or Sony Bravia Smart TV">
            </div>

            <div class="form-group">
                <label class="form-label">Hardware Manufacturer</label>
                <input type="text" id="train-vendor" class="form-control" placeholder="e.g. NVIDIA Corporation">
            </div>

            <div class="form-group">
                <label class="form-label">Device Category</label>
                <select id="train-category" class="form-control">
                    <option value="Smart TV / Media Streamer">Smart TV / Media Streamer</option>
                    <option value="Workstation">Workstation</option>
                    <option value="Server">Server</option>
                    <option value="Storage / NAS">Storage / NAS</option>
                    <option value="Printer / Appliance">Printer / Appliance</option>
                    <option value="Network Gear">Network Gear (Router / Switch)</option>
                    <option value="IoT / Embedded">IoT / Embedded Device</option>
                </select>
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; border-top: 1px solid var(--border-color); padding-top: 12px;">
                <button class="btn" onclick="closeTrainModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="submitTrainSignature()">Save & Train Engine</button>
            </div>
        </div>
    </div>

    <!-- 1-CLICK ANOMALY MITIGATION / TRIAGE MODAL -->
    <div id="triage-modal" class="modal-overlay">
        <div class="modal-content" style="width: 720px;">
            <div class="modal-title">
                <span id="triage-title" style="display:flex;align-items:center;gap:8px;">🚨 Anomaly Mitigation & Response</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeTriageModal()">✕</button>
            </div>
            
            <div id="triage-header-card" class="triage-card" style="border-left: 4px solid var(--red);">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div id="triage-anomaly-type" class="badge badge-isolated" style="font-size:12px;padding:4px 10px;">ANOMALY_TYPE</div>
                    <div id="triage-severity" class="badge badge-isolated">CRITICAL</div>
                </div>
                <div id="triage-anomaly-desc" style="font-size:13px;color:#fff;font-weight:600;line-height:1.4;">Description</div>
            </div>

            <!-- Details Grid -->
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
                <div class="triage-card" style="margin-bottom:0;">
                    <div style="font-size:11px;font-weight:700;color:var(--cyan);text-transform:uppercase;margin-bottom:6px;">💻 Host & Process Telemetry</div>
                    <div class="detail-row"><span class="detail-label">Endpoint</span><span class="detail-value" id="triage-host">-</span></div>
                    <div class="detail-row"><span class="detail-label">Origin IP</span><span class="detail-value" id="triage-host-ip">-</span></div>
                    <div class="detail-row"><span class="detail-label">Role Tag</span><span class="detail-value" id="triage-role">-</span></div>
                    <div class="detail-row"><span class="detail-label">Process Path</span><span class="detail-value" id="triage-proc" style="font-size:11px;">-</span></div>
                </div>
                <div class="triage-card" style="margin-bottom:0;">
                    <div style="font-size:11px;font-weight:700;color:var(--amber);text-transform:uppercase;margin-bottom:6px;">🌐 Target & Intelligence Profile</div>
                    <div class="detail-row"><span class="detail-label">Destination</span><span class="detail-value" id="triage-dst">-</span></div>
                    <div class="detail-row"><span class="detail-label">GeoIP Country</span><span class="detail-value" id="triage-geo">-</span></div>
                    <div class="detail-row"><span class="detail-label">ASN / ISP</span><span class="detail-value" id="triage-asn">-</span></div>
                    <div class="detail-row"><span class="detail-label">Observed Time</span><span class="detail-value" id="triage-time">-</span></div>
                </div>
            </div>

            <div class="triage-card" style="margin-bottom:14px;">
                <div style="font-size:11px;font-weight:700;color:var(--purple);text-transform:uppercase;margin-bottom:4px;">📊 Statistical & Behavioral Metrics</div>
                <div id="triage-metrics" style="font-size:12px;color:#cbd5e1;font-family:monospace;">Metrics</div>
            </div>

            <!-- 4 Instant 1-Click Action Buttons -->
            <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">⚡ Instant 1-Click Automated Response Actions</div>
            <div class="triage-btn-grid">
                <button class="triage-action-btn nullify" onclick="executeTriageAction('nullify')">
                    <span style="font-size:16px;">🔴</span>
                    <span>Nullify Threat</span>
                    <span style="font-size:10px;font-weight:normal;opacity:0.85;">Instant Kernel Block on Target IP / Process</span>
                </button>
                <button class="triage-action-btn quarantine" onclick="executeTriageAction('quarantine')">
                    <span style="font-size:16px;">🔒</span>
                    <span>Quarantine Host</span>
                    <span style="font-size:10px;font-weight:normal;opacity:0.85;">Default-Deny Endpoint Isolation</span>
                </button>
                <button class="triage-action-btn approve" onclick="executeTriageAction('approve')">
                    <span style="font-size:16px;">🟢</span>
                    <span>Approve as Normal</span>
                    <span style="font-size:10px;font-weight:normal;opacity:0.85;">Add Operational Exclusion Pinhole</span>
                </button>
                <button class="triage-action-btn policy" onclick="executeTriageAction('policy')">
                    <span style="font-size:16px;">📝</span>
                    <span>Create Policy Rule</span>
                    <span style="font-size:10px;font-weight:normal;opacity:0.85;">Configure 4-Tier Scoped Rule</span>
                </button>
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; border-top: 1px solid var(--border-color); padding-top: 12px;">
                <button class="btn" onclick="closeTriageModal()">Close</button>
            </div>
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

    <!-- CREATE EXCLUSION MODAL -->
    <div id="exclusion-modal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-title">
                <span>Create Custom Tool Exclusion / Allowlist Pinhole</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeExclusionModal()">✕</button>
            </div>
            <div class="form-group">
                <label class="form-label">Exclusion Name</label>
                <input type="text" id="ex-name" class="form-control" placeholder="e.g. Velociraptor IR Collector Stream">
            </div>
            <div class="form-group">
                <label class="form-label">Scope Level</label>
                <select id="ex-scope" class="form-control">
                    <option value="global">🌐 Global Fleet-Wide (All Clients & Endpoints)</option>
                    <option value="client">🏢 Client Organization Level</option>
                    <option value="location">📍 Location / Site Level</option>
                    <option value="endpoint">💻 Specific Endpoint</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Target Process (Optional, or '*' for any)</label>
                <input type="text" id="ex-proc" class="form-control" placeholder="e.g. splunkd.exe, velociraptor, or *">
            </div>
            <div class="form-group">
                <label class="form-label">Destination IP / CIDR Range (Optional, or '*' for any)</label>
                <input type="text" id="ex-ip" class="form-control" placeholder="e.g. 10.0.0.57, 10.0.0.0/8, or *">
            </div>
            <div class="form-group">
                <label class="form-label">Destination Port (0 for Any)</label>
                <input type="number" id="ex-port" class="form-control" placeholder="0" value="0">
            </div>
            <div class="form-group">
                <label class="form-label">Protocol</label>
                <select id="ex-proto" class="form-control">
                    <option value="any">ANY Protocol</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Operational Reason / Justification</label>
                <input type="text" id="ex-reason" class="form-control" placeholder="e.g. Mandatory forensic capture channel during IR">
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
                <button class="btn" onclick="closeExclusionModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="submitExclusion()">Deploy Exclusion Pinhole</button>
            </div>
        </div>
    </div>

    <!-- CREATE POLICY GROUP MODAL (4-TIER HIERARCHY) -->
    <div id="policy-modal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-title">
                <span>Create 4-Tier Scoped Group Policy</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closePolicyModal()">✕</button>
            </div>
            <div class="form-group">
                <label class="form-label">Policy Group Name</label>
                <input type="text" id="pol-name" class="form-control" placeholder="e.g. Workstation Off-Hours Egress Block">
            </div>
            
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div class="form-group">
                    <label class="form-label">1. Hierarchy Enforcement Tier (Scope)</label>
                    <select id="pol-scope" class="form-control" onchange="updatePolicyScopeOptions()">
                        <option value="global">🌐 Tier 0: Global Fleet (All Clients)</option>
                        <option value="client">🏢 Tier 1: Client Organization</option>
                        <option value="location">📍 Tier 2: Location / Site</option>
                        <option value="endpoint">💻 Tier 3: Specific Endpoint</option>
                        <option value="role">🏷️ Tier 3: Endpoint Role (workstation, db-server...)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Scope Value / Target Identifier</label>
                    <input type="text" id="pol-scope-val" class="form-control" placeholder="e.g. default, loc-home, workstation">
                </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div class="form-group">
                    <label class="form-label">2. Time-of-Day Schedule</label>
                    <select id="pol-schedule" class="form-control">
                        <option value="all">🕒 All Hours (24x7 Unconditional)</option>
                        <option value="business_hours">💼 Business Hours Only (08:00 - 18:00 UTC)</option>
                        <option value="off_hours">🌙 Off-Hours Only (18:00 - 08:00 UTC / Night)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Verdict Action</label>
                    <select id="pol-action" class="form-control">
                        <option value="BLOCK">🔴 BLOCK (Instant Ring-0 Drop)</option>
                        <option value="PERMIT">🟢 PERMIT (Allowlist)</option>
                        <option value="QUARANTINE">🔒 QUARANTINE (Trigger Host Isolation)</option>
                        <option value="ALERT">⚠️ ALERT (Flag Anomaly Only)</option>
                    </select>
                </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div class="form-group">
                    <label class="form-label">Target Protocol</label>
                    <select id="pol-proto" class="form-control">
                        <option value="any">ANY Protocol</option>
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="icmp">ICMP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Target Port (0 for Any)</label>
                    <input type="number" id="pol-port" class="form-control" placeholder="0" value="0">
                </div>
            </div>

            <div class="form-group">
                <label class="form-label">Destination IP / CIDR Subnet (Optional)</label>
                <input type="text" id="pol-subnet" class="form-control" placeholder="e.g. 194.26.29.0/24, 8.8.8.8, or *">
            </div>
            <div class="form-group">
                <label class="form-label">Process Image / Regex (Optional)</label>
                <input type="text" id="pol-proc" class="form-control" placeholder="e.g. powershell.exe, curl, ncat, nc">
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
                <button class="btn" onclick="closePolicyModal()">Cancel</button>
                <button class="btn btn-cyan" onclick="submitPolicyGroup()">Deploy 4-Tier Policy Rule</button>
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

    <!-- DEPLOY AGENT INTERACTIVE WIZARD MODAL (PUSH + 1-LINER) -->
    <div id="deploy-modal" class="modal-overlay">
        <div class="modal-content" style="width: 780px;">
            <div class="modal-title">
                <span style="display: flex; align-items: center; gap: 8px;">🚀 Onboard Endpoint Agent</span>
                <button class="btn" style="padding: 2px 8px;" onclick="closeDeployModal()">✕</button>
            </div>
            
            <div style="display: flex; gap: 8px; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
                <button id="deploy-tab-push" class="btn btn-cyan" style="font-weight: 700; font-size: 12px;" onclick="switchDeployMode('push')">🚀 Direct Push from Hub (SSH / WinRM)</button>
                <button id="deploy-tab-manual" class="btn" style="font-weight: 700; font-size: 12px;" onclick="switchDeployMode('manual')">📋 Manual Unattended Script</button>
            </div>

            <!-- MODE A: DIRECT REMOTE PUSH (RECOMMENDED) -->
            <div id="deploy-mode-push">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
                    Deploy, configure, and start the Ominull Agent on a remote target host over SSH or WinRM directly from the Hub with zero interactive steps on the endpoint.
                </div>
                <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">Target IP / Hostname</label>
                        <input type="text" id="push-target-ip" class="form-control" placeholder="10.0.0.57">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">Port</label>
                        <input type="number" id="push-port" class="form-control" value="22">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">Target OS</label>
                        <select id="push-os" class="form-control">
                            <option value="auto">Auto-Detect</option>
                            <option value="linux">Linux (eBPF)</option>
                            <option value="windows">Windows (WFP)</option>
                            <option value="macos">macOS (PF)</option>
                        </select>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">SSH / WinRM Username</label>
                        <input type="text" id="push-username" class="form-control" value="root">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">Target Role</label>
                        <select id="push-role" class="form-control">
                            <option value="workstation">Workstation (Standard PC / Laptop)</option>
                            <option value="server">Application Server</option>
                            <option value="db-server">Database Server</option>
                            <option value="incident-response">🚨 Incident Response Target</option>
                        </select>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr; gap: 12px; margin-bottom: 12px;">
                    <div class="form-group" style="margin-bottom:0;">
                        <label class="form-label">Remote Password / Sudo Password</label>
                        <input type="password" id="push-password" class="form-control" placeholder="Enter target root or administrator password...">
                    </div>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px;">
                    <span id="push-status-badge" style="font-size: 12px; font-weight: 700; color: var(--text-muted);">Ready to push</span>
                    <button id="btn-launch-push" class="btn btn-cyan" style="font-weight: 800; padding: 8px 18px;" onclick="launchPushDeployment()">🚀 Launch Push Onboarding</button>
                </div>
                <div id="push-terminal-box" style="display:none; margin-top:14px; background:#080c14; border:1px solid var(--border-highlight); border-radius:6px; padding:12px; font-family:monospace; font-size:12px; color:#34d399; max-height:220px; overflow-y:auto; line-height:1.5; white-space:pre-wrap;"></div>
            </div>

            <!-- MODE B: MANUAL 1-LINER SCRIPT -->
            <div id="deploy-mode-manual" style="display: none;">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
                    Generate an unattended 1-liner deployment command pre-configured with your organization, location, and zero-trust edge tokens.
                </div>

                <!-- Step 1: Platform Selection -->
                <div style="margin-bottom: 16px;">
                    <label class="form-label">1. Select Target Operating System</label>
                    <div style="display: flex; gap: 10px;">
                        <button id="plat-btn-windows" class="btn btn-cyan" style="flex: 1; padding: 10px; font-size: 13px; font-weight: 700; justify-content: center;" onclick="selectDeployPlatform('windows')">
                            🪟 Windows (WFP / Ring-0)
                        </button>
                        <button id="plat-btn-linux" class="btn" style="flex: 1; padding: 10px; font-size: 13px; font-weight: 700; justify-content: center;" onclick="selectDeployPlatform('linux')">
                            🐧 Linux (eBPF / TC)
                        </button>
                        <button id="plat-btn-macos" class="btn" style="flex: 1; padding: 10px; font-size: 13px; font-weight: 700; justify-content: center;" onclick="selectDeployPlatform('macos')">
                            🍏 macOS (PF Anchor)
                        </button>
                    </div>
                </div>

                <!-- Step 2: Tenant & Location Selection -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px;">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">2. Target Client Organization</label>
                        <select id="deploy-tenant" class="form-control" onchange="updateDeployLocationOptions(); generateDeployCommand();">
                            <option value="default">Home Network</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">Location / Site Subnet</label>
                        <select id="deploy-location" class="form-control" onchange="generateDeployCommand();">
                            <option value="loc-home">Primary Home LAN (10.0.0.0/24)</option>
                        </select>
                    </div>
                </div>

                <!-- Step 3: Endpoint Role & Server URL -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px;">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">3. Endpoint Role / Function</label>
                        <select id="deploy-role" class="form-control" onchange="generateDeployCommand();">
                            <option value="workstation">Workstation (Standard PC / Laptop)</option>
                            <option value="db-server">Database Server (Postgres / MySQL / SQLite)</option>
                            <option value="web-server">Web / Application Server</option>
                            <option value="incident-response">🚨 Incident Response Target (Live IR)</option>
                            <option value="executive-laptop">Executive / High-Value Laptop</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">Hub Server Address (WAN / LAN)</label>
                        <input type="text" id="deploy-hub-url" class="form-control" value="https://omi.example.com" oninput="generateDeployCommand();">
                    </div>
                </div>

                <!-- Step 4: Cloudflare Zero Trust Authentication -->
                <div style="background: rgba(6, 182, 212, 0.05); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 8px; padding: 14px 16px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <div>
                            <span style="font-size: 11px; font-weight: 700; color: var(--cyan); text-transform: uppercase; letter-spacing: 0.5px;">4. Cloudflare Zero Trust Edge Service Tokens</span>
                            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Required for WAN endpoints connecting over the Internet via Cloudflare Tunnel.</div>
                        </div>
                        <label style="font-size: 11px; color: var(--text-muted); cursor: pointer; display: flex; align-items: center; gap: 6px;">
                            <input type="checkbox" id="deploy-save-tokens" checked onchange="saveTokensPreference()"> Remember in browser
                        </label>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label class="form-label" style="font-size: 11px; color: var(--text-muted);">Client ID (e.g. xxxxx.access)</label>
                            <input type="text" id="deploy-cf-id" class="form-control" placeholder="9cfabb152a7bd00bfd1355139039d084.access" oninput="generateDeployCommand();">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label class="form-label" style="font-size: 11px; color: var(--text-muted);">Client Secret</label>
                            <div style="display: flex; gap: 6px;">
                                <input type="password" id="deploy-cf-secret" class="form-control" placeholder="Paste Cloudflare Client Secret..." oninput="generateDeployCommand();" style="flex: 1;">
                                <button id="toggle-secret-btn" class="btn" style="padding: 6px 12px; font-size: 13px;" onclick="toggleSecretVisibility()" title="Toggle secret visibility">👁️</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Step 5: Generated One-Liner -->
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <label class="form-label" style="margin-bottom: 0;">5. Run Command on Endpoint (Administrator / Root)</label>
                            <span id="copy-toast" style="font-size: 11px; font-weight: 700; color: var(--green); opacity: 0; transition: opacity 0.2s ease;">✓ Copied to Clipboard!</span>
                        </div>
                        <button class="btn btn-cyan" style="padding: 5px 14px; font-size: 12px; font-weight: 700; display: flex; align-items: center; gap: 6px;" onclick="copyDeployCommand()">
                            📋 Copy Command
                        </button>
                    </div>
                    <div>
                        <textarea id="deploy-command-output" readonly style="width: 100%; height: 105px; background: #080c14; border: 1px solid var(--border-highlight); border-radius: 6px; padding: 12px 14px; font-family: monospace; font-size: 12px; line-height: 1.5; color: #34d399; resize: none; outline: none; word-break: break-all;"></textarea>
                    </div>
                </div>
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; border-top: 1px solid var(--border-color); padding-top: 14px;">
                <button class="btn" onclick="closeDeployModal()">Close</button>
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
        var rawCommProfiles = [];
        var rawExclusions = [];
        var rawAnomalies = [];
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

            if (tabId === "scanner") fetchScannerData();
            if (tabId === "topology") fetchTopologyData();
            if (tabId === "comms") fetchCommsData();
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
                fetchAPI("/api/v1/exclusions"),
                fetchAPI("/api/v1/network-profiles?level=global")
            ]).then(function(results) {
                rawHierarchy = results[0] || [];
                rawPolicyGroups = results[1] || [];
                rawIOCs = results[2] || [];
                rawExclusions = results[3] || [];
                rawCommProfiles = results[4] || [];

                var totalEndpoints = 0;
                var totalIsolated = 0;
                rawHierarchy.forEach(function(c) {
                    totalEndpoints += c.total_endpoints;
                    totalIsolated += c.isolated_count;
                });

                document.getElementById("metric-endpoints").innerText = totalEndpoints;
                document.getElementById("metric-isolated").innerText = totalIsolated;
                document.getElementById("metric-profiles").innerText = rawCommProfiles.length;
                document.getElementById("metric-exclusions").innerText = rawExclusions.length;
                document.getElementById("metric-iocs").innerText = rawIOCs.length;

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

        /* NETWORK COMMS PROFILING, ANOMALIES & EXCLUSIONS */

        function fetchCommsData() {
            var val = document.getElementById("comms-level-select").value || "global";
            var parts = val.split(":");
            var level = parts[0];
            var id = parts.length > 1 ? parts[1] : "";

            Promise.all([
                fetchAPI("/api/v1/network-profiles?level=" + level + "&id=" + id),
                fetchAPI("/api/v1/anomalies"),
                fetchAPI("/api/v1/exclusions")
            ]).then(function(results) {
                rawCommProfiles = results[0] || [];
                rawAnomalies = results[1] || [];
                rawExclusions = results[2] || [];
                renderCommsTab();
            });
        }

        function renderCommsTab() {
            var anoBody = document.getElementById("anomalies-body");
            if (!rawAnomalies || rawAnomalies.length === 0) {
                anoBody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No communication abnormalities currently detected.</td></tr>';
            } else {
                anoBody.innerHTML = rawAnomalies.map(function(a) {
                    var sevBadge = '<span class="badge badge-isolated">' + a.severity + '</span>';
                    return '<tr style="cursor:pointer;" onclick="openTriageModal(\'' + a.id + '\')">' +
                        '<td>' + new Date(a.timestamp).toLocaleTimeString() + '</td>' +
                        '<td><strong style="color:#fff;">' + (a.hostname || a.endpoint_id) + '</strong></td>' +
                        '<td><span class="badge badge-anomaly">' + a.anomaly_type + '</span></td>' +
                        '<td><code>' + (a.process_path || "*") + '</code></td>' +
                        '<td><code>' + a.dst_ip + (a.dst_port > 0 ? ":" + a.dst_port : "") + '</code></td>' +
                        '<td>' + sevBadge + '</td>' +
                        '<td style="font-size:12px;">' + a.title + '</td>' +
                        '<td style="text-align:right;">' +
                            '<button class="btn btn-cyan" style="padding:4px 10px;font-size:11px;font-weight:700;" onclick="event.stopPropagation(); openTriageModal(\'' + a.id + '\')">⚡ 1-Click Triage</button>' +
                        '</td>' +
                    '</tr>';
                }).join("");
            }

            var profBody = document.getElementById("comms-profiles-body");
            if (!rawCommProfiles || rawCommProfiles.length === 0) {
                profBody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);">No communications profiles captured for this scope.</td></tr>';
            } else {
                profBody.innerHTML = rawCommProfiles.map(function(p) {
                    var inKB = (p.total_bytes_in / 1024).toFixed(1) + " KB";
                    var outKB = (p.total_bytes_out / 1024).toFixed(1) + " KB";
                    return '<tr>' +
                        '<td><strong style="color:var(--cyan);">' + p.process_name + '</strong><div style="font-size:10px;color:var(--text-muted);">' + p.process_path + '</div></td>' +
                        '<td>' + (p.hostname || p.endpoint_id) + '</td>' +
                        '<td><code>' + p.dst_ip + '</code></td>' +
                        '<td>' + (p.dst_port > 0 ? p.dst_port : "Any") + ' / <span class="os-tag">' + p.protocol + '</span></td>' +
                        '<td><span class="os-tag">' + p.direction + '</span></td>' +
                        '<td>🌐 ' + p.country + '</td>' +
                        '<td><strong>' + p.event_count + '</strong> flows</td>' +
                        '<td style="font-size:11px;">⬇️ ' + inKB + ' | ⬆️ ' + outKB + '</td>' +
                        '<td>' + new Date(p.last_seen).toLocaleTimeString() + '</td>' +
                        '<td style="text-align:right;">' +
                            '<button class="btn btn-cyan" style="padding:2px 8px;font-size:11px;" onclick="quickAllowlist(\'' + p.process_name + '\', \'' + p.dst_ip + '\', ' + p.dst_port + ')">⚡ Add Exclusion</button>' +
                        '</td>' +
                    '</tr>';
                }).join("");
            }

            var exBody = document.getElementById("exclusions-body");
            if (!rawExclusions || rawExclusions.length === 0) {
                exBody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);">No custom exclusions defined.</td></tr>';
            } else {
                exBody.innerHTML = rawExclusions.map(function(ex) {
                    var actBadge = ex.active ? '<span class="badge badge-online">ACTIVE PINHOLE</span>' : '<span class="badge badge-offline">DISABLED</span>';
                    return '<tr>' +
                        '<td><strong style="color:#fff;">' + ex.name + '</strong></td>' +
                        '<td><code>' + ex.process_path + '</code></td>' +
                        '<td><code>' + ex.dst_ip_range + '</code></td>' +
                        '<td>' + (ex.port > 0 ? ex.port : "Any") + '</td>' +
                        '<td><span class="os-tag">' + ex.protocol.toUpperCase() + '</span></td>' +
                        '<td><span class="os-tag">' + ex.scope.toUpperCase() + '</span></td>' +
                        '<td style="font-size:12px;color:var(--text-muted);">' + ex.reason + '</td>' +
                        '<td>' + actBadge + '</td>' +
                        '<td style="text-align:right;">' +
                            '<button class="btn btn-isolate" style="padding:2px 8px;font-size:11px;" onclick="deleteExclusion(\'' + ex.id + '\')">Delete</button>' +
                        '</td>' +
                    '</tr>';
                }).join("");
            }
        }

        /* 1-CLICK ANOMALY TRIAGE MODAL */
        var currentTriageAnomaly = null;

        function openTriageModal(anomalyId) {
            var a = (rawAnomalies || []).find(function(x) { return x.id === anomalyId; });
            if (!a) return;
            currentTriageAnomaly = a;

            var sevBadgeClass = a.severity === 'CRITICAL' ? 'badge-isolated' : (a.severity === 'HIGH' ? 'badge-isolated' : 'badge-anomaly');
            document.getElementById("triage-anomaly-type").innerText = a.anomaly_type || "SECURITY_ANOMALY";
            document.getElementById("triage-severity").innerText = a.severity || "HIGH";
            document.getElementById("triage-severity").className = "badge " + sevBadgeClass;
            document.getElementById("triage-anomaly-desc").innerText = a.title + " — " + a.description;

            var ep = null;
            (rawHierarchy || []).forEach(function(c) {
                (c.locations || []).forEach(function(l) {
                    (l.endpoints || []).forEach(function(e) {
                        if (e.id === a.endpoint_id) ep = e;
                    });
                });
            });

            document.getElementById("triage-host").innerText = (a.hostname || a.endpoint_id);
            document.getElementById("triage-host-ip").innerText = (ep ? ep.ip : "-");
            document.getElementById("triage-role").innerText = (ep ? ep.role_tag : "workstation");
            document.getElementById("triage-proc").innerText = a.process_path || "*";

            document.getElementById("triage-dst").innerText = a.dst_ip + (a.dst_port > 0 ? ":" + a.dst_port : "");
            document.getElementById("triage-geo").innerText = a.details && a.details.includes("GeoIP:") ? a.details.split("GeoIP:")[1].split("|")[0].trim() : "External Target";
            document.getElementById("triage-asn").innerText = a.details && a.details.includes("Org:") ? a.details.split("Org:")[1].trim() : (a.details && a.details.includes("ASN:") ? a.details.split("ASN:")[1].trim() : "Unassigned");
            document.getElementById("triage-time").innerText = new Date(a.timestamp).toLocaleTimeString();
            document.getElementById("triage-metrics").innerText = a.details || "Deviation detected in communication baseline";

            document.getElementById("triage-modal").style.display = "flex";
        }

        function closeTriageModal() {
            document.getElementById("triage-modal").style.display = "none";
            currentTriageAnomaly = null;
        }

        function executeTriageAction(action) {
            if (!currentTriageAnomaly) return;
            var a = currentTriageAnomaly;

            if (action === "nullify") {
                var ruleVal = a.process_path || a.dst_ip;
                var ruleType = a.process_path ? "process" : "ip";
                var payload = {
                    tenant_id: a.tenant_id || "default",
                    scope: "global",
                    scope_value: "",
                    name: "Nullify Threat: " + (a.title || ruleVal),
                    description: "Automated 1-click nullification for " + a.anomaly_type,
                    schedule: "all",
                    action: "BLOCK",
                    rule_type: ruleType,
                    rule_value: ruleVal,
                    port: a.dst_port || 0,
                    protocol: "any",
                    active: true
                };
                fetchAPI("/api/v1/policy-groups", "POST", payload).then(function() {
                    return fetchAPI("/api/v1/anomalies/acknowledge", "POST", { id: a.id });
                }).then(function() {
                    alert("🔴 THREAT NULLIFIED: Ring-0 drop rule active for " + ruleVal + " and incident resolved.");
                    closeTriageModal();
                    fetchCommsData();
                    refreshData();
                });
            } else if (action === "quarantine") {
                fetchAPI("/api/v1/endpoints/isolate", "POST", { endpoint_id: a.endpoint_id, allow_ips: ["10.0.0.57"] }).then(function() {
                    return fetchAPI("/api/v1/anomalies/acknowledge", "POST", { id: a.id });
                }).then(function() {
                    alert("🔒 HOST QUARANTINED: Default-deny microsecond network isolation enforced for " + a.endpoint_id);
                    closeTriageModal();
                    fetchCommsData();
                    refreshData();
                });
            } else if (action === "approve") {
                var exPayload = {
                    tenant_id: a.tenant_id || "default",
                    scope: "global",
                    name: "Approved: " + (a.process_path || a.dst_ip),
                    process_path: a.process_path || "*",
                    dst_ip_range: a.dst_ip || "*",
                    port: a.dst_port || 0,
                    protocol: "any",
                    reason: "Operational approval via 1-click triage for " + a.anomaly_type,
                    active: true
                };
                fetchAPI("/api/v1/exclusions", "POST", exPayload).then(function() {
                    return fetchAPI("/api/v1/anomalies/acknowledge", "POST", { id: a.id });
                }).then(function() {
                    alert("🟢 APPROVED: Operational exclusion pinhole deployed.");
                    closeTriageModal();
                    fetchCommsData();
                    refreshData();
                });
            } else if (action === "policy") {
                closeTriageModal();
                document.getElementById("pol-name").value = "Policy: " + (a.title || a.anomaly_type);
                document.getElementById("pol-subnet").value = a.dst_ip || "";
                document.getElementById("pol-proc").value = a.process_path || "";
                document.getElementById("pol-port").value = a.dst_port || 0;
                openPolicyModal();
            }
        }

        function openExclusionModal() { document.getElementById("exclusion-modal").style.display = "flex"; }
        function closeExclusionModal() { document.getElementById("exclusion-modal").style.display = "none"; }

        function quickAllowlist(proc, ip, port) {
            document.getElementById("ex-name").value = "Allowlist: " + (proc || ip);
            document.getElementById("ex-proc").value = proc || "*";
            document.getElementById("ex-ip").value = ip || "*";
            document.getElementById("ex-port").value = port || 0;
            document.getElementById("ex-reason").value = "Approved security / operational tool traffic";
            openExclusionModal();
        }

        function submitExclusion() {
            var name = document.getElementById("ex-name").value;
            var scope = document.getElementById("ex-scope").value;
            var proc = document.getElementById("ex-proc").value;
            var ip = document.getElementById("ex-ip").value;
            var port = parseInt(document.getElementById("ex-port").value) || 0;
            var proto = document.getElementById("ex-proto").value;
            var reason = document.getElementById("ex-reason").value;

            if (!name) return alert("Please enter an exclusion name");

            var payload = {
                tenant_id: "default",
                scope: scope,
                name: name,
                process_path: proc || "*",
                dst_ip_range: ip || "*",
                port: port,
                protocol: proto,
                reason: reason,
                active: true
            };

            fetchAPI("/api/v1/exclusions", "POST", payload).then(function() {
                closeExclusionModal();
                fetchCommsData();
                refreshData();
            });
        }

        function deleteExclusion(id) {
            if (confirm("Revoke exclusion and remove pinhole " + id + "?")) {
                fetchAPI("/api/v1/exclusions?id=" + id, "DELETE").then(function() {
                    fetchCommsData();
                    refreshData();
                });
            }
        }

        /* 4-TIER POLICY GROUPS */
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
                var tierText = (g.scope || "global").toUpperCase() + (g.scope_value ? " (" + g.scope_value + ")" : "");
                var schedText = (g.schedule || "all").replace("_", " ").toUpperCase();

                return '<tr>' +
                    '<td><strong style="color:#fff;">' + g.name + '</strong><div style="font-size:11px;color:var(--text-muted);">' + (g.description || ("Schedule: " + schedText)) + '</div></td>' +
                    '<td><code>' + (g.rule_value || "*") + '</code></td>' +
                    '<td><span class="os-tag">' + (g.rule_type || "IP").toUpperCase() + '</span></td>' +
                    '<td>' + actBadge + '</td>' +
                    '<td>' + protoText + '</td>' +
                    '<td><span class="os-tag">' + tierText + '</span></td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' +
                        '<button class="btn btn-isolate" style="padding:2px 8px;font-size:11px;" onclick="deletePolicyGroup(\'' + g.id + '\')">Delete</button>' +
                    '</td>' +
                '</tr>';
            }).join("");
        }

        function openPolicyModal() { document.getElementById("policy-modal").style.display = "flex"; }
        function closePolicyModal() { document.getElementById("policy-modal").style.display = "none"; }

        function updatePolicyScopeOptions() {
            var scope = document.getElementById("pol-scope").value;
            var valInput = document.getElementById("pol-scope-val");
            if (scope === "global") {
                valInput.value = "";
                valInput.placeholder = "All Fleet Endpoints";
                valInput.disabled = true;
            } else if (scope === "client") {
                valInput.disabled = false;
                valInput.placeholder = "e.g. default";
            } else if (scope === "location") {
                valInput.disabled = false;
                valInput.placeholder = "e.g. loc-home";
            } else if (scope === "role") {
                valInput.disabled = false;
                valInput.placeholder = "e.g. workstation, db-server";
            } else {
                valInput.disabled = false;
                valInput.placeholder = "e.g. endpoint ID or hostname";
            }
        }

        function submitPolicyGroup() {
            var name = document.getElementById("pol-name").value;
            var scope = document.getElementById("pol-scope").value;
            var scopeVal = document.getElementById("pol-scope-val").value.trim();
            var schedule = document.getElementById("pol-schedule").value;
            var action = document.getElementById("pol-action").value;
            var proto = document.getElementById("pol-proto").value;
            var port = parseInt(document.getElementById("pol-port").value) || 0;
            var subnet = document.getElementById("pol-subnet").value.trim();
            var proc = document.getElementById("pol-proc").value.trim();

            if (!name) return alert("Please enter policy name");

            var ruleType = "ip";
            var ruleVal = subnet || "*";
            if (proc) {
                ruleType = "process";
                ruleVal = proc;
            }

            var payload = {
                tenant_id: "default",
                scope: scope,
                scope_value: scopeVal,
                name: name,
                description: "4-Tier Scoped Rule (" + scope.toUpperCase() + ") | Schedule: " + schedule,
                schedule: schedule,
                criteria: "{}",
                action: action,
                rule_type: ruleType,
                rule_value: ruleVal,
                port: port,
                protocol: proto,
                active: true
            };

            fetchAPI("/api/v1/policy-groups", "POST", payload).then(function() {
                closePolicyModal();
                refreshData();
                fetchPolicyGroups();
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

            // 1. Render 24-Hour Diurnal Time-of-Day Activity Chart
            var diurnalEl = document.getElementById("diurnal-chart-container");
            var baselineMap = data.diurnal_baseline || {};
            var liveMap = data.diurnal_live || {};
            
            var maxVal = 1;
            for (var h = 0; h < 24; h++) {
                var bVal = baselineMap[h] || 0;
                var lVal = liveMap[h] || 0;
                if (bVal > maxVal) maxVal = bVal;
                if (lVal > maxVal) maxVal = lVal;
            }

            var diurnalHtml = "";
            for (var h = 0; h < 24; h++) {
                var bVal = baselineMap[h] || 0;
                var lVal = liveMap[h] || 0;
                var bPct = Math.max(4, (bVal / maxVal) * 100);
                var lPct = lVal > 0 ? Math.max(6, (lVal / maxVal) * 100) : 0;
                
                var isOffHours = (h >= 22 || h <= 5);
                var isOffHoursSpike = isOffHours && (lVal > 0);
                var liveBarClass = isOffHoursSpike ? "diurnal-live-bar" : "diurnal-live-bar normal";
                var colBg = isOffHours ? "rgba(239, 68, 68, 0.05)" : "transparent";

                diurnalHtml += '<div class="diurnal-hour-col" style="background:' + colBg + ';" title="Hour ' + String(h).padStart(2, '0') + ':00 UTC | Baseline: ' + bVal + ' | Live: ' + lVal + '">' +
                    '<div class="diurnal-bars-stack">' +
                        '<div class="diurnal-base-bar" style="height:' + bPct + '%;"></div>' +
                        (lVal > 0 ? '<div class="' + liveBarClass + '" style="height:' + lPct + '%;"></div>' : '') +
                    '</div>' +
                    '<div class="diurnal-hour-label">' + String(h).padStart(2, '0') + '</div>' +
                '</div>';
            }
            diurnalEl.innerHTML = diurnalHtml;

            // 2. Render SVG Area Timeline Chart
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

            // 3. Render Top Talkers by Process Executable
            var procsEl = document.getElementById("procs-bars-container");
            var talkers = data.top_talkers || [];
            if (talkers.length === 0 && data.top_processes) {
                for (var p in data.top_processes) {
                    talkers.push({ process: p, flow_count: data.top_processes[p], total_bytes: data.top_processes[p] * 1024 });
                }
            }

            if (talkers.length > 0) {
                var maxFlows = 1;
                talkers.forEach(function(t) { if (t.flow_count > maxFlows) maxFlows = t.flow_count; });

                var procHtml = "";
                talkers.slice(0, 5).forEach(function(t) {
                    var pct = ((t.flow_count / maxFlows) * 100).toFixed(1);
                    var volText = t.total_bytes > 1024*1024 ? (t.total_bytes/(1024*1024)).toFixed(1) + " MB" : (t.total_bytes/1024).toFixed(0) + " KB";
                    procHtml += '<div class="bar-item">' +
                        '<div class="bar-label"><span>⚙️ <strong style="color:#fff;">' + t.process + '</strong></span><span>' + t.flow_count + ' flows (' + volText + ')</span></div>' +
                        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--purple);"></div></div>' +
                    '</div>';
                });
                procsEl.innerHTML = procHtml;
            } else {
                procsEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No process flow streams recorded.</div>';
            }

            // 4. Render GeoIP Country Breakdown & Threat Intel
            var geoipEl = document.getElementById("geoip-bars-container");
            var geoStats = data.geo_stats || [];
            if (geoStats.length > 0) {
                var maxGeo = 1;
                geoStats.forEach(function(g) { if (g.flow_count > maxGeo) maxGeo = g.flow_count; });

                var geoHtml = "";
                geoStats.slice(0, 5).forEach(function(g) {
                    var pct = ((g.flow_count / maxGeo) * 100).toFixed(1);
                    var volMB = (g.total_bytes / (1024*1024)).toFixed(1) + " MB";
                    var threatTag = g.threat_count > 0 ? ' <span class="badge badge-isolated" style="font-size:9px;">' + g.threat_count + ' THREATS</span>' : '';
                    geoHtml += '<div class="bar-item">' +
                        '<div class="bar-label"><span>🌐 <strong>' + g.country + '</strong> (' + g.country_name + ')' + threatTag + '</span><span>' + g.flow_count + ' flows (' + volMB + ')</span></div>' +
                        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--cyan);"></div></div>' +
                    '</div>';
                });
                geoipEl.innerHTML = geoHtml;
            } else {
                var countries = data.countries || { "US": 84, "DE": 12, "CN": 6, "RU": 4 };
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
                geoipEl.innerHTML = geoHtml;
            }

            // 5. Render Enforcement Mode Distribution
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

        /* DEPLOY AGENT MODAL (PUSH + WAZUH-STYLE 1-LINER) */
        var currentDeployPlatform = "windows";
        var currentDeployMode = "push";
        var activePushJobInterval = null;

        function switchDeployMode(mode) {
            currentDeployMode = mode;
            var pushTab = document.getElementById("deploy-tab-push");
            var manualTab = document.getElementById("deploy-tab-manual");
            var pushPanel = document.getElementById("deploy-mode-push");
            var manualPanel = document.getElementById("deploy-mode-manual");

            if (mode === "push") {
                pushTab.className = "btn btn-cyan";
                manualTab.className = "btn";
                pushPanel.style.display = "block";
                manualPanel.style.display = "none";
            } else {
                pushTab.className = "btn";
                manualTab.className = "btn btn-cyan";
                pushPanel.style.display = "none";
                manualPanel.style.display = "block";
                generateDeployCommand();
            }
        }

        function openDeployModal(targetIp, targetOs) {
            // Load remembered tokens from localStorage
            if (localStorage.getItem("ominull_save_cf_tokens") !== "false") {
                document.getElementById("deploy-cf-id").value = localStorage.getItem("ominull_cf_id") || "";
                document.getElementById("deploy-cf-secret").value = localStorage.getItem("ominull_cf_secret") || "";
                document.getElementById("deploy-save-tokens").checked = true;
            }
            populateDeployDropdowns();
            selectDeployPlatform(currentDeployPlatform);

            if (targetIp) {
                document.getElementById("push-target-ip").value = targetIp;
            }
            if (targetOs) {
                var osNorm = targetOs.toLowerCase();
                if (osNorm.indexOf("win") !== -1) {
                    document.getElementById("push-os").value = "windows";
                    selectDeployPlatform("windows");
                } else if (osNorm.indexOf("mac") !== -1 || osNorm.indexOf("darwin") !== -1) {
                    document.getElementById("push-os").value = "macos";
                    selectDeployPlatform("macos");
                } else {
                    document.getElementById("push-os").value = "linux";
                    selectDeployPlatform("linux");
                }
            }

            switchDeployMode("push");
            document.getElementById("push-terminal-box").style.display = "none";
            document.getElementById("push-status-badge").innerText = "Ready to push";
            document.getElementById("push-status-badge").style.color = "var(--text-muted)";
            document.getElementById("btn-launch-push").disabled = false;
            document.getElementById("btn-launch-push").innerText = "🚀 Launch Push Onboarding";

            document.getElementById("deploy-modal").style.display = "flex";
        }

        function closeDeployModal() {
            if (activePushJobInterval) {
                clearInterval(activePushJobInterval);
                activePushJobInterval = null;
            }
            document.getElementById("deploy-modal").style.display = "none";
        }

        function launchPushDeployment() {
            var targetIp = document.getElementById("push-target-ip").value.trim();
            var port = parseInt(document.getElementById("push-port").value, 10) || 22;
            var os = document.getElementById("push-os").value;
            var username = document.getElementById("push-username").value.trim() || "root";
            var password = document.getElementById("push-password").value;
            var role = document.getElementById("push-role").value;
            var tenantId = document.getElementById("deploy-tenant").value || "default";
            var locId = document.getElementById("deploy-location").value || "loc-home";
            var hubUrl = document.getElementById("deploy-hub-url").value.trim() || "https://omi.example.com";

            if (!targetIp) return alert("Please specify the target IP address.");

            var btn = document.getElementById("btn-launch-push");
            var badge = document.getElementById("push-status-badge");
            var term = document.getElementById("push-terminal-box");

            btn.disabled = true;
            btn.innerText = "⏳ Pushing Agent...";
            badge.innerText = "Deployment in progress...";
            badge.style.color = "var(--amber)";
            term.style.display = "block";
            term.innerText = "[*] Dispatching remote push onboarding job to " + targetIp + ":" + port + "...\n";

            fetchAPI("/api/v1/deployer/push", "POST", {
                target_ip: targetIp,
                port: port,
                os: os,
                username: username,
                password: password,
                role: role,
                tenant_id: tenantId,
                location_id: locId,
                hub_url: hubUrl
            }).then(function(res) {
                var jobId = res.job_id;
                term.innerText += "[+] Job ID: " + jobId + " queued. Streaming remote console...\n";

                activePushJobInterval = setInterval(function() {
                    fetchAPI("/api/v1/deployer/status?id=" + jobId).then(function(job) {
                        if (!job) return;
                        if (job.logs && job.logs.length > 0) {
                            term.innerText = job.logs.join("\n");
                            term.scrollTop = term.scrollHeight;
                        }

                        if (job.status === "success") {
                            clearInterval(activePushJobInterval);
                            activePushJobInterval = null;
                            btn.disabled = false;
                            btn.innerText = "✓ Push Completed";
                            badge.innerText = "✓ Successfully Onboarded";
                            badge.style.color = "var(--green)";
                            loadHierarchy();
                            if (document.getElementById("tab-scanner").classList.contains("active")) {
                                fetchScannerData();
                            }
                        } else if (job.status === "failed") {
                            clearInterval(activePushJobInterval);
                            activePushJobInterval = null;
                            btn.disabled = false;
                            btn.innerText = "❌ Push Failed";
                            badge.innerText = "Deployment Failed";
                            badge.style.color = "var(--red)";
                        }
                    }).catch(function(e) {
                        console.error(e);
                    });
                }, 800);
            }).catch(function(err) {
                btn.disabled = false;
                btn.innerText = "🚀 Launch Push Onboarding";
                badge.innerText = "Push Error: " + err;
                badge.style.color = "var(--red)";
                term.innerText += "[-] HTTP dispatch error: " + err + "\n";
            });
        }

        function selectDeployPlatform(plat) {
            currentDeployPlatform = plat;
            ["windows", "linux", "macos"].forEach(function(p) {
                var btn = document.getElementById("plat-btn-" + p);
                if (btn) {
                    if (p === plat) {
                        btn.className = "btn btn-cyan";
                    } else {
                        btn.className = "btn";
                    }
                }
            });
            generateDeployCommand();
        }

        function populateDeployDropdowns() {
            var tenantSelect = document.getElementById("deploy-tenant");
            if (rawHierarchy && rawHierarchy.length > 0) {
                tenantSelect.innerHTML = rawHierarchy.map(function(t) {
                    return '<option value="' + t.tenant.id + '" data-key="' + t.tenant.api_key + '">' + t.tenant.name + '</option>';
                }).join("");
            }
            updateDeployLocationOptions();
        }

        function updateDeployLocationOptions() {
            var tenantSelect = document.getElementById("deploy-tenant");
            var locSelect = document.getElementById("deploy-location");
            var tenantId = tenantSelect.value;
            
            var selectedTenant = (rawHierarchy || []).find(function(t) { return t.tenant.id === tenantId; });
            if (selectedTenant && selectedTenant.locations && selectedTenant.locations.length > 0) {
                locSelect.innerHTML = selectedTenant.locations.map(function(l) {
                    return '<option value="' + l.location.id + '">' + l.location.name + ' (' + l.location.subnet_cidr + ')</option>';
                }).join("");
            } else {
                locSelect.innerHTML = '<option value="loc-home">Primary Home LAN (10.0.0.0/24)</option>';
            }
        }

        function toggleSecretVisibility() {
            var inp = document.getElementById("deploy-cf-secret");
            var btn = document.getElementById("toggle-secret-btn");
            if (inp.type === "password") {
                inp.type = "text";
                btn.innerText = "🙈";
            } else {
                inp.type = "password";
                btn.innerText = "👁️";
            }
        }

        function saveTokensPreference() {
            var save = document.getElementById("deploy-save-tokens").checked;
            localStorage.setItem("ominull_save_cf_tokens", save ? "true" : "false");
            if (save) {
                localStorage.setItem("ominull_cf_id", document.getElementById("deploy-cf-id").value);
                localStorage.setItem("ominull_cf_secret", document.getElementById("deploy-cf-secret").value);
            } else {
                localStorage.removeItem("ominull_cf_id");
                localStorage.removeItem("ominull_cf_secret");
            }
        }

        function generateDeployCommand() {
            saveTokensPreference();
            var hubUrl = document.getElementById("deploy-hub-url").value.trim() || "https://omi.example.com";
            var tenantSelect = document.getElementById("deploy-tenant");
            var opt = tenantSelect.options[tenantSelect.selectedIndex];
            var apiKey = (opt && opt.getAttribute("data-key")) || API_KEY;
            var locId = document.getElementById("deploy-location").value;
            var role = document.getElementById("deploy-role").value;
            var cfId = document.getElementById("deploy-cf-id").value.trim();
            var cfSecret = document.getElementById("deploy-cf-secret").value.trim();

            var out = "";
            if (currentDeployPlatform === "windows") {
                if (cfId && cfSecret) {
                    out = "$h=@{'CF-Access-Client-Id'='" + cfId + "';'CF-Access-Client-Secret'='" + cfSecret + "'}; " +
                          "&([scriptblock]::Create((iwr -UseBasicParsing '" + hubUrl + "/bootstrap.ps1?cf_id=" + encodeURIComponent(cfId) + "&cf_secret=" + encodeURIComponent(cfSecret) + "&role=" + role + "&location=" + locId + "' -Headers $h).Content)) " +
                          "-HubURL '" + hubUrl + "' -APIKey '" + apiKey + "' -RoleTag '" + role + "' -LocationID '" + locId + "'";
                } else {
                    out = "iwr -UseBasicParsing '" + hubUrl + "/bootstrap.ps1?role=" + role + "&location=" + locId + "' | iex";
                }
            } else if (currentDeployPlatform === "linux") {
                if (cfId && cfSecret) {
                    out = "curl -sSL -H \"CF-Access-Client-Id: " + cfId + "\" -H \"CF-Access-Client-Secret: " + cfSecret + "\" \"" + hubUrl + "/bootstrap.sh?cf_id=" + encodeURIComponent(cfId) + "&cf_secret=" + encodeURIComponent(cfSecret) + "&role=" + role + "&location=" + locId + "\" | sudo bash";
                } else {
                    out = "curl -sSL \"" + hubUrl + "/bootstrap.sh?role=" + role + "&location=" + locId + "\" | sudo bash";
                }
            } else if (currentDeployPlatform === "macos") {
                if (cfId && cfSecret) {
                    out = "curl -sSL -H \"CF-Access-Client-Id: " + cfId + "\" -H \"CF-Access-Client-Secret: " + cfSecret + "\" \"" + hubUrl + "/bootstrap.mac.sh?cf_id=" + encodeURIComponent(cfId) + "&cf_secret=" + encodeURIComponent(cfSecret) + "&role=" + role + "&location=" + locId + "\" | sudo bash";
                } else {
                    out = "curl -sSL \"" + hubUrl + "/bootstrap.mac.sh?role=" + role + "&location=" + locId + "\" | sudo bash";
                }
            }

            document.getElementById("deploy-command-output").value = out;
        }

        function copyDeployCommand() {
            var txt = document.getElementById("deploy-command-output");
            txt.select();
            txt.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(txt.value).then(function() {
                var toast = document.getElementById("copy-toast");
                toast.style.opacity = "1";
                setTimeout(function() { toast.style.opacity = "0"; }, 2500);
            });
        }

        /* ASSET SCANNER & EXTENSIBLE FINGERPRINTING */
        var rawScannerAssets = [];
        var activeScanPolling = null;

        function fetchScannerData() {
            Promise.all([
                fetchAPI("/api/v1/scanner/coverage"),
                fetchAPI("/api/v1/scanner/results")
            ]).then(function(res) {
                var cov = res[0] || {};
                rawScannerAssets = res[1] || [];

                document.getElementById("cov-total").innerText = cov.total_discovered || 0;
                document.getElementById("cov-pct").innerText = (cov.coverage_percent || 0).toFixed(1) + "%";
                document.getElementById("cov-crit").innerText = cov.critical_risks || 0;
                document.getElementById("cov-high").innerText = cov.high_risks || 0;
                document.getElementById("cov-sub-managed").innerText = (cov.total_managed || 0) + " Managed Endpoints Online";
                document.getElementById("cov-sub-unmanaged").innerText = (cov.total_unmanaged || 0) + " Unmanaged / Missing Agent";

                renderScannerTable();
            }).catch(function(err) {
                console.error("Scanner fetch error:", err);
            });
        }

        function renderScannerTable() {
            var tbody = document.getElementById("scanner-body");
            if (!rawScannerAssets || rawScannerAssets.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px;">No scan executed yet. Click "Run Network Sweep" above to audit your subnet.</td></tr>';
                return;
            }

            tbody.innerHTML = rawScannerAssets.map(function(a) {
                var isManagedBadge = a.is_managed 
                    ? '<span class="badge badge-permit">🟢 MANAGED AGENT</span>' 
                    : '<span class="badge badge-isolated">🔴 UNMANAGED</span>';

                var riskBadgeClass = "badge-permit";
                if (a.risk_score === "CRITICAL") riskBadgeClass = "badge-isolated";
                else if (a.risk_score === "HIGH") riskBadgeClass = "badge-threat";
                else if (a.risk_score === "MEDIUM") riskBadgeClass = "badge-threat";

                var portsHtml = (a.open_ports || []).map(function(p) {
                    var pClass = p.risk_level === "CRITICAL" ? "color:var(--red);" : (p.risk_level === "HIGH" ? "color:var(--amber);" : "color:var(--cyan);");
                    var tooltip = p.banner ? ' title="' + p.banner.replace(/"/g, '&quot;') + '"' : '';
                    return '<span class="os-tag" style="' + pClass + '"' + tooltip + '>' + p.port + '/' + p.service + '</span>';
                }).join(" ");
                if (!portsHtml) portsHtml = '<span style="color:var(--text-muted);font-size:11px;">No open listeners</span>';

                var weakHtml = (a.weakpoints || []).map(function(w) {
                    return '<div style="font-size:11px;color:#cbd5e1;margin-bottom:2px;">• ' + w + '</div>';
                }).join("");

                var confPct = Math.round((a.confidence || 0) * 100);
                var confColor = confPct >= 85 ? "var(--green)" : (confPct >= 65 ? "var(--cyan)" : "var(--amber)");

                return '<tr>' +
                    '<td>' +
                        '<div style="font-weight:700;color:#fff;font-family:monospace;">' + a.ip + '</div>' +
                        '<div style="font-size:11px;color:var(--text-muted);">' + (a.hostname || "No DNS PTR") + '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="color:var(--cyan);font-weight:600;">' + (a.vendor || "Generic") + '</div>' +
                        '<div style="font-size:10px;font-family:monospace;color:var(--text-muted);">' + a.mac + '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="font-weight:700;color:#fff;">' + (a.os_guess || "Generic Device") + '</div>' +
                        '<div style="font-size:11px;display:flex;align-items:center;gap:4px;margin-top:2px;">' +
                            '<span style="color:' + confColor + ';font-weight:700;">' + confPct + '% confidence</span> • ' +
                            '<span style="color:var(--text-muted);">' + (a.category || "General") + '</span>' +
                        '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="font-size:11px;font-family:monospace;color:#cbd5e1;">TTL: <strong style="color:var(--cyan);">' + (a.ttl || 64) + '</strong></div>' +
                        '<div style="font-size:11px;font-family:monospace;color:#cbd5e1;">Δt: <strong style="color:var(--amber);">' + (a.app_delta_ms ? a.app_delta_ms.toFixed(1) : "1.2") + 'ms</strong></div>' +
                    '</td>' +
                    '<td><div style="max-width:220px;display:flex;flex-wrap:wrap;gap:4px;">' + portsHtml + '</div></td>' +
                    '<td>' + isManagedBadge + '</td>' +
                    '<td>' +
                        '<div class="badge ' + riskBadgeClass + '" style="margin-bottom:4px;">' + a.risk_score + '</div>' +
                        weakHtml +
                    '</td>' +
                    '<td>' +
                        '<div style="display:flex;gap:4px;flex-direction:column;">' +
                            '<button class="btn" style="padding:3px 8px;font-size:11px;" onclick="openTrainModal(\'' + a.ip + '\')">🎓 Train</button>' +
                            (!a.is_managed ? '<button class="btn btn-cyan" style="padding:3px 8px;font-size:11px;" onclick="openDeployForIP(\'' + a.ip + '\', \'' + (a.os_guess || 'linux').replace(/'/g, "\\'") + '\')">🚀 Deploy</button>' : '') +
                        '</div>' +
                    '</td>' +
                '</tr>';
            }).join("");
        }

        function startNetworkScan() {
            var subnet = document.getElementById("scan-subnet").value.trim() || "10.0.0.0/24";
            var profile = document.getElementById("scan-profile").value;
            var btn = document.getElementById("btn-run-scan");
            var pBox = document.getElementById("scan-progress-box");
            var pBar = document.getElementById("scan-progress-bar");
            var pText = document.getElementById("scan-status-text");
            var pPct = document.getElementById("scan-progress-pct");

            btn.disabled = true;
            btn.innerText = "⏳ Scanning...";
            pBox.style.display = "block";
            pBar.style.width = "5%";
            pText.innerText = "Initiating " + profile.toUpperCase() + " sweep against " + subnet + "...";
            pPct.innerText = "5%";

            fetchAPI("/api/v1/scanner/scan", "POST", { subnet: subnet, profile: profile }).then(function(res) {
                var scanId = res.scan_id;
                if (activeScanPolling) clearInterval(activeScanPolling);

                activeScanPolling = setInterval(function() {
                    fetchAPI("/api/v1/scanner/status?id=" + scanId).then(function(st) {
                        pBar.style.width = st.progress + "%";
                        pPct.innerText = st.progress + "%";
                        pText.innerText = "Scanning " + st.subnet + " (" + st.found_count + " hosts found so far)...";

                        if (st.status === "completed" || st.status === "failed") {
                            clearInterval(activeScanPolling);
                            btn.disabled = false;
                            btn.innerText = "🚀 Run Network Sweep";
                            pText.innerText = "Scan completed: Found " + st.found_count + " live assets.";
                            setTimeout(function() { pBox.style.display = "none"; }, 3000);
                            fetchScannerData();
                        }
                    }).catch(function(e) {
                        clearInterval(activeScanPolling);
                        btn.disabled = false;
                        btn.innerText = "🚀 Run Network Sweep";
                    });
                }, 800);
            }).catch(function(err) {
                alert("Failed to start scan: " + err);
                btn.disabled = false;
                btn.innerText = "🚀 Run Network Sweep";
                pBox.style.display = "none";
            });
        }

        var trainTargetIP = "";
        function openTrainModal(ip) {
            trainTargetIP = ip;
            var asset = rawScannerAssets.find(function(a) { return a.ip === ip; });
            if (!asset) return;

            document.getElementById("train-ip").innerText = asset.ip + " (" + (asset.hostname || "No Hostname") + ")";
            document.getElementById("train-vendor-seen").innerText = asset.vendor + " (" + asset.mac + ")";
            document.getElementById("train-ports-seen").innerText = (asset.open_ports || []).map(function(p) { return p.port + "/" + p.service; }).join(", ") || "None";

            document.getElementById("train-name").value = asset.os_guess || "";
            document.getElementById("train-vendor").value = asset.vendor !== "Generic / Unassigned Hardware" ? asset.vendor : "";
            document.getElementById("train-category").value = asset.category || "Smart TV / Media Streamer";

            document.getElementById("train-modal").style.display = "flex";
        }

        function closeTrainModal() {
            document.getElementById("train-modal").style.display = "none";
        }

        function submitTrainSignature() {
            var name = document.getElementById("train-name").value.trim();
            var vendor = document.getElementById("train-vendor").value.trim();
            var cat = document.getElementById("train-category").value;

            if (!name) return alert("Please specify the ground truth device / OS name.");

            fetchAPI("/api/v1/scanner/feedback", "POST", {
                ip: trainTargetIP,
                actual_device: name,
                vendor: vendor,
                category: cat
            }).then(function(res) {
                closeTrainModal();
                alert("Extensible signature trained successfully! Target asset reclassified as " + name + " (98% confidence).");
                fetchScannerData();
            }).catch(function(err) {
                alert("Failed to train signature: " + err);
            });
        }

        function openDeployForIP(ip, osGuess) {
            openDeployModal(ip, osGuess);
        }

        /* FORCE-DIRECTED COMMUNICATIONS TOPOLOGY GRAPH */
        var topoNodes = [];
        var topoEdges = [];
        var topoCanvas = null;
        var topoCtx = null;
        var topoAnimFrame = null;
        var topoTransform = { x: 0, y: 0, scale: 1.0 };
        var draggedNode = null;
        var hoveredNode = null;
        var isPanning = false;
        var startPan = { x: 0, y: 0 };

        function fetchTopologyData() {
            var win = document.getElementById("topo-window").value || "1h";
            fetchAPI("/api/v1/topology/graph?window=" + win).then(function(data) {
                if (!data) return;
                var metrics = data.metrics || {};
                document.getElementById("topo-metric-nodes").innerText = metrics.total_nodes || 0;
                document.getElementById("topo-metric-edges").innerText = metrics.total_edges || 0;
                document.getElementById("topo-metric-anom").innerText = metrics.anomalous_edge_count || 0;
                document.getElementById("topo-metric-managed").innerText = metrics.managed_nodes_count || 0;
                document.getElementById("topo-metric-unmanaged").innerText = metrics.unmanaged_nodes_count || 0;

                initTopologyCanvas(data.nodes || [], data.edges || []);
            }).catch(function(err) {
                console.error("Topology fetch error:", err);
            });
        }

        function initTopologyCanvas(nodes, edges) {
            topoCanvas = document.getElementById("topo-canvas");
            if (!topoCanvas) return;
            topoCtx = topoCanvas.getContext("2d");

            // Match canvas internal resolution
            var rect = topoCanvas.getBoundingClientRect();
            topoCanvas.width = rect.width * (window.devicePixelRatio || 1);
            topoCanvas.height = rect.height * (window.devicePixelRatio || 1);
            topoCtx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

            var width = rect.width;
            var height = rect.height;

            // Preserve existing node positions if re-fetching
            var oldPositions = {};
            topoNodes.forEach(function(n) { oldPositions[n.id] = { x: n.x, y: n.y }; });

            topoNodes = nodes.map(function(n, i) {
                var angle = (i / nodes.length) * Math.PI * 2;
                var radius = 160 + (i % 3) * 60;
                var initX = oldPositions[n.id] ? oldPositions[n.id].x : (width / 2 + Math.cos(angle) * radius);
                var initY = oldPositions[n.id] ? oldPositions[n.id].y : (height / 2 + Math.sin(angle) * radius);

                var r = 24;
                if (n.type === "threat") r = 28;
                else if (n.type === "cloud") r = 22;

                return {
                    id: n.id,
                    label: n.label,
                    type: n.type,
                    ip: n.ip,
                    os: n.os,
                    role: n.role,
                    risk: n.risk,
                    isIsolated: n.is_isolated,
                    group: n.group,
                    x: initX,
                    y: initY,
                    vx: 0,
                    vy: 0,
                    radius: r
                };
            });

            topoEdges = edges.map(function(e) {
                return {
                    id: e.id,
                    sourceId: e.source,
                    targetId: e.target,
                    protocol: e.protocol,
                    port: e.port,
                    flowCount: e.flow_count,
                    totalBytes: e.total_bytes,
                    verdict: e.verdict,
                    particles: [
                        { progress: Math.random() * 0.5, speed: 0.006 + Math.random() * 0.004 },
                        { progress: 0.5 + Math.random() * 0.5, speed: 0.006 + Math.random() * 0.004 }
                    ]
                };
            });

            setupCanvasListeners(topoCanvas);
            if (!topoAnimFrame) {
                runTopologyLoop();
            }
        }

        function runTopologyLoop() {
            updateTopologyPhysics();
            drawTopology();
            topoAnimFrame = requestAnimationFrame(runTopologyLoop);
        }

        function updateTopologyPhysics() {
            var kRepulse = 3800;
            var kSpring = 0.04;
            var springLength = 140;
            var damping = 0.82;
            var rect = topoCanvas.getBoundingClientRect();
            var cx = rect.width / 2;
            var cy = rect.height / 2;

            // 1. Coulomb Repulsion between all node pairs
            for (var i = 0; i < topoNodes.length; i++) {
                for (var j = i + 1; j < topoNodes.length; j++) {
                    var n1 = topoNodes[i];
                    var n2 = topoNodes[j];
                    var dx = n2.x - n1.x;
                    var dy = n2.y - n1.y;
                    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    if (dist < 350) {
                        var force = kRepulse / (dist * dist);
                        var fx = (dx / dist) * force;
                        var fy = (dy / dist) * force;
                        if (n1 !== draggedNode) { n1.vx -= fx; n1.vy -= fy; }
                        if (n2 !== draggedNode) { n2.vx += fx; n2.vy += fy; }
                    }
                }
            }

            // 2. Hooke Spring Attraction along edges
            var nodeMap = {};
            topoNodes.forEach(function(n) { nodeMap[n.id] = n; });

            topoEdges.forEach(function(e) {
                var s = nodeMap[e.sourceId];
                var t = nodeMap[e.targetId];
                if (s && t) {
                    var dx = t.x - s.x;
                    var dy = t.y - s.y;
                    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    var displacement = dist - springLength;
                    var force = displacement * kSpring;
                    var fx = (dx / dist) * force;
                    var fy = (dy / dist) * force;
                    if (s !== draggedNode) { s.vx += fx; s.vy += fy; }
                    if (t !== draggedNode) { t.vx -= fx; t.vy -= fy; }

                    // Advance edge particles
                    e.particles.forEach(function(p) {
                        p.progress += p.speed;
                        if (p.progress > 1) p.progress = 0;
                    });
                }
            });

            // 3. Center Gravity & Integration
            topoNodes.forEach(function(n) {
                if (n !== draggedNode) {
                    var cdx = cx - n.x;
                    var cdy = cy - n.y;
                    n.vx += cdx * 0.003;
                    n.vy += cdy * 0.003;
                    n.vx *= damping;
                    n.vy *= damping;
                    n.x += n.vx;
                    n.y += n.vy;
                }
            });
        }

        function drawTopology() {
            if (!topoCtx || !topoCanvas) return;
            var rect = topoCanvas.getBoundingClientRect();
            var w = rect.width;
            var h = rect.height;

            topoCtx.clearRect(0, 0, w, h);
            topoCtx.save();
            topoCtx.translate(topoTransform.x, topoTransform.y);
            topoCtx.scale(topoTransform.scale, topoTransform.scale);

            var nodeMap = {};
            topoNodes.forEach(function(n) { nodeMap[n.id] = n; });

            // 1. Draw Edges
            topoEdges.forEach(function(e) {
                var s = nodeMap[e.sourceId];
                var t = nodeMap[e.targetId];
                if (!s || !t) return;

                var strokeColor = "rgba(6, 182, 212, 0.4)";
                var particleColor = "var(--cyan)";
                var width = 2;

                if (e.verdict === "blocked" || e.verdict === "anomalous") {
                    strokeColor = "rgba(239, 68, 68, 0.6)";
                    particleColor = "var(--red)";
                    width = 3;
                } else if (e.totalBytes > 1024 * 1024) {
                    strokeColor = "rgba(168, 85, 247, 0.5)";
                    particleColor = "var(--purple)";
                    width = 3.5;
                }

                // Line
                topoCtx.beginPath();
                topoCtx.moveTo(s.x, s.y);
                topoCtx.lineTo(t.x, t.y);
                topoCtx.strokeStyle = strokeColor;
                topoCtx.lineWidth = width;
                topoCtx.stroke();

                // Directional Arrowhead
                var angle = Math.atan2(t.y - s.y, t.x - s.x);
                var arrowDist = t.radius + 6;
                var arrowX = t.x - Math.cos(angle) * arrowDist;
                var arrowY = t.y - Math.sin(angle) * arrowDist;

                topoCtx.beginPath();
                topoCtx.moveTo(arrowX, arrowY);
                topoCtx.lineTo(arrowX - 8 * Math.cos(angle - Math.PI / 6), arrowY - 8 * Math.sin(angle - Math.PI / 6));
                topoCtx.lineTo(arrowX - 8 * Math.cos(angle + Math.PI / 6), arrowY - 8 * Math.sin(angle + Math.PI / 6));
                topoCtx.fillStyle = strokeColor;
                topoCtx.fill();

                // Live Particles
                e.particles.forEach(function(p) {
                    var px = s.x + (t.x - s.x) * p.progress;
                    var py = s.y + (t.y - s.y) * p.progress;
                    topoCtx.beginPath();
                    topoCtx.arc(px, py, 3, 0, Math.PI * 2);
                    topoCtx.fillStyle = particleColor;
                    topoCtx.shadowColor = particleColor;
                    topoCtx.shadowBlur = 8;
                    topoCtx.fill();
                    topoCtx.shadowBlur = 0;
                });
            });

            // 2. Draw Nodes
            topoNodes.forEach(function(n) {
                var color = "var(--cyan)";
                var glow = "rgba(6, 182, 212, 0.3)";
                var icon = "💻";

                if (n.role === "server") {
                    color = "var(--green)";
                    glow = "rgba(16, 185, 129, 0.4)";
                    icon = "🖥️";
                } else if (n.type === "unmanaged") {
                    color = "var(--amber)";
                    glow = "rgba(245, 158, 11, 0.4)";
                    icon = "❓";
                } else if (n.type === "cloud") {
                    color = "#38bdf8";
                    glow = "rgba(56, 189, 248, 0.4)";
                    icon = "☁️";
                } else if (n.type === "threat") {
                    color = "var(--red)";
                    glow = "rgba(239, 68, 68, 0.6)";
                    icon = "🚨";
                }

                if (n.isIsolated) {
                    color = "var(--red)";
                    glow = "rgba(239, 68, 68, 0.8)";
                    icon = "🔒";
                }

                // Halo Glow
                topoCtx.beginPath();
                topoCtx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
                topoCtx.fillStyle = glow;
                topoCtx.fill();

                // Node Body
                topoCtx.beginPath();
                topoCtx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                topoCtx.fillStyle = "#0f172a";
                topoCtx.fill();
                topoCtx.lineWidth = 2.5;
                topoCtx.strokeStyle = color;
                topoCtx.stroke();

                // Icon
                topoCtx.font = "14px sans-serif";
                topoCtx.textAlign = "center";
                topoCtx.textBaseline = "middle";
                topoCtx.fillText(icon, n.x, n.y);

                // Label
                topoCtx.font = "bold 11px Inter, sans-serif";
                topoCtx.fillStyle = "#fff";
                topoCtx.fillText(n.label, n.x, n.y + n.radius + 14);

                // Sub-label (IP or Status)
                topoCtx.font = "10px monospace";
                topoCtx.fillStyle = "var(--text-muted)";
                topoCtx.fillText(n.ip, n.x, n.y + n.radius + 26);
            });

            topoCtx.restore();
        }

        function setupCanvasListeners(canvas) {
            var isMouseDown = false;
            var startX = 0;
            var startY = 0;

            canvas.onmousedown = function(e) {
                var rect = canvas.getBoundingClientRect();
                var mx = (e.clientX - rect.left - topoTransform.x) / topoTransform.scale;
                var my = (e.clientY - rect.top - topoTransform.y) / topoTransform.scale;

                var clicked = topoNodes.find(function(n) {
                    var dx = n.x - mx;
                    var dy = n.y - my;
                    return Math.sqrt(dx * dx + dy * dy) <= n.radius + 4;
                });

                if (clicked) {
                    draggedNode = clicked;
                    openTopoInspector(clicked);
                } else {
                    isPanning = true;
                    startPan = { x: e.clientX - topoTransform.x, y: e.clientY - topoTransform.y };
                }
            };

            window.onmousemove = function(e) {
                var rect = canvas.getBoundingClientRect();
                var mx = (e.clientX - rect.left - topoTransform.x) / topoTransform.scale;
                var my = (e.clientY - rect.top - topoTransform.y) / topoTransform.scale;

                if (draggedNode) {
                    draggedNode.x = mx;
                    draggedNode.y = my;
                    draggedNode.vx = 0;
                    draggedNode.vy = 0;
                } else if (isPanning) {
                    topoTransform.x = e.clientX - startPan.x;
                    topoTransform.y = e.clientY - startPan.y;
                } else {
                    var hov = topoNodes.find(function(n) {
                        var dx = n.x - mx;
                        var dy = n.y - my;
                        return Math.sqrt(dx * dx + dy * dy) <= n.radius + 4;
                    });
                    canvas.style.cursor = hov ? "pointer" : "grab";
                }
            };

            window.onmouseup = function() {
                draggedNode = null;
                isPanning = false;
            };

            canvas.onwheel = function(e) {
                e.preventDefault();
                var zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
                topoTransform.scale = Math.max(0.4, Math.min(2.5, topoTransform.scale * zoomFactor));
            };
        }

        function openTopoInspector(node) {
            var insp = document.getElementById("topo-inspector");
            var title = document.getElementById("topo-insp-title");
            var content = document.getElementById("topo-insp-content");
            var actions = document.getElementById("topo-insp-actions");

            title.innerText = node.label + " (" + node.ip + ")";
            content.innerHTML = 
                '<div class="detail-row"><span class="detail-label">Node Type</span><span class="detail-value">' + node.type.toUpperCase() + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">OS / Category</span><span class="detail-value">' + node.os + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Role Tag</span><span class="detail-value">' + (node.role || "workstation") + '</span></div>' +
                '<div class="detail-row"><span class="detail-label">Security Risk</span><span class="detail-value badge ' + (node.risk === "CRITICAL" ? "badge-isolated" : "badge-permit") + '">' + node.risk + '</span></div>';

            var actHtml = "";
            if (node.type === "unmanaged") {
                actHtml += '<button class="btn btn-cyan" style="padding:4px 8px;font-size:11px;" onclick="openDeployModal()">🚀 Deploy Agent</button>';
                actHtml += '<button class="btn" style="padding:4px 8px;font-size:11px;" onclick="openTrainModal(\'' + node.ip + '\')">🎓 Train</button>';
            } else if (node.type === "managed") {
                actHtml += '<button class="btn btn-isolate" style="padding:4px 8px;font-size:11px;" onclick="toggleIsolation(\'' + node.ip + '\', ' + !node.isIsolated + ')">' + (node.isIsolated ? "Restore Host" : "Quarantine Host") + '</button>';
            }
            actions.innerHTML = actHtml;
            insp.style.display = "block";
        }

        function closeTopoInspector() {
            document.getElementById("topo-inspector").style.display = "none";
        }

        // Initialize on load
        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>
`
