package detector

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

func evidenceOf(t *testing.T, a storage.AnomalyAlert) map[string]any {
	t.Helper()
	fields := map[string]any{}
	if err := json.Unmarshal([]byte(a.Evidence), &fields); err != nil {
		t.Fatalf("evidence of %s is not an object: %q", a.ID, a.Evidence)
	}
	return fields
}

// The fixed page list, and what is recorded or digested instead.
func TestClassifyPagesOnlyTheFixedList(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	cfg.LabCIDRs = []string{"10.20.0.0/24"}
	cfg.InfraCIDRs = []string{"10.0.0.1/32", "10.0.1.0/24"}
	cx := NewClassContext(cfg, []storage.Endpoint{
		{ID: "agent-ws", RoleTag: storage.RoleAgent, IP: "10.0.0.10"},
		{ID: "laptop", IP: "10.0.0.11"},
		{ID: "guest", IP: "10.20.0.101", Presence: storage.PresenceParked},
		{ID: "srv", RoleTag: "server", IP: "10.0.0.2", Presence: storage.PresenceAlwaysOn},
		{ID: "pc", IP: "10.0.0.12", Presence: storage.PresenceAlwaysOn},
	}, nil)
	targets := func(ips ...string) string {
		var list []map[string]any
		for _, ip := range ips {
			list = append(list, map[string]any{"ip": ip, "ports": []int{22}})
		}
		raw, _ := json.Marshal(map[string]any{"sweep_targets": list, "floor_ports": []int{}})
		return string(raw)
	}
	home, infra := make([]string, 0, 10), make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		home = append(home, fmt.Sprintf("10.0.0.%d", 100+i))
		infra = append(infra, fmt.Sprintf("10.0.1.%d", 1+i))
	}
	for _, c := range []struct {
		name string
		a    storage.AnomalyAlert
		want string
	}{
		{"confident threat intel", storage.AnomalyAlert{AnomalyType: "THREAT_INTEL_MATCH", Evidence: `{"intel_confidence":90}`}, storage.ClassPage},
		{"weak threat intel", storage.AnomalyAlert{AnomalyType: "THREAT_INTEL_MATCH", Evidence: `{"intel_confidence":40}`}, storage.ClassRecord},
		{"threat intel confidence from an old description", storage.AnomalyAlert{AnomalyType: "THREAT_INTEL_MATCH", Description: "feed x (confidence 60%)"}, storage.ClassRecord},
		{"decoy", storage.AnomalyAlert{AnomalyType: "DECOY_TOUCH"}, storage.ClassPage},
		{"lab escape", storage.AnomalyAlert{AnomalyType: "LAB_ESCAPE"}, storage.ClassPage},
		{"new place upload", storage.AnomalyAlert{AnomalyType: "NEW_PLACE_UPLOAD"}, storage.ClassPage},
		{"agent first visit", storage.AnomalyAlert{AnomalyType: "AGENT_NEW_DESTINATION", Title: "claude reached a destination it never has: x.example"}, storage.ClassRecord},
		{"agent first visit with an upload", storage.AnomalyAlert{AnomalyType: "AGENT_NEW_DESTINATION", Evidence: `{"first_upload_bytes":2000000}`}, storage.ClassPage},
		{"agent upload volume", storage.AnomalyAlert{AnomalyType: "AGENT_UPLOAD_VOLUME"}, storage.ClassPage},
		{"sensitive port out", storage.AnomalyAlert{AnomalyType: "SENSITIVE_PORT_EGRESS"}, storage.ClassPage},
		{"off hours", storage.AnomalyAlert{AnomalyType: "OFF_HOURS_ACTIVITY"}, storage.ClassRecord},
		{"novel destination", storage.AnomalyAlert{AnomalyType: "NOVEL_DESTINATION"}, storage.ClassRecord},
		{"new LAN device", storage.AnomalyAlert{ID: "alert-disc-1", AnomalyType: "NOVEL_DESTINATION"}, storage.ClassDigest},
		{"bandwidth", storage.AnomalyAlert{AnomalyType: "BANDWIDTH_SPIKE"}, storage.ClassRecord},
		{"dns bypass", storage.AnomalyAlert{AnomalyType: "AGENT_DNS_BYPASS"}, storage.ClassRecord},
		{"cloud storage", storage.AnomalyAlert{AnomalyType: "CLOUD_STORAGE_EGRESS"}, storage.ClassDigest},
		{"returned", storage.AnomalyAlert{AnomalyType: "ENDPOINT_RETURNED"}, storage.ClassDigest},
		{"collector health", storage.AnomalyAlert{AnomalyType: "COLLECTOR_HEALTH"}, storage.ClassRecord},
		{"beacon, rare and strong", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"score":0.95,"span_minutes":40,"beacon_devices":1}`}, storage.ClassPage},
		{"beacon, common", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"score":0.95,"span_minutes":40,"beacon_devices":4}`}, storage.ClassDigest},
		{"beacon, short", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"score":0.95,"span_minutes":11,"beacon_devices":1}`}, storage.ClassDigest},
		{"beacon, resolver", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstIP: "1.1.1.1", DstPort: 53, Evidence: `{"score":0.99,"span_minutes":60,"beacon_devices":1}`}, storage.ClassDigest},
		{"beacon, LAN resolver", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstIP: "10.0.0.1", DstPort: 853, Evidence: `{"score":0.99,"span_minutes":60,"beacon_devices":1}`}, storage.ClassDigest},
		{"beacon on port 53 to a public non-resolver", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstIP: "203.0.113.53", DstPort: 53, Evidence: `{"score":0.99,"span_minutes":60,"beacon_devices":1}`}, storage.ClassPage},
		{"beacon, rarity unknown", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"score":0.95,"span_minutes":40,"beacon_devices_unknown":true}`}, storage.ClassPage},
		{"beacon stored before rarity", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"score":0.95,"span_minutes":40}`}, storage.ClassDigest},
		{"beacon, tunnel front", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"tunnel_service":true}`}, storage.ClassPage},
		{"beacon, browser on a tunnel front", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 443, Evidence: `{"tunnel_service":true,"browser":true}`}, storage.ClassDigest},
		{"infra host silent", storage.AnomalyAlert{AnomalyType: "ENDPOINT_SILENT", EndpointID: "srv"}, storage.ClassPage},
		{"always-on desktop silent", storage.AnomalyAlert{AnomalyType: "ENDPOINT_SILENT", EndpointID: "pc"}, storage.ClassRecord},
		{"laptop silent", storage.AnomalyAlert{AnomalyType: "ENDPOINT_SILENT", EndpointID: "laptop"}, storage.ClassRecord},
		{"scan from a laptop", storage.AnomalyAlert{AnomalyType: "PORT_SCAN_RECON", EndpointID: "laptop", DstIP: "203.0.113.4"}, storage.ClassPage},
		{"scan from an agent host, outward", storage.AnomalyAlert{AnomalyType: "PORT_SCAN_RECON", EndpointID: "agent-ws", DstIP: "203.0.113.4"}, storage.ClassRecord},
		{"scan from an agent host into the lab", storage.AnomalyAlert{AnomalyType: "PORT_SCAN_RECON", EndpointID: "agent-ws", DstIP: "10.20.0.5"}, storage.ClassRecord},
		{"scan from an agent host into home", storage.AnomalyAlert{AnomalyType: "PORT_SCAN_RECON", EndpointID: "agent-ws", DstIP: "10.0.0.50"}, storage.ClassPage},
		{"scan of loopback", storage.AnomalyAlert{AnomalyType: "PORT_SCAN_RECON", EndpointID: "laptop", DstIP: "127.0.0.1"}, storage.ClassRecord},
		{"sweep to a floor port", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "agent-ws", DstPort: 445}, storage.ClassPage},
		{"ssh round of the lab", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "agent-ws", DstPort: 22,
			Evidence: targets("10.20.0.101", "10.20.0.102", "10.20.0.103", "10.0.0.1", "10.0.0.2")}, storage.ClassRecord},
		{"fan-out to ten home hosts", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "agent-ws", DstPort: 22, Evidence: targets(home...)}, storage.ClassPage},
		{"personal host sweeping the infrastructure", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "laptop", DstPort: 22, Evidence: targets(infra...)}, storage.ClassPage},
		{"agent workstation's round of the infrastructure", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "agent-ws", DstPort: 22, Evidence: targets(infra...)}, storage.ClassRecord},
		{"lab host sweeping home", storage.AnomalyAlert{AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "guest", DstPort: 22, Evidence: targets("10.0.0.100")}, storage.ClassPage},
		{"unknown detector", storage.AnomalyAlert{AnomalyType: "SOMETHING_NEW"}, storage.ClassPage},
	} {
		if got, why := cx.Classify(c.a); got != c.want {
			t.Errorf("%s: class %s (%s), want %s", c.name, got, why, c.want)
		}
	}
}

// A threat-list match pages at intel_page_confidence or above, else it is
// recorded; it isolates only a host whose role is in auto_isolate_roles.
func TestThreatIntelPagesByConfidenceAndIsolatesByRole(t *testing.T) {
	engine, store := noiseEngine(t)
	var isolated []string
	engine.onAutoIsolate = func(endpoint, _ string) error {
		isolated = append(isolated, endpoint)
		return nil
	}
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "lap", TenantID: "default", Hostname: "lap", Status: "online", LastSeenAt: now},
		{ID: "srv", TenantID: "default", Hostname: "srv", RoleTag: "server", Status: "online", LastSeenAt: now},
		{ID: "ws", TenantID: "default", Hostname: "ws", RoleTag: storage.RoleAgent, Status: "online", LastSeenAt: now},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	hit := func(endpoint, dst string, conf int) {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: endpoint, Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: dst, DstPort: 443, BytesOut: 900, ProcessPath: "/usr/bin/curl",
			ThreatMatch: &storage.IOC{Value: dst, Source: "test-feed", ThreatType: "c2", Confidence: conf, Active: true}})
	}
	hit("lap", "185.220.101.5", 90)
	hit("srv", "185.220.101.6", 90)
	hit("ws", "185.220.101.7", 90)
	hit("lap", "185.220.101.8", 40)
	got := map[string]storage.AnomalyAlert{}
	for _, a := range anomaliesOfType(t, store, "THREAT_INTEL_MATCH") {
		got[a.DstIP] = a
	}
	if len(got) != 4 {
		t.Fatalf("four matches should raise four findings, got %d", len(got))
	}
	for dst, want := range map[string]string{"185.220.101.5": storage.ClassPage, "185.220.101.6": storage.ClassPage,
		"185.220.101.7": storage.ClassPage, "185.220.101.8": storage.ClassRecord} {
		if c := storage.AlertClass(got[dst]); c != want {
			t.Errorf("%s: class %s, want %s", dst, c, want)
		}
	}
	if got["185.220.101.8"].HeldReason != storage.HeldHunt {
		t.Errorf("a weak match is recorded (held), got held %q", got["185.220.101.8"].HeldReason)
	}
	if len(isolated) != 1 || isolated[0] != "lap" {
		t.Fatalf("isolated %v, want only the personal laptop on its confident match", isolated)
	}
}

// A second page about the same device, rule and counterparty joins the open
// incident and is held, not pushed again; one that raises the severity is an
// escalation and stays open.
func TestARepeatPageJoinsItsIncident(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	ep := storage.Endpoint{ID: "lap", TenantID: "default", Hostname: "lap"}
	page := func(id, sev string, at time.Time) storage.AnomalyAlert {
		ev := storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: at, Direction: "OUTBOUND", DstIP: "198.51.100.7", DstPort: 445}
		engine.recordAnomaly(ev, threatintel.GeoRecord{}, ep, storage.AnomalyAlert{ID: id, TenantID: "default", EndpointID: "lap", Hostname: "lap",
			AnomalyType: "SENSITIVE_PORT_EGRESS", Severity: sev, Title: "smb out", DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: at})
		a, err := store.GetAnomalyAlert(id)
		if err != nil {
			t.Fatalf("alert %s not written: %v", id, err)
		}
		return a
	}
	first := page("p1", "HIGH", now.Add(-3*time.Hour))
	again := page("p2", "HIGH", now.Add(-2*time.Hour))
	worse := page("p3", "CRITICAL", now.Add(-time.Hour))
	later := page("p4", "HIGH", now.Add(26*time.Hour))
	if first.HeldReason != "" || evidenceOf(t, first)["incident"] != "inc-p1" {
		t.Fatalf("the first page opens inc-p1 and stays open: %q %s", first.HeldReason, first.Evidence)
	}
	if again.HeldReason != storage.HeldIncident || evidenceOf(t, again)["incident"] != "inc-p1" {
		t.Fatalf("a repeat joins inc-p1, held: %q %s", again.HeldReason, again.Evidence)
	}
	if ev := evidenceOf(t, worse); worse.HeldReason != "" || ev["incident"] != "inc-p1" || ev["escalation"] != true {
		t.Fatalf("a worse page escalates inc-p1 and stays open: %q %s", worse.HeldReason, worse.Evidence)
	}
	if later.HeldReason != "" || evidenceOf(t, later)["incident"] != "inc-p4" {
		t.Fatalf("past page_incident_hours a page opens a new incident: %q %s", later.HeldReason, later.Evidence)
	}
}

// A lab guest reaching a home host pages; its DNS and time lookups and the
// sensor's own heartbeat to the hub do not.
func TestALabHostReachingHomePages(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	guest := storage.Endpoint{ID: "guest", TenantID: "default", Hostname: "guest", Status: "online", LastSeenAt: now, IP: "10.20.0.101"}
	if err := store.UpsertEndpoint(guest); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointPresence("guest", storage.PresenceParked); err != nil {
		t.Fatal(err)
	}
	flow := func(dst string, port uint16, path string, at time.Time) {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "guest", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: dst, DstPort: port, BytesOut: 300, ProcessPath: path})
	}
	flow("10.0.0.1", 53, "/usr/lib/systemd/systemd-resolved", now)
	flow("10.0.0.1", 123, "/usr/lib/systemd/systemd-timesyncd", now)
	flow("10.0.0.58", 9443, "/opt/ominull/bin/ominulld", now)
	if got := anomaliesOfType(t, store, "LAB_ESCAPE"); len(got) != 0 {
		t.Fatalf("lookups and the sensor raised %d lab escapes", len(got))
	}
	flow("10.0.0.77", 8080, "/usr/bin/python3", now.Add(time.Second))
	got := anomaliesOfType(t, store, "LAB_ESCAPE")
	if len(got) != 1 || storage.AlertClass(got[0]) != storage.ClassPage || got[0].HeldReason != "" {
		t.Fatalf("a lab host reaching a home host should page once, got %+v", got)
	}
}

// Any connection to a decoy address pages, whatever the program.
func TestADecoyTouchPages(t *testing.T) {
	engine, store := noiseEngine(t)
	cfg := store.GetDetectionTuning()
	cfg.DecoyAddrs = []string{"10.0.0.250"}
	if _, err := store.SaveDetectionTuning(cfg, "test"); err != nil {
		t.Fatal(err)
	}
	engine.tuningAt = time.Time{}
	now := time.Now().UTC()
	engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "10.0.0.251", DstPort: 22, ProcessPath: "/usr/bin/ssh"})
	if got := anomaliesOfType(t, store, "DECOY_TOUCH"); len(got) != 0 {
		t.Fatalf("a neighbour of the decoy raised %d", len(got))
	}
	engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "10.0.0.250", DstPort: 22, ProcessPath: "/usr/bin/ssh"})
	got := anomaliesOfType(t, store, "DECOY_TOUCH")
	if len(got) != 1 || storage.AlertClass(got[0]) != storage.ClassPage {
		t.Fatalf("a decoy touch should page once, got %+v", got)
	}
}

// Any program on a device sending a megabyte to a place nothing on it ever
// reached pages once; the same upload to a known place does not.
func TestABulkUploadToANewPlacePages(t *testing.T) {
	engine, store := noiseEngine(t)
	start := time.Now().UTC().Add(-10 * 24 * time.Hour)
	curl := "/usr/bin/curl"
	engine.Evaluate(agentEvent("lap", curl, "known.example", "203.0.113.10", 443, 2000, start))
	now := time.Now().UTC().Add(-time.Hour)
	engine.Evaluate(agentEvent("lap", curl, "known.example", "203.0.113.10", 443, 4<<20, now))
	if got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD"); len(got) != 0 {
		t.Fatalf("an upload to a known place raised %d", len(got))
	}
	engine.Evaluate(agentEvent("lap", curl, "drop.attacker.example", "198.51.100.40", 443, 0, now))
	engine.Evaluate(agentEvent("lap", curl, "drop.attacker.example", "198.51.100.40", 443, 2<<20, now.Add(time.Minute)))
	engine.Evaluate(agentEvent("lap", curl, "drop.attacker.example", "198.51.100.40", 443, 2<<20, now.Add(2*time.Minute)))
	got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD")
	if len(got) != 1 || storage.AlertClass(got[0]) != storage.ClassPage {
		t.Fatalf("a bulk upload to a new place should page once, got %+v", got)
	}
}

// A known destination by role is not a new place whatever its borrowed name
// reads: the offsite backup's rclone paired with Google, and Claude Code
// sending to its maker's published range under another Anthropic domain. An
// unpaired program to the same Google address still pages.
func TestNewPlaceUploadSkipsKnownDestinationsByRole(t *testing.T) {
	engine, store := noiseEngine(t)
	cfg := store.GetDetectionTuning()
	cfg.ExpectedRules = append(cfg.ExpectedRules, storage.ExpectedRule{ID: "rclone-google", Reason: "fixture", Findings: []string{storage.KindNewPlaceUpload},
		Programs: []storage.ExpectedProgram{{Path: "/usr/local/bin/rclone"}}, Networks: []string{"as15169"}})
	if _, err := store.SaveDetectionTuning(cfg, "test"); err != nil {
		t.Fatal(err)
	}
	engine.tuningAt = time.Time{}
	start := time.Now().UTC().Add(-10 * 24 * time.Hour)
	engine.Evaluate(agentEvent("lap", "/usr/bin/curl", "known.example", "203.0.113.10", 443, 2000, start))
	now := time.Now().UTC().Add(-time.Hour)
	rclone := "/usr/local/bin/rclone"
	engine.Evaluate(agentEvent("lap", rclone, "firebaseremoteconfig.googleapis.com", "172.217.118.4", 443, 0, now))
	engine.Evaluate(agentEvent("lap", rclone, "firebaseremoteconfig.googleapis.com", "172.217.118.4", 443, 32<<20, now.Add(time.Minute)))
	engine.Evaluate(agentEvent("lap", claudePath, "claudeusercontent.com", "160.79.104.10", 443, 0, now))
	engine.Evaluate(agentEvent("lap", claudePath, "claudeusercontent.com", "160.79.104.10", 443, 2<<20, now.Add(time.Minute)))
	if got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD"); len(got) != 0 {
		t.Fatalf("known destinations by role raised %d new-place uploads: %+v", len(got), got)
	}
	engine.Evaluate(agentEvent("lap", "/usr/bin/curl", "storage.googleapis.com", "172.217.118.5", 443, 0, now))
	engine.Evaluate(agentEvent("lap", "/usr/bin/curl", "storage.googleapis.com", "172.217.118.5", 443, 2<<20, now.Add(time.Minute)))
	if got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD"); len(got) != 1 {
		t.Fatalf("an unpaired upload to a new Google host should page once, got %d", len(got))
	}
}

// Antigravity (agy) uploading to a Google API host on Google's own network,
// as the published feeds attribute it, is the runtime working. To a Cloud
// Storage host it still pages (anyone's bucket lives there), and so does any
// other program to a Google API host, and agy to one of those names on
// Google's rented compute.
func TestAgyToGoogleAPIsIsItsMakerButCloudStorageStillPages(t *testing.T) {
	google := threatintel.NetworkPrefix{Country: "US", CountryName: "United States", ASN: "AS15169", Org: "Google LLC",
		Tenancy: threatintel.TenancyVendor, Source: "google"}
	cloud := threatintel.NetworkPrefix{Country: "US", CountryName: "United States", ASN: "AS396982", Org: "Google Cloud (customer range)",
		Tenancy: threatintel.TenancyHosting, Source: "google-cloud"}
	entries := threatintel.BuiltinAttribution()
	for _, p := range []string{"172.217.118.0/24", "2607:f8b0:4002::/48"} {
		g := google
		g.Prefix = p
		entries = append(entries, g)
	}
	cloud.Prefix = "34.54.84.0/24"
	entries = append(entries, cloud)
	if _, err := threatintel.LoadAttribution(entries, "test feeds"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = threatintel.LoadAttribution(threatintel.BuiltinAttribution(), "built-in") })

	engine, store := noiseEngine(t)
	start := time.Now().UTC().Add(-10 * 24 * time.Hour)
	engine.Evaluate(agentEvent("lap", "/usr/bin/curl", "known.example", "203.0.113.10", 443, 2000, start))
	now := time.Now().UTC().Add(-time.Hour)
	const agy = "/home/u/.local/bin/agy"
	upload := func(path, name, ip string) {
		engine.Evaluate(agentEvent("lap", path, name, ip, 443, 0, now))
		engine.Evaluate(agentEvent("lap", path, name, ip, 443, 2<<20, now.Add(time.Minute)))
	}
	upload(agy, "generativelanguage.googleapis.com", "172.217.118.4")
	upload(agy, "oauthaccountmanager.googleapis.com", "2607:f8b0:4002::5f")
	if got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD"); len(got) != 0 {
		t.Fatalf("agy to Google's API hosts raised %d new-place uploads: %+v", len(got), got)
	}
	for i, c := range []struct{ path, name, ip string }{
		{agy, "storage.googleapis.com", "172.217.118.5"},
		{agy, "www.googleapis.com", "172.217.118.7"},
		{"/usr/bin/curl", "people-pa.googleapis.com", "172.217.118.6"},
		{agy, "play.googleapis.com", "34.54.84.110"},
	} {
		upload(c.path, c.name, c.ip)
		if got := anomaliesOfType(t, store, "NEW_PLACE_UPLOAD"); len(got) != i+1 {
			t.Fatalf("%s to %s on %s: %d new-place uploads, want %d", c.path, c.name, c.ip, len(got), i+1)
		}
	}
}

// A port scan of the host's own loopback, or replies from a server's port to
// many client ports, is not a scan.
func TestPortScanSkipsLoopbackAndReplies(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for p := 0; p < 40; p++ {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "127.0.0.1", DstPort: uint16(8000 + p), ProcessPath: "/usr/bin/node"})
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			SrcPort: 5432, DstIP: "10.0.0.9", DstPort: uint16(40000 + p), ProcessPath: "/usr/lib/postgresql/postgres"})
	}
	if got := anomaliesOfType(t, store, "PORT_SCAN_RECON"); len(got) != 0 {
		t.Fatalf("loopback and replies raised %d port scans", len(got))
	}
	for p := 0; p < 40; p++ {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			SrcPort: 51000, DstIP: "10.0.0.9", DstPort: uint16(1 + p), ProcessPath: "/usr/bin/nmap"})
	}
	if got := anomaliesOfType(t, store, "PORT_SCAN_RECON"); len(got) != 1 {
		t.Fatalf("a real scan should raise once, got %d", len(got))
	}
}

// The pveproxy shape: a daemon (perl) listening on 8006 answers many clients.
// The agent reports every accepted connection as the listener's port talking
// to the client's own port, once per client socket, so the host seemed to reach
// many ports and many hosts. A listener's replies are served, never a scan or a
// fan-out, whatever the clients' ports are (Linux ephemeral, Windows ephemeral).
func TestAListenerAnsweringManyClientsIsServedNotScanning(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		port := uint16(33000 + i*700) // across the Linux and the Windows ephemeral ranges
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "pve", Timestamp: now.Add(time.Duration(i) * 100 * time.Millisecond),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.5", SrcPort: 8006,
			DstIP: "10.0.0." + itoa(20+i), DstPort: port, BytesOut: 4000, ProcessPath: "/usr/bin/perl", UserIdentity: "www-data"})
		// One client opening many connections to the same listener.
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "pve", Timestamp: now.Add(time.Duration(i) * 100 * time.Millisecond),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.5", SrcPort: 8006,
			DstIP: "10.0.0.99", DstPort: uint16(40000 + i), BytesOut: 4000, ProcessPath: "/usr/bin/perl", UserIdentity: "www-data"})
	}
	for _, kind := range []string{"PORT_SCAN_RECON", "LATERAL_PORT_SWEEP", "LAB_ESCAPE"} {
		if got := anomaliesOfType(t, store, kind); len(got) != 0 {
			t.Fatalf("a listener answering clients raised %d %s findings: %q", len(got), kind, got[0].Title)
		}
	}
	// The same process reaching out from its own ephemeral ports is still a fan-out.
	for i := 0; i < 40; i++ {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "pve", Timestamp: now.Add(time.Minute + time.Duration(i)*100*time.Millisecond),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.5", SrcPort: uint16(50000 + i),
			DstIP: "10.0.0." + itoa(100+i), DstPort: 8006, BytesOut: 400, ProcessPath: "/usr/bin/perl", UserIdentity: "www-data"})
	}
	if got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP"); len(got) != 1 {
		t.Fatalf("the same process fanning out from ephemeral ports raised %d sweeps, want 1", len(got))
	}
}

// The ephemeral boundary is policy data: a network whose clients start lower
// than the default counts those replies as served too.
func TestTheEphemeralRangeIsTuningData(t *testing.T) {
	ev := storage.Event{Direction: "OUTBOUND", SrcPort: 8006, DstPort: 20000}
	cfg := storage.DefaultDetectionTuning()
	if servedFlow(ev, cfg) {
		t.Fatal("a reply to port 20000 is served under the default 32768 boundary")
	}
	cfg.EphemeralPortFrom = 10000
	if !servedFlow(ev, cfg) {
		t.Fatal("a reply to port 20000 is not served with ephemeral_port_from 10000")
	}
	if servedFlow(storage.Event{Direction: "OUTBOUND", SrcPort: 50000, DstPort: 8006}, cfg) || servedFlow(storage.Event{Direction: "OUTBOUND", DstPort: 50000}, cfg) {
		t.Fatal("a client's own connection, or a flow with no local port, is served")
	}
}

// The retired novelty, off-hours and rate findings write nothing, while
// destination history is still kept for the new-place upload rule.
func TestRetiredNoiseFindingsAreNotWritten(t *testing.T) {
	engine, store := noiseEngine(t)
	night := time.Now().UTC().Truncate(24 * time.Hour).Add(3 * time.Hour)
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "linux-01", Timestamp: night.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: "198.51.100.9", DstPort: 443, BytesOut: 1000 + int64(i), ProcessPath: "/usr/bin/suspicious"})
	}
	engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "linux-01", Timestamp: night.Add(time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND", DstIP: "198.51.100.9", DstPort: 443, BytesOut: 500 << 20, ProcessPath: "/usr/bin/suspicious"})
	engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "linux-01", Timestamp: night, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "159.65.0.9", DstPort: 443, BytesOut: 200, ProcessPath: "/usr/bin/python3.13", CommandLine: "python3.13 x.py"})
	for _, kind := range []string{"OFF_HOURS_ACTIVITY", "NOVEL_PROCESS_EGRESS", "NOVEL_DESTINATION", "BANDWIDTH_SPIKE"} {
		if got := anomaliesOfType(t, store, kind); len(got) != 0 {
			t.Fatalf("%d %s findings were written", len(got), kind)
		}
	}
}

// HTTPS to a public resolver that carried nothing out looked nothing up.
func TestResolverBypassNeedsBytesOnHTTPS(t *testing.T) {
	ev := storage.Event{Direction: "OUTBOUND", DstIP: "1.1.1.1", DstPort: 443}
	if isResolverBypass(ev) {
		t.Fatal("a 0-byte probe to 1.1.1.1:443 is not a lookup")
	}
	ev.BytesOut = 120
	if !isResolverBypass(ev) {
		t.Fatal("HTTPS carrying data to 1.1.1.1 is a DoH lookup")
	}
	if !isResolverBypass(storage.Event{Direction: "OUTBOUND", DstIP: "9.9.9.9", DstPort: 853}) {
		t.Fatal("DNS over TLS to a public resolver is a bypass")
	}
	if isResolverBypass(storage.Event{Direction: "OUTBOUND", DstIP: "10.0.0.1", DstPort: 53}) {
		t.Fatal("the estate's own resolver is not a bypass")
	}
}

// An impossible rate is a collector-health note, once an hour per endpoint,
// recorded and never paged.
func TestAnImpossibleRateIsANoteNotAnAlert(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	ev := storage.Event{TenantID: "default", EndpointID: "win", Timestamp: now, DstIP: "203.0.113.5", DstPort: 443, ProcessPath: `C:\x.exe`}
	ep := storage.Endpoint{ID: "win", TenantID: "default", Hostname: "win"}
	engine.NoteImplausibleRate(ev, ep, 1e13, 1.25e9, 3, now)
	engine.NoteImplausibleRate(ev, ep, 1e13, 1.25e9, 1, now.Add(time.Minute))
	got := anomaliesOfType(t, store, "COLLECTOR_HEALTH")
	if len(got) != 1 || storage.AlertClass(got[0]) != storage.ClassRecord || got[0].HeldReason == "" {
		t.Fatalf("want one held collector-health record, got %+v", got)
	}
	if n, _ := store.CountAnomalyAlerts("", true); n != 0 {
		t.Fatalf("a collector note is an open alert (%d open)", n)
	}
}

// The counterparty keeps unrelated pages apart: two threat-list addresses at
// one provider, two outages of one host, a lab escape during an open sweep.
func TestIncidentKeysKeepSeparatePagesApart(t *testing.T) {
	key := func(typ, ip, evidence string) string {
		a := storage.AnomalyAlert{EndpointID: "ep", AnomalyType: typ, DstIP: ip, Evidence: evidence}
		var ev classEvidence
		_ = json.Unmarshal([]byte(evidence), &ev)
		return incidentKey(a, ev)
	}
	owner := `{"destination_owner":"Hosting Co"}`
	for _, c := range [][2]string{
		{key("THREAT_INTEL_MATCH", "203.0.113.1", owner), key("THREAT_INTEL_MATCH", "203.0.113.2", owner)},
		{key("ENDPOINT_SILENT", "", `{"last_seen_at":"2026-10-31T10:00:00Z"}`), key("ENDPOINT_SILENT", "", `{"last_seen_at":"2026-10-31T14:00:00Z"}`)},
		{key("LATERAL_PORT_SWEEP", "10.0.0.5", `{}`), key("LAB_ESCAPE", "10.0.0.5", `{"target_zone":"infra"}`)},
		{key("PORT_SCAN_RECON", "10.0.0.5", `{}`), key("PORT_SCAN_RECON", "10.0.0.6", `{}`)},
	} {
		if c[0] == c[1] {
			t.Errorf("one incident for two pages: %s", c[0])
		}
	}
	if key("LATERAL_PORT_SWEEP", "10.0.0.5", `{}`) != key("LATERAL_PORT_SWEEP", "10.0.0.9", `{}`) {
		t.Error("one sweep's alerts should stay one incident")
	}
}
