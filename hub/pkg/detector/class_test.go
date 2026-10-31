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
	cfg.InfraCIDRs = []string{"10.0.0.1/32"}
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
	home := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		home = append(home, fmt.Sprintf("10.0.0.%d", 100+i))
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
		{"beacon, resolver", storage.AnomalyAlert{AnomalyType: "C2_BEACONING", DstPort: 53, Evidence: `{"score":0.99,"span_minutes":60,"beacon_devices":1}`}, storage.ClassDigest},
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
