package detector

import (
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func dnsEngine(t *testing.T) (*Engine, *storage.Store) {
	t.Helper()
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	ep := storage.Endpoint{ID: "ws", TenantID: "default", Hostname: "ws", IP: "10.0.0.128", OS: "Linux", Status: "online", RoleTag: "workstation", LastSeenAt: now, CreatedAt: now.Add(-30 * 24 * time.Hour)}
	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("seeding endpoint: %v", err)
	}
	tuning := store.GetDetectionTuning()
	tuning.DecoyNames = []string{"s3.vault-archive.lan"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()
	return engine, store
}

func dnsFindings(t *testing.T, store *storage.Store) []storage.AnomalyAlert {
	t.Helper()
	all, err := store.ListAnomalyAlerts("default", 100)
	if err != nil {
		t.Fatalf("listing findings: %v", err)
	}
	return all
}

// A lookup of a decoy name, or of a name under it, pages once per client and
// decoy; the endpoint holding the client address is named.
func TestDecoyNameLookupPages(t *testing.T) {
	engine, store := dnsEngine(t)
	engine.NoteDNSLookup(DNSLookup{RouterID: "gw", ClientIP: "10.0.0.128", Domain: "s3.vault-archive.lan"}, nil)
	engine.NoteDNSLookup(DNSLookup{RouterID: "gw", ClientIP: "10.0.0.128", Domain: "bucket.s3.vault-archive.lan"}, nil)
	engine.NoteDNSLookup(DNSLookup{RouterID: "gw", ClientIP: "10.0.0.128", Domain: "vault-archive.lan"}, nil)
	engine.NoteDNSLookup(DNSLookup{RouterID: "gw", ClientIP: "10.0.0.128", Domain: "nots3.vault-archive.lan"}, nil)
	got := dnsFindings(t, store)
	if len(got) != 1 {
		t.Fatalf("want one decoy finding, got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.AnomalyType != "DECOY_TOUCH" || a.EndpointID != "ws" || a.Hostname != "ws" || storage.AlertClass(a) != storage.ClassPage {
		t.Fatalf("decoy lookup recorded as %s/%s/%s class %s", a.AnomalyType, a.EndpointID, a.Hostname, storage.AlertClass(a))
	}
	if !strings.Contains(a.Evidence, `"domain":"s3.vault-archive.lan"`) || !strings.Contains(a.Evidence, `"lookup_by":"10.0.0.128"`) {
		t.Fatalf("evidence lacks the name or client: %s", a.Evidence)
	}

	// Another device looking it up is its own finding, with no endpoint.
	engine.NoteDNSLookup(DNSLookup{RouterID: "gw", ClientIP: "10.0.0.36", Domain: "s3.vault-archive.lan"}, nil)
	got = dnsFindings(t, store)
	if len(got) != 2 {
		t.Fatalf("a second device's lookup was not recorded: %d", len(got))
	}
}

// A feed match pages at the feed's confidence when it reaches
// intel_page_confidence and is recorded below it; nothing is isolated.
func TestThreatListedLookupFollowsFeedConfidence(t *testing.T) {
	engine, store := dnsEngine(t)
	isolated := 0
	engine.onAutoIsolate = func(string, string) error { isolated++; return nil }
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.128", Domain: "c2.example-bad.com"},
		&storage.IOC{Value: "c2.example-bad.com", Type: "domain", Source: "threatfox", ThreatType: "malicious domain", Confidence: 90})
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.36", Domain: "drop.example-meh.com"},
		&storage.IOC{Value: "drop.example-meh.com", Type: "domain", Source: "urlhaus", ThreatType: "malicious domain", Confidence: 50})
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.128", Domain: "c2.example-bad.com"},
		&storage.IOC{Value: "c2.example-bad.com", Type: "domain", Source: "threatfox", ThreatType: "malicious domain", Confidence: 90})
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.128", Domain: "example.com"}, nil)
	got := dnsFindings(t, store)
	if len(got) != 2 {
		t.Fatalf("want two intel findings, got %d", len(got))
	}
	class := map[string]string{}
	for _, a := range got {
		if a.AnomalyType != "THREAT_INTEL_MATCH" {
			t.Fatalf("unexpected %s", a.AnomalyType)
		}
		class[a.Title] = storage.AlertClass(a)
	}
	if class["ws looked up threat-listed c2.example-bad.com"] != storage.ClassPage {
		t.Fatalf("a 90%% match did not page: %v", class)
	}
	if class["10.0.0.36 looked up threat-listed drop.example-meh.com"] != storage.ClassRecord {
		t.Fatalf("a 50%% match was not just recorded: %v", class)
	}
	if isolated != 0 {
		t.Fatalf("a lookup isolated a device")
	}
}

// Two devices without an agent looking up the same decoy, and one device
// looking up two listed names, are separate incidents: each pages.
func TestDNSTripwireIncidentsSplitByDeviceAndName(t *testing.T) {
	engine, store := dnsEngine(t)
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.36", Domain: "s3.vault-archive.lan"}, nil)
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.77", Domain: "s3.vault-archive.lan"}, nil)
	ioc := func(name string) *storage.IOC {
		return &storage.IOC{Value: name, Type: "domain", Source: "threatfox", ThreatType: "malicious domain", Confidence: 90}
	}
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.128", Domain: "c2-a.bad.example"}, ioc("c2-a.bad.example"))
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.128", Domain: "c2-b.bad.example"}, ioc("c2-b.bad.example"))
	got := dnsFindings(t, store)
	if len(got) != 4 {
		t.Fatalf("want 4 findings, got %d", len(got))
	}
	for _, a := range got {
		if storage.AlertClass(a) != storage.ClassPage || a.HeldReason != "" {
			t.Errorf("%s was not paged on its own: class %s held %q", a.Title, storage.AlertClass(a), a.HeldReason)
		}
	}
}

// A retired machine that once held the address is not blamed.
func TestDNSTripwireSkipsRetiredEndpoint(t *testing.T) {
	engine, store := dnsEngine(t)
	now := time.Now().UTC()
	old := storage.Endpoint{ID: "old-laptop", TenantID: "default", Hostname: "aaa-old-laptop", IP: "10.0.0.36", OS: "Linux", Status: "online", LastSeenAt: now.Add(-90 * 24 * time.Hour), CreatedAt: now.Add(-200 * 24 * time.Hour)}
	if err := store.UpsertEndpoint(old); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireEndpoint("old-laptop"); err != nil {
		t.Fatal(err)
	}
	engine.NoteDNSLookup(DNSLookup{ClientIP: "10.0.0.36", Domain: "s3.vault-archive.lan"}, nil)
	got := dnsFindings(t, store)
	if len(got) != 1 || got[0].EndpointID != "" {
		t.Fatalf("lookup filed under %q/%q", got[0].EndpointID, got[0].Hostname)
	}
}
