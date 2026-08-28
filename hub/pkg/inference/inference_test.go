package inference

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func dcProfile() storage.FlowProfile {
	return storage.FlowProfile{
		IP:              "10.0.4.12",
		Subnet:          "10.0.4.0/24",
		Flows:           4200,
		Bytes:           31000000,
		SourceEndpoints: 9,
		SourceLocations: 2,
		Processes:       []string{"C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\svchost.exe"},
		Ports: []storage.FlowPortStat{
			{Port: 389, Flows: 1800, Bytes: 14000000, Sources: 9, Proto: "TCP"},
			{Port: 88, Flows: 1400, Bytes: 9000000, Sources: 9, Proto: "TCP"},
			{Port: 445, Flows: 620, Bytes: 6000000, Sources: 6, Proto: "TCP"},
			{Port: 135, Flows: 380, Bytes: 2000000, Sources: 5, Proto: "TCP"},
		},
		FanOutFlows: 0,
		LastSeen:    time.Now().UTC(),
	}
}

// The headline case: a host nothing has probed and nothing runs on, named
// from the shape of the traffic other hosts send it.
func TestDomainControllerFromFlowAlone(t *testing.T) {
	holders := map[string]int{"10.0.4.0/24|88": 1, "10.0.4.0/24|389": 1}

	res, ok := Evaluate(dcProfile(), holders)
	if !ok {
		t.Fatal("a textbook domain-controller fan-in was not identified")
	}
	if res.Role != "domain-controller" {
		t.Fatalf("wrong role: %q", res.Role)
	}
	if res.Confidence < 0.75 || res.Confidence > maxConfidence {
		t.Errorf("confidence %.2f is outside the band flow evidence supports", res.Confidence)
	}

	// The rationale is the whole point: it has to state what was actually
	// observed, in terms an operator can argue with.
	for _, want := range []string{"9 agented endpoints", "2 locations", "lsass.exe", "389/88", "fan-in without any fan-out", "nothing else on 10.0.4.0/24 answers"} {
		if !strings.Contains(res.Rationale, want) {
			t.Errorf("rationale is missing %q: %s", want, res.Rationale)
		}
	}
}

// A busy workstation talks outward as much as it is talked to. Fan-in alone
// is not identity; fan-in without fan-out is.
func TestFanOutDisqualifiesInfrastructure(t *testing.T) {
	p := dcProfile()
	p.FanOutFlows = 9000
	p.FanOutTargets = 240

	if res, ok := Evaluate(p, nil); ok && res.Role == "domain-controller" {
		t.Errorf("a host with heavy fan-out was called a domain controller: %+v", res)
	}
}

// One host talking to another is a conversation, not a service.
func TestTooFewSourcesIsNotAService(t *testing.T) {
	p := dcProfile()
	p.SourceEndpoints = 1

	if _, ok := Evaluate(p, nil); ok {
		t.Error("a single endpoint's traffic was enough to name a role")
	}
}

// Kerberos is what separates the directory server from the CA beside it.
func TestKerberosExcludesCertificateAuthority(t *testing.T) {
	p := storage.FlowProfile{
		IP: "10.0.4.30", Subnet: "10.0.4.0/24", Flows: 900, SourceEndpoints: 5,
		Processes: []string{"C:\\Windows\\System32\\certutil.exe"},
		Ports: []storage.FlowPortStat{
			{Port: 135, Flows: 500, Bytes: 400000, Sources: 5},
			{Port: 443, Flows: 400, Bytes: 900000, Sources: 5},
		},
		LastSeen: time.Now().UTC(),
	}
	res, ok := Evaluate(p, nil)
	if !ok || res.Role != "certificate-authority" {
		t.Fatalf("expected a certificate authority, got %+v (matched=%v)", res, ok)
	}

	p.Ports = append(p.Ports, storage.FlowPortStat{Port: 88, Flows: 800, Bytes: 500000, Sources: 5})
	p.Ports = append(p.Ports, storage.FlowPortStat{Port: 389, Flows: 700, Bytes: 400000, Sources: 5})
	res, ok = Evaluate(p, nil)
	if !ok || res.Role != "domain-controller" {
		t.Fatalf("once Kerberos appears the host is a domain controller, got %+v (matched=%v)", res, ok)
	}
}

// Inference is deterministic: the same traffic always yields the same call
// and the same sentence, which is what makes it arguable.
func TestEvaluateIsDeterministic(t *testing.T) {
	holders := map[string]int{"10.0.4.0/24|88": 1}
	first, _ := Evaluate(dcProfile(), holders)
	for i := 0; i < 20; i++ {
		again, _ := Evaluate(dcProfile(), holders)
		if again != first {
			t.Fatalf("inference is not deterministic:\n%+v\n%+v", first, again)
		}
	}
}

// End to end against the store: events in, an asset with a role and a
// rationale out, and never a claim that outranks an agent.
func TestRunOnceNamesTheDirectoryServer(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "inference.db"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	sources := []struct{ id, ip string }{
		{"win11-a", "10.0.4.15"},
		{"win11-b", "10.0.4.31"},
		{"win11-c", "10.0.4.44"},
		{"win11-d", "10.0.4.46"},
	}
	for _, src := range sources {
		if err := store.UpsertEndpoint(storage.Endpoint{
			ID: src.id, TenantID: "default", Hostname: src.id, OS: "Windows 11 Enterprise",
			IP: src.ip, RoleTag: "workstation", DriverVersion: "1.1.0", Status: "online",
			LastSeenAt: now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertEndpoint: %v", err)
		}
	}

	var events []storage.Event
	for i, src := range sources {
		for _, port := range []uint16{389, 88, 445, 135} {
			events = append(events, storage.Event{
				TenantID: "default", EndpointID: src.id, Timestamp: now.Add(-time.Duration(i) * time.Minute),
				Layer: "ALE_AUTH_CONNECT", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
				SrcIP: src.ip, DstIP: "10.0.4.12", SrcPort: 49000 + uint16(i), DstPort: port,
				BytesIn: 21000, BytesOut: 9000, ProcessPath: "C:\\Windows\\System32\\lsass.exe",
			})
		}
	}
	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch: %v", err)
	}

	engine := New(store)
	n, err := engine.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n == 0 {
		t.Fatal("inference found nothing in a window full of directory traffic")
	}

	assets, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	var dc *storage.Asset
	for i := range assets {
		if assets[i].IP == "10.0.4.12" {
			dc = &assets[i]
		}
	}
	if dc == nil {
		t.Fatal("no asset was created for the address every endpoint authenticates against")
	}
	if dc.Role != "domain-controller" {
		t.Errorf("role = %q, want domain-controller", dc.Role)
	}
	if dc.Rationale == "" {
		t.Error("an inference without a rationale is not correctable")
	}
	if dc.HasAgent() {
		t.Error("the inferred asset should carry no agent")
	}

	// The workstations that produced the evidence keep their own role.
	for _, a := range assets {
		if a.AgentEndpointID != "" && a.Role != "workstation" {
			t.Errorf("inference changed an agented host's role: %s -> %q", a.AgentEndpointID, a.Role)
		}
	}

	status := engine.Status()
	if status["inferred_count"].(int) == 0 {
		t.Error("status does not report what the pass concluded")
	}
}
