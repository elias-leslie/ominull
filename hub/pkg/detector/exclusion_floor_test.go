package detector

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// An exclusion silences the behavioural detectors for the traffic it names,
// and nothing else: a threat-list match (with its auto-isolation) and a
// sensitive-port egress still raise, and an expired exclusion matches nothing.
func TestExclusionsNeverHideTheFloorDetectors(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "floor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	tuning := storage.DefaultDetectionTuning()
	tuning.WarmupHours = 0
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	var isolated int32
	engine := New(store, make(chan storage.Event, 8), func(string, string) error {
		atomic.AddInt32(&isolated, 1)
		return nil
	})
	now := time.Now().UTC()
	tool := "/usr/bin/python3.13"
	if err := store.CreateExclusion(storage.Exclusion{ID: "ex-tool", TenantID: "default", Scope: "global", Name: "tool",
		ProcessPath: tool, Reason: "fixture", Active: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	flow := func(endpoint, dst string, port uint16, path string, ioc *storage.IOC) storage.Event {
		return storage.Event{TenantID: "default", EndpointID: endpoint, Timestamp: now, Action: "PERMIT",
			Direction: "OUTBOUND", DstIP: dst, DstPort: port, BytesOut: 800, ProcessPath: path, ThreatMatch: ioc}
	}

	// The excluded tool's ordinary egress is silenced.
	engine.Evaluate(flow("linux-1", "159.65.0.9", 8443, tool, nil))
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 0 {
		t.Fatalf("excluded traffic raised %d interpreter findings", len(got))
	}

	// The same tool reaching a threat-listed address still raises and isolates.
	engine.Evaluate(flow("linux-1", "185.220.101.5", 443, tool,
		&storage.IOC{Value: "185.220.101.5", Source: "test-feed", ThreatType: "c2", Confidence: 100, Active: true}))
	if got := anomaliesOfType(t, store, "THREAT_INTEL_MATCH"); len(got) != 1 {
		t.Fatalf("an exclusion hid a threat-list match: %d findings", len(got))
	}
	if atomic.LoadInt32(&isolated) != 1 {
		t.Fatalf("an exclusion hid the auto-isolation")
	}

	// ...and on a sensitive port still raises.
	engine.Evaluate(flow("linux-1", "159.65.0.10", 445, tool, nil))
	if got := anomaliesOfType(t, store, "SENSITIVE_PORT_EGRESS"); len(got) != 1 {
		t.Fatalf("an exclusion hid a sensitive-port egress: %d findings", len(got))
	}

	// The batch path applies the same rules.
	exclusions, err := store.ListExclusions("default")
	if err != nil {
		t.Fatal(err)
	}
	engine.EvaluateBatch([]storage.Event{flow("linux-2", "159.65.0.11", 3389, tool, nil)},
		BatchSnapshot{Endpoint: storage.Endpoint{ID: "linux-2", RoleTag: "workstation"}, Exclusions: exclusions})
	if got := anomaliesOfType(t, store, "SENSITIVE_PORT_EGRESS"); len(got) != 2 {
		t.Fatalf("batch path: an exclusion hid a sensitive-port egress: %d findings", len(got))
	}

	// An expired exclusion matches nothing.
	if err := store.CreateExclusion(storage.Exclusion{ID: "ex-tool", TenantID: "default", Scope: "global", Name: "tool",
		ProcessPath: tool, Reason: "fixture", Active: true, CreatedAt: now, ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	engine.Evaluate(flow("linux-3", "159.65.0.12", 8443, tool, nil))
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 1 {
		t.Fatalf("an expired exclusion still silenced traffic: %d findings", len(got))
	}
}
