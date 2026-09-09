package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// Opt-in comparable synthetic query profile; it never opens a fleet database.
func TestTopologyPerformanceFixture(t *testing.T) {
	if os.Getenv("OMINULL_TOPOLOGY_PERF") != "1" {
		t.Skip("opt-in performance fixture")
	}
	s := newTestStore(t)
	now := time.Now().UTC().Add(-time.Minute)
	events := make([]Event, 100000)
	for i := range events {
		events[i] = Event{TenantID: "fixture", EndpointID: "fixture", Timestamp: now.Add(-time.Duration(i) * time.Millisecond), SrcIP: fmt.Sprintf("10.0.%d.%d", (i%1007)/250, (i%1007)%250+1), DstIP: fmt.Sprintf("2001:db8::%x", i%83+1), Protocol: 6, DstPort: 443, ProcessPath: "/usr/bin/fixture", Domain: "fixture.example.invalid", Action: "PERMIT", BytesOut: 100}
	}
	if err := s.InsertEventsBatch(events); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		start := time.Now()
		g, err := s.GetTopologyWorkspace(time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("sample=%d events=%d nodes=%d edges=%d conversations=%d query_ms=%.2f json_bytes=%d", i, len(events), len(g.Nodes), len(g.Edges), len(g.Conversations), float64(elapsed.Microseconds())/1000, len(raw))
	}
}
