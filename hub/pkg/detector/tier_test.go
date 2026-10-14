package detector

import (
	"encoding/json"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The behavioural detectors write hunt leads, never alerts; on an agent-heavy
// endpoint the lead is also muted to LOW with the detector's severity kept.
// Deterministic detectors keep paging.
func TestBehaviouralFindingsAreHuntLeadsAndMutedOnAgentHeavyHosts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		heavy     bool
		wantSev   string
		wantMuted bool
	}{
		{"stable host", false, "HIGH", false},
		{"agent-heavy host", true, "LOW", true},
		{"agent runtime observed", false, "LOW", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, store := noiseEngine(t)
			if tc.heavy {
				cfg := store.GetDetectionTuning()
				cfg.AgentHeavyEndpoints = []string{"linux-41"}
				if _, err := store.SaveDetectionTuning(cfg, "test"); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			if tc.name == "agent runtime observed" {
				if _, _, err := store.ObserveAgentDestination("default", "linux-41", "claude-code", "api.example", 10, now); err != nil {
					t.Fatal(err)
				}
			}
			engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "linux-41", Timestamp: now,
				Action: "PERMIT", Direction: "OUTBOUND", DstIP: "159.65.0.9", DstPort: 8443, BytesOut: 800,
				ProcessPath: "/usr/bin/python3.13"})
			engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "linux-41", Timestamp: now,
				Action: "PERMIT", Direction: "OUTBOUND", DstIP: "159.65.0.10", DstPort: 3389, BytesOut: 800,
				ProcessPath: "/usr/bin/xfreerdp"})

			got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS")
			if len(got) != 1 {
				t.Fatalf("expected one interpreter finding, got %d", len(got))
			}
			a := got[0]
			if a.HeldReason != storage.HeldHunt || storage.TierOf(a) != storage.TierHunt || a.Severity != tc.wantSev {
				t.Fatalf("interpreter finding held %q severity %q, want hunt %s", a.HeldReason, a.Severity, tc.wantSev)
			}
			var ev map[string]any
			if err := json.Unmarshal([]byte(a.Evidence), &ev); err != nil {
				t.Fatal(err)
			}
			if ev["tier"] != "hunt" || (ev["muted"] == storage.MutedAgentHeavy) != tc.wantMuted ||
				(tc.wantMuted && ev["detector_severity"] != "HIGH") {
				t.Fatalf("evidence = %v", ev)
			}
			if ev["command_line"] == nil && ev["protocol_name"] == nil {
				t.Fatalf("flow context lost: %v", ev)
			}
			sens := anomaliesOfType(t, store, "SENSITIVE_PORT_EGRESS")
			if len(sens) != 1 || sens[0].HeldReason != "" || sens[0].Severity != "CRITICAL" {
				t.Fatalf("a deterministic finding must keep paging: %+v", sens)
			}
			if n, _ := store.CountAnomalyAlerts("", true); n != 1 {
				t.Fatalf("open count = %d, want only the paging finding", n)
			}
		})
	}
}

func TestReplayReportsPagingBeforeAndAfterTheTiers(t *testing.T) {
	now := time.Now().UTC()
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	alerts := []storage.AnomalyAlert{
		{ID: "1", AnomalyType: "NOVEL_DESTINATION", Hostname: "ws", Timestamp: at(0), Evidence: `{"destination_owner":"a"}`},
		{ID: "2", AnomalyType: "OFF_HOURS_ACTIVITY", Hostname: "ws", Timestamp: at(1), HeldReason: storage.HeldHunt},
		{ID: "3", AnomalyType: "LATERAL_PORT_SWEEP", Hostname: "ws", Timestamp: at(2)},
		{ID: "4", AnomalyType: "ENDPOINT_SILENT", Hostname: "srv", Timestamp: at(3)},
		{ID: "5", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "srv", Timestamp: at(4), HeldReason: storage.HeldLearning},
		{ID: "alert-disc-1", AnomalyType: "NOVEL_DESTINATION", Hostname: "srv", Timestamp: at(5), Evidence: `{"destination_owner":"b"}`},
	}
	res := Replay(alerts, storage.DefaultDetectionTuning())
	p := res.Paging
	if p.Before != 5 || p.After != 3 || p.Hunt != 2 {
		t.Fatalf("paging = %d -> %d (hunt %d), want 5 -> 3 (hunt 2)", p.Before, p.After, p.Hunt)
	}
	if p.ByHost["ws"] != [2]int{3, 1} || p.ByHost["srv"] != [2]int{2, 2} {
		t.Fatalf("by host = %v", p.ByHost)
	}
	if p.ByType["NOVEL_DESTINATION"] != [2]int{2, 1} || p.ByType["LATERAL_PORT_SWEEP"] != [2]int{1, 1} {
		t.Fatalf("by type = %v", p.ByType)
	}
}
