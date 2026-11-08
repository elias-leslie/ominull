package detector

import (
	"encoding/json"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// A hunt-tier finding (the new-device finding of the retired subnet sweep is
// the one type left) is held as a lead; on an agent-heavy endpoint it is also
// muted to LOW with the detector's severity kept. Paging types are untouched.
func TestHuntLeadsAreHeldAndMutedOnAgentHeavyHosts(t *testing.T) {
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
			cfg := storage.DefaultDetectionTuning()
			if tc.heavy {
				cfg.AgentHeavyEndpoints = []string{"linux-41"}
			}
			observed := func() bool { return tc.name == "agent runtime observed" }
			a := storage.AnomalyAlert{AnomalyType: "NOVEL_DESTINATION", EndpointID: "linux-41", Severity: "HIGH", Evidence: `{"command_line":"x"}`}
			applyTier(&a, storage.Endpoint{ID: "linux-41"}, cfg, observed)
			if a.HeldReason != storage.HeldHunt || storage.TierOf(a) != storage.TierHunt || a.Severity != tc.wantSev {
				t.Fatalf("hunt finding held %q severity %q, want hunt %s", a.HeldReason, a.Severity, tc.wantSev)
			}
			var ev map[string]any
			if err := json.Unmarshal([]byte(a.Evidence), &ev); err != nil {
				t.Fatal(err)
			}
			if ev["tier"] != "hunt" || (ev["muted"] == storage.MutedAgentHeavy) != tc.wantMuted ||
				(tc.wantMuted && ev["detector_severity"] != "HIGH") {
				t.Fatalf("evidence = %v", ev)
			}
			sweep := storage.AnomalyAlert{AnomalyType: "SENSITIVE_PORT_EGRESS", Severity: "CRITICAL"}
			applyTier(&sweep, storage.Endpoint{ID: "linux-41"}, cfg, observed)
			if sweep.HeldReason != "" || sweep.Severity != "CRITICAL" {
				t.Fatalf("a deterministic finding must keep paging: %+v", sweep)
			}
		})
	}
}

func TestReplayReportsPagingBeforeAndAfterTheClasses(t *testing.T) {
	now := time.Now().UTC()
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	alerts := []storage.AnomalyAlert{
		{ID: "1", AnomalyType: "NOVEL_DESTINATION", Hostname: "ws", Timestamp: at(0), Evidence: `{"destination_owner":"a"}`},
		{ID: "2", AnomalyType: "OFF_HOURS_ACTIVITY", Hostname: "ws", Timestamp: at(1), HeldReason: storage.HeldHunt},
		{ID: "3", AnomalyType: "LATERAL_PORT_SWEEP", EndpointID: "ws", Hostname: "ws", Timestamp: at(2), DstPort: 445},
		{ID: "4", AnomalyType: "ENDPOINT_SILENT", Hostname: "srv", Timestamp: at(3)},
		{ID: "5", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "srv", Timestamp: at(4), HeldReason: storage.HeldLearning},
		{ID: "alert-disc-1", AnomalyType: "NOVEL_DESTINATION", Hostname: "srv", Timestamp: at(5), Evidence: `{"destination_owner":"b"}`},
		{ID: "6", AnomalyType: "THREAT_INTEL_MATCH", EndpointID: "srv", Hostname: "srv", Timestamp: at(6), DstIP: "203.0.113.9", Severity: "HIGH", Evidence: `{"intel_confidence":50}`},
		// One incident: the same device, rule and decoy; the critical one escalates it.
		{ID: "7", AnomalyType: "DECOY_TOUCH", EndpointID: "ws", Hostname: "ws", Timestamp: at(7), DstIP: "10.0.0.250", Severity: "HIGH"},
		{ID: "8", AnomalyType: "DECOY_TOUCH", EndpointID: "ws", Hostname: "ws", Timestamp: at(8), DstIP: "10.0.0.250", Severity: "HIGH"},
		{ID: "9", AnomalyType: "DECOY_TOUCH", EndpointID: "ws", Hostname: "ws", Timestamp: at(9), DstIP: "10.0.0.250", Severity: "CRITICAL"},
		// A day later the same touch is a new incident.
		{ID: "10", AnomalyType: "DECOY_TOUCH", EndpointID: "ws", Hostname: "ws", Timestamp: at(9 + 25*60), DstIP: "10.0.0.250", Severity: "CRITICAL"},
	}
	res := Replay(alerts, storage.DefaultDetectionTuning())
	p := res.Paging
	if p.Before != 10 || p.After != 5 || p.Hunt != 5 {
		t.Fatalf("paging = %d -> %d (hunt %d), want 10 -> 5 (hunt 5)", p.Before, p.After, p.Hunt)
	}
	if p.ByClass[storage.ClassPage] != 5 || p.ByClass[storage.ClassRecord] != 4 || p.ByClass[storage.ClassDigest] != 1 {
		t.Fatalf("by class = %v", p.ByClass)
	}
	if p.Incidents != 3 || p.Pushes != 4 {
		t.Fatalf("incidents %d, pushes %d; want 3 incidents (sweep, two decoy days) and 4 pushes (one escalation)", p.Incidents, p.Pushes)
	}
	if len(p.Pages) != 4 || p.Pages[1].ID != "7" || p.Pages[1].Alerts != 2 || !p.Pages[2].Escalation || p.Pages[2].Alerts != 1 {
		t.Fatalf("pages = %+v", p.Pages)
	}
	if p.ByType["LATERAL_PORT_SWEEP"] != [2]int{1, 1} || p.ByType["THREAT_INTEL_MATCH"] != [2]int{1, 0} {
		t.Fatalf("by type = %v", p.ByType)
	}
}
