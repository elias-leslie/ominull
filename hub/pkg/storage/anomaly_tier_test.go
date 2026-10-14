package storage

import (
	"testing"
	"time"
)

// The one-time move of earlier behavioural findings: learning-held findings
// and the sweep's new-device findings keep their reason, other types keep
// paging, and a second call moves nothing.
func TestBackfillHuntTierMovesEarlierBehaviouralFindingsOnce(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	for _, a := range []AnomalyAlert{
		{ID: "a", AnomalyType: "NOVEL_DESTINATION"},
		{ID: "b", AnomalyType: "OFF_HOURS_ACTIVITY", Acknowledged: true},
		{ID: "c", AnomalyType: "NOVEL_PROCESS_EGRESS", HeldReason: HeldLearning},
		{ID: "alert-disc-1", AnomalyType: "NOVEL_DESTINATION"},
		{ID: "d", AnomalyType: "LATERAL_PORT_SWEEP"},
	} {
		a.TenantID, a.EndpointID, a.Timestamp = "t", "e", now
		if err := s.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	types := []string{"NOVEL_DESTINATION", "NOVEL_PROCESS_EGRESS", "OFF_HOURS_ACTIVITY"}
	n, err := s.BackfillHuntTier(types)
	if err != nil || n != 2 {
		t.Fatalf("moved %d (%v), want 2", n, err)
	}
	want := map[string]string{"a": HeldHunt, "b": HeldHunt, "c": HeldLearning, "alert-disc-1": "", "d": ""}
	for id, held := range want {
		a, err := s.GetAnomalyAlert(id)
		if err != nil || a.HeldReason != held {
			t.Fatalf("%s held %v (%v), want %q", id, a, err, held)
		}
	}
	if err := s.CreateAnomalyAlert(AnomalyAlert{ID: "late", TenantID: "t", EndpointID: "e", AnomalyType: "NOVEL_DESTINATION", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.BackfillHuntTier(types); err != nil || n != 0 {
		t.Fatalf("second backfill moved %d (%v)", n, err)
	}

	_, open, _ := s.QueryAnomalyAlerts("", 10, 0, false, "", "", "", HeldExclude)
	_, hunt, _ := s.QueryAnomalyAlerts("", 10, 0, false, "", "", "", HeldHuntOnly)
	_, held, _ := s.QueryAnomalyAlerts("", 10, 0, false, "", "", "", HeldOnly)
	if open != 3 || hunt != 2 || held != 1 {
		t.Fatalf("views open %d hunt %d held %d, want 3 2 1", open, hunt, held)
	}
	w, err := s.SummariseHuntLeads(now.Add(-time.Hour))
	if err != nil || w.Total != 2 || w.ByType["NOVEL_DESTINATION"] != 1 {
		t.Fatalf("hunt summary = %+v (%v)", w, err)
	}
}
