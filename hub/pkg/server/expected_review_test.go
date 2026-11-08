package server

import (
	"net/http"
	"testing"
)

// Marking a finding whose rule id already exists dismisses it only if that
// rule still covers it.
func TestMarkingAgainstAStoredRuleThatNoLongerCoversIsRefused(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	ev := `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`
	seedFinding(t, store, "g-1", "/usr/bin/backup-agent", ev)
	seedFinding(t, store, "g-2", "/usr/bin/backup-agent", ev)
	if code, _ := markFinding(t, srv, "g-1"); code != http.StatusOK {
		t.Fatalf("first mark: %d", code)
	}
	tu := store.GetDetectionTuning()
	for i := range tu.ExpectedRules {
		if len(markedRules(store)) > 0 && tu.ExpectedRules[i].ID == markedRules(store)[0].ID {
			tu.ExpectedRules[i].Networks = []string{"Another Net"} // narrowed by hand
		}
	}
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	code, body := markFinding(t, srv, "g-2")
	if code != http.StatusConflict {
		t.Fatalf("mark against a rule that no longer covers it = %d %v", code, body)
	}
	if f, _ := store.GetAnomalyAlert("g-2"); f.Acknowledged {
		t.Error("the finding was dismissed though no rule covers it")
	}
}
