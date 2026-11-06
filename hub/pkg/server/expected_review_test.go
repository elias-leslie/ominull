package server

import (
	"net/http"
	"testing"

	"ominull/hub/pkg/storage"
)

// A rule that omits max_hosts admits the default, not any number: leaving it
// out widens a bound of three and is not a change from eight.
func TestOmittingMaxHostsIsJudgedByWhatItMeans(t *testing.T) {
	t.Parallel()
	rule := func(max int, proto string) storage.ExpectedRule {
		return storage.ExpectedRule{ID: "admin", Reason: "r", Findings: []string{storage.KindLateralSweep}, Hosts: []string{"ws"},
			Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22, MaxHosts: max, Protocol: proto}
	}
	for _, c := range []struct {
		name     string
		was, now storage.ExpectedRule
		loosens  bool
	}{
		{"three hosts to the default", rule(3, ""), rule(0, ""), true},
		{"the default spelled out", rule(storage.AdminFanoutMaxDefault, ""), rule(0, ""), false},
		{"the default left out then spelled", rule(0, ""), rule(storage.AdminFanoutMaxDefault, ""), false},
		{"default down to three", rule(0, ""), rule(3, ""), false},
		{"tcp to any", rule(0, "tcp"), rule(0, "any"), true},
		{"any to the empty clause", rule(0, "any"), rule(0, ""), false},
		{"any to tcp", rule(0, "any"), rule(0, "tcp"), false},
	} {
		if got := ruleLoosens(c.was, c.now); got != c.loosens {
			t.Errorf("%s: loosens = %v, want %v", c.name, got, c.loosens)
		}
	}
	exact := storage.ExpectedRule{ID: "x", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "/opt/App/Tool", Exact: true}}}
	loose := exact
	loose.Programs = []storage.ExpectedProgram{{Path: "/opt/App/Tool"}}
	if !ruleLoosens(exact, loose) || ruleLoosens(loose, exact) {
		t.Error("an exact program path becoming a folded one must loosen, not the reverse")
	}
}

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
