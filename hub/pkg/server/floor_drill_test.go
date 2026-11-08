package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
)

// On a hub running the shipped tuning every floor rule raises, the feed says
// so, and the drill leaves no finding, isolation or audit row behind.
func TestTheFloorDrillRaisesEveryRuleAndStoresNothing(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if f := srv.floorDrillFinding(now); f.SeverityID != ocsfSevCritical {
		t.Fatalf("a drill that never ran = %+v", f)
	}
	rec := srv.runFloorDrill(now)
	// Eleven floor rules (decoy touch, lab escape and the rare beacon among
	// them), and the sweeps again as each program a shipped rule names.
	if len(rec.Missed) != 0 || rec.Cases <= 11 {
		t.Fatalf("drill = %+v, want a clean run of more than the eleven floor rules", rec)
	}
	if f := srv.floorDrillFinding(now); f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved {
		t.Fatalf("clean drill on the feed = %+v", f)
	}
	if alerts, err := store.ListAnomalyAlerts("", 100); err != nil || len(alerts) != 0 {
		t.Fatalf("the drill stored %d findings (%v)", len(alerts), err)
	}
	page, err := store.AuditHistory("", 50, "", storage.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Entries {
		if strings.Contains(e.Action, "ISOLATE") {
			t.Fatalf("the drill isolated something: %+v", e)
		}
	}
}

// Blinding a floor rule on a test hub - a container network over the LAN, an
// expected rule over an internet range, which still reaches the burst - makes
// the drill raise a CRITICAL naming the rules it missed. Switching bandwidth
// off does not, since the burst is floor, and a rule over a floor port or the
// range no longer reaches the sweeps.
func TestLooseningAFloorRuleMakesTheDrillRaise(t *testing.T) {
	t.Parallel()
	rule := func(port int, dst string) storage.ExpectedRule {
		r := storage.ExpectedRule{ID: "test-rule", Reason: "test", Port: port}
		if dst != "" {
			r.Prefixes = []string{dst}
		}
		return r
	}
	add := func(t *testing.T, s *storage.Store, r storage.ExpectedRule) {
		tu := s.GetDetectionTuning()
		tu.ExpectedRules = append(tu.ExpectedRules, r)
		if _, err := s.SaveDetectionTuning(tu, "test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name   string
		blind  func(*testing.T, *storage.Store)
		missed []string
	}{
		{"bandwidth off", func(t *testing.T, s *storage.Store) {
			tu := s.GetDetectionTuning()
			tu.BandwidthOn = false
			if _, err := s.SaveDetectionTuning(tu, "test"); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"container network over the LAN", func(t *testing.T, s *storage.Store) {
			tu := s.GetDetectionTuning()
			tu.ContainerCIDRs = []string{"192.168.250.0/24"}
			if _, err := s.SaveDetectionTuning(tu, "test"); err != nil {
				t.Fatal(err)
			}
		}, []string{"lateral sweep", "lab escape", "agent ssh fan-out reaching a floor port", "lateral rule on a floor port"}},
		{"rule on SMB", func(t *testing.T, s *storage.Store) { add(t, s, rule(445, "")) }, nil},
		{"rule on an internet range", func(t *testing.T, s *storage.Store) { add(t, s, rule(0, "203.0.113.0/24")) },
			[]string{"rare beacon"}},
	} {
		srv, store := setupTestServer(t)
		c.blind(t, store)
		now := time.Now().UTC()
		rec := srv.runFloorDrill(now)
		var got []string
		for _, m := range rec.Missed {
			if rule := m[:strings.Index(m, ": ")]; !strings.HasSuffix(rule, ")") {
				got = append(got, rule)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.missed, ",") {
			t.Errorf("%s: missed %q, want %q", c.name, rec.Missed, c.missed)
		}
		f := srv.floorDrillFinding(now)
		if len(c.missed) > 0 && (f.SeverityID != ocsfSevCritical || f.StatusID != ocsfStatusNew || !strings.Contains(f.Message, c.missed[0])) {
			t.Errorf("%s: feed = %+v", c.name, f)
		}
		store.Close()
	}
}

// A drill that has not run for more than eight days is a CRITICAL; one that
// missed runs again on the next check, and a clean recent one does not.
func TestAnOverdueOrMissedDrillIsHandled(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	set := func(rec floorDrillRecord) {
		raw, _ := json.Marshal(rec)
		if err := store.SetSetting(floorDrillSetting, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	set(floorDrillRecord{RanAt: now.Add(-9 * 24 * time.Hour), Cases: 8})
	if f := srv.floorDrillFinding(now); f.SeverityID != ocsfSevCritical || !strings.Contains(f.Message, "stopped") {
		t.Fatalf("overdue drill = %+v", f)
	}
	set(floorDrillRecord{RanAt: now.Add(-time.Hour), Cases: 8})
	srv.floorDrillDue(now)
	if rec, _ := srv.lastFloorDrill(); !rec.RanAt.Equal(now.Add(-time.Hour)) {
		t.Fatal("a clean drill an hour old ran again")
	}
	set(floorDrillRecord{RanAt: now.Add(-time.Hour), Cases: 8, Missed: []string{"port sweep: no PORT_SCAN_RECON was raised"}})
	srv.floorDrillDue(now)
	if rec, _ := srv.lastFloorDrill(); !rec.RanAt.Equal(now) || len(rec.Missed) != 0 {
		t.Fatalf("a missed drill did not run again: %+v", rec)
	}
}

// An applied policy change is drilled at once, without waiting for the
// weekly run.
func TestAPolicyChangeIsDrilledAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.runFloorDrill(time.Now().UTC().Add(-time.Hour))
	saved := time.Now().UTC()
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":12}`, ""); w.Code != http.StatusOK {
		t.Fatalf("tightening save = %d %s", w.Code, w.Body.String())
	}
	// Judged against the save, not a wall-clock minute: under -race with the
	// whole package running the save itself can take longer than that.
	if rec, _ := srv.lastFloorDrill(); rec.RanAt.Before(saved) {
		t.Fatalf("the change was not drilled: %+v", rec)
	}
}

// A rule narrowed to a host, a range or a port gets the floor cases that fit
// its corner, and a rule over a container network gets none the code exempts.
func TestTheDrillCoversScopedRules(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	tu := store.GetDetectionTuning()
	tu.ContainerCIDRs = []string{"172.18.0.0/16"}
	for _, r := range []storage.ExpectedRule{
		{ID: "dev", Hosts: []string{"linux-dev"}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/python3.13"}}},
		{ID: "lab", Prefixes: []string{"10.9.0.0/16"}},
		{ID: "proxy", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/docker-proxy"}}, Prefixes: []string{"172.18.0.0/16"}, Port: 7070, Protocol: "tcp"},
		{ID: "local", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/python3.12"}}, Prefixes: []string{"127.0.0.1/32"}, Port: 7070, Protocol: "tcp"},
		{ID: "bridge", Prefixes: []string{"172.18.0.0/16"}},
	} {
		r.Reason = "test"
		tu.ExpectedRules = append(tu.ExpectedRules, r)
	}
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	cases, err := detector.Drill(store, now)
	if err != nil {
		t.Fatal(err)
	}
	var scoped []string
	for _, c := range cases {
		if _, id, ok := strings.Cut(c.Rule, " under rule "); ok && id != "" {
			switch id {
			case "dev", "lab", "proxy", "local", "bridge":
				scoped = append(scoped, c.Rule)
			}
		}
		if miss := judgeDrillCase(c); miss != "" {
			t.Errorf("missed: %s", miss)
		}
	}
	want := []string{
		"threat-list match under rule dev", "sensitive port under rule dev", "port sweep under rule dev",
		"lateral sweep under rule dev", "resolver bypass under rule dev",
		"lateral sweep under rule lab",
	}
	sort.Strings(scoped)
	sort.Strings(want)
	if strings.Join(scoped, "|") != strings.Join(want, "|") {
		t.Fatalf("scoped cases = %q, want %q", scoped, want)
	}
	if rec := srv.runFloorDrill(now); len(rec.Missed) != 0 {
		t.Fatalf("drill with scoped rules missed %q", rec.Missed)
	}
}

// A rule that lets a shell-like program (ssh) fan out to inventoried hosts on
// port 22 is drilled like any other: the program trips the lateral sweep at its
// lower host count, so the first sweep is recorded rather than paged, and the
// case only has to raise. The migrated admin ssh rules missed the live drill
// because the case demanded a page.
func TestTheDrillAcceptsARecordedSweepFromAnInterpreterRule(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := store.GetDetectionTuning()
	tu.ExpectedRules = append(tu.ExpectedRules, storage.ExpectedRule{ID: "admin-ssh-ws", Reason: "test", Findings: []string{storage.KindLateralSweep},
		Hosts: []string{"ws"}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}, {Path: "c:/windows/system32/openssh/ssh.exe"}}, Port: 22, MaxHosts: 8})
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	if rec := srv.runFloorDrill(time.Now().UTC()); len(rec.Missed) != 0 {
		t.Fatalf("drill with an admin ssh rule missed %q", rec.Missed)
	}
}
