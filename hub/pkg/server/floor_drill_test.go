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
	// Eight floor rules, and both sweeps as each shipped quiet process but
	// systemd-resolved, which the code exempts as a local resolver.
	if want := 8 + 2*(len(storage.DefaultDetectionTuning().QuietProcesses)-1); len(rec.Missed) != 0 || rec.Cases != want {
		t.Fatalf("drill = %+v, want %d clean cases", rec, want)
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
// exclusion over an internet range, which still reaches the burst - makes the
// drill raise a CRITICAL naming the rules it missed. Switching bandwidth off
// does not, since the burst is floor, and an exclusion over a floor port or
// the range no longer reaches the sweeps.
func TestLooseningAFloorRuleMakesTheDrillRaise(t *testing.T) {
	t.Parallel()
	exclusion := func(port uint16, dst string) storage.Exclusion {
		return storage.Exclusion{ID: "ex-" + dst, TenantID: "default", Scope: "global", Name: "test", DstIPRange: dst, Port: port,
			Reason: "test", Active: true, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
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
		}, []string{"lateral sweep", "agent ssh fan-out reaching a floor port"}},
		{"exclusion on SMB", func(t *testing.T, s *storage.Store) {
			if err := s.CreateExclusion(exclusion(445, "")); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"exclusion on an internet range", func(t *testing.T, s *storage.Store) {
			if err := s.CreateExclusion(exclusion(0, "203.0.113.0/24")); err != nil {
				t.Fatal(err)
			}
		}, []string{"bandwidth burst"}},
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
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":12}`, ""); w.Code != http.StatusOK {
		t.Fatalf("tightening save = %d %s", w.Code, w.Body.String())
	}
	if rec, _ := srv.lastFloorDrill(); time.Since(rec.RanAt) > time.Minute {
		t.Fatalf("the change was not drilled: %+v", rec)
	}
}

// An exclusion scoped to one endpoint, location or program gets its own floor
// cases, built only of traffic it matches, and they raise, since no exclusion
// reaches the floor rules; the burst is left out. A case its traffic cannot
// make is skipped: the sweeps for an installed container runtime (exempt in
// code), anything outside one loopback port, a lateral sweep inside a
// container network.
func TestTheDrillCoversScopedExclusions(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	tu := store.GetDetectionTuning()
	tu.ContainerCIDRs = []string{"172.18.0.0/16"}
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	for _, ex := range []storage.Exclusion{
		{ID: "ex-dev", Scope: "endpoint", ScopeValue: "linux-dev", ProcessPath: "/usr/bin/python3.13"},
		{ID: "ex-lab", Scope: "location", ScopeValue: "lab", DstIPRange: "10.9.0.0/16"},
		{ID: "ex-proxy", Scope: "global", ProcessPath: "/usr/bin/docker-proxy", DstIPRange: "172.18.0.0/16", Port: 7070, Protocol: "tcp"},
		{ID: "ex-local", Scope: "global", ProcessPath: "/usr/bin/python3.12", DstIPRange: "127.0.0.1/32", Port: 7070, Protocol: "tcp"},
		{ID: "ex-bridge", Scope: "location", ScopeValue: "lab", DstIPRange: "172.18.0.0/16"},
	} {
		ex.TenantID, ex.Name, ex.Reason, ex.Active, ex.CreatedAt, ex.ExpiresAt = "default", "test", "test", true, now, now.Add(time.Hour)
		if err := store.CreateExclusion(ex); err != nil {
			t.Fatal(err)
		}
	}
	cases, err := detector.Drill(store, now)
	if err != nil {
		t.Fatal(err)
	}
	var scoped []string
	for _, c := range cases {
		if strings.Contains(c.Rule, " under exclusion ") {
			scoped = append(scoped, c.Rule)
		}
		if miss := judgeDrillCase(c); miss != "" {
			t.Errorf("missed: %s", miss)
		}
	}
	want := []string{
		"threat-list match under exclusion ex-dev", "sensitive port under exclusion ex-dev", "port sweep under exclusion ex-dev",
		"lateral sweep under exclusion ex-dev", "resolver bypass under exclusion ex-dev",
		"lateral sweep under exclusion ex-lab",
	}
	sort.Strings(scoped)
	sort.Strings(want)
	if strings.Join(scoped, "|") != strings.Join(want, "|") {
		t.Fatalf("scoped cases = %q, want %q", scoped, want)
	}
	if rec := srv.runFloorDrill(now); len(rec.Missed) != 0 {
		t.Fatalf("drill with scoped exclusions missed %q", rec.Missed)
	}
}
