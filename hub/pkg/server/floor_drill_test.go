package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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
	if len(rec.Missed) != 0 || rec.Cases != 8 {
		t.Fatalf("drill = %+v", rec)
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
// exclusion over a floor port or an internet range - makes the drill raise a
// CRITICAL naming the rules it missed. Switching bandwidth off does not, since
// the burst is floor.
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
		}, []string{"agent ssh fan-out reaching a floor port"}},
		{"exclusion on an internet range", func(t *testing.T, s *storage.Store) {
			if err := s.CreateExclusion(exclusion(0, "203.0.113.0/24")); err != nil {
				t.Fatal(err)
			}
		}, []string{"port sweep", "bandwidth burst"}},
	} {
		srv, store := setupTestServer(t)
		c.blind(t, store)
		now := time.Now().UTC()
		rec := srv.runFloorDrill(now)
		var got []string
		for _, m := range rec.Missed {
			got = append(got, m[:strings.Index(m, ":")])
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
