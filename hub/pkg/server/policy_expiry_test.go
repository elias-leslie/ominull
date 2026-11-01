package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestPolicyExpiryFeedWarnsBeforeAnExclusionOrKnownWorkloadLapses(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	day := 24 * time.Hour
	tuning := store.GetDetectionTuning()
	tuning.KnownWorkloads = nil
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	exclusion := func(id string, expires time.Time, active bool) {
		t.Helper()
		if err := store.CreateExclusion(storage.Exclusion{ID: id, TenantID: "default", Scope: "global", Name: id,
			ProcessPath: "/usr/bin/" + id, Reason: "fixture", Active: active, CreatedAt: now, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing to renew: said as such, with the next one due.
	exclusion("ex-backup", now.Add(60*day+time.Hour), true)
	f, err := srv.policyExpiryFinding(now)
	if err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved ||
		f.Message != "No exclusion or known workload expires within 30 days; the next, exclusion ex-backup, expires in 60 days" {
		t.Fatalf("nothing due: %q", f.Message)
	}

	// Inside the warning window: a daily item that says how to renew. A row
	// switched off or lapsed more than a week ago is not counted.
	exclusion("ex-backup", now.Add(29*day+time.Hour), true)
	exclusion("ex-off", now.Add(2*day), false)
	exclusion("ex-gone", now.Add(-8*day), true)
	f, _ = srv.policyExpiryFinding(now)
	want := "1 exclusion expires within 30 days (soonest: ex-backup in 29 days). Renew if still wanted: " +
		"re-POST an exclusion to /api/v1/exclusions, same id and fields, later expires_at"
	if f.SeverityID != ocsfSevMedium || f.StatusID != ocsfStatusNew || f.Message != want {
		t.Fatalf("got %q\nwant %q", f.Message, want)
	}
	rows, _ := f.Unmapped["expiring"].([]map[string]any)
	if len(rows) != 1 || rows[0]["name"] != "ex-backup" || rows[0]["days_left"] != 29 {
		t.Fatalf("expiring rows: %v", f.Unmapped["expiring"])
	}

	// A known workload too, and a lapse in the last week leads.
	tuning.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "cli", ExpiresAt: now.Add(10 * day)}}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	exclusion("ex-lapsed", now.Add(-2*day-time.Hour), true)
	f, _ = srv.policyExpiryFinding(now)
	want = "2 exclusions and 1 known workload expire within 30 days (1 already lapsed, ex-lapsed 3 days ago). Renew if still wanted: " +
		"re-POST an exclusion to /api/v1/exclusions, same id and fields, later expires_at; " +
		"re-save the detection tuning with a later expires_at on a known workload"
	if f.Message != want || len(f.Message) > 300 {
		t.Fatalf("got %q\nwant %q", f.Message, want)
	}

	// The lead time is a hub setting, bounded.
	_ = store.SetSetting(policyExpiryWarnDaysSetting, "5")
	if got := srv.policyExpiryWarn(); got != 5*day {
		t.Fatalf("warn window = %v", got)
	}
	_ = store.SetSetting(policyExpiryWarnDaysSetting, "400")
	if got := srv.policyExpiryWarn(); got != policyExpiryWarnDaysMax*day {
		t.Fatalf("an over-long window is clamped: %v", got)
	}

	w := httptest.NewRecorder()
	srv.handleNightshiftFeed(w, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v4", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"uid":"ominull.detection.expiring"`) {
		t.Fatalf("feed lacks the expiry finding: %d", w.Code)
	}
}
