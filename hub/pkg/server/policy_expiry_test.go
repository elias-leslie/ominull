package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestPolicyExpiryFeedWarnsBeforeAnExpectedRuleLapses(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	day := 24 * time.Hour
	// A save drops a rule already past its expiry, so the test's clock runs
	// ten days ahead of the saves: rules that lapse by then were alive when
	// saved.
	now := time.Now().UTC().Add(10 * day)
	tuning := store.GetDetectionTuning()
	var shipped []storage.ExpectedRule
	for _, r := range tuning.ExpectedRules {
		r.ExpiresAt = time.Time{}
		shipped = append(shipped, r)
	}
	tuning.ExpectedRules = shipped
	rules := map[string]time.Time{}
	save := func() {
		t.Helper()
		cfg := tuning
		cfg.ExpectedRules = append([]storage.ExpectedRule(nil), shipped...)
		for id, expires := range rules {
			cfg.ExpectedRules = append(cfg.ExpectedRules, storage.ExpectedRule{ID: id, Reason: "fixture", ExpiresAt: expires,
				Programs: []storage.ExpectedProgram{{Path: "/usr/bin/" + id}}})
		}
		if _, err := store.SaveDetectionTuning(cfg, "test"); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing to renew: said as such, with the next one due.
	rules["backup"] = now.Add(60*day + time.Hour)
	save()
	f, err := srv.policyExpiryFinding(now)
	if err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved ||
		f.Message != "No expected rule expires within 30 days; the next, expected rule backup, expires in 60 days" {
		t.Fatalf("nothing due: %q", f.Message)
	}

	// Inside the warning window: a daily item that says how to renew. A rule
	// that lapsed more than a week ago is not counted.
	rules["backup"] = now.Add(29*day + time.Hour)
	rules["gone"] = now.Add(-8 * day)
	save()
	f, _ = srv.policyExpiryFinding(now)
	want := "1 expected rule expires within 30 days (soonest: backup in 29 days). Renew if still wanted: " +
		"re-POST the rule to /api/v1/detection/expected, same id and fields, later expires_at"
	if f.SeverityID != ocsfSevMedium || f.StatusID != ocsfStatusNew || f.Message != want {
		t.Fatalf("got %q\nwant %q", f.Message, want)
	}
	rows, _ := f.Unmapped["expiring"].([]map[string]any)
	if len(rows) != 1 || rows[0]["name"] != "backup" || rows[0]["days_left"] != 29 {
		t.Fatalf("expiring rows: %v", f.Unmapped["expiring"])
	}

	// A lapse in the last week leads.
	rules["gh"] = now.Add(10 * day)
	rules["lapsed"] = now.Add(-2*day - time.Hour)
	save()
	f, _ = srv.policyExpiryFinding(now)
	want = "3 expected rules expire within 30 days (1 already lapsed, lapsed 3 days ago). Renew if still wanted: " +
		"re-POST the rule to /api/v1/detection/expected, same id and fields, later expires_at"
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
	srv.handleHealthFindings(w, httptest.NewRequest(http.MethodGet, "/api/v1/health/findings", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"uid":"ominull.detection.expiring"`) {
		t.Fatalf("feed lacks the expiry finding: %d", w.Code)
	}
}
