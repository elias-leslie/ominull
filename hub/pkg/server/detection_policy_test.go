package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// policyPost sends one detection-policy write with the admin key. The last
// argument is unused; callers pass "".
func policyPost(srv *Server, method, path, body, _ string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// noteKinds is the first half (before the colon) of each policy note.
func noteKinds(notes []storage.AuditEntry) []string {
	var kinds []string
	for _, n := range notes {
		kinds = append(kinds, strings.SplitN(n.Details, ":", 2)[0])
	}
	return kinds
}

func policyNotes(t *testing.T, store *storage.Store) []storage.AuditEntry {
	t.Helper()
	page, err := store.AuditHistory("", 100, "", storage.AuditFilter{Action: policyChangedAudit})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

// A policy save applies at once and leaves a note naming what changed and the
// credential; a save that changes nothing leaves none.
func TestAPolicySaveAppliesWithANote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	rules := append(storage.DefaultDetectionTuning().ExpectedRules, storage.ExpectedRule{ID: "extra-curl", Reason: "r",
		Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as64500"}})
	raw, _ := json.Marshal(map[string]any{"beacon_enabled": false, "expected_rules": rules})
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""); w.Code != http.StatusOK {
		t.Fatalf("save = %d %s", w.Code, w.Body.String())
	}
	if got := store.GetDetectionTuning(); got.BeaconOn || len(got.ExpectedRules) != len(rules) {
		t.Fatal("the save did not apply")
	}
	notes := policyNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "changed detection tuning") ||
		!strings.Contains(notes[0].Details, "credential api-key (unverified)") {
		t.Fatalf("notes = %+v", notes)
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{}`, ""); w.Code != http.StatusOK {
		t.Fatalf("empty save = %d", w.Code)
	}
	if len(policyNotes(t, store)) != 1 {
		t.Fatal("a save with no change left a note")
	}
}

// Marking a finding expected writes the rule and acknowledges the finding on
// the first request; deleting a rule applies at once too.
func TestMarkingExpectedAndDeletingARuleApply(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedFinding(t, store, "f-wait", "/opt/acme/backup-agent", `{"destination_asn":"AS64500","destination_tenancy":"isp"}`)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/expected/mark", `{"id":"f-wait"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("mark = %d %s", w.Code, w.Body.String())
	}
	if al, _ := store.GetAnomalyAlert("f-wait"); !al.Acknowledged || len(markedRules(store)) != 1 {
		t.Fatal("the rule did not land")
	}
	id := markedRules(store)[0].ID
	if w := policyPost(srv, http.MethodDelete, "/api/v1/detection/expected?id="+id, "", ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	if _, ok := store.GetDetectionTuning().RuleByID(id); ok {
		t.Fatal("the rule was not deleted")
	}
	if len(policyNotes(t, store)) != 2 {
		t.Fatalf("notes = %+v", policyNotes(t, store))
	}
}

// Silence is part of the floor: no save switches it off, tap or not.
func TestSilenceDetectionCannotBeSwitchedOff(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"silence_enabled":false}`, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "floor") {
		t.Fatalf("silence off = %d %s", w.Code, w.Body.String())
	}
	if !store.GetDetectionTuning().SilenceOn {
		t.Fatal("silence detection is off")
	}
}

// Concurrent saves are serialised: each patch lands over the one before it,
// so none of them is lost.
func TestConcurrentSavesAreNotLost(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	bodies := []string{`{"beacon_score_threshold":0.7}`, `{"warmup_hours":6}`, `{"beacon_cooldown_minutes":10}`, `{"bandwidth_cooldown_minutes":2}`, `{"silence_after_minutes":10}`}
	var wg sync.WaitGroup
	for _, b := range bodies {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", b, ""); w.Code != http.StatusOK {
				t.Errorf("%s = %d %s", b, w.Code, w.Body.String())
			}
		}(b)
	}
	wg.Wait()
	got := store.GetDetectionTuning()
	if got.BeaconScore != 0.7 || got.WarmupHours != 6 || got.BeaconCooldownMin != 10 || got.BandwidthCooldown != 2 || got.SilenceAfterMinutes != 10 {
		t.Fatalf("a concurrent save was lost: %+v", got)
	}
}

// The Aico push carries the day's changes as a note, and an unsound
// tuning row as a critical finding.
func TestTheFeedReportsPolicyChangesAndAnUnsoundRow(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	find := func(uid string) feedFinding {
		t.Helper()
		findings, err := srv.detectionPolicySection(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.FindingInfo["uid"] == uid {
				return f
			}
		}
		t.Fatalf("no %s finding", uid)
		return feedFinding{}
	}
	if f := find("ominull.detection.changes"); f.StatusID != ocsfStatusResolved {
		t.Fatalf("quiet day = %+v", f)
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":12}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	f := find("ominull.detection.changes")
	changes, _ := f.Unmapped["changes"].([]map[string]any)
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusNew || len(changes) != 1 ||
		!strings.Contains(changes[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("change note = %+v", f)
	}
	if f := find("ominull.detection.invalid"); f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved {
		t.Fatalf("sound row = %+v", f)
	}

	for _, settings := range []string{`{"beacon_enabled":`, `{"expected_rules":[{"id":"x","reason":"x","workload":"python3 *","networks":["*"],"expires_at":"2099-01-01T00:00:00Z"}]}`} {
		if _, err := store.DB().Exec(`UPDATE detection_tuning SET settings = ? WHERE id = 1`, settings); err != nil {
			t.Fatal(err)
		}
		f = find("ominull.detection.invalid")
		if f.SeverityID != ocsfSevCritical || f.StatusID != ocsfStatusNew || f.Unmapped["problem"] == "" {
			t.Fatalf("unsound row %s = %+v", settings, f)
		}
	}
}

// Retiring a host takes it off the silence floor, a loosening the hub
// signs on the first request.
func TestRetiringAHostStopsWatchingIt(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "srv-1", TenantID: "t-01", Hostname: "web", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointIsolation("srv-1", true, nil); err != nil {
		t.Fatal(err)
	}
	watched := func() bool {
		ep, err := store.GetEndpoint("srv-1")
		if err != nil || ep == nil {
			t.Fatalf("endpoint: %v", err)
		}
		_, on := ep.QuietAllowance(time.Hour)
		return on && ep.Status != "retired"
	}

	if !watched() {
		t.Fatal("the host starts unwatched")
	}
	retire := `{"endpoint_id":"srv-1","reason":"decommissioned"}`
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""); w.Code != http.StatusOK || watched() {
		t.Fatalf("retire = %d %s watched=%v", w.Code, w.Body.String(), watched())
	}
	if ep, _ := store.GetEndpoint("srv-1"); ep.Status != "retired" || ep.IsIsolated {
		t.Fatalf("the host was not retired and released: %+v", ep)
	}
	// Retiring a host already retired changes nothing.
	n := len(policyNotes(t, store))
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""); w.Code != http.StatusOK || len(policyNotes(t, store)) != n {
		t.Fatalf("retire again = %d %s", w.Code, w.Body.String())
	}
	kinds := noteKinds(policyNotes(t, store))
	if len(kinds) != 1 || !strings.HasPrefix(kinds[0], "changed endpoint watch retire") {
		t.Fatalf("notes = %v", kinds)
	}
}

// Acknowledging or deleting findings hides them from the feed's open counts,
// so the detection-policy note counts every one, and a tenant key cannot reach
// another tenant's finding by id.
func TestAcknowledgedAndDeletedFindingsShowOnTheFeedNote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, tn := range []storage.Tenant{{ID: "t-alpha", Name: "Alpha", APIKey: "key-alpha", CreatedAt: now}, {ID: "t-beta", Name: "Beta", APIKey: "key-beta", CreatedAt: now}} {
		if err := store.CreateTenant(tn); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []storage.AnomalyAlert{
		{ID: "a1", TenantID: "t-alpha", AnomalyType: "C2_BEACONING", Severity: "HIGH"},
		{ID: "b1", TenantID: "t-beta", AnomalyType: "THREAT_INTEL_MATCH", Severity: "CRITICAL"},
		{ID: "b2", TenantID: "t-beta", AnomalyType: "NOVEL_DESTINATION", Severity: "MEDIUM"},
	} {
		a.Hostname, a.Title, a.Timestamp = "h", "x", now
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	post := func(key, path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d %s", path, body, w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	note := func() feedFinding {
		t.Helper()
		findings, err := srv.detectionPolicySection(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.FindingInfo["uid"] == "ominull.detection.changes" {
				return f
			}
		}
		t.Fatal("no detection policy note")
		return feedFinding{}
	}
	acked := func(id string) bool {
		a, err := store.GetAnomalyAlert(id)
		if err != nil {
			t.Fatal(err)
		}
		return a.Acknowledged
	}

	// Another tenant's finding by id is out of reach, and nothing is noted.
	if out := post("key-alpha", "/api/v1/anomalies/acknowledge", `{"ids":["b1"]}`); out["acknowledged"] != float64(0) || acked("b1") {
		t.Fatalf("tenant alpha acknowledged beta's finding: %v", out)
	}
	if f := note(); f.StatusID != ocsfStatusResolved {
		t.Fatalf("nothing was acknowledged yet the note says %+v", f)
	}
	if out := post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"ids":["a1","b1"]}`); out["acknowledged"] != float64(2) {
		t.Fatalf("admin acknowledge = %v", out)
	}
	f := note()
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	if f.StatusID != ocsfStatusNew || len(dismissed) != 1 ||
		!strings.Contains(f.Message, "2 findings acknowledged (2 HIGH or CRITICAL)") ||
		!strings.Contains(dismissed[0]["change"].(string), "C2_BEACONING, THREAT_INTEL_MATCH") ||
		!strings.Contains(dismissed[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("note after acknowledging = %+v", f)
	}
	// A repeat acknowledges nothing new and adds nothing; all, then clear, are counted.
	post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"id":"a1"}`)
	if out := post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"all":true}`); out["acknowledged"] != float64(1) {
		t.Fatalf("acknowledge all = %v", out)
	}
	if out := post("mock_admin_token", "/api/v1/anomalies/clear", `{}`); out["deleted"] != float64(3) {
		t.Fatalf("clear = %v", out)
	}
	f = note()
	dismissed, _ = f.Unmapped["dismissed"].([]map[string]any)
	if len(dismissed) != 3 || f.Message != "3 findings acknowledged (2 HIGH or CRITICAL) and 3 acknowledged findings deleted in the last 24 h" {
		t.Fatalf("note after clearing = %q %v", f.Message, dismissed)
	}
}

func feedNote(t *testing.T, srv *Server, uid string) feedFinding {
	t.Helper()
	findings, err := srv.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.FindingInfo["uid"] == uid {
			return f
		}
	}
	t.Fatalf("no %s note", uid)
	return feedFinding{}
}

// The note counts every acknowledgement in the window, not one page of them,
// so a HIGH acknowledgement followed by many small ones is still counted and
// still listed.
func TestEveryDismissalInTheWindowIsCounted(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	seed := func(id, typ, sev string) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "default", AnomalyType: typ, Severity: sev,
			Hostname: "h", Title: "x", Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	ack := func(id string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/anomalies/acknowledge", strings.NewReader(`{"id":"`+id+`"}`))
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("acknowledge %s = %d %s", id, w.Code, w.Body.String())
		}
	}
	seed("crit", "THREAT_INTEL_MATCH", "CRITICAL")
	ack("crit")
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("low-%02d", i)
		seed(id, "NOVEL_DESTINATION", "LOW")
		ack(id)
	}
	f := feedNote(t, srv, "ominull.detection.changes")
	if !strings.HasPrefix(f.Message, "61 findings acknowledged (1 HIGH or CRITICAL)") {
		t.Fatalf("note = %q", f.Message)
	}
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	listed := false
	for _, d := range dismissed {
		listed = listed || strings.Contains(d["change"].(string), "THREAT_INTEL_MATCH")
	}
	if !listed || len(dismissed) != feedDismissedListShown || f.Unmapped["dismissed_omitted"] != 61-feedDismissedListShown {
		t.Fatalf("listed the CRITICAL row = %v, %d rows, %v omitted", listed, len(dismissed), f.Unmapped["dismissed_omitted"])
	}
}

// A failed acknowledgement rolls back, so it writes no FINDINGS_ACKNOWLEDGED
// row and the feed note does not count or list a dismissal that never happened.
func TestAFailedAcknowledgementIsNotNoted(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, id := range []string{"f1", "f2"} {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "default", AnomalyType: "C2_BEACONING",
			Severity: "HIGH", Hostname: "h", Title: "x", Timestamp: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER reject_f2_ack BEFORE UPDATE ON anomaly_alerts WHEN OLD.id = 'f2'
		BEGIN SELECT RAISE(ABORT, 'rejected test acknowledgement'); END`); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"ids":["f1","f2"]}`, `{"all":true}`} {
		if w := adminPost(srv, "/api/v1/anomalies/acknowledge", body, ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: rejected acknowledgement = %d %s", body, w.Code, w.Body.String())
		}
	}
	page, err := store.AuditHistory("", 100, "", storage.AuditFilter{Action: findingsAcknowledgedAudit})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("a rolled-back acknowledgement was recorded: %+v", page.Entries)
	}
	if f := feedNote(t, srv, "ominull.detection.changes"); f.StatusID != ocsfStatusResolved {
		t.Fatalf("nothing was acknowledged yet the note says %+v", f)
	}
}

// A workload rule needs an expiry in the future when it is added, moving one
// later is signed while moving another earlier applies plainly, and the feed
// note names expired rules and a saved row weaker than the floor.
func TestWorkloadRuleExpiryAndTheFloorAreShown(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, body := range []string{
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli"}`,
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2020-01-01T00:00:00Z"}`,
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2099-01-01T00:00:00Z"}`,
	} {
		if w := policyPost(srv, http.MethodPost, "/api/v1/detection/expected", body, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "expires_at") {
			t.Fatalf("%s = %d %s", body, w.Code, w.Body.String())
		}
	}

	until := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	saved := storage.DefaultDetectionTuning()
	saved.ExpectedRules = append(saved.ExpectedRules,
		storage.ExpectedRule{ID: "gh", Workload: "/usr/bin/gh", Networks: []string{"as36459"}, Reason: "cli", ExpiresAt: until},
		storage.ExpectedRule{ID: "ssh", Workload: "/usr/bin/ssh", Networks: []string{"as36459"}, Reason: "git", ExpiresAt: until})
	if _, err := store.SaveDetectionTuning(saved, "test"); err != nil {
		t.Fatal(err)
	}
	rules := store.GetDetectionTuning().ExpectedRules
	for i := range rules {
		switch rules[i].ID {
		case "gh":
			rules[i].ExpiresAt = until.Add(-time.Hour)
		case "ssh":
			rules[i].ExpiresAt = until.Add(time.Hour)
		}
	}
	raw, _ := json.Marshal(map[string]any{"expected_rules": rules})
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""); w.Code != http.StatusOK {
		t.Fatalf("save = %d %s", w.Code, w.Body.String())
	}
	gh, _ := store.GetDetectionTuning().RuleByID("gh")
	ssh, _ := store.GetDetectionTuning().RuleByID("ssh")
	if !gh.ExpiresAt.Equal(until.Add(-time.Hour)) || !ssh.ExpiresAt.Equal(until.Add(time.Hour)) {
		t.Fatalf("both expiries should apply on the first request: %v %v", gh.ExpiresAt, ssh.ExpiresAt)
	}

	// A row saved weaker than the floor, holding an expired workload rule.
	row := `{"silence_enabled":true,"silence_after_minutes":60,"bandwidth_enabled":true,"expected_rules":[{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2020-01-01T00:00:00Z"}]}`
	if _, err := store.DB().Exec(`UPDATE detection_tuning SET settings = ? WHERE id = 1`, row); err != nil {
		t.Fatal(err)
	}
	findings, err := srv.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.FindingInfo["uid"] == "ominull.detection.invalid" && f.SeverityID != ocsfSevInformational {
			t.Fatalf("an expired rule or a value past the floor is not an unsound row: %+v", f)
		}
		if f.FindingInfo["uid"] != "ominull.detection.changes" {
			continue
		}
		clamped, _ := f.Unmapped["floor_clamped"].([]string)
		expired, _ := f.Unmapped["expected_rules_expired"].([]string)
		if f.StatusID != ocsfStatusNew || len(clamped) != 1 || !strings.Contains(clamped[0], "silence_after_minutes 60") ||
			len(expired) != 1 || !strings.Contains(f.Message, "detection floor") {
			t.Fatalf("feed note = %+v", f)
		}
		return
	}
	t.Fatal("no detection policy note")
}
