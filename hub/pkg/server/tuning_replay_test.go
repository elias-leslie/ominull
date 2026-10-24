package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// testExpiry is a known workload expiry a month out.
var testExpiry = time.Now().Add(30 * 24 * time.Hour)

func replayRequest(srv *Server, method, path, key string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// seedNpmFindings records n npm findings and one curl finding an hour ago.
func seedNpmFindings(t *testing.T, store *storage.Store, n int) time.Time {
	t.Helper()
	at := time.Now().UTC().Add(-time.Hour)
	ev := func(cmd string) string {
		return fmt.Sprintf(`{"command_line":%q,"destination_owner":"Cloudflare, Inc.","destination_asn":"AS13335","destination_tenancy":"shared-cdn"}`, cmd)
	}
	for i := 0; i < n; i++ {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{
			ID: fmt.Sprintf("npm-%d", i), TenantID: "default", EndpointID: "e1", AnomalyType: "NOVEL_PROCESS_EGRESS",
			Severity: "MEDIUM", Title: "npm", ProcessPath: "/opt/node/bin/node", Evidence: ev("node /opt/node/lib/npm-cli.js ci"), Timestamp: at.Add(-time.Duration(i) * time.Hour), // outside one another's cooldown
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateAnomalyAlert(storage.AnomalyAlert{
		ID: "curl-1", TenantID: "default", EndpointID: "e1", AnomalyType: "NOVEL_PROCESS_EGRESS",
		Severity: "MEDIUM", Title: "curl", ProcessPath: "/usr/bin/curl", Evidence: ev("curl https://x"), Timestamp: at,
	}); err != nil {
		t.Fatal(err)
	}
	return at
}

var npmKnown = []storage.KnownWorkload{{Workload: "node /opt/node/lib/npm-cli.js", Owner: "as13335", Reason: "npm registry", ExpiresAt: testExpiry}}

func TestTuningReplayPreviewsADraftWithoutSavingIt(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedNpmFindings(t, store, 4)

	w := replayRequest(srv, http.MethodGet, "/api/v1/detection/tuning/replay", "mock_admin_token", nil)
	var got struct{ Before, After int }
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got.Before != 5 || got.After != 5 {
		t.Fatalf("saved tuning replay = %d %s", w.Code, w.Body.String())
	}
	draft := store.GetDetectionTuning()
	draft.KnownWorkloads = npmKnown
	w = replayRequest(srv, http.MethodPost, "/api/v1/detection/tuning/replay", "mock_admin_token", map[string]any{"tuning": draft})
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got.Before != 5 || got.After != 1 {
		t.Fatalf("draft replay = %d %s", w.Code, w.Body.String())
	}
	if len(store.GetDetectionTuning().KnownWorkloads) != 0 {
		t.Fatal("a replay must not save the draft")
	}
	draft.KnownWorkloads = []storage.KnownWorkload{{Workload: "node /opt/node/lib/npm-cli.js", Owner: "cloudflare"}}
	if w := replayRequest(srv, http.MethodPost, "/api/v1/detection/tuning/replay", "mock_admin_token", map[string]any{"tuning": draft}); w.Code != http.StatusBadRequest {
		t.Fatalf("a draft with an unexplained exclusion was replayed: %d", w.Code)
	}
	if w := replayRequest(srv, http.MethodGet, "/api/v1/detection/tuning/replay?from=2026-01-01&to=2026-12-31", "mock_admin_token", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("a window over the ceiling was accepted: %d", w.Code)
	}
}

func TestResolvingFindingsRecordsWhy(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedNpmFindings(t, store, 3)
	tu := store.GetDetectionTuning()
	tu.KnownWorkloads = npmKnown
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}

	if w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_tenant_token", map[string]any{"covered": true}); w.Code != http.StatusForbidden {
		t.Fatalf("a tenant key resolved findings in bulk: %d", w.Code)
	}
	if w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token", map[string]any{"ids": []string{"curl-1"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("findings were resolved without a reason: %d", w.Code)
	}

	if w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token", map[string]any{"ids": []string{"curl-1"}, "reason": "x", "verdict": "fine"}); w.Code != http.StatusBadRequest {
		t.Fatalf("a verdict outside the enum was accepted: %d", w.Code)
	}
	w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token", map[string]any{"covered": true})
	var got struct {
		Resolved int            `json:"resolved"`
		ByReason map[string]int `json:"by_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got.Resolved != 3 {
		t.Fatalf("covered resolve = %d %s", w.Code, w.Body.String())
	}
	if reason, _, _, ok := store.AnomalyResolution("npm-0"); !ok || reason != "covered by tuning: known workload: npm registry" {
		t.Fatalf("resolution reason = %q %v", reason, ok)
	}
	if a, _ := store.GetAnomalyAlert("curl-1"); a.Acknowledged {
		t.Fatal("a finding the tuning does not cover was resolved")
	}

	w = replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token", map[string]any{"ids": []string{"curl-1"}, "reason": "agent research fetch, triaged"})
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got.Resolved != 1 {
		t.Fatalf("resolve by id = %d %s", w.Code, w.Body.String())
	}
	if a, _ := store.GetAnomalyAlert("curl-1"); !a.Acknowledged {
		t.Fatal("the named finding was not resolved")
	}
}

// Resolving closes findings like acknowledging them, so the Nightshift feed's
// detection-policy note counts and lists what a resolve closed, by id and in
// a covered batch; a verdict on a finding already closed adds nothing.
func TestResolvingFindingsIsCountedOnTheFeedNote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedNpmFindings(t, store, 3)
	if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: "crit", TenantID: "default", EndpointID: "e1", AnomalyType: "THREAT_INTEL_MATCH",
		Severity: "CRITICAL", Title: "known bad", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	tu := store.GetDetectionTuning()
	tu.KnownWorkloads = npmKnown
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	resolve := func(body map[string]any, want int) {
		t.Helper()
		w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token", body)
		var got struct {
			Resolved int `json:"resolved"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got.Resolved != want {
			t.Fatalf("resolve %v = %d %s", body, w.Code, w.Body.String())
		}
	}
	resolve(map[string]any{"ids": []string{"crit"}, "reason": "checked"}, 1)
	f := feedNote(t, srv, "ominull.detection.changes")
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	if f.StatusID != ocsfStatusNew || !strings.HasPrefix(f.Message, "1 finding acknowledged (1 HIGH or CRITICAL)") ||
		len(dismissed) != 1 || !strings.Contains(dismissed[0]["change"].(string), "THREAT_INTEL_MATCH") ||
		!strings.Contains(dismissed[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("note after resolving the CRITICAL finding = %q %v", f.Message, dismissed)
	}
	resolve(map[string]any{"covered": true}, 3)
	// The operator's later verdict relabels the closed finding and is not a
	// second dismissal.
	resolve(map[string]any{"ids": []string{"crit"}, "reason": "confirmed", "verdict": storage.VerdictMalicious}, 1)
	f = feedNote(t, srv, "ominull.detection.changes")
	dismissed, _ = f.Unmapped["dismissed"].([]map[string]any)
	listed := false
	for _, d := range dismissed {
		listed = listed || strings.Contains(d["change"].(string), "THREAT_INTEL_MATCH")
	}
	if !strings.HasPrefix(f.Message, "4 findings acknowledged (1 HIGH or CRITICAL)") || !listed || len(dismissed) != 2 {
		t.Fatalf("note after the covered batch = %q %v", f.Message, dismissed)
	}
}

// The console's tuning sheet posts only the fields it shows; saving it must
// not erase the known workloads it does not show.
func TestASaveWithoutKnownWorkloadsKeepsThem(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := store.GetDetectionTuning()
	tu.KnownWorkloads = npmKnown
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	// Starting the off-hours window later shrinks it, which loosens: the
	// test owner approves it.
	sheet := httptest.NewRequest(http.MethodPost, "/api/v1/detection/tuning", strings.NewReader(`{"off_hours_start":23}`))
	sheet.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveAuthorized(t, srv.Handler(), sheet); w.Code != http.StatusOK {
		t.Fatalf("sheet-shaped save = %d %s", w.Code, w.Body.String())
	}
	if got := store.GetDetectionTuning(); len(got.KnownWorkloads) != 1 || got.OffHoursStart != 23 {
		t.Fatalf("after a sheet save: %d known workloads, start %d", len(got.KnownWorkloads), got.OffHoursStart)
	}
	if w := replayRequest(srv, http.MethodPost, "/api/v1/detection/tuning", "mock_admin_token", map[string]any{"Known_Workloads": []any{}}); w.Code != http.StatusOK {
		t.Fatalf("explicit clear = %d", w.Code)
	}
	if got := store.GetDetectionTuning(); len(got.KnownWorkloads) != 0 {
		t.Fatal("an explicit empty list should clear the known workloads")
	}
}
