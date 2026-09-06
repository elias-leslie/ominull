package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func learningCall(t *testing.T, srv *Server, method, path, body, role string) (int, map[string]interface{}) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Content-Type", "application/json")
	switch role {
	case "tenant":
		r.Header.Set("X-API-Key", "mock_tenant_token")
	default:
		r.Header.Set("X-API-Key", "mock_admin_token")
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func seedLearningEndpoint(t *testing.T, store *storage.Store, id, role string) {
	t.Helper()
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: id, TenantID: "default", LocationID: "loc-home", Hostname: id,
		OS: "Linux", RoleTag: role, Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding %s: %v", id, err)
	}
}

// Opening a window is an administrator action, and it says what it covers in
// words rather than in a UUID.
func TestOpeningAWindowNamesWhatItCovers(t *testing.T) {
	srv, store := setupTestServer(t)
	seedLearningEndpoint(t, store, "ep-1", "workstation")

	code, body := learningCall(t, srv, http.MethodPost, "/api/v1/learning/windows",
		`{"scope_type":"endpoint","scope_id":"ep-1","hours":2,"note":"new host"}`, "admin")
	if code != http.StatusOK {
		t.Fatalf("opening: %d %v", code, body)
	}
	window, _ := body["window"].(map[string]interface{})
	if window["scope_label"] != "ep-1" {
		t.Fatalf("the window does not name its scope: %v", window)
	}
	if window["status"] != storage.LearningActive {
		t.Fatalf("a fresh window is not active: %v", window["status"])
	}

	windows, err := store.ListLearningWindows("", true)
	if err != nil || len(windows) != 1 {
		t.Fatalf("the window was not stored: %v %v", windows, err)
	}
}

// A window nobody may open at will is the whole safety of learning mode: while
// one is open the fleet stops reporting.
func TestOnlyAnAdministratorOpensOrClosesAWindow(t *testing.T) {
	srv, store := setupTestServer(t)
	seedLearningEndpoint(t, store, "ep-1", "workstation")

	if code, _ := learningCall(t, srv, http.MethodPost, "/api/v1/learning/windows",
		`{"scope_type":"endpoint","scope_id":"ep-1","hours":2}`, "tenant"); code != http.StatusForbidden {
		t.Fatalf("a tenant opened a learning window: %d", code)
	}

	w, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "ep-1", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if code, _ := learningCall(t, srv, http.MethodPost, "/api/v1/learning/windows/close",
		fmt.Sprintf(`{"id":%q}`, w.ID), "tenant"); code != http.StatusForbidden {
		t.Fatalf("a tenant closed a learning window: %d", code)
	}

	// Reading is open, because an analyst who cannot see that findings are
	// being held will misread a quiet console.
	if code, body := learningCall(t, srv, http.MethodGet, "/api/v1/learning/windows", "", "tenant"); code != http.StatusOK {
		t.Fatalf("a tenant cannot read the windows: %d %v", code, body)
	}
}

// Nothing applies itself, and nothing applies by wildcard: the ids are named,
// and a proposal that no longer stands is refused rather than guessed at.
func TestProposalsApplyOnlyWhenNamed(t *testing.T) {
	srv, store := setupTestServer(t)
	seedLearningEndpoint(t, store, "ep-1", "workstation")
	seedLearningEndpoint(t, store, "ep-2", "workstation")

	w, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeLocation, ScopeID: "loc-home", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	now := time.Now().UTC()
	obs := []storage.LearningObservation{}
	for _, ep := range []string{"ep-1", "ep-2"} {
		obs = append(obs, storage.LearningObservation{
			WindowID: w.ID, EndpointID: ep, Kind: storage.LearnPair,
			Key: "backup-agent@acme vendor", Count: 200, FirstSeen: now, LastSeen: now,
		})
	}
	if err := store.RecordLearningObservations(obs); err != nil {
		t.Fatalf("recording: %v", err)
	}

	code, body := learningCall(t, srv, http.MethodGet, "/api/v1/learning/proposals?window="+w.ID, "", "admin")
	if code != http.StatusOK {
		t.Fatalf("reading proposals: %d %v", code, body)
	}
	list, _ := body["proposals"].([]interface{})
	if len(list) == 0 {
		t.Fatal("a window with observations proposed nothing")
	}
	first, _ := list[0].(map[string]interface{})
	id, _ := first["id"].(string)
	if first["subject"] != "backup-agent@acme vendor" {
		t.Fatalf("the proposal names the wrong thing: %v", first)
	}
	if first["corroboration"] == nil || first["evidence"] == nil {
		t.Fatalf("the proposal carries no argument: %v", first)
	}

	// An id from another window, or one that was never proposed, changes nothing.
	code, body = learningCall(t, srv, http.MethodPost, "/api/v1/learning/proposals/apply",
		fmt.Sprintf(`{"window":%q,"ids":["%s:quiet_pair:not-a-real-pair"]}`, w.ID, w.ID), "admin")
	if code != http.StatusOK {
		t.Fatalf("apply: %d %v", code, body)
	}
	if applied, _ := body["applied"].([]interface{}); len(applied) != 0 {
		t.Fatalf("an unproposed id was applied: %v", applied)
	}
	if store.GetDetectionTuning().IsVouchedPair("backup-agent", "acme vendor", "vendor") {
		t.Fatal("the tuning changed without the proposal being named")
	}

	// Naming it applies exactly it.
	code, body = learningCall(t, srv, http.MethodPost, "/api/v1/learning/proposals/apply",
		fmt.Sprintf(`{"window":%q,"ids":[%q]}`, w.ID, id), "admin")
	if code != http.StatusOK {
		t.Fatalf("apply: %d %v", code, body)
	}
	if applied, _ := body["applied"].([]interface{}); len(applied) != 1 {
		t.Fatalf("the named proposal was not applied: %v", body)
	}
	tuning := store.GetDetectionTuning()
	if !tuning.IsVouchedPair("backup-agent", "acme vendor", "vendor") {
		t.Fatal("the applied proposal did not reach the tuning")
	}
	if tuning.IsVouchedPair("curl", "acme vendor", "vendor") {
		t.Fatal("applying a pair silenced the whole network")
	}

	// Applying is an administrator action.
	if code, _ := learningCall(t, srv, http.MethodPost, "/api/v1/learning/proposals/apply",
		fmt.Sprintf(`{"window":%q,"ids":[%q]}`, w.ID, id), "tenant"); code != http.StatusForbidden {
		t.Fatalf("a tenant applied a proposal: %d", code)
	}
}

// Rented compute is barred from the quiet lists in code. A learning proposal is
// the other door into those lists, and it has to be barred there too.
func TestLearningNeverProposesRentedCompute(t *testing.T) {
	srv, store := setupTestServer(t)
	seedLearningEndpoint(t, store, "ep-1", "workstation")
	w, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "ep-1", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	now := time.Now().UTC()
	if err := store.RecordLearningObservations([]storage.LearningObservation{{
		WindowID: w.ID, EndpointID: "ep-1", Kind: storage.LearnPair,
		Key: "python3.13@rented cloud, listed by github", Count: 900, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	_, body := learningCall(t, srv, http.MethodGet, "/api/v1/learning/proposals?window="+w.ID, "", "admin")
	list, _ := body["proposals"].([]interface{})
	for _, raw := range list {
		p, _ := raw.(map[string]interface{})
		id, _ := p["id"].(string)
		code, applied := learningCall(t, srv, http.MethodPost, "/api/v1/learning/proposals/apply",
			fmt.Sprintf(`{"window":%q,"ids":[%q]}`, w.ID, id), "admin")
		if code != http.StatusOK {
			t.Fatalf("apply: %d %v", code, applied)
		}
	}
	// Even if such an observation reaches the table, the tuning refuses to
	// enforce the pair - hosting is barred in code, on both doors.
	if store.GetDetectionTuning().IsVouchedPair("python3.13", "rented cloud, listed by github", storage.TenancyHosting) {
		t.Fatal("a learning proposal vouched for rented compute")
	}
}
