package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/terminal"
)

// limitsCall sends one remote shell limits request with the test admin key.
func limitsCall(srv *Server, method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1/terminal/limits", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "test-admin-key-12345")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

type limitsView struct {
	Limits     terminalLimitsJSON `json:"limits"`
	Defaults   terminalLimitsJSON `json:"defaults"`
	Saved      bool               `json:"saved"`
	Changed    bool               `json:"changed"`
	ApprovalID string             `json:"approval_id"`
}

func mustLimits(t *testing.T, w *httptest.ResponseRecorder) limitsView {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	var v limitsView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func limitNotes(t *testing.T, store *storage.Store) []storage.AuditEntry {
	t.Helper()
	page, err := store.AuditHistory("", 100, "", storage.AuditFilter{Action: terminalLimitsAudit})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

func TestTerminalLimitsStartAtFourHoursAndRefuseUnsafeValues(t *testing.T) {
	t.Parallel()
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	v := mustLimits(t, limitsCall(srv, http.MethodGet, ""))
	want := terminalLimitsJSON{MaxDurationSeconds: 4 * 3600, IdleTimeoutSeconds: 15 * 60, MaxPerEndpoint: 3, MaxPerTenant: 8}
	if v.Limits != want || v.Defaults != want || v.Saved {
		t.Fatalf("fresh hub limits = %+v", v)
	}
	for _, body := range []string{
		`{"max_duration_seconds":90000}`,                          // over 24h
		`{"max_duration_seconds":60}`,                             // under 5m
		`{"max_duration_seconds":5430}`,                           // not whole minutes
		`{"idle_timeout_seconds":30}`,                             // under a minute
		`{"max_duration_seconds":600,"idle_timeout_seconds":900}`, // idle past the session
		`{"max_per_endpoint":0}`,
		`{"max_per_endpoint":11}`,
		`{"max_per_tenant":51}`,
		`{"max_per_endpoint":5,"max_per_tenant":4}`,
		`{"max_per_endpoint":"3"}`,
	} {
		if w := limitsCall(srv, http.MethodPut, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s, want 400", body, w.Code, w.Body.String())
		}
	}
	if got := srv.terminalMgr.Limits(); got != terminal.DefaultLimits() {
		t.Fatalf("a refused change moved the limits: %+v", got)
	}

	// Only an admin changes them; any signed-in role reads them.
	tok, err := hubauth.GenerateJWT(hubauth.Claims{Username: "ana", Role: hubauth.RoleAnalyst, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for method, code := range map[string]int{http.MethodPut: http.StatusForbidden, http.MethodGet: http.StatusOK} {
		r := httptest.NewRequest(method, "/api/v1/terminal/limits", strings.NewReader(`{"max_per_tenant":4}`))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != code {
			t.Errorf("analyst %s = %d, want %d", method, w.Code, code)
		}
	}
}

// Lowering a limit only tightens: it applies at once, survives a restart
// (the saved row wins over the startup flags) and is audited.
func TestLoweringTerminalLimitsAppliesAtOnce(t *testing.T) {
	t.Parallel()
	srv, store, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	v := mustLimits(t, limitsCall(srv, http.MethodPut, `{"max_duration_seconds":7200,"max_per_tenant":4}`))
	if !v.Changed || !v.Saved || v.Limits.MaxDurationSeconds != 7200 || v.Limits.MaxPerTenant != 4 || v.Limits.MaxPerEndpoint != 3 {
		t.Fatalf("lowered limits = %+v", v)
	}
	if srv.terminalMgr.MaxDuration() != 2*time.Hour {
		t.Fatal("the manager kept the old session length")
	}
	notes := limitNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "lowered: Remote shell: sessions run up to 2 hours (was 4 hours); 4 open in all (was 8)") {
		t.Fatalf("notes = %+v", notes)
	}
	// A restart applies the startup flags, then the saved limits over them.
	srv.SetTerminalLimits(terminal.Limits{MaxDuration: 3 * time.Hour, IdleTimeout: 20 * time.Minute})
	got := srv.terminalMgr.Limits()
	if got.MaxDuration != 2*time.Hour || got.PerTenant != 4 {
		t.Fatalf("after restart = %+v", got)
	}
	v = mustLimits(t, limitsCall(srv, http.MethodGet, ""))
	if v.Defaults.MaxDurationSeconds != 3*3600 || v.Defaults.IdleTimeoutSeconds != 1200 {
		t.Fatalf("startup defaults = %+v", v.Defaults)
	}
	// Saving the same values again changes nothing and signs nothing.
	if v := mustLimits(t, limitsCall(srv, http.MethodPut, `{"max_duration_seconds":7200}`)); v.Changed {
		t.Fatal("an unchanged save counted as a change")
	}
}

// Raising a limit is signed at once and audited in plain words: the first
// request applies it, with the authorization id and what changed.
func TestRaisingTerminalLimitsIsAuthorizedAtOnce(t *testing.T) {
	t.Parallel()
	srv, store, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	body := `{"max_duration_seconds":21600,"max_per_endpoint":2}`
	v := mustLimits(t, limitsCall(srv, http.MethodPut, body))
	if v.ApprovalID == "" || v.Limits.MaxDurationSeconds != 21600 || srv.terminalMgr.MaxDuration() != 6*time.Hour {
		t.Fatalf("raise = %+v", v)
	}
	if !authorizedAuditHas(t, store, terminalLimitsTarget, v.ApprovalID, "Remote shell: sessions run up to 6 hours (was 4 hours); 2 open per endpoint (was 3)") {
		t.Fatalf("no ACTION_AUTHORIZED row for the raise: %+v", authorizedAudit(t, store))
	}
	notes := limitNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "raised") || !strings.Contains(notes[0].Details, v.ApprovalID) {
		t.Fatalf("notes = %+v", notes)
	}
	// Going back to the startup defaults shortens sessions but allows a third
	// per endpoint again: a change with any raise is signed too.
	v = mustLimits(t, limitsCall(srv, http.MethodPut, `{"reset":true}`))
	if v.ApprovalID == "" || v.Saved || v.Limits != limitsJSON(terminal.DefaultLimits()) {
		t.Fatalf("reset = %+v", v)
	}
	if got := len(authorizedAudit(t, store)); got != 2 {
		t.Fatalf("authorizations = %d, want 2", got)
	}
}

// A terminal request may ask for less than the hub's maximum, never more; the
// authorization says how long, and the signed payload stays the program
// alone, which is all agents check a terminal grant against.
func TestTerminalAuthorizationShowsTheSessionLength(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body string
		want string
		d    time.Duration
	}{
		{`{"endpoint_id":"ep-long","program":"/bin/sh"}`, "up to 4 hours,", 4 * time.Hour},
		{`{"endpoint_id":"ep-long","program":"/bin/sh","max_duration_seconds":5400}`, "up to 90 minutes,", 90 * time.Minute},
		{`{"endpoint_id":"ep-long","program":"/bin/sh","max_duration_seconds":999999}`, "up to 4 hours,", 4 * time.Hour},
	} {
		srv, store, _, cleanup := setupTestServerWithResponse(t)
		seedTerminalEndpoint(t, srv, "default", "ep-long")
		w := limitsLikePost(srv, tc.body)
		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			cleanup()
			t.Fatalf("%s: session = %d %s", tc.body, w.Code, w.Body.String())
		}
		if !authorizedAuditHas(t, store, "Interactive /bin/sh on ep-long, recorded, "+tc.want) {
			t.Errorf("%s: authorization audit = %+v", tc.body, authorizedAudit(t, store))
		}
		var s struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &s)
		if left := time.Until(s.ExpiresAt); left < tc.d-time.Minute || left > tc.d {
			t.Errorf("%s: session expires in %s, want %s", tc.body, left, tc.d)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", strings.NewReader(tc.body))
		r.Header.Set("X-Role", "admin")
		plan, ok := srv.resolveTerminal(httptest.NewRecorder(), r, []byte(tc.body))
		if !ok || string(plan.Payload) != `{"program":"/bin/sh"}` || plan.SessionSeconds != int64(tc.d/time.Second) {
			t.Errorf("%s: plan payload %s, %d s", tc.body, plan.Payload, plan.SessionSeconds)
		}
		cleanup()
	}
}

func limitsLikePost(srv *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "test-admin-key-12345")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}
