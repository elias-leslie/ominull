package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func stewardDo(srv *Server, key, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// The steward: its own key reaching only its routes; a screen only for a
// stuck run on that machine, inside its maintenance window, never
// unattended, for 30 minutes at most; signed at once under those fixed
// defaults; host-locked machines refused; the session ends with the run.
func TestStewardScreen(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	const ep = "windows-lap"
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: ep, TenantID: "default", Hostname: "laptop-2", OS: "Windows 11 Home", Status: "online",
		LastSeenAt: time.Now().UTC(), ResponseCapabilities: `{"isolate":true,"screen":{"input":true}}`}); err != nil {
		t.Fatal(err)
	}

	// The key: issued once by an administrator, never shown again.
	w := adminDo(srv, http.MethodPost, "/api/v1/integrations/steward/key", "")
	var issued struct {
		Key string `json:"key"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &issued) != nil || !strings.HasPrefix(issued.Key, "nss_") {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	key := issued.Key
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/endpoints"},
		{http.MethodPost, "/api/v1/maintenance/run"},
		{http.MethodPost, "/api/v1/integrations/steward/key"},
		{http.MethodGet, "/api/v1/screen/sessions"},
	} {
		if w := stewardDo(srv, key, tc.method, tc.path, "{}"); w.Code != http.StatusForbidden {
			t.Errorf("steward key on %s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if w := stewardDo(srv, key, http.MethodGet, "/api/v1/maintenance/wait?ids=nope&wait=0", ""); w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("steward key should reach maint wait: %d %s", w.Code, w.Body.String())
	}

	// A run on the machine that is merely running is not stuck.
	audit := `{"endpoint_ids":["` + ep + `"],"packages":["windows-audit"],"mode":"audit"}`
	w = adminDo(srv, http.MethodPost, "/api/v1/maintenance/run", audit)
	var run struct {
		Jobs []packageRunJob `json:"jobs"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &run) != nil || len(run.Jobs) != 1 {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	jobID := run.Jobs[0].JobID
	lease := offerAndAck(t, srv, ep)[0].LeaseID
	if code, _ := heartbeat(t, srv, ep, `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running"}`); code != http.StatusOK {
		t.Fatal("heartbeat")
	}
	open := func(body string) *httptest.ResponseRecorder {
		return stewardDo(srv, key, http.MethodPost, "/api/v1/screen/sessions", body)
	}
	for body, want := range map[string]string{
		`{"endpoint_id":"` + ep + `","mode":"control"}`:                                "steward_run",
		`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `"}`:  "not waiting on a dialog or stalled",
		`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"nope"}`:           "no such maintenance run",
		`{"endpoint_id":"` + ep + `","steward_run":"` + jobID + `","unattended":true}`: "nobody at the keyboard",
	} {
		w := open(body)
		if w.Code < 400 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	// Only the steward names a run.
	if w := adminDo(srv, http.MethodPost, "/api/v1/screen/sessions", `{"endpoint_id":"`+ep+`","steward_run":"`+jobID+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("admin with steward_run: %d %s", w.Code, w.Body.String())
	}

	// Stuck: waiting on a dialog. The shipped window is closed (or the
	// machine's clock unknown), so the steward is told to escalate instead.
	if code, _ := heartbeat(t, srv, ep, `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"needs_hands","idle_seconds":200,
		"window":{"title":"Uninstall Wave Tool","process":"unins000.exe","pid":4242,"session":1}}`); code != http.StatusOK {
		t.Fatal("needs_hands heartbeat")
	}
	stuck := `{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `"}`
	w = open(stuck)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "maintenance window") {
		t.Fatalf("outside the window: %d %s", w.Code, w.Body.String())
	}

	// Inside the window the same request is signed and opens at once.
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id="+ep, `{"endpoint_id":"`+ep+`","ranges":["00:00-23:59"],"clock":"utc"}`); w.Code != http.StatusOK {
		t.Fatalf("window: %d %s", w.Code, w.Body.String())
	}
	w = open(`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `","max_duration_seconds":7200}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("a stuck run inside its window should open without a second round: %d %s", w.Code, w.Body.String())
	}
	var sess map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &sess)
	sid, _ := sess["session_id"].(string)
	if sid == "" || sess["connect_token"] == nil {
		t.Fatalf("session: %v", sess)
	}
	// A longer request never widens the fixed 30 minutes.
	live, _ := srv.terminalMgr.GetSession(sid)
	if live == nil || time.Until(live.ExpiresAt) > 30*time.Minute+5*time.Second {
		t.Fatalf("session length should be the steward's fixed 30 minutes: %+v", live)
	}
	if stewardRunOf(sid) != jobID {
		t.Fatal("session not bound to its run")
	}
	if n := auditCount(t, srv.store, "ACTION_AUTHORIZED"); n == 0 {
		t.Fatal("the signed screen should leave an ACTION_AUTHORIZED audit row")
	}
	// While the run is stuck the sweep leaves it; once it moves on, it ends.
	if srv.stewardSessionSweep() != 0 {
		t.Fatal("swept a session whose run is still stuck")
	}
	if code, _ := heartbeat(t, srv, ep, `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running"}`); code != http.StatusOK {
		t.Fatal("running heartbeat")
	}
	if srv.stewardSessionSweep() != 1 {
		t.Fatal("the session should end once its run is no longer stuck")
	}
	if live, _ := srv.terminalMgr.GetSession(sid); live != nil && live.IsLive() {
		t.Fatal("session still live")
	}

	// A host-locked machine never takes the steward.
	srv.trust.mu.Lock()
	srv.trust.init()
	seen := srv.trust.reports[ep]
	seen.report.HostAuthority, seen.report.ManifestSeq = true, 1<<20
	srv.trust.reports[ep] = seen
	srv.trust.mu.Unlock()
	if code, _ := heartbeat(t, srv, ep, `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"needs_hands","idle_seconds":200}`); code != http.StatusOK {
		t.Fatal("needs_hands heartbeat")
	}
	w = open(`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "locked on the host") {
		t.Fatalf("host-locked: %d %s", w.Code, w.Body.String())
	}

	// Revoked, the key is just a wrong key.
	if w := adminDo(srv, http.MethodDelete, "/api/v1/integrations/steward/key", ""); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := stewardDo(srv, key, http.MethodGet, "/api/v1/maintenance/wait?ids=x&wait=0", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d", w.Code)
	}
}
