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
// stuck run on that machine; the owner's rule token (raised with one tap,
// kept by Nightshift) approves it without asking, narrowed but never
// widened; host-locked machines refused; the session ends with the run.
func TestStewardScreen(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	owner := ownerOf(t, srv)
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
		{http.MethodPost, "/api/v1/screen/steward"},
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
	w = adminPost(srv, "/api/v1/maintenance/run", audit, "")
	if w.Code == http.StatusAccepted {
		id := pendingID(t, w)
		owner.approve(t, id)
		w = adminPost(srv, "/api/v1/maintenance/run", audit, id)
	}
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
	open := func(body string) *httptest.ResponseRecorder { return stewardDo(srv, key, http.MethodPost, "/api/v1/screen/sessions", body) }
	for body, want := range map[string]string{
		`{"endpoint_id":"` + ep + `","mode":"control"}`:                                           "steward_run",
		`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `"}`:             "not waiting on a dialog or stalled",
		`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"nope"}`:                      "no such maintenance run",
		`{"endpoint_id":"` + ep + `","steward_run":"` + jobID + `","unattended":true}`:            "nobody at the keyboard",
		`{"endpoint_id":"ep-lap","mode":"control","steward_run":"` + jobID + `","rule_token":""}`: "",
	} {
		w := open(body)
		if w.Code < 400 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	// Only the steward names a run.
	if w := adminPost(srv, "/api/v1/screen/sessions", `{"endpoint_id":"`+ep+`","steward_run":"`+jobID+`"}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("admin with steward_run: %d %s", w.Code, w.Body.String())
	}

	// Stuck: waiting on a dialog. Without a rule the steward's ask goes to the owner.
	if code, _ := heartbeat(t, srv, ep, `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"needs_hands","idle_seconds":200,
		"window":{"title":"Uninstall Wave Tool","process":"unins000.exe","pid":4242,"session":1}}`); code != http.StatusOK {
		t.Fatal("needs_hands heartbeat")
	}
	w = open(`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `"}`)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "Nightshift's steward (steward key) will see and control the screen") ||
		!strings.Contains(w.Body.String(), "to unstick maintenance run "+jobID) {
		t.Fatalf("an uncovered steward session should ask the owner: %d %s", w.Code, w.Body.String())
	}

	// The owner raises the setting once (the steward cannot), and gets the token.
	raise := `{"endpoint_id":"` + ep + `","mode":"control","max_minutes":20,"only_in_window":false}`
	if w := stewardDo(srv, key, http.MethodPost, "/api/v1/screen/steward", raise); w.Code != http.StatusForbidden {
		t.Fatalf("the steward raised its own rule: %d", w.Code)
	}
	w = adminPost(srv, "/api/v1/screen/steward", raise, "")
	id := pendingID(t, w)
	if !strings.Contains(w.Body.String(), "Let the steward use the screen") || !strings.Contains(w.Body.String(), "up to 20 minutes each time") {
		t.Fatalf("raise ask: %s", w.Body.String())
	}
	owner.approve(t, id)
	w = adminPost(srv, "/api/v1/screen/steward", raise, id)
	var raised struct {
		Token string                 `json:"rule_token"`
		Rule  map[string]interface{} `json:"rule"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &raised) != nil || raised.Token == "" || raised.Rule["max_seconds"] != float64(1200) {
		t.Fatalf("raise: %d %s", w.Code, w.Body.String())
	}
	if w := adminDo(srv, http.MethodGet, "/api/v1/screen/steward?approval_id="+id, ""); !strings.Contains(w.Body.String(), raised.Token) {
		t.Fatalf("token by approval id: %d %s", w.Code, w.Body.String())
	}

	// A wider narrowing is ignored: a longer session still asks.
	w = open(`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `","rule_token":"` + raised.Token + `","max_duration_seconds":1200,"narrow":{"max_seconds":3600}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("a covered steward session should open without asking: %d %s", w.Code, w.Body.String())
	}
	var sess map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &sess)
	sid, _ := sess["session_id"].(string)
	if sid == "" || sess["connect_token"] == nil {
		t.Fatalf("session: %v", sess)
	}
	live, _ := srv.terminalMgr.GetSession(sid)
	if live == nil || time.Until(live.ExpiresAt) > 20*time.Minute+5*time.Second {
		t.Fatalf("session length should be the rule's: %+v", live)
	}
	if stewardRunOf(sid) != jobID {
		t.Fatal("session not bound to its run")
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
	w = open(`{"endpoint_id":"` + ep + `","mode":"control","steward_run":"` + jobID + `","rule_token":"` + raised.Token + `"}`)
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
