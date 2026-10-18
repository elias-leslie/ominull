package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func adminDo(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, adminRequest(method, path, body))
	return w
}

func playbookTestServer(t *testing.T) *Server {
	t.Helper()
	srv, store := setupTestServer(t)
	t.Cleanup(func() { store.Close() })
	srv.responseEnabled = true
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"audit.ps1", "cleanup.ps1", "maintenance-mode.ps1"} {
		syncRealPackage(t, srv, f)
	}
	return srv
}

const testPlaybook = `{"playbook":{"id":"weekly-tidy","name":"Weekly tidy","maintenance_mode":true,
	"steps":[{"package":"windows-cleanup","mode":"enforce"},{"package":"windows-audit","mode":"audit"}]}}`

// Playbooks are saved as data: checked against the library, never run by a
// save, and removed by id.
func TestPlaybookSettings(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	for body, want := range map[string]string{
		`{"playbook":{"id":"x","name":"A","steps":[{"package":"windows-audit","mode":"audit"}]}}`:                                                "id:",
		`{"playbook":{"id":"ok-id","name":"A","steps":[]}}`:                                                                                      "1-8 steps",
		`{"playbook":{"id":"ok-id","name":"A","steps":[{"package":"windows-audit","mode":"fix"}]}}`:                                              "mode must be",
		`{"playbook":{"id":"ok-id","name":"A","steps":[{"package":"windows-nope","mode":"audit"}]}}`:                                             "no package",
		`{"playbook":{"id":"ok-id","name":"A","steps":[{"package":"windows-maintenance-mode","mode":"enforce"}]}}`:                               "switched by the playbook",
		`{"playbook":{"id":"ok-id","name":"A","steps":[{"package":"windows-audit","mode":"audit"},{"package":"windows-audit","mode":"audit"}]}}`: "repeats",
	} {
		if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s (want %q)", body, w.Code, w.Body.String(), want)
		}
	}
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", testPlaybook); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	var view struct {
		Playbooks []playbook `json:"playbooks"`
	}
	_ = json.Unmarshal(adminDo(srv, http.MethodGet, "/api/v1/maintenance/playbooks", "").Body.Bytes(), &view)
	if len(view.Playbooks) != 1 || len(view.Playbooks[0].Steps) != 2 || !view.Playbooks[0].MaintenanceMode {
		t.Fatalf("view: %+v", view)
	}
	if n := finishJobs(t, srv, "ep-lap"); n != 0 {
		t.Fatalf("saving a playbook ran %d jobs", n)
	}
	if w := adminDo(srv, http.MethodDelete, "/api/v1/maintenance/playbooks?id=weekly-tidy", ""); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "weekly-tidy") {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
}

// A playbook run asks once for every step, then runs the steps one after
// another inside maintenance mode, with grants that live for the window.
func TestPlaybookRunInOrder(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", testPlaybook); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	run := `{"playbook_id":"weekly-tidy","endpoint_ids":["ep-lap"]}`
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/playbooks/run", run, ""))
	owner := ownerOf(t, srv)
	v, err := owner.auth.GetApproval(id, "")
	if err != nil {
		t.Fatal(err)
	}
	// cleanup 60 min + audit 5 min + 10 min slack per step and for each
	// maintenance mode run: 1 h 45 min, so a 2-hour window.
	for _, want := range []string{`Playbook "Weekly tidy"`, "one step after another, all within 2 hours",
		"1. windows-maintenance-mode (enforce)", "2. windows-cleanup (enforce)", "3. windows-audit (audit)", "4. windows-maintenance-mode (revert)"} {
		if !strings.Contains(v.Summary, want) {
			t.Fatalf("summary lacks %q: %s", want, v.Summary)
		}
	}
	if v.Offer != "" {
		t.Fatalf("a playbook run must not offer an approve-all rule: %q", v.Offer)
	}
	owner.approve(t, id)
	w := adminPost(srv, "/api/v1/maintenance/playbooks/run", run, id)
	if w.Code != http.StatusCreated {
		t.Fatalf("approved run: %d %s", w.Code, w.Body.String())
	}

	want := []string{"windows-maintenance-mode", "windows-cleanup", "windows-audit", "windows-maintenance-mode"}
	for i, name := range want {
		offers, err := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute)
		if err != nil || len(offers) != 1 {
			t.Fatalf("step %d: want exactly one job offered, got %d (%v)", i+1, len(offers), err)
		}
		var p response.ScriptExecPayload
		_ = json.Unmarshal([]byte(offers[0].PayloadJSON), &p)
		sc, _ := srv.scriptsStore.GetScript("default", p.ScriptID)
		if sc == nil || sc.Name != name {
			t.Fatalf("step %d ran %+v, want %s", i+1, sc, name)
		}
		if g := offers[0].Grant; g.ExpiresAt-g.IssuedAt != 2*3600 {
			t.Fatalf("step %d grant lives %ds, want the 2-hour window", i+1, g.ExpiresAt-g.IssuedAt)
		}
		if i == 0 && (p.Parameters["mode"] != "enforce" || p.Parameters["hours"] != "2") {
			t.Fatalf("maintenance mode should be on for the window: %v", p.Parameters)
		}
		if i == 3 && p.Parameters["mode"] != "revert" {
			t.Fatalf("maintenance mode should end the run: %v", p.Parameters)
		}
		if !srv.playbookBusyHosts()["ep-lap"] {
			t.Fatal("the schedule must leave a machine alone while a playbook runs on it")
		}
		if err := srv.responseStore.AcknowledgeJob("default", "ep-lap", offers[0].JobID, offers[0].LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
		srv.advancePlaybookRuns(time.Now().UTC())
		if more, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute); len(more) != 0 {
			t.Fatalf("step %d: the next step started before this one ended", i+1)
		}
		if err := srv.responseStore.CompleteJob("default", "ep-lap", offers[0].JobID, offers[0].LeaseID, &response.JobResult{
			JobID: offers[0].JobID, LeaseID: offers[0].LeaseID, State: response.StateSucceeded, Stdout: `{"v":1,"state":"ok","reboot":false,"changed":[]}`}); err != nil {
			t.Fatal(err)
		}
		srv.advancePlaybookRuns(time.Now().UTC())
	}
	rv := srv.playbookRunView(id)
	if rv == nil || !rv.Done || len(rv.Hosts["ep-lap"]) != 4 || rv.Hosts["ep-lap"][3].Result != "ok" {
		t.Fatalf("run view: %+v", rv)
	}
	for _, r := range srv.playbookRuns() {
		for _, st := range r.Steps {
			if st.Item != "" {
				t.Fatal("a finished run keeps no script payloads")
			}
		}
	}
	if srv.playbookBusyHosts()["ep-lap"] {
		t.Fatal("a finished run still holds the machine")
	}
}

// A step that has not started when the window ends is not started at all.
func TestPlaybookRunWindowEnds(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", testPlaybook); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	run := `{"playbook_id":"weekly-tidy","endpoint_ids":["ep-lap"]}`
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/playbooks/run", run, ""))
	ownerOf(t, srv).approve(t, id)
	if w := adminPost(srv, "/api/v1/maintenance/playbooks/run", run, id); w.Code != http.StatusCreated {
		t.Fatalf("approved run: %d %s", w.Code, w.Body.String())
	}
	if n := finishJobs(t, srv, "ep-lap"); n != 1 {
		t.Fatalf("first step: %d jobs", n)
	}
	srv.advancePlaybookRuns(time.Now().UTC().Add(3 * time.Hour))
	rv := srv.playbookRunView(id)
	if rv == nil || !rv.Done {
		t.Fatalf("the run should have ended: %+v", rv)
	}
	steps := rv.Hosts["ep-lap"]
	if steps[0].Result != "ok" || steps[1].State != "not_started" || steps[3].State != "not_started" {
		t.Fatalf("steps: %+v", steps)
	}
	if n := finishJobs(t, srv, "ep-lap"); n != 0 {
		t.Fatalf("a step started after the window: %d", n)
	}
}
