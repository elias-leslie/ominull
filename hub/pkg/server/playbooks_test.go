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

// startPlaybook runs a saved playbook: authorized and started in the one
// request. It returns the run's id and the audit text of its authorization.
func startPlaybook(t *testing.T, srv *Server, run string) (string, string) {
	t.Helper()
	authorityOf(t, srv)
	w := postAdmin(srv, "/api/v1/maintenance/playbooks/run", run)
	if w.Code != http.StatusCreated {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	authz := auditRowsOf(t, srv.store, "ACTION_AUTHORIZED")
	words := authorityWords(t, srv)
	if out.Run.ID == "" || len(authz) != 1 || !strings.Contains(authz[0].Details, out.Run.ID) || len(words) != 1 {
		t.Fatalf("the run should carry its authorization id: %s %+v %v", w.Body.String(), authz, words)
	}
	return out.Run.ID, words[0]
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

// A playbook run is authorized once for every step, then runs the steps one
// after another inside maintenance mode, with grants that live for the window.
func TestPlaybookRunInOrder(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", testPlaybook); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	run := `{"playbook_id":"weekly-tidy","endpoint_ids":["ep-lap"]}`
	id, summary := startPlaybook(t, srv, run)
	// cleanup 60 min + audit 5 min + 10 min slack per step and for each
	// maintenance mode run: 1 h 45 min, so a 2-hour window.
	// Steps that change something wait for people by default.
	for _, want := range []string{`Playbook "Weekly tidy"`, "in order within 2 hours",
		"keep awake on, settings hours=2; cleanup; audit (audit); keep awake off", "Steps that change something: waits while someone is using the machine"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("authorization lacks %q: %s", want, summary)
		}
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
		if (i == 1) != (p.Parameters["when_busy"] == "wait") {
			t.Fatalf("step %d: only the cleanup waits for people: %v", i+1, p.Parameters)
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
	id, _ := startPlaybook(t, srv, run)
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

// "Don't wait for open apps" runs the changing steps even with someone at
// the machine, and the authorization says so.
func TestPlaybookRunDontWait(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", testPlaybook); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	run := `{"playbook_id":"weekly-tidy","endpoint_ids":["ep-lap"],"dont_wait":true}`
	_, summary := startPlaybook(t, srv, run)
	if !strings.Contains(summary, "does not wait for open apps or games") {
		t.Fatalf("summary: %s", summary)
	}
	finishJobs(t, srv, "ep-lap") // maintenance mode on
	srv.advancePlaybookRuns(time.Now().UTC())
	offers, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute)
	if len(offers) != 1 {
		t.Fatalf("want the cleanup offered, got %d", len(offers))
	}
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(offers[0].PayloadJSON), &p)
	if p.Parameters["when_busy"] != "run" {
		t.Fatalf("cleanup should not wait: %v", p.Parameters)
	}
}

// A restart step holds the next one until the restart time has passed and
// the machine has checked in again.
func TestPlaybookWaitsForTheRestart(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	syncRealPackage(t, srv, "reboot.ps1")
	book := `{"playbook":{"id":"patch","name":"Patch","steps":[{"package":"windows-reboot","mode":"enforce"},{"package":"windows-audit","mode":"audit"}]}}`
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/playbooks", book); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	run := `{"playbook_id":"patch","endpoint_ids":["ep-lap"]}`
	_, summary := startPlaybook(t, srv, run)
	// The names shorten to fit once the window sentence is in.
	if !strings.Contains(summary, "reboot") || !strings.Contains(summary, "careful") {
		t.Fatalf("the restart must show as careful: %s", summary)
	}
	offers, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute)
	if len(offers) != 1 {
		t.Fatalf("restart step: %d offers", len(offers))
	}
	o := offers[0]
	_ = srv.responseStore.AcknowledgeJob("default", "ep-lap", o.JobID, o.LeaseID, true, "")
	if err := srv.responseStore.CompleteJob("default", "ep-lap", o.JobID, o.LeaseID, &response.JobResult{JobID: o.JobID, LeaseID: o.LeaseID,
		State: response.StateSucceeded, Stdout: `{"v":1,"state":"fixed","reboot":false,"changed":["restart in 10 min"],"detail":{"restart_in_seconds":600}}`}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	srv.advancePlaybookRuns(now)
	srv.advancePlaybookRuns(now.Add(5 * time.Minute))
	if n, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute); len(n) != 0 {
		t.Fatal("the next step started before the restart")
	}
	srv.advancePlaybookRuns(now.Add(15 * time.Minute)) // past the hold, but not seen since
	if n, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute); len(n) != 0 {
		t.Fatal("the next step started before the machine came back")
	}
	ep, _ := srv.store.GetEndpoint("ep-lap")
	ep.LastSeenAt = now.Add(14 * time.Minute)
	if err := srv.store.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	srv.advancePlaybookRuns(now.Add(15 * time.Minute))
	if n, _ := srv.responseStore.OfferPendingJobs("default", "ep-lap", 10, time.Minute); len(n) != 1 {
		t.Fatal("the audit should start once the machine is back")
	}
}

// The maintenance window is one fleet setting that enforce runs carry and
// audits do not; the schedule never restarts a machine.
func TestMaintenanceWindowSetting(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	syncRealPackage(t, srv, "reboot.ps1")
	for body, want := range map[string]string{
		`{"window":"25:00-02:00"}`:                             "HH:MM-HH:MM",
		`{"window":"02:00-02:00"}`:                             "start and end different",
		`{"window":"01:00-05:00","package":"windows-cleanup"}`: "on its own",
	} {
		if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/settings", body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/settings", `{"window":"22:00-06:00"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"window":"22:00-06:00"`) {
		t.Fatalf("set: %d %s", w.Code, w.Body.String())
	}
	tenant := "default"
	windows, _ := srv.packageHosts(tenant, []string{"ep-lap"})
	settings, _ := srv.maintenanceSettings(tenant)
	for mode, want := range map[string]string{"enforce": "22:00-06:00", "audit": ""} {
		sc, _ := srv.findPackage(tenant, "windows-cleanup")
		it, _, err := srv.buildPackageItem(tenant, sc, mode, []string{"ep-lap"}, windows, settings, nil)
		if err != nil {
			t.Fatal(err)
		}
		var p response.ScriptExecPayload
		_ = json.Unmarshal([]byte(it.Raw), &p)
		if p.Parameters["window"] != want {
			t.Errorf("%s run carries window %q, want %q", mode, p.Parameters["window"], want)
		}
	}
	// Clearing goes back to the shipped default window.
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/settings", `{"window":""}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"window":"01:00-05:00"`) {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	// Enabled with enforce on the fleet, the restart package still never runs on a schedule.
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/settings", `{"package":"windows-reboot","enabled":true,"mode":"enforce"}`); w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	srv.maintBlocks.kicks.Wait()
	srv.runMaintenanceSchedules(time.Now().UTC())
	for _, b := range srv.maintBlocks.list() {
		if strings.Contains(b.Package, "reboot") {
			t.Fatalf("the schedule asked to restart: %+v", b)
		}
	}
	jobs, _ := srv.responseStore.ScriptJobs(tenant, "ep-lap", mustScriptID(t, srv, "windows-reboot"), 5)
	if len(jobs) != 0 {
		t.Fatalf("the schedule restarted the machine: %d jobs", len(jobs))
	}
}

func mustScriptID(t *testing.T, srv *Server, name string) string {
	t.Helper()
	sc, err := srv.findPackage("default", name)
	if err != nil {
		t.Fatal(err)
	}
	return sc.ID
}
