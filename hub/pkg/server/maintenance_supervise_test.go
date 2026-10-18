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

// offerAndAck offers ep's pending jobs and acknowledges them all.
func offerAndAck(t *testing.T, srv *Server, ep string) []*response.JobOffer {
	t.Helper()
	offers, err := srv.responseStore.OfferPendingJobs("default", ep, 4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offers {
		if err := srv.responseStore.AcknowledgeJob("default", ep, o.JobID, o.LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	return offers
}

// heartbeat posts a heartbeat the way an agent does.
func heartbeat(t *testing.T, srv *Server, ep, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/progress", strings.NewReader(body))
	req.Header.Set("X-Device-Endpoint-ID", ep)
	w := httptest.NewRecorder()
	srv.handleResponseProgress(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func waitFor(t *testing.T, srv *Server, query string) waitView {
	t.Helper()
	w := adminDo(srv, http.MethodGet, "/api/v1/maintenance/wait?"+query, "")
	var v waitView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("wait %s: %d %s", query, w.Code, w.Body.String())
	}
	return v
}

// A supervised run: heartbeats move it to running, a stalled or needs_hands
// phase shows as the run's state with the window, a cancel request rides the
// heartbeat reply, a run that goes quiet reads stalled, and maint wait
// returns on attention and on the result, waking on the event.
func TestSupervisedRun(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	ownerOf(t, srv)
	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`
	w := adminPost(srv, "/api/v1/maintenance/run", audit, "")
	if w.Code == http.StatusAccepted {
		id := pendingID(t, w)
		ownerOf(t, srv).approve(t, id)
		w = adminPost(srv, "/api/v1/maintenance/run", audit, id)
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	var run struct {
		RunID string          `json:"run_id"`
		Jobs  []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	if len(run.Jobs) != 1 {
		t.Fatalf("jobs: %s", w.Body.String())
	}
	jobID := run.Jobs[0].JobID

	// Before the agent takes it: waiting, and a short wait returns unchanged.
	if v := waitFor(t, srv, "ids="+jobID+"&wait=0"); len(v.Entries) != 1 || v.Entries[0].State != "waiting" || v.AnyFinal {
		t.Fatalf("waiting: %+v", v)
	}
	offers := offerAndAck(t, srv, "ep-lap")
	lease := offers[0].LeaseID

	// Wrong lease, unknown phase, other machine: refused.
	if code, _ := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"nope","phase":"running"}`); code == http.StatusOK {
		t.Fatal("a heartbeat with the wrong lease was taken")
	}
	if code, _ := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"dancing"}`); code == http.StatusOK {
		t.Fatal("an unknown phase was taken")
	}
	if code, _ := heartbeat(t, srv, "ep-other", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running"}`); code == http.StatusOK {
		t.Fatal("another machine's heartbeat was taken")
	}
	code, out := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running","progress_pct":40,"message":"checking\u0007 updates","cpu_ms":1200}`)
	if code != http.StatusOK || out["cancel"] != false {
		t.Fatalf("heartbeat: %d %v", code, out)
	}
	job, _ := srv.responseStore.GetJob("default", jobID)
	if job.State != response.StateRunning {
		t.Fatalf("job state %s, want running", job.State)
	}
	live := srv.liveRun(job, time.Now().UTC())
	if live.State != "running" || live.Progress == nil || live.Progress.Pct != 40 || live.Progress.Message != "checking updates" {
		t.Fatalf("live: %+v %+v", live, live.Progress)
	}

	// A wait started now is woken by the needs_hands heartbeat.
	type res struct {
		v   waitView
		dur time.Duration
	}
	done := make(chan res, 1)
	if run.RunID == "" {
		t.Fatal("the run has no id")
	}
	go func() {
		start := time.Now()
		var v waitView
		w := adminDo(srv, http.MethodGet, "/api/v1/maintenance/wait?ids="+run.RunID+"&wait=20", "")
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		done <- res{v, time.Since(start)}
	}()
	time.Sleep(200 * time.Millisecond)
	if code, _ := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"needs_hands","idle_seconds":200,
		"window":{"title":"Uninstall Wave Tool","process":"unins000.exe","pid":4242,"session":1}}`); code != http.StatusOK {
		t.Fatalf("needs_hands heartbeat: %d", code)
	}
	r := <-done
	if r.dur > 10*time.Second || !r.v.Attention || len(r.v.Entries) != 1 {
		t.Fatalf("the wait was not woken by the event (%s): %+v", r.dur, r.v)
	}
	e := r.v.Entries[0]
	if e.State != "needs_hands" || e.Window == nil || e.Window.Title != "Uninstall Wave Tool" || e.Host != "laptop-1" ||
		!strings.Contains(e.Reason, "Uninstall Wave Tool") || e.Package != "windows-audit" {
		t.Fatalf("entry: %+v", e)
	}

	// Cancel rides the next heartbeat's reply.
	if w := adminPost(srv, "/api/v1/response/jobs/cancel", `{"job_id":"`+jobID+`"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	if _, out := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running"}`); out["cancel"] != true {
		t.Fatalf("the cancel did not reach the agent: %v", out)
	}

	// Gone quiet: stalled with the reason.
	sups, _ := srv.responseStore.Supervision("default", []string{jobID})
	job, _ = srv.responseStore.GetJob("default", jobID)
	run2 := derivePackageRun(job, time.Now().UTC())
	applySupervision(run2, sups[jobID], time.Now().Add(5*time.Minute))
	if run2.State != "stalled" || !strings.Contains(run2.Reason, "no word from the machine") {
		t.Fatalf("quiet run: %+v", run2)
	}

	// The result ends it: final, cancelled counts as failed.
	if err := srv.responseStore.CompleteJob("default", "ep-lap", jobID, lease, &response.JobResult{JobID: jobID, LeaseID: lease,
		State: response.StateCancelled, ErrorCode: "CANCELLED"}); err != nil {
		t.Fatal(err)
	}
	v := waitFor(t, srv, "ids="+jobID+"&wait=5")
	if !v.AnyFinal || !v.Failed || v.Entries[0].State != "cancelled" {
		t.Fatalf("after the result: %+v", v)
	}
	if code, _ := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"running"}`); code != http.StatusConflict {
		t.Fatalf("a heartbeat after the end: %d", code)
	}
	if v := waitFor(t, srv, "ids=nope&wait=0"); len(v.Unknown) != 1 {
		t.Fatalf("unknown ids: %+v", v)
	}
}

// One-off scripts: one owner tap per run, an approval that says what the
// script is and why, never a baseline or a rule, the run record keeps the
// script, and promoting it needs a package header and a new name.
func TestOneOffScript(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	ownerOf(t, srv)
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: "ep-lin", TenantID: "default", Hostname: "box-1", OS: "Ubuntu 24.04", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	src := "Get-Process | Select-Object -First 3\n::progress:: done\n"
	body := func(extra string) string {
		b, _ := json.Marshal(map[string]interface{}{"endpoint_ids": []string{"ep-lap"}, "name": "list processes", "shell": "powershell",
			"source": src, "reason": "find what holds the uninstaller"})
		if extra != "" {
			return extra
		}
		return string(b)
	}
	for _, bad := range []string{
		`{"endpoint_ids":["ep-lap"],"name":"x","shell":"powershell","source":"x"}`,                                  // no reason
		`{"endpoint_ids":["ep-lap"],"name":"x","shell":"cmd","source":"x","reason":"y"}`,                            // shell
		`{"endpoint_ids":["ep-lin"],"name":"x","shell":"powershell","source":"x","reason":"y"}`,                     // platform
		`{"endpoint_ids":["ep-lap"],"name":"x","shell":"powershell","source":"x","reason":"y","timeout_seconds":5}`, // timeout
	} {
		if w := adminPost(srv, "/api/v1/maintenance/script", bad, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body.String())
		}
	}
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/script", body(""), ""))
	v, err := ownerOf(t, srv).auth.GetApproval(id, "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != "Run a one-off script" || !strings.Contains(v.Summary, `One-off script "list processes"`) ||
		!strings.Contains(v.Summary, "2 lines of PowerShell") || !strings.Contains(v.Summary, "Why: find what holds the uninstaller") {
		t.Fatalf("approval: %q %q", v.Action, v.Summary)
	}
	if v.Offer != "" {
		t.Fatalf("a one-off script was offered as a rule: %q", v.Offer)
	}
	ownerOf(t, srv).approve(t, id)
	w := adminPost(srv, "/api/v1/maintenance/script", body(""), id)
	if w.Code != http.StatusCreated {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	var run struct {
		RunID string          `json:"run_id"`
		Jobs  []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	if run.RunID != id || len(run.Jobs) != 1 {
		t.Fatalf("run: %s", w.Body.String())
	}
	// The approval is spent: the same request asks again.
	if w := adminPost(srv, "/api/v1/maintenance/script", body(""), ""); w.Code != http.StatusAccepted {
		t.Fatalf("a second run did not ask again: %d", w.Code)
	}
	job, _ := srv.responseStore.GetJob("default", run.Jobs[0].JobID)
	p, ok := scriptJobPayload(job)
	if !ok || p.Source != src || !isOneOffScript(p.ScriptID) || p.Interpreter != "powershell.exe" {
		t.Fatalf("the run record does not keep the script: %+v", p)
	}
	offers := offerAndAck(t, srv, "ep-lap")
	_ = srv.responseStore.CompleteJob("default", "ep-lap", job.ID, offers[0].LeaseID, &response.JobResult{JobID: job.ID, LeaseID: offers[0].LeaseID,
		State: response.StateFailed, ExitCode: 3, Stdout: "boom\n"})
	wv := waitFor(t, srv, "ids="+run.RunID+"&wait=2")
	if len(wv.Entries) != 1 || wv.Entries[0].State != "failed" || wv.Entries[0].Reason != "exit code 3" ||
		wv.Entries[0].Package != "one-off: list processes" || wv.Entries[0].Line != "boom" {
		t.Fatalf("one-off result: %+v", wv)
	}
	lw := adminDo(srv, http.MethodGet, "/api/v1/maintenance/script", "")
	if lw.Code != http.StatusOK || !strings.Contains(lw.Body.String(), `"reason":"find what holds the uninstaller"`) {
		t.Fatalf("list: %d %s", lw.Code, lw.Body.String())
	}

	// Promote: needs a package header, then a new name.
	if w := adminPost(srv, "/api/v1/maintenance/script/promote", `{"job_id":"`+job.ID+`"}`, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "package header") {
		t.Fatalf("promote without header: %d %s", w.Code, w.Body.String())
	}
	header := `# ominull-package: {"name":"windows-list-procs","title":"List processes","description":"Lists the top processes.","category":"maintenance","risk":"safe","reboot":false,"timeout":300,"interval":"weekly","params":[]}`
	pb, _ := json.Marshal(map[string]string{"source": header + "\n" + src})
	w = adminPost(srv, "/api/v1/maintenance/script/promote", string(pb), "")
	if w.Code != http.StatusCreated {
		t.Fatalf("promote: %d %s", w.Code, w.Body.String())
	}
	if w := adminPost(srv, "/api/v1/maintenance/script/promote", string(pb), ""); w.Code != http.StatusConflict {
		t.Fatalf("promoting the same name twice: %d %s", w.Code, w.Body.String())
	}
}
