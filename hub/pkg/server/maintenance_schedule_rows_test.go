package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// A scheduled enforce run of released safe packages inside the machine's
// window goes without asking when the owner's Approvals row says auto, with
// no work session open: auto means always, not only in a session. A row set
// to session asks for the same run once the session has ended.
func TestScheduledInWindowRunFollowsAutoRowWithoutSession(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	now := time.Now().UTC()
	online := func(at time.Time) {
		t.Helper()
		if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-kid", TenantID: "default", Hostname: "kid-laptop", OS: "Windows 11 Home", Status: "online", LastSeenAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	online(now)
	updates, _ := syncRealPackage(t, srv, "updates.ps1")
	cleanup, _ := syncRealPackage(t, srv, "cleanup.ps1")
	// The machine runs 4 h behind UTC; its window is the two hours around
	// now in machine time.
	off := -240
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-kid"] = trustReportSeen{report: response.AgentTrustReport{V: 1, UTCOffset: &off}, at: time.Now()}
	srv.trust.mu.Unlock()
	h := now.Add(time.Duration(off) * time.Minute).Hour()
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id=ep-kid", fmt.Sprintf(`{"ranges":["%02d:00-%02d:00"]}`, (h+23)%24, (h+1)%24)); w.Code != http.StatusOK {
		t.Fatalf("window: %d %s", w.Code, w.Body.String())
	}

	// The owner's rows as Nightshift pushes them: everything auto but
	// isolation, and a work session that has already ended.
	rows := map[string]string{}
	for _, id := range []string{"agent_update", "capability", "maintenance.in", "maintenance.out", "other", "reboot.in", "reboot.out",
		"remote.lab", "remote.people", "security.in", "security.out"} {
		rows["ominull."+id] = responseauth.RowAuto
	}
	rows["ominull.isolation"] = responseauth.RowAsk
	ended := &responseauth.RowSession{Start: time.Now().Add(-12 * time.Hour), End: time.Now().Add(-time.Minute)}
	save := &responseauth.ApprovalRowsInput{Rows: rows, Session: ended}
	ask, err := owner.auth.AskApprovalRows(save)
	if err != nil || ask.Approval == nil {
		t.Fatalf("rows ask: %v %+v", err, ask)
	}
	owner.approve(t, ask.Approval.ID)
	save.ApprovalID = ask.Approval.ID
	if res, err := owner.auth.SetApprovalRows(save); err != nil || !res.Accepted || res.Rows.SessionOpen {
		t.Fatalf("rows save: %v %+v", err, res)
	}

	countJobs := func(scriptID string) int {
		t.Helper()
		jobs, err := srv.responseStore.ScriptJobs("default", "ep-kid", scriptID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(jobs)
	}
	for _, body := range []string{
		`{"package":"windows-updates","endpoint_id":"ep-kid","enabled":true,"mode":"enforce","reason":"kid laptop: updates in window"}`,
		`{"package":"windows-cleanup","endpoint_id":"ep-kid","enabled":true,"mode":"enforce","reason":"kid laptop: cleanup in window"}`,
	} {
		if w := adminPut(srv, "/api/v1/maintenance/settings?endpoint_id=ep-kid", body); w.Code != http.StatusOK {
			t.Fatalf("settings: %d %s", w.Code, w.Body.String())
		}
	}
	srv.runMaintenanceSchedules(now)
	if p := owner.auth.PendingApprovals(); len(p) != 0 {
		t.Fatalf("a scheduled in-window run under an auto row asked the owner: %+v", p)
	}
	if countJobs(updates.ID) != 1 || countJobs(cleanup.ID) != 1 {
		t.Fatalf("scheduled runs not dispatched: updates %d, cleanup %d", countJobs(updates.ID), countJobs(cleanup.ID))
	}
	jobs, _ := srv.responseStore.ScriptJobs("default", "ep-kid", updates.ID, 1)
	if jobs[0].RequestedBy != schedulerName {
		t.Fatalf("the job was not the schedule's: %q", jobs[0].RequestedBy)
	}
	finishJobs(t, srv, "ep-kid")

	// The same runs under a session-only row, with the session over, ask.
	rows["ominull.maintenance.in"] = responseauth.RowChoiceSession
	if res, err := owner.auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: rows, Session: ended}); err != nil || !res.Accepted {
		t.Fatalf("tightening: %v %+v", err, res)
	}
	later := now.Add(8 * 24 * time.Hour) // both packages due again, same hour of the day
	online(later)
	srv.runMaintenanceSchedules(later)
	p := owner.auth.PendingApprovals()
	if len(p) != 2 || p[0].Row != "ominull.maintenance.in" || p[1].Row != "ominull.maintenance.in" {
		t.Fatalf("a session-only row with no session should ask once per package: %+v", p)
	}
}

// A manual enforce run whose row says ask goes without asking while the
// owner's work session is open (the authority approves it as "session"),
// instead of answering 202 and telling the owner to approve on their phone.
func TestManualRunUnderAskRowRunsWhileSessionOpen(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "cleanup.ps1")
	off := 0
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-lap"] = trustReportSeen{report: response.AgentTrustReport{V: 1, UTCOffset: &off}, at: time.Now()}
	srv.trust.mu.Unlock()
	h := time.Now().UTC().Hour()
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id=ep-lap", fmt.Sprintf(`{"ranges":["%02d:00-%02d:00"]}`, (h+23)%24, (h+1)%24)); w.Code != http.StatusOK {
		t.Fatalf("window: %d %s", w.Code, w.Body.String())
	}
	rows := map[string]string{"ominull.maintenance.in": responseauth.RowAsk}
	open := &responseauth.RowSession{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	save := &responseauth.ApprovalRowsInput{Rows: rows, Session: open}
	ask, err := owner.auth.AskApprovalRows(save)
	if err != nil || ask.Approval == nil {
		t.Fatalf("rows ask: %v %+v", err, ask)
	}
	owner.approve(t, ask.Approval.ID)
	save.ApprovalID = ask.Approval.ID
	if res, err := owner.auth.SetApprovalRows(save); err != nil || !res.Accepted || !res.Rows.SessionOpen {
		t.Fatalf("rows save: %v %+v", err, res)
	}
	enforce := `{"endpoint_ids":["ep-lap"],"packages":["windows-cleanup"],"mode":"enforce"}`
	if w := adminPost(srv, "/api/v1/maintenance/run", enforce, ""); w.Code != http.StatusCreated {
		t.Fatalf("a run during an open work session should go without asking: %d %s", w.Code, w.Body.String())
	}
	if p := owner.auth.PendingApprovals(); len(p) != 0 {
		t.Fatalf("the owner was asked: %+v", p)
	}
}
