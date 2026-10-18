package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// finishJobsWith completes every offered job on ep with stdout.
func finishJobsWith(t *testing.T, srv *Server, ep, stdout string) int {
	t.Helper()
	offers, err := srv.responseStore.OfferPendingJobs("default", ep, 20, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offers {
		_ = srv.responseStore.AcknowledgeJob("default", ep, o.JobID, o.LeaseID, true, "")
		if err := srv.responseStore.CompleteJob("default", ep, o.JobID, o.LeaseID, &response.JobResult{
			JobID: o.JobID, LeaseID: o.LeaseID, State: response.StateSucceeded, Stdout: stdout}); err != nil {
			t.Fatal(err)
		}
	}
	return len(offers)
}

// Audit-then-enforce: a safe package set to on_drift enforce keeps auditing;
// a scheduled audit that finds drift makes the next pass ask for one enforce
// run there, dispatched once approved, and nothing more until the next audit.
// Careful packages and categories cannot take the setting.
func TestAuditThenEnforce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	now := time.Now().UTC()
	online := func(at time.Time) {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	online(now)
	sc, _ := syncRealPackage(t, srv, "cleanup.ps1")
	syncRealPackage(t, srv, "software-removal.ps1")
	jobs := func() []*response.JobRecord {
		list, err := srv.responseStore.ScriptJobs("default", "ep-lap", sc.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return list
	}
	for body, want := range map[string]int{
		`{"package":"windows-cleanup","on_drift":"sometimes"}`:              http.StatusBadRequest,
		`{"package":"windows-software-removal","on_drift":"enforce"}`:       http.StatusBadRequest,
		`{"category":"maintenance","on_drift":"enforce"}`:                   http.StatusBadRequest,
		`{"package":"windows-cleanup","enabled":true,"on_drift":"enforce"}`: http.StatusOK,
	} {
		if w := adminPut(srv, "/api/v1/maintenance/settings", body); w.Code != want {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	srv.maintBlocks.kicks.Wait()
	srv.runMaintenanceSchedules(now)
	if n := len(jobs()); n != 1 {
		t.Fatalf("the baseline audit should run at once: %d jobs", n)
	}
	finishJobsWith(t, srv, "ep-lap", `{"v":1,"state":"drift","reboot":false,"changed":[]}`)

	later := now.Add(10 * time.Minute)
	online(later)
	srv.runMaintenanceSchedules(later)
	pending := owner.auth.PendingApprovals()
	if len(jobs()) != 1 || len(pending) != 1 || !strings.Contains(pending[0].Summary, "enforce") {
		t.Fatalf("drift should ask once for enforce: %d jobs %+v", len(jobs()), pending)
	}
	online(later.Add(time.Minute))
	srv.runMaintenanceSchedules(later.Add(time.Minute))
	if p := owner.auth.PendingApprovals(); len(p) != 1 {
		t.Fatalf("asked twice: %d", len(p))
	}
	ask := pending[0]
	if _, err := owner.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ask.ID, Decision: "approve", Assertion: owner.approver.Assert(ask.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	online(later.Add(2 * time.Minute))
	srv.runMaintenanceSchedules(later.Add(2 * time.Minute))
	list := jobs()
	if len(list) != 2 {
		t.Fatalf("the approved enforce run was not dispatched: %d", len(list))
	}
	if run := derivePackageRun(list[0], later); run.Mode != "enforce" {
		t.Fatalf("newest job is %q, want enforce", run.Mode)
	}
	finishJobsWith(t, srv, "ep-lap", `{"v":1,"state":"fixed","reboot":false,"changed":["temp"]}`)
	online(later.Add(3 * time.Minute))
	srv.runMaintenanceSchedules(later.Add(3 * time.Minute))
	if len(jobs()) != 2 || len(owner.auth.PendingApprovals()) != 0 {
		t.Fatalf("a fixed host ran or asked again: %d", len(jobs()))
	}

	// Only a scheduled audit's drift counts.
	hand := &response.JobRecord{RequestedBy: "admin"}
	if driftNeedsFix([]*response.JobRecord{hand}) || driftNeedsFix(nil) {
		t.Fatal("a hand run or no run triggered a fix")
	}
}
