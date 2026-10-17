package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// A package run asks the owner once; the "approve all like this" answer
// makes later identical runs (by hand or by schedule) go through without a
// tap, while the schedule never asks for anything the rule does not cover.
func TestPackageRunsUnderOwnerApprovalAndSchedule(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	srcRaw, err := os.ReadFile("../../../packages/windows/audit.ps1") // a released package
	if err != nil {
		t.Fatal(err)
	}
	src := string(srcRaw)
	schema := `{"parameters":[{"name":"mode","type":"enum","enum":["audit","enforce"],"default":"audit","required":true}]}`
	sc, sv, _, err := srv.scriptsStore.SyncScript("default", "windows-audit", "Checks standards.", "powershell.exe", src, schema,
		`{"package":"windows-audit","title":"Standards check","risk":"safe","timeout":300}`, "ops")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/run", body, ""))
	v, err := owner.auth.GetApproval(id, "")
	if err != nil || v.Kind != string(response.ActionKindScriptExec) || !strings.Contains(v.Summary, "windows-audit (audit)") {
		t.Fatalf("approval: %v %+v", err, v)
	}
	if _, err := owner.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: id, Decision: "rule", Assertion: owner.approver.Assert(v.Challenge, "rule")}); err != nil {
		t.Fatal(err)
	}
	w := adminPost(srv, "/api/v1/maintenance/run", body, id)
	if w.Code != http.StatusCreated {
		t.Fatalf("approved run: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Jobs []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Jobs) != 1 || out.Jobs[0].EndpointID != "ep-lap" || out.Jobs[0].Package != "windows-audit" {
		t.Fatalf("jobs: %s", w.Body.String())
	}
	job, err := srv.responseStore.GetJob("default", out.Jobs[0].JobID)
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Grant   response.EndpointGrant `json:"grant"`
		Payload string                 `json:"payload"`
	}
	if err := json.Unmarshal([]byte(job.RequestJSON), &req); err != nil || req.Grant.ActionDigest != responseauth.ItemDigest(req.Payload) {
		t.Fatalf("the job's grant must bind its own payload: %v %+v", err, req.Grant)
	}

	// The same run again goes through under the rule, without a tap.
	if w := adminPost(srv, "/api/v1/maintenance/run", body, ""); w.Code != http.StatusCreated {
		t.Fatalf("covered run should not ask: %d %s", w.Code, w.Body.String())
	}

	// Let both jobs finish cleanly, then schedule the package daily.
	offers, err := srv.responseStore.OfferPendingJobs("default", "ep-lap", 4, time.Minute)
	if err != nil || len(offers) != 2 {
		t.Fatalf("offer: %v %d", err, len(offers))
	}
	for _, o := range offers {
		if err := srv.responseStore.AcknowledgeJob("default", "ep-lap", o.JobID, o.LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
		if err := srv.responseStore.CompleteJob("default", "ep-lap", o.JobID, o.LeaseID, &response.JobResult{
			JobID: o.JobID, LeaseID: o.LeaseID, State: response.StateSucceeded, Stdout: `{"v":1,"state":"ok","reboot":false,"changed":[]}`}); err != nil {
			t.Fatal(err)
		}
	}
	sched, err := srv.scriptsStore.CreateSchedule("default", sc.ID, sv.Version, []string{"ep-lap"}, map[string]string{"mode": "audit"},
		"daily", now.Add(-time.Minute), nil, 0, 300, packageMaxOutput, "ops")
	if err != nil {
		t.Fatal(err)
	}
	enforce, err := srv.scriptsStore.CreateSchedule("default", sc.ID, sv.Version, []string{"ep-lap"}, map[string]string{"mode": "enforce"},
		"daily", now.Add(-time.Minute), nil, 0, 300, packageMaxOutput, "ops")
	if err != nil {
		t.Fatal(err)
	}
	countJobs := func() int {
		jobs, err := srv.responseStore.ScriptJobs("default", "ep-lap", sc.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(jobs)
	}
	srv.runMaintenanceSchedules(now)
	if n := countJobs(); n != 2 {
		t.Fatalf("a package that just succeeded is not due: %d jobs", n)
	}

	// A day later, with the laptop online, the audit schedule runs under
	// the rule; the enforce one is not covered and waits without asking.
	later := now.Add(25 * time.Hour)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: later}); err != nil {
		t.Fatal(err)
	}
	srv.runMaintenanceSchedules(later)
	if n := countJobs(); n != 3 {
		t.Fatalf("the due audit run was not dispatched: %d jobs", n)
	}
	if p := owner.auth.PendingApprovals(); len(p) != 0 {
		t.Fatalf("the schedule asked the owner: %+v", p)
	}
	blocks := srv.maintBlocks.list()
	if len(blocks) != 1 || blocks[0].Package != "windows-audit (enforce)" {
		t.Fatalf("the uncovered schedule should be reported waiting: %+v", blocks)
	}
	got, _ := srv.scriptsStore.GetSchedule("default", sched.ID)
	if got.RunsCount != 1 {
		t.Fatalf("runs counted: %d", got.RunsCount)
	}
	if got, _ := srv.scriptsStore.GetSchedule("default", enforce.ID); got.RunsCount != 0 {
		t.Fatalf("the uncovered schedule ran: %d", got.RunsCount)
	}
	// The new run is open: not due again until it finishes.
	srv.runMaintenanceSchedules(later.Add(2 * time.Hour))
	if n := countJobs(); n != 3 {
		t.Fatalf("a second run started while one is open: %d jobs", n)
	}

	findings, err := srv.maintenanceFindings(later)
	if err != nil || len(findings) != 2 || findings[1].SeverityID != ocsfSevMedium || findings[0].SeverityID != ocsfSevInformational {
		t.Fatalf("feed: %v %+v", err, findings)
	}
}

func TestPackageRunDue(t *testing.T) {
	now := time.Now()
	done := func(ago time.Duration, stdout string) *response.JobRecord {
		res, _ := json.Marshal(response.JobResult{State: response.StateSucceeded, Stdout: stdout})
		at := now.Add(-ago)
		return &response.JobRecord{State: response.StateSucceeded, RequestedAt: at, CompletedAt: &at, ResultJSON: string(res)}
	}
	ok := `{"v":1,"state":"ok","reboot":false,"changed":[]}`
	skipped := `{"v":1,"state":"skipped","reboot":false,"changed":[]}`
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		jobs []*response.JobRecord
		want bool
	}{
		"never run":                     {nil, true},
		"recent success":                {[]*response.JobRecord{done(time.Hour, ok)}, false},
		"old success":                   {[]*response.JobRecord{done(2*day, ok)}, true},
		"skipped just now":              {[]*response.JobRecord{done(10*time.Minute, skipped), done(2*day, ok)}, false},
		"skipped over an hour ago":      {[]*response.JobRecord{done(2*time.Hour, skipped), done(2*day, ok)}, true},
		"open run":                      {[]*response.JobRecord{{State: response.StateRunning, RequestedAt: now.Add(-time.Minute)}}, false},
		"skips since an old success ok": {[]*response.JobRecord{done(90*time.Minute, skipped), done(3*time.Hour, skipped), done(2*day, ok)}, true},
	} {
		if got := packageRunDue(c.jobs, day, now); got != c.want {
			t.Errorf("%s: due=%v, want %v", name, got, c.want)
		}
	}
}
