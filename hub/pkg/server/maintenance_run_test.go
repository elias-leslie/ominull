package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

// syncRealPackage puts a released package from packages/windows (or, for a
// "linux/x.sh" file, packages/linux) into the library the way ominullctl
// scripts sync does.
func syncRealPackage(t *testing.T, srv *Server, file string) (*scripts.Script, *scripts.PackageHeader) {
	t.Helper()
	if !strings.Contains(file, "/") {
		file = "windows/" + file
	}
	raw, err := os.ReadFile("../../../packages/" + file)
	if err != nil {
		t.Fatal(err)
	}
	h, err := scripts.ParsePackageHeader(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := json.Marshal(h.Schema())
	meta, _ := json.Marshal(map[string]interface{}{"package": h.Name, "title": h.Title, "category": h.Category,
		"interval": h.Interval, "risk": h.Risk, "reboot": h.Reboot, "timeout": h.Timeout, "platform": h.PlatformName(), "role": h.Role})
	sc, _, _, err := srv.scriptsStore.SyncScript("default", h.Name, h.Description, h.Interpreter(), string(raw), string(schema), string(meta), "ops")
	if err != nil {
		t.Fatal(err)
	}
	return sc, h
}

func adminPut(srv *Server, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, adminRequest(http.MethodPut, path, body))
	srv.maintBlocks.kicks.Wait() // the pass a settings change starts runs at the real time
	return w
}

// finishJobs completes every offered job on an endpoint with an ok result.
func finishJobs(t *testing.T, srv *Server, ep string) int {
	t.Helper()
	offers, err := srv.responseStore.OfferPendingJobs("default", ep, 20, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offers {
		if err := srv.responseStore.AcknowledgeJob("default", ep, o.JobID, o.LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
		if err := srv.responseStore.CompleteJob("default", ep, o.JobID, o.LeaseID, &response.JobResult{
			JobID: o.JobID, LeaseID: o.LeaseID, State: response.StateSucceeded, Stdout: `{"v":1,"state":"ok","reboot":false,"changed":[]}`}); err != nil {
			t.Fatal(err)
		}
	}
	return len(offers)
}

// Package runs: a baseline audit needs no tap, enforce asks once and the
// "approve all like this" answer covers it (and auditing with the same
// settings) from then on.
func TestPackageRunsUnderOwnerApproval(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "audit.ps1")

	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`
	w := adminPost(srv, "/api/v1/maintenance/run", audit, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("a baseline audit should run without a tap: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Jobs []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Jobs) != 1 || out.Jobs[0].Package != "windows-audit" {
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

	enforce := strings.Replace(audit, `"audit"}`, `"enforce"}`, 1)
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/run", enforce, ""))
	v, err := owner.auth.GetApproval(id, "")
	if err != nil || v.Kind != string(response.ActionKindScriptExec) || !strings.Contains(v.Summary, "windows-audit (enforce)") {
		t.Fatalf("approval: %v %+v", err, v)
	}
	if _, err := owner.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: id, Decision: "rule", Assertion: owner.approver.Assert(v.Challenge, "rule")}); err != nil {
		t.Fatal(err)
	}
	if w := adminPost(srv, "/api/v1/maintenance/run", enforce, id); w.Code != http.StatusCreated {
		t.Fatalf("approved run: %d %s", w.Code, w.Body.String())
	}
	if w := adminPost(srv, "/api/v1/maintenance/run", enforce, ""); w.Code != http.StatusCreated {
		t.Fatalf("a covered run should not ask: %d %s", w.Code, w.Body.String())
	}
}

// The schedule runs effective settings: enabling a safe package in audit
// mode needs no tap; changed settings ask once and run after the tap; a
// category switch turns a package off without asking.
func TestMaintenanceScheduleRunsEffectiveSettings(t *testing.T) {
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
	sc, h := syncRealPackage(t, srv, "audit.ps1")
	countJobs := func() int {
		jobs, err := srv.responseStore.ScriptJobs("default", "ep-lap", sc.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(jobs)
	}

	// Off by default: nothing runs.
	srv.runMaintenanceSchedules(now)
	if n := countJobs(); n != 0 {
		t.Fatalf("a package nobody enabled ran: %d", n)
	}
	// Settings are validated.
	for body, want := range map[string]int{
		`{"package":"windows-audit","mode":"sometimes"}`:             http.StatusBadRequest,
		`{"package":"windows-audit","params":{"no_such":"1"}}`:       http.StatusBadRequest,
		`{"category":"security","mode":"enforce"}`:                   http.StatusBadRequest,
		`{"package":"windows-nothing","enabled":true}`:               http.StatusBadRequest,
		`{"package":"windows-audit","enabled":true,"every":"daily"}`: http.StatusBadRequest,
	} {
		if w := adminPut(srv, "/api/v1/maintenance/settings", body); w.Code != want {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"package":"windows-audit","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	srv.runMaintenanceSchedules(now)
	if n := countJobs(); n != 1 {
		t.Fatalf("an enabled baseline audit should run at once: %d jobs", n)
	}
	if p := owner.auth.PendingApprovals(); len(p) != 0 {
		t.Fatalf("a baseline audit asked the owner: %+v", p)
	}
	srv.runMaintenanceSchedules(now.Add(time.Minute))
	if n := countJobs(); n != 1 {
		t.Fatalf("a second run started while one is open: %d", n)
	}
	finishJobs(t, srv, "ep-lap")
	srv.runMaintenanceSchedules(now.Add(2 * time.Hour))
	if n := countJobs(); n != 1 {
		t.Fatalf("a package that just succeeded is not due: %d", n)
	}

	// A host override that changes a setting asks the owner once.
	var p *scripts.PackageParam
	for i := range h.Params {
		if h.Params[i].Type == "int" {
			p = &h.Params[i]
			break
		}
	}
	if p == nil {
		t.Fatal("windows-audit declares no int setting to change")
	}
	val := *p.Min
	if fmt.Sprint(val) == p.DefaultValue() {
		val = *p.Max
	}
	noReason := fmt.Sprintf(`{"package":"windows-audit","endpoint_id":"ep-lap","params":{%q:"%d"}}`, p.Name, val)
	if w := adminPut(srv, "/api/v1/maintenance/settings", noReason); w.Code != http.StatusBadRequest {
		t.Fatalf("an override without a reason: %d %s", w.Code, w.Body.String())
	}
	body := fmt.Sprintf(`{"package":"windows-audit","endpoint_id":"ep-lap","params":{%q:"%d"},"reason":"tested on this laptop"}`, p.Name, val)
	w := adminPut(srv, "/api/v1/maintenance/settings?endpoint_id=ep-lap", body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), fmt.Sprintf("%q:\"%d\"", p.Name, val)) {
		t.Fatalf("override: %d %s", w.Code, w.Body.String())
	}
	later := now.Add(25 * time.Hour)
	online(later)
	srv.runMaintenanceSchedules(later)
	pending := owner.auth.PendingApprovals()
	if countJobs() != 1 || len(pending) != 1 || !strings.Contains(pending[0].Summary, p.Name) {
		t.Fatalf("changed settings should ask once, showing the change: %d jobs %+v", countJobs(), pending)
	}
	// The laptop drops off and comes back: the same ask is still the one.
	online(later.Add(-time.Hour))
	srv.runMaintenanceSchedules(later.Add(time.Minute))
	online(later.Add(2 * time.Minute))
	srv.runMaintenanceSchedules(later.Add(2 * time.Minute))
	if p := owner.auth.PendingApprovals(); len(p) != 1 {
		t.Fatalf("the schedule asked twice: %d", len(p))
	}
	findings, err := srv.maintenanceFindings(later)
	if err != nil || len(findings) != 2 || findings[1].SeverityID != ocsfSevMedium {
		t.Fatalf("a waiting run should show on the board: %v %+v", err, findings)
	}
	ask := pending[0]
	if _, err := owner.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ask.ID, Decision: "approve", Assertion: owner.approver.Assert(ask.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	srv.runMaintenanceSchedules(later.Add(2*time.Minute + 10*time.Second))
	if n := countJobs(); n != 2 {
		t.Fatalf("the approved run was not dispatched: %d", n)
	}
	finishJobs(t, srv, "ep-lap")

	// The category switch turns it off on this host without asking.
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"category":"maintenance","endpoint_id":"ep-lap","enabled":false,"reason":"on loan"}`); w.Code != http.StatusOK {
		t.Fatalf("category: %d %s", w.Code, w.Body.String())
	}
	muchLater := later.Add(50 * time.Hour)
	online(muchLater)
	srv.runMaintenanceSchedules(muchLater)
	if n := countJobs(); n != 2 || len(owner.auth.PendingApprovals()) != 0 {
		t.Fatalf("a switched-off category ran or asked: %d", n)
	}
	var view struct {
		Categories []struct {
			Name string `json:"name"`
			On   *bool  `json:"enabled"`
		} `json:"categories"`
	}
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, adminRequest(http.MethodGet, "/api/v1/maintenance/settings?endpoint_id=ep-lap", ""))
	_ = json.Unmarshal(rw.Body.Bytes(), &view)
	if len(view.Categories) != 2 || view.Categories[0].Name != "maintenance" || view.Categories[0].On == nil || *view.Categories[0].On {
		t.Fatalf("settings view: %s", rw.Body.String())
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
