package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func TestMaintenancePackages(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	srv.responseEnabled = true
	for _, ep := range []storage.Endpoint{
		{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", IP: "10.0.0.21", OS: "Windows 11 Home"},
		{ID: "ep-srv", TenantID: "default", Hostname: "srv-1", IP: "10.0.0.22", OS: "linux"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	schema := `{"parameters":[{"name":"mode","type":"enum","enum":["audit","enforce"],"default":"audit"}]}`
	cleanup, _, _, err := srv.scriptsStore.SyncScript("default", "windows-cleanup", "Clears old system files.", "powershell.exe",
		"Write-Output 1", schema, `{"package":"windows-cleanup","title":"Cleanup","risk":"safe","reboot":true,"timeout":3600}`, "ops")
	if err != nil {
		t.Fatal(err)
	}
	audit, _, _, err := srv.scriptsStore.SyncScript("default", "windows-audit", "Checks standards.", "powershell.exe",
		"Write-Output 2", schema, `{"package":"windows-audit","title":"Standards check","timeout":300}`, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.scriptsStore.CreateScript("default", "plain", "not a package", "powershell.exe", "x", "", "ops"); err != nil {
		t.Fatal(err)
	}

	run := func(scriptID, mode, stdout string, finish bool) *response.JobRecord {
		t.Helper()
		payload, _ := json.Marshal(response.ScriptExecPayload{ScriptID: scriptID, ScriptVersion: 1, Interpreter: "powershell.exe",
			Parameters: map[string]string{"mode": mode}, TimeoutSeconds: 3600})
		grant := &response.EndpointGrant{Version: response.GrantVersion, GrantID: "g-" + scriptID + mode, TenantID: "default",
			EndpointID: "ep-lap", ActionKind: response.ActionKindScriptExec, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
		job, err := srv.responseStore.CreateJob("default", "ep-lap", response.ActionKindScriptExec, "ops", grant, string(payload), "")
		if err != nil {
			t.Fatal(err)
		}
		if !finish {
			return job
		}
		offers, err := srv.responseStore.OfferPendingJobs("default", "ep-lap", 4, time.Minute)
		if err != nil || len(offers) != 1 {
			t.Fatalf("offer: %v %d", err, len(offers))
		}
		if err := srv.responseStore.AcknowledgeJob("default", "ep-lap", job.ID, offers[0].LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
		if err := srv.responseStore.CompleteJob("default", "ep-lap", job.ID, offers[0].LeaseID, &response.JobResult{
			JobID: job.ID, LeaseID: offers[0].LeaseID, State: response.StateSucceeded, Stdout: stdout}); err != nil {
			t.Fatal(err)
		}
		return job
	}
	run(cleanup.ID, "audit", `{"v":1,"state":"drift","reboot":false,"changed":[]}`, true)
	time.Sleep(5 * time.Millisecond)
	fixed := run(cleanup.ID, "enforce", "noise\n"+`{"v":1,"state":"fixed","reboot":true,"changed":["temp","dism"],"detail":{"freed":1}}`, true)
	time.Sleep(5 * time.Millisecond)
	broken := run(audit.ID, "audit", "garbage", true)

	get := func(ep string) []packageStatus {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.handleMaintenance(rec, httptest.NewRequest("GET", "/api/v1/maintenance?endpoint_id="+ep, nil))
		if rec.Code != 200 {
			t.Fatalf("maintenance %s: %d %s", ep, rec.Code, rec.Body.String())
		}
		var out struct{ Packages []packageStatus }
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Packages
	}
	pkgs := get("ep-lap")
	if len(pkgs) != 2 || pkgs[0].Name != "windows-audit" || pkgs[1].Name != "windows-cleanup" {
		t.Fatalf("packages: %+v", pkgs)
	}
	if l := pkgs[1].Last; l == nil || l.JobID != fixed.ID || l.State != "fixed" || !l.Reboot || l.Mode != "enforce" || len(l.Changed) != 2 || pkgs[1].Timeout != 3600 {
		t.Fatalf("cleanup latest run: %+v", l)
	}
	if l := pkgs[0].Last; l == nil || l.JobID != broken.ID || l.State != "failed" || l.Reason == "" {
		t.Fatalf("a run without a result line must read failed: %+v", l)
	}
	if got := get("ep-srv"); len(got) != 0 {
		t.Fatalf("a Linux host was offered Windows packages: %+v", got)
	}

	// An open run past its timeout plus grace has lost its result.
	open := run(audit.ID, "enforce", "", false)
	open.State = response.StateRunning
	if r := derivePackageRun(open, time.Now().Add(2*time.Hour)); r.State != "no_result" {
		t.Fatalf("stale open run: %s", r.State)
	}
	if r := derivePackageRun(open, time.Now()); r.State != "running" {
		t.Fatalf("fresh open run: %s", r.State)
	}

	page := func(query string) string {
		t.Helper()
		req := httptest.NewRequest("GET", "/console/jobs"+query, nil)
		req.AddCookie(sessionFor(t, srv, "admin", "admin"))
		rec := httptest.NewRecorder()
		srv.handleJobsPage(rec, req)
		return rec.Body.String()
	}
	body := page("?id=" + fixed.ID)
	for _, want := range []string{"Cleanup package on laptop-1", "<dt>Mode</dt><dd>enforce</dd>", "<dt>Result</dt><dd>Fixed</dd>",
		"<dt>Reboot needed</dt><dd>Yes</dd>", "<dt>Changed</dt><dd>temp, dism</dd>"} {
		if !strings.Contains(body, want) {
			t.Errorf("package job view lacks %q", want)
		}
	}
	body = page("?view=history")
	for _, want := range []string{"Cleanup package", "Needs changes", "Standards check package"} {
		if !strings.Contains(body, want) {
			t.Errorf("finished list lacks %q", want)
		}
	}
}
