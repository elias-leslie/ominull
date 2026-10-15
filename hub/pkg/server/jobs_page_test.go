package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func TestJobsPage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	get := func(query, role string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", "/console/jobs"+query, nil)
		if role != "" {
			req.AddCookie(sessionFor(t, srv, role, role))
		}
		rec := httptest.NewRecorder()
		srv.handleJobsPage(rec, req)
		return rec
	}

	srv.responseEnabled = false
	if body := get("", "admin").Body.String(); !strings.Contains(body, "Remote response is turned off") {
		t.Error("a hub without remote response lists jobs")
	}
	srv.responseEnabled = true

	if rec := get("", ""); rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("no session: %d %q, want a redirect to the console sign-in", rec.Code, rec.Header().Get("Location"))
	}

	for _, ep := range []storage.Endpoint{
		{ID: "ep-web", TenantID: "default", Hostname: "web-01", IP: "10.0.0.11", OS: "linux"},
		{ID: "ep-db", TenantID: "default", Hostname: "db-01", IP: "10.0.0.12", OS: "linux"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	create := func(endpoint string, kind response.ActionKind) *response.JobRecord {
		t.Helper()
		grant := &response.EndpointGrant{
			Version: response.GrantVersion, GrantID: "g-" + endpoint + string(kind), TenantID: "default", EndpointID: endpoint,
			ActionKind: kind, OperatorID: "ops@example.invalid",
			IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		job, err := srv.responseStore.CreateJob("default", endpoint, kind, "ops@example.invalid", grant, "{}", "")
		if err != nil {
			t.Fatalf("CreateJob: %v", err)
		}
		return job
	}
	queued := create("ep-web", response.ActionKindForensicCollect)
	finished := create("ep-db", response.ActionKindScriptExec)
	offers, err := srv.responseStore.OfferPendingJobs("default", "ep-db", 4, time.Minute)
	if err != nil || len(offers) != 1 {
		t.Fatalf("offer: %v %d", err, len(offers))
	}
	if err := srv.responseStore.AcknowledgeJob("default", "ep-db", finished.ID, offers[0].LeaseID, true, ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.responseStore.CompleteJob("default", "ep-db", finished.ID, offers[0].LeaseID, &response.JobResult{
		JobID: finished.ID, LeaseID: offers[0].LeaseID, State: response.StateFailed, ExitCode: 3, DurationMs: 1250,
		Stdout: "disk <full>", Stderr: "df: /mnt: denied\n",
	}); err != nil {
		t.Fatal(err)
	}

	body := get("", "admin").Body.String()
	for _, want := range []string{
		`href="/console/jobs?id=` + queued.ID + `"`, "Evidence collection", "web-01", "Waiting for the agent",
		`aria-current="page">In flight <span class="dim-3">1</span>`, `Finished <span class="dim-3">1</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("in-flight list lacks %q", want)
		}
	}
	if strings.Contains(body, finished.ID) || strings.Contains(body, "jobs.js") {
		t.Error("the in-flight list shows a finished job or loads the job script")
	}
	if body := get("?view=history", "admin").Body.String(); !strings.Contains(body, finished.ID) || strings.Contains(body, queued.ID) {
		t.Error("the finished list does not hold exactly the finished job")
	}

	body = get("?id="+finished.ID, "admin").Body.String()
	for _, want := range []string{
		"Script on db-01", `data-state="crit"`, "Failed", "<dt>Exit code</dt><dd>3</dd>", "<dt>Took</dt><dd>1.25s</dd>",
		"disk &lt;full&gt;", "df: /mnt: denied</pre>", "What happened", "agent on db-01", `src="/jobs.js?v=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("finished job view lacks %q", want)
		}
	}
	for _, internal := range []string{"leased to", "completed state=", "job accepted by endpoint", "endpoint:ep-db"} {
		if strings.Contains(body, internal) {
			t.Errorf("job history shows the internal note %q", internal)
		}
	}
	if strings.Contains(body, `id="job-cancel"`) || strings.Contains(body, `data-open="1"`) {
		t.Error("a finished job offers cancel or keeps polling")
	}

	body = get("?id="+queued.ID, "admin").Body.String()
	for _, want := range []string{`id="job-cancel"`, `data-open="1"`, "closes without running", "Nothing yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("queued job view lacks %q", want)
		}
	}
	// Offered but not acked is still withdrawn outright.
	if _, err := srv.responseStore.OfferPendingJobs("default", "ep-web", 4, time.Minute); err != nil {
		t.Fatal(err)
	}
	body = get("?id="+queued.ID, "admin").Body.String()
	for _, want := range []string{"Offered to the agent", "closes without running", "hub"} {
		if !strings.Contains(body, want) {
			t.Errorf("offered job view lacks %q", want)
		}
	}
	if body := get("?id="+queued.ID, "viewer").Body.String(); strings.Contains(body, `id="job-cancel"`) {
		t.Error("a read-only role is offered cancel")
	}
	if body := get("?id=nope", "admin").Body.String(); !strings.Contains(body, "No response job with ID \u201cnope\u201d.") || strings.Contains(body, "jobs.js") {
		t.Error("an unknown job id is not explained")
	}
}
