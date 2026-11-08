package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/posture"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func postureOf(t *testing.T, srv *Server, query string) postureView {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, adminRequest(http.MethodGet, "/api/v1/posture"+query, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("posture: %d %s", w.Code, w.Body.String())
	}
	var v postureView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func postureControl(t *testing.T, v postureView, id string) postureControlView {
	t.Helper()
	for _, p := range v.Packs {
		for _, c := range p.Controls {
			if c.ID == id {
				return c
			}
		}
	}
	t.Fatalf("no control %s in the report", id)
	return postureControlView{}
}

func resultOn(t *testing.T, c postureControlView, endpoint string) postureResult {
	t.Helper()
	for _, r := range c.Results {
		if r.EndpointID == endpoint {
			return r
		}
	}
	t.Fatalf("%s has no result on %s: %+v", c.ID, endpoint, c.Results)
	return postureResult{}
}

// One Windows machine with a finished baseline run, one Linux machine with none.
func postureFixture(t *testing.T) *Server {
	t.Helper()
	srv, store := setupTestServer(t)
	t.Cleanup(func() { store.Close() })
	srv.responseEnabled = true
	authorityOf(t, srv)
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "windows-lap", TenantID: "default", Hostname: "lap", OS: "Windows 11 Home", Status: "online", LastSeenAt: now},
		{ID: "linux-box", TenantID: "default", Hostname: "box", OS: "Ubuntu 24.04 Linux", Status: "online", LastSeenAt: now},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	syncRealPackage(t, srv, "security-baseline.ps1")
	w := postAdmin(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["windows-lap"],"packages":["windows-security-baseline"],"mode":"audit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	finishJobsWith(t, srv, "windows-lap", `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[`+
		`{"id":"auth.wdigest_off","expected":"0","actual":"1","state":"fail","risk":"safe"},`+
		`{"id":"remote.rdp_protected","expected":"NLA on","actual":"NLA on","state":"pass","risk":"safe"},`+
		`{"id":"audit.records_forwarded","expected":"forwarded","actual":"workstation","state":"na","risk":"safe"}]}}`)
	return srv
}

// A run's controls become pack answers; a machine with no result is unknown and
// unknown stays out of the percent; a Linux box gets no Windows-only control.
func TestPostureScoresFromRuns(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	v := postureOf(t, srv, "")
	if r := resultOn(t, postureControl(t, v, "auth.wdigest_off"), "windows-lap"); r.State != posture.Fail || r.Actual != "1" || r.JobID == "" || r.At == nil {
		t.Fatalf("failing control: %+v", r)
	}
	if r := resultOn(t, postureControl(t, v, "remote.rdp_protected"), "windows-lap"); r.State != posture.Pass {
		t.Fatalf("passing control: %+v", r)
	}
	if r := resultOn(t, postureControl(t, v, "audit.records_forwarded"), "windows-lap"); r.State != posture.NA {
		t.Fatalf("na control: %+v", r)
	}
	if r := resultOn(t, postureControl(t, v, "account.admin_separation"), "windows-lap"); r.State != posture.Unknown {
		t.Fatalf("the run did not report this one: %+v", r)
	}
	for _, c := range []string{"auth.wdigest_off", "remote.rdp_protected"} {
		for _, r := range postureControl(t, v, c).Results {
			if r.EndpointID == "linux-box" {
				t.Fatalf("%s is Windows only: %+v", c, r)
			}
		}
	}
	if r := resultOn(t, postureControl(t, v, "ssh.password_auth_off"), "linux-box"); r.State != posture.Unknown {
		t.Fatalf("nothing ran on the Linux box: %+v", r)
	}
	for _, p := range v.Packs {
		if p.ID != "disa-windows-stig" {
			continue
		}
		if p.Score.Pass != 0 || p.Score.Fail != 1 || p.Score.Percent == nil || *p.Score.Percent != 0 {
			t.Fatalf("score: %+v", p.Score)
		}
	}
	one := postureOf(t, srv, "?endpoint_id=linux-box")
	for _, p := range one.Packs {
		for _, c := range p.Controls {
			if c.Fleet {
				t.Fatalf("a machine's view has no fleet controls: %s", c.ID)
			}
			for _, r := range c.Results {
				if r.EndpointID != "linux-box" {
					t.Fatalf("another machine in the view: %+v", r)
				}
			}
		}
	}
}

func TestPostureAcceptedRiskAndFinding(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	w := adminPut(srv, "/api/v1/maintenance/settings", `{"endpoint_id":"windows-lap","accept_risk":"auth.wdigest_off","accepted":true,"reason":"old app"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	v := postureOf(t, srv, "")
	r := resultOn(t, postureControl(t, v, "auth.wdigest_off"), "windows-lap")
	if r.State != posture.Accepted || r.Reason != "old app" {
		t.Fatalf("accepted: %+v", r)
	}
	f, err := srv.postureFinding(time.Now().UTC())
	if err != nil || f.FindingInfo["uid"] != "ominull.posture" {
		t.Fatalf("finding: %v %+v", err, f)
	}
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved {
		t.Fatalf("no critical control fails, so it stays a note: %+v", f)
	}
}

// A critical control failing raises the row to the board, never higher.
func TestPostureFindingCritical(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	sc, _ := syncRealPackage(t, srv, "linux/security-baseline.sh")
	sv, err := srv.scriptsStore.GetScriptVersion("default", sc.ID, sc.LatestVersion)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"endpoint_id": "linux-box", "package": "linux-security-baseline", "sha256": sv.DigestSHA256, "mode": "audit",
		"stdout": `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[{"id":"ssh.protocol_1_off","expected":"off","actual":"on","state":"fail","risk":"safe"}]}}`})
	if w := postAdmin(srv, "/api/v1/maintenance/host-run", string(raw)); w.Code != http.StatusOK {
		t.Fatalf("record: %d %s", w.Code, w.Body.String())
	}
	f, err := srv.postureFinding(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevMedium || f.StatusID != ocsfStatusNew || !strings.Contains(f.Message, "on box") {
		t.Fatalf("critical: %+v", f)
	}
}

func TestPostureAttestLapses(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	if r := postureControl(t, postureOf(t, srv, ""), "ir.console_mfa").Results[0]; r.State != posture.Unknown {
		t.Fatalf("nobody confirmed: %+v", r)
	}
	for _, bad := range []string{
		`{"control":"auth.wdigest_off","state":"pass","note":"x","days":5}`,
		`{"control":"ir.console_mfa","state":"maybe","note":"x","days":5}`,
		`{"control":"ir.console_mfa","state":"pass","note":"","days":5}`,
		`{"control":"ir.console_mfa","state":"pass","note":"x","days":0}`,
	} {
		if w := postAdmin(srv, "/api/v1/posture/attest", bad); w.Code < 400 {
			t.Fatalf("%s: %d", bad, w.Code)
		}
	}
	if w := postAdmin(srv, "/api/v1/posture/attest", `{"control":"ir.console_mfa","state":"pass","note":"owner confirmed","days":90}`); w.Code != http.StatusOK {
		t.Fatalf("attest: %d %s", w.Code, w.Body.String())
	}
	if r := postureControl(t, postureOf(t, srv, ""), "ir.console_mfa").Results[0]; r.State != posture.Pass || r.Actual != "owner confirmed" {
		t.Fatalf("confirmed: %+v", r)
	}
	later, err := srv.postureReport("", "", time.Now().UTC().AddDate(0, 0, 91))
	if err != nil {
		t.Fatal(err)
	}
	if r := postureControl(t, later, "ir.console_mfa").Results[0]; r.State != posture.Unknown {
		t.Fatalf("a lapsed confirmation is unknown: %+v", r)
	}
	if w := postAdmin(srv, "/api/v1/posture/attest", `{"control":"ir.console_mfa","state":"clear"}`); w.Code != http.StatusOK {
		t.Fatalf("clear: %d", w.Code)
	}
	if r := postureControl(t, postureOf(t, srv, ""), "ir.console_mfa").Results[0]; r.State != posture.Unknown {
		t.Fatalf("cleared: %+v", r)
	}
}

// The packs are data: a replacement takes over, a bad one is refused, and
// removing it goes back to the shipped rows.
func TestPosturePacksAreData(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	body := `{"stale_days":7,"packs":[{"id":"mine","title":"Mine","controls":[{"id":"my.wdigest","title":"WDigest","severity":"high",` +
		`"evidence":[{"platforms":["windows"],"package":"windows-security-baseline","control":"auth.wdigest_off"}]}]}]}`
	if w := adminPut(srv, "/api/v1/posture/packs", body); w.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", w.Code, w.Body.String())
	}
	v := postureOf(t, srv, "")
	if !v.Saved || len(v.Packs) != 1 || v.Packs[0].ID != "mine" {
		t.Fatalf("replaced: %+v", v)
	}
	if r := resultOn(t, postureControl(t, v, "my.wdigest"), "windows-lap"); r.State != posture.Fail {
		t.Fatalf("a new row reads the same evidence: %+v", r)
	}
	if w := adminPut(srv, "/api/v1/posture/packs", `{"packs":[{"id":"mine"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad catalog: %d", w.Code)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, adminRequest(http.MethodDelete, "/api/v1/posture/packs", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	if v := postureOf(t, srv, ""); v.Saved || len(v.Packs) < 5 {
		t.Fatalf("back to shipped: %+v", v.Packs)
	}
}

func TestPostureDownloadNamesAFile(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, adminRequest(http.MethodGet, "/api/v1/posture?download=1", ""))
	if !strings.Contains(w.Header().Get("Content-Disposition"), "ominull-posture-") {
		t.Fatalf("headers: %v", w.Header())
	}
}

// A root-access run lands in the same run records, and is refused unless what
// ran is the library's current version on a machine it fits.
func TestHostRunRecordsAsOrdinaryRun(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	sc, _ := syncRealPackage(t, srv, "linux/security-baseline.sh")
	sv, err := srv.scriptsStore.GetScriptVersion("default", sc.ID, sc.LatestVersion)
	if err != nil {
		t.Fatal(err)
	}
	out := `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[` +
		`{"id":"ssh.password_auth_off","expected":"no","actual":"yes","state":"fail","risk":"safe"}]}}`
	post := func(ep, pkg, sum, mode string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"endpoint_id": ep, "package": pkg, "sha256": sum, "mode": mode, "stdout": out})
		return postAdmin(srv, "/api/v1/maintenance/host-run", string(raw))
	}
	for name, c := range map[string]struct {
		w    *httptest.ResponseRecorder
		code int
	}{
		"no machine":  {post("nope", "linux-security-baseline", sv.DigestSHA256, "audit"), http.StatusNotFound},
		"no package":  {post("linux-box", "nope", sv.DigestSHA256, "audit"), http.StatusNotFound},
		"wrong OS":    {post("windows-lap", "linux-security-baseline", sv.DigestSHA256, "audit"), http.StatusBadRequest},
		"not current": {post("linux-box", "linux-security-baseline", strings.Repeat("0", 64), "audit"), http.StatusConflict},
		"enforce":     {post("linux-box", "linux-security-baseline", sv.DigestSHA256, "enforce"), http.StatusBadRequest},
	} {
		if c.w.Code != c.code {
			t.Errorf("%s: %d %s", name, c.w.Code, c.w.Body.String())
		}
	}
	if w := post("linux-box", "linux-security-baseline", sv.DigestSHA256, "audit"); w.Code != http.StatusOK {
		t.Fatalf("record: %d %s", w.Code, w.Body.String())
	}
	if r := resultOn(t, postureControl(t, postureOf(t, srv, ""), "ssh.password_auth_off"), "linux-box"); r.State != posture.Fail || r.Actual != "yes" {
		t.Fatalf("the run reads back: %+v", r)
	}
	jobs, err := srv.responseStore.ScriptJobs("default", "linux-box", sc.ID, 5)
	if err != nil || len(jobs) != 1 || jobs[0].State != response.StateSucceeded || jobs[0].AuthorizationGrantID != "" || !strings.HasPrefix(jobs[0].RequestedBy, "root access") {
		t.Fatalf("job: %v %+v", err, jobs)
	}
	offers, err := srv.responseStore.OfferPendingJobs("default", "linux-box", 5, time.Minute)
	if err != nil || len(offers) != 0 {
		t.Fatalf("a recorded run is never offered to the agent: %v %+v", err, offers)
	}
}

func TestPostureRoutesRefuseOtherRoles(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	for _, c := range []struct{ method, path, body, role string }{
		{http.MethodGet, "/api/v1/posture", "", "tenant"},
		{http.MethodGet, "/api/v1/posture/packs", "", "tenant"},
		{http.MethodPut, "/api/v1/posture/packs", `{}`, "operator"},
		{http.MethodDelete, "/api/v1/posture/packs", "", "operator"},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("X-Role", c.role)
		h := map[string]http.HandlerFunc{"/api/v1/posture": srv.handlePosture, "/api/v1/posture/packs": srv.handlePosturePacks}[c.path]
		h(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s as %s: %d", c.method, c.path, c.role, w.Code)
		}
	}
	for _, h := range []http.HandlerFunc{requireAdmin(srv.handleHostRun), requireAdmin(srv.handlePostureAttest)} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.Header.Set("X-Role", "operator")
		h(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("an admin route let an operator in: %d", w.Code)
		}
	}
}

// What the hub answers itself, machine by machine.
func TestPostureHubAnswers(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	report := func(rep response.AgentTrustReport) {
		srv.trust.mu.Lock()
		srv.trust.init()
		srv.trust.reports["linux-box"] = trustReportSeen{report: rep, at: time.Now().UTC()}
		srv.trust.mu.Unlock()
	}
	isolation := func() postureResult {
		return resultOn(t, postureControl(t, postureOf(t, srv, ""), "isolation.ready"), "linux-box")
	}
	if r := isolation(); r.State != posture.Unknown {
		t.Fatalf("no report yet: %+v", r)
	}
	for _, c := range []struct {
		rep  response.AgentTrustReport
		want string
	}{
		{response.AgentTrustReport{Keys: "pinned", Profile: "respond"}, posture.Pass},
		{response.AgentTrustReport{Keys: "unpinned", Profile: "respond"}, posture.Fail},
		{response.AgentTrustReport{Keys: "pinned", Profile: "monitor"}, posture.Fail},
		{response.AgentTrustReport{Keys: "pinned", Profile: "respond", Ceiling: "monitor"}, posture.NA},
		{response.AgentTrustReport{Keys: "pinned", Profile: "respond", Ceiling: "monitor-signed-scripts"}, posture.NA},
		{response.AgentTrustReport{Keys: "pinned", Profile: "respond", Ceiling: "made-up-level"}, posture.NA},
		{response.AgentTrustReport{Keys: "pinned", Profile: "respond", Ceiling: "isolate"}, posture.Pass},
	} {
		report(c.rep)
		if r := isolation(); r.State != c.want {
			t.Errorf("%+v: got %+v", c.rep, r)
		}
	}
	report(response.AgentTrustReport{Keys: "unpinned", Profile: "respond"})
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"endpoint_id":"linux-box","accept_risk":"hub.isolation_ready","accepted":true,"reason":"lab"}`); w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	if r := isolation(); r.State != posture.Accepted || r.Reason != "lab" || r.Key != "hub.isolation_ready" {
		t.Fatalf("accepted hub answer: %+v", r)
	}
	if r := resultOn(t, postureControl(t, postureOf(t, srv, ""), "ir.agents_reporting"), "linux-box"); r.State != posture.Pass {
		t.Fatalf("seen just now: %+v", r)
	}
}

// Old answers: stale on the dot, and a baseline that is too old fails only on a
// machine that could have answered; an unrecognized OS still gets hub answers.
func TestPostureOldAnswers(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	syncRealPackage(t, srv, "audit.ps1")
	w := postAdmin(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["windows-lap"],"packages":["windows-audit"],"mode":"audit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	finishJobsWith(t, srv, "windows-lap", `{"v":1,"state":"ok","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[{"id":"defender","state":"pass"}]}}`)
	now := time.Now().UTC()
	baseline := func(at time.Time) postureResult {
		ep, err := srv.store.GetEndpoint("windows-lap")
		if err != nil {
			t.Fatal(err)
		}
		ep.LastSeenAt = at
		if err := srv.store.UpsertEndpoint(*ep); err != nil {
			t.Fatal(err)
		}
		v, err := srv.postureReport("", "", now.AddDate(0, 0, 20))
		if err != nil {
			t.Fatal(err)
		}
		return resultOn(t, postureControl(t, v, "baseline.recent"), "windows-lap")
	}
	if r := baseline(now.AddDate(0, 0, 20)); r.State != posture.Fail {
		t.Fatalf("online, and its checks are 20 days old: %+v", r)
	}
	if r := baseline(now); r.State != posture.Unknown {
		t.Fatalf("offline for 20 days cannot answer: %+v", r)
	}
	v, err := srv.postureReport("", "", now.AddDate(0, 0, 20))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultOn(t, postureControl(t, v, "auth.wdigest_off"), "windows-lap"); !r.Stale || r.State != posture.Fail {
		t.Fatalf("an old answer is marked and still counts: %+v", r)
	}
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: "odd-os", TenantID: "default", Hostname: "odd", OS: "", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	v = postureOf(t, srv, "")
	if r := resultOn(t, postureControl(t, v, "isolation.ready"), "odd-os"); r.State != posture.Unknown {
		t.Fatalf("an unrecognized OS keeps the hub's answers: %+v", r)
	}
	if r := resultOn(t, postureControl(t, v, "baseline.recent"), "odd-os"); r.State != posture.Unknown {
		t.Fatalf("baseline on an unrecognized OS: %+v", r)
	}
}

func TestPostureFleetAnswers(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	e := &postureEval{s: srv, now: time.Now().UTC()}
	ev := posture.Evidence{Params: map[string]int{"alerts_days": 90, "flows_days": 30, "audit_days": 365}}
	if r := e.retentionResult(ev); r.State != posture.Unknown {
		t.Fatalf("no sweep yet: %+v", r)
	}
	if r := e.drillResult(posture.Evidence{Params: map[string]int{"max_age_days": 8}}); r.State != posture.Fail || r.Actual != "never ran" {
		t.Fatalf("no drill: %+v", r)
	}
}

// A run that failed on the machine reads as a failed job, and its controls count
// for nothing without a report line.
func TestHostRunFailedExit(t *testing.T) {
	t.Parallel()
	srv := postureFixture(t)
	sc, _ := syncRealPackage(t, srv, "linux/security-baseline.sh")
	sv, err := srv.scriptsStore.GetScriptVersion("default", sc.ID, sc.LatestVersion)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"endpoint_id": "linux-box", "package": "linux-security-baseline", "sha256": sv.DigestSHA256, "mode": "audit",
		"stdout": `{"v":1,"state":"failed","reboot":false,"changed":[],"detail":{"reason":"bad"}}`, "exit_code": 1})
	if w := postAdmin(srv, "/api/v1/maintenance/host-run", string(raw)); w.Code != http.StatusOK {
		t.Fatalf("record: %d %s", w.Code, w.Body.String())
	}
	jobs, err := srv.responseStore.ScriptJobs("default", "linux-box", sc.ID, 5)
	if err != nil || len(jobs) != 1 || jobs[0].State != response.StateFailed {
		t.Fatalf("job: %v %+v", err, jobs)
	}
}
