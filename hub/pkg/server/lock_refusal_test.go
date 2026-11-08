package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

// The lock table matches the agent's: the terminal only under no lock,
// respond or engagement; hub-signed scripts only under no lock or engagement,
// never where a host authority is pinned.
func TestLockRefusalTable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ceiling  string
		hostAuth bool
		allowed  string // capabilities allowed, of terminal/screen/script
	}{
		{"", false, "terminal script"},
		{"engagement", false, "terminal script"},
		{"respond", false, "terminal"},
		{"isolate", false, ""},
		{"monitor", false, ""},
		{"signed-scripts", false, ""},
		{"signed-scripts", true, ""},
		{"monitor-signed-scripts", true, ""},
		{"", true, "terminal"},
		{"some-future-level", false, ""},
	} {
		for _, c := range []string{"terminal", "script"} {
			why := lockRefusal("box", &response.AgentTrustReport{Ceiling: tc.ceiling, HostAuthority: tc.hostAuth}, c)
			want := strings.Contains(tc.allowed, c)
			if (why == "") != want {
				t.Errorf("ceiling %q host authority %v %s: refusal %q, want allowed %v", tc.ceiling, tc.hostAuth, c, why, want)
			}
			if why != "" && !strings.HasPrefix(why, "box ") {
				t.Errorf("reason does not name the machine: %q", why)
			}
		}
	}
	if why := lockRefusal("workstation", &response.AgentTrustReport{Ceiling: "signed-scripts"}, "terminal"); why != "workstation is locked to signed-scripts on the machine itself; a terminal is not allowed there" {
		t.Errorf("terminal reason: %q", why)
	}
}

// A request to a machine whose lock refuses it is refused at once with the
// reason and nothing is signed; an unlocked machine is authorized at once.
func TestLockedMachineRefusedBeforeSigning(t *testing.T) {
	t.Parallel()
	srv, store, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	seedScreenEndpoint(t, srv, "win-locked", `{"isolate":true,"screen":{"input":true}}`)
	seedScreenEndpoint(t, srv, "win-ha", `{"isolate":true,"screen":{"input":true}}`)
	seedScreenEndpoint(t, srv, "win-free", `{"isolate":true,"screen":{"input":true}}`)
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["win-locked"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Ceiling: "signed-scripts", Profile: "engagement"}}
	srv.trust.reports["win-ha"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Profile: "engagement", HostAuthority: true}}
	srv.trust.reports["win-free"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Profile: "engagement"}}
	srv.trust.mu.Unlock()
	jwt, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: hubauth.RoleAdmin, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	call := func(path, body string) (int, map[string]interface{}) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	authorizedActions := func() int {
		n := 0
		logs, _ := store.ListAuditLogs("", 200)
		for _, l := range logs {
			if l.Action == "ACTION_AUTHORIZED" {
				n++
			}
		}
		return n
	}

	for _, tc := range []struct{ path, body, want string }{
		{"/api/v1/terminal/sessions", `{"endpoint_id":"win-locked","program":"powershell.exe"}`, "win-locked is locked to signed-scripts on the machine itself; a terminal is not allowed there"},
		{"/api/v1/maintenance/script", `{"endpoint_ids":["win-free","win-ha"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`, "takes only scripts signed by the key pinned"},
		{"/api/v1/maintenance/script", `{"endpoint_ids":["win-locked"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`, "has no host authority pinned"},
		// The console's one-script run, not only maintenance: queued, the agent
		// refuses every offer and the job fails 30 offers later as never taken.
		{"/api/v1/scripts/run", `{"script_id":"s","version":1,"endpoint_id":"win-ha"}`, "takes only scripts signed by the key pinned"},
	} {
		code, m := call(tc.path, tc.body)
		msg, _ := m["error"].(string)
		if code != http.StatusForbidden || !strings.Contains(msg, tc.want) {
			t.Fatalf("%s %s: %d %v", tc.path, tc.body, code, m)
		}
	}
	if n := authorizedActions(); n != 0 {
		t.Fatalf("a locked machine was authorized %d times", n)
	}
	// An unlocked machine is authorized on the first request.
	if code, m := call("/api/v1/maintenance/script", `{"endpoint_ids":["win-free"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`); code != http.StatusCreated {
		t.Fatalf("free machine: %d %v", code, m)
	}
	if n := authorizedActions(); n != 1 {
		t.Fatalf("authorizations after the free machine: %d", n)
	}
}

// A machine on a profile without the right drops the offer in silence, so the
// hub says so first. A manifest the hub has just signed counts over the report.
func TestProfileWithoutScriptsIsRefused(t *testing.T) {
	t.Parallel()
	if why := lockRefusal("box", &response.AgentTrustReport{Profile: "respond"}, "script"); !strings.Contains(why, "respond permission profile") {
		t.Fatalf("respond and scripts: %q", why)
	}
	for _, profile := range []string{"", "engagement", "monitor-scripts", "not-a-profile"} {
		if why := lockRefusal("box", &response.AgentTrustReport{Profile: profile}, "script"); why != "" {
			t.Fatalf("%q and scripts: %q", profile, why)
		}
	}
	if why := lockRefusal("box", &response.AgentTrustReport{Profile: "respond"}, "terminal"); why != "" {
		t.Fatalf("respond and a terminal: %q", why)
	}
	// A reason a profile change would not cure comes first.
	if why := lockRefusal("box", &response.AgentTrustReport{Profile: "respond", HostAuthority: true}, "script"); !strings.Contains(why, "over SSH") {
		t.Fatalf("host authority on respond: %q", why)
	}
	if why := lockRefusal("box", &response.AgentTrustReport{Profile: "respond", Ceiling: "signed-scripts"}, "script"); !strings.Contains(why, "no scripts at all") {
		t.Fatalf("signed-scripts on respond: %q", why)
	}
	// A monitor-only host is held there, so nothing tells the owner to raise it.
	for _, profile := range []string{"monitor", "monitor-scripts"} {
		why := lockRefusal("box", &response.AgentTrustReport{Profile: profile}, "terminal")
		if !strings.Contains(why, profile+" permission profile") || strings.Contains(why, "change its profile") {
			t.Fatalf("%s and a terminal: %q", profile, why)
		}
	}
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	srv.trust.mu.Lock()
	srv.trust.init()
	then := time.Now().Add(-time.Hour)
	srv.trust.reports["raised"] = trustReportSeen{at: then, report: response.AgentTrustReport{V: 1, Profile: "respond", ManifestSeq: 2}}
	srv.trust.manifests["raised"] = &response.CapabilityManifest{Profile: "engagement", Seq: 3, IssuedAt: then.Add(time.Minute).Unix()}
	// The agent reported after that manifest and still holds the old one: it declined.
	srv.trust.reports["declined"] = trustReportSeen{at: then.Add(time.Hour), report: response.AgentTrustReport{V: 1, Profile: "respond", ManifestSeq: 2}}
	srv.trust.manifests["declined"] = &response.CapabilityManifest{Profile: "engagement", Seq: 3, IssuedAt: then.Add(time.Minute).Unix()}
	// A hub restored from backup holds an older manifest than the agent.
	srv.trust.reports["ahead"] = trustReportSeen{at: then, report: response.AgentTrustReport{V: 1, Profile: "engagement", ManifestSeq: 5}}
	srv.trust.manifests["ahead"] = &response.CapabilityManifest{Profile: "respond", Seq: 3, IssuedAt: then.Add(time.Minute).Unix()}
	// Lowered: refused at once, while the agent catches up.
	srv.trust.reports["lowered"] = trustReportSeen{at: then, report: response.AgentTrustReport{V: 1, Profile: "engagement", ManifestSeq: 2}}
	srv.trust.manifests["lowered"] = &response.CapabilityManifest{Profile: "respond", Seq: 3, IssuedAt: then.Add(time.Minute).Unix()}
	srv.trust.mu.Unlock()
	for id, refused := range map[string]bool{"raised": false, "declined": true, "ahead": false, "lowered": true} {
		if why := srv.machineRefusal(id, "script"); (why != "") != refused {
			t.Errorf("%s: %q", id, why)
		}
	}
	// One request names every machine that would refuse it.
	rec := httptest.NewRecorder()
	if !srv.refuseLocked(rec, "script", "declined", "raised", "lowered") || rec.Code != http.StatusForbidden {
		t.Fatalf("mixed targets: %d", rec.Code)
	}
	if body := rec.Body.String(); strings.Count(body, "respond permission profile") != 2 {
		t.Fatalf("both refused machines should be named: %s", body)
	}
	if why := srv.machineRefusal("no-report", "script"); why != "" {
		t.Fatalf("a machine with no report is left to its agent: %q", why)
	}
}

// A scheduled package on a machine that takes no scripts queues nothing and
// shows up as blocked with the reason, then clears when the profile changes.
func TestScheduleBlocksOnProfileWithoutScripts(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	authorityOf(t, srv)
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	sc, _ := syncRealPackage(t, srv, "cleanup.ps1")
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-lap"] = trustReportSeen{at: now, report: response.AgentTrustReport{V: 1, Profile: "respond"}}
	srv.trust.mu.Unlock()
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"package":"windows-cleanup","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	srv.maintBlocks.kicks.Wait()
	srv.runMaintenanceSchedules(now)
	jobs := func() int {
		list, err := srv.responseStore.ScriptJobs("default", "ep-lap", sc.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if n := jobs(); n != 0 {
		t.Fatalf("a machine that refuses scripts got %d jobs", n)
	}
	blocks := srv.maintBlocks.list()
	if len(blocks) != 1 || !strings.Contains(blocks[0].Reason, "respond permission profile") || blocks[0].Endpoints[0] != "ep-lap" {
		t.Fatalf("blocks: %+v", blocks)
	}
	srv.trust.mu.Lock()
	srv.trust.manifests["ep-lap"] = &response.CapabilityManifest{Profile: "engagement", Seq: 1, IssuedAt: now.Add(time.Minute).Unix()}
	srv.trust.mu.Unlock()
	srv.runMaintenanceSchedules(now)
	if n := jobs(); n != 1 {
		t.Fatalf("after the profile change: %d jobs", n)
	}
	if blocks := srv.maintBlocks.list(); len(blocks) != 0 {
		t.Fatalf("the block should clear: %+v", blocks)
	}
}
