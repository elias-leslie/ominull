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
	if why := lockRefusal("davion", &response.AgentTrustReport{Ceiling: "signed-scripts"}, "terminal"); why != "davion is locked to signed-scripts on the machine itself; a terminal is not allowed there" {
		t.Errorf("terminal reason: %q", why)
	}
}

// A request to a machine whose lock refuses it is refused at once with the
// reason, and no owner approval is asked for; other machines still ask.
func TestLockedMachineRefusedBeforeAsking(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
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
	srv.trust.reports["win-free"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Profile: "respond"}}
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
	pending := func() int {
		return len(auth.PendingApprovals())
	}

	for _, tc := range []struct{ path, body, want string }{
		{"/api/v1/terminal/sessions", `{"endpoint_id":"win-locked","program":"powershell.exe"}`, "win-locked is locked to signed-scripts on the machine itself; a terminal is not allowed there"},
		{"/api/v1/maintenance/script", `{"endpoint_ids":["win-free","win-ha"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`, "takes only Nightshift-signed scripts"},
		{"/api/v1/maintenance/script", `{"endpoint_ids":["win-locked"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`, "has no host authority pinned"},
	} {
		code, m := call(tc.path, tc.body)
		msg, _ := m["error"].(string)
		if code != http.StatusForbidden || !strings.Contains(msg, tc.want) {
			t.Fatalf("%s %s: %d %v", tc.path, tc.body, code, m)
		}
	}
	if n := pending(); n != 0 {
		t.Fatalf("a locked machine cost the owner %d approval asks", n)
	}
	// Unlocked machines still ask the owner.
	if code, m := call("/api/v1/maintenance/script", `{"endpoint_ids":["win-free"],"shell":"powershell","source":"Write-Output 1","name":"t","reason":"test"}`); code != http.StatusAccepted {
		t.Fatalf("free machine: %d %v", code, m)
	}
	if n := pending(); n != 1 {
		t.Fatalf("pending after the free machine: %d", n)
	}
}
