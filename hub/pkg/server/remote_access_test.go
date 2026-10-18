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

// Remote access off: on at once (closing open sessions), refuses terminal and
// screen before anyone is asked, and only the owner's tap switches it back.
func TestServer_RemoteAccessOff(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	seedScreenEndpoint(t, srv, "win-ra", `{"isolate":true,"screen":{"input":true}}`)
	seedScreenEndpoint(t, srv, "win-free", `{"isolate":true,"screen":{"input":true}}`)
	jwt, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: hubauth.RoleAdmin, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwt) }
	client := &http.Client{}
	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		bearer(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	if code, m := call(http.MethodGet, "/api/v1/remote-access/settings?endpoint_id=win-ra", ""); code != 200 || m["off"] != false {
		t.Fatalf("default: %d %v", code, m)
	}
	// A live session on the machine is closed when remote access goes off.
	g := &response.EndpointGrant{Version: response.GrantVersion, GrantID: "g-ra", TenantID: "default", EndpointID: "win-ra",
		ActionKind: response.ActionKindTerminalSession, ActionDigest: strings.Repeat("0", 64), OperatorID: "admin",
		ResponseSessionID: "rs", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	live, err := srv.terminalMgr.CreateSession("default", "win-ra", "admin", "powershell.exe", g)
	if err != nil {
		t.Fatal(err)
	}
	code, m := call(http.MethodPut, "/api/v1/remote-access/settings", `{"endpoint_id":"win-ra","off":true}`)
	if code != 200 || m["changed"] != true || m["approval_id"] != nil || m["sessions_closed"] != float64(1) {
		t.Fatalf("off: %d %v", code, m)
	}
	if ended, _, reason, _, _ := srv.terminalMgr.SessionEnd(live.SessionID); !ended || reason != "remote access switched off" {
		t.Fatalf("live session not closed: %v %q", ended, reason)
	}
	if _, m := call(http.MethodGet, "/api/v1/remote-access/settings", ""); len(m["off"].([]interface{})) != 1 {
		t.Fatalf("fleet view: %v", m)
	}

	// Refused before any approval is asked for, terminal and screen alike.
	for path, body := range map[string]string{
		"/api/v1/screen/sessions":   `{"endpoint_id":"win-ra","mode":"view"}`,
		"/api/v1/terminal/sessions": `{"endpoint_id":"win-ra","program":"powershell.exe"}`,
	} {
		if code, m := call(http.MethodPost, path, body); code != http.StatusForbidden || !strings.Contains(m["error"].(string), "switched off") {
			t.Fatalf("%s: %d %v", path, code, m)
		}
	}
	// Other machines are untouched.
	if code, _ := call(http.MethodPost, "/api/v1/screen/sessions", `{"endpoint_id":"win-free","mode":"view"}`); code != http.StatusAccepted {
		t.Fatalf("other machine: %d", code)
	}

	// Switching it back on loosens: the owner's tap first.
	code, m = call(http.MethodPut, "/api/v1/remote-access/settings", `{"endpoint_id":"win-ra","off":false}`)
	if code != http.StatusAccepted || m["approval_id"] == nil {
		t.Fatalf("on: %d %v", code, m)
	}
	view, _ := auth.GetApproval(m["approval_id"].(string), "")
	if view.Action != "Allow remote terminal and screen again" || !strings.Contains(view.Summary, "allowed again on endpoint win-ra") {
		t.Fatalf("approval %q %q", view.Action, view.Summary)
	}
	if !srv.remoteAccessOff("win-ra") {
		t.Fatal("switched back on before the owner approved")
	}
	resp := doApproved(t, srv, client, http.MethodPut, ts.URL+"/api/v1/remote-access/settings", `{"endpoint_id":"win-ra","off":false}`, bearer)
	resp.Body.Close()
	if resp.StatusCode != 200 || srv.remoteAccessOff("win-ra") {
		t.Fatalf("on approved: %d", resp.StatusCode)
	}

	// An unreadable row refuses everywhere until rewritten.
	_ = srv.store.SetSetting(remoteAccessKey, "{broken")
	if !srv.remoteAccessOff("win-free") {
		t.Fatal("unreadable settings must refuse")
	}
	if code, _ := call(http.MethodPut, "/api/v1/remote-access/settings", `{"off":true}`); code != http.StatusBadRequest {
		t.Fatalf("no endpoint: %d", code)
	}
}
