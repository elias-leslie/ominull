package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func TestTerminalPage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	srv.responseEnabled = false
	off := httptest.NewRecorder()
	offReq := httptest.NewRequest("GET", "/console/terminal", nil)
	offReq.AddCookie(sessionFor(t, srv, "admin", "admin"))
	srv.handleTerminalPage(off, offReq)
	if body := off.Body.String(); !strings.Contains(body, "Remote response is turned off") || strings.Contains(body, "terminal.js") {
		t.Error("a hub without remote response offers terminals")
	}
	srv.responseEnabled = true
	for _, ep := range []storage.Endpoint{
		{ID: "ep-web", TenantID: "default", Hostname: "web-01", IP: "10.0.0.11", OS: "linux"},
		{ID: "ep-win", TenantID: "default", Hostname: "win-01", IP: "10.0.0.12", OS: "windows"},
		{ID: "ep-nokey", TenantID: "default", Hostname: "nokey-01", IP: "10.0.0.13", OS: "linux", ResponseCapabilities: `{"response_key":false}`},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	open := func(endpoint, program string) string {
		t.Helper()
		grant := &response.EndpointGrant{
			Version: response.GrantVersion, GrantID: "g-" + endpoint + program, TenantID: "default", EndpointID: endpoint,
			ActionKind: response.ActionKindTerminalSession, OperatorID: "admin",
			IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		sess, err := srv.terminalMgr.CreateSession("default", endpoint, "admin", program, grant)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		return sess.SessionID
	}
	live := open("ep-web", "/bin/bash")
	for range 2 {
		open("ep-web", "/bin/sh")
	}
	ended := open("ep-win", "powershell.exe")
	if err := srv.terminalMgr.CloseSession(ended, "test"); err != nil {
		t.Fatal(err)
	}

	get := func(query, role string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/console/terminal"+query, nil)
		if role != "" {
			req.AddCookie(sessionFor(t, srv, role, role))
		}
		rec := httptest.NewRecorder()
		srv.handleTerminalPage(rec, req)
		return rec
	}

	if rec := get("", ""); rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("no session: %d %q, want a redirect to the console sign-in", rec.Code, rec.Header().Get("Location"))
	}

	rec := get("", "admin")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`href="/console/terminal?session=` + live + `"`,
		"Already has 3 terminals open",
		"been given the hub",
		`powershell.exe`,
		`src="/terminal.js?v=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	if strings.Contains(body, ended) {
		t.Error("an ended session is listed as running")
	}
	if strings.Contains(body, "xterm.js") {
		t.Error("the list loads xterm")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("page CSP %q", csp)
	}

	body = get("?session="+live+"&new=1", "admin").Body.String()
	for _, want := range []string{`id="term"`, `data-fresh="1"`, "vendor/xterm.js", `data-host="web-01"`, "&#34;session_id&#34;:&#34;" + live} {
		if !strings.Contains(body, want) {
			t.Errorf("session view lacks %q", want)
		}
	}

	if body := get("?session="+ended, "admin").Body.String(); !strings.Contains(body, "This terminal has ended") || strings.Contains(body, `id="term"`) {
		t.Error("an ended session is not reported as ended")
	}
	if body := get("?session=nope", "admin").Body.String(); !strings.Contains(body, "running anymore") {
		t.Error("an unknown session is not reported")
	}

	body = get("?session="+live, "auditor").Body.String()
	if !strings.Contains(body, "open or join them") || strings.Contains(body, "terminal.js") || strings.Contains(body, "xterm.js") {
		t.Error("an auditor gets the terminal")
	}
	if body := get("", "auditor").Body.String(); strings.Contains(body, `id="term-open"`) || strings.Contains(body, "terminal.js") {
		t.Error("an auditor gets the open form")
	}
}
