package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

func TestScreenCapabilities(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw          string
		screen, inpt bool
		norm         string
	}{
		{`{"isolate":true,"screen":{"input":true}}`, true, true, `{"isolate":true,"collect":false,"screen":{"input":true}}`},
		{`{"isolate":true,"screen":{"input":false}}`, true, false, `{"isolate":true,"collect":false,"screen":{"input":false}}`},
		{`{"isolate":true,"screen":true}`, true, false, `{"isolate":true,"collect":false,"screen":{"input":false}}`},
		{`{"isolate":true,"screen":false}`, false, false, `{"isolate":true,"collect":false}`},
		{`{"isolate":true,"screen":"yes"}`, false, false, `{"isolate":true,"collect":false}`},
		{`{"isolate":true}`, false, false, `{"isolate":true,"collect":false}`},
	} {
		c := parseResponseCapabilities(tc.raw)
		if c.Screen != tc.screen || c.ScreenInput != tc.inpt {
			t.Errorf("%s parsed screen=%v input=%v", tc.raw, c.Screen, c.ScreenInput)
		}
		got := normalizeResponseCapabilities([]byte(tc.raw))
		if got != tc.norm {
			t.Errorf("%s normalized to %s, want %s", tc.raw, got, tc.norm)
		}
		if again := normalizeResponseCapabilities([]byte(got)); again != got {
			t.Errorf("%s does not round-trip: %s", got, again)
		}
	}
	for _, tc := range []struct {
		raw     string
		control bool
		why     string
	}{
		{`{"isolate":true}`, false, "reports no screen capability"},
		{``, false, "reports no screen capability"},
		{`{"screen":{"input":true},"response_key":false}`, false, "no tenant response key pinned"},
		{`{"screen":{"input":false}}`, true, "ask for a view-only session"},
		{`{"screen":{"input":false}}`, false, ""},
		{`{"screen":{"input":true}}`, true, ""},
	} {
		ok, why := parseResponseCapabilities(tc.raw).screenAvailable(tc.control)
		if ok != (tc.why == "") || !strings.Contains(why, tc.why) {
			t.Errorf("%s control=%v: %v %q", tc.raw, tc.control, ok, why)
		}
	}
}

func seedScreenEndpoint(t *testing.T, srv *Server, id, caps string) {
	t.Helper()
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: id, OS: "windows", Status: "online", ResponseCapabilities: caps}); err != nil {
		t.Fatal(err)
	}
}

func TestServer_ScreenSessionFlow(t *testing.T) {
	t.Parallel()
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	seedScreenEndpoint(t, srv, "win-scr", `{"isolate":true,"screen":{"input":true},"terminal":{"programs":["powershell.exe"]}}`)
	seedScreenEndpoint(t, srv, "win-watch", `{"isolate":true,"screen":{"input":false}}`)
	seedScreenEndpoint(t, srv, "linux-noscr", `{"isolate":true,"terminal":{"programs":["/bin/bash"]}}`)

	jwt, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: hubauth.RoleAdmin, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwt) }
	client := &http.Client{}
	open := func(body string) (*http.Response, map[string]interface{}) {
		t.Helper()
		resp := doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/screen/sessions", body, bearer)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(raw, &m)
		return resp, m
	}

	// Refusals before any approval is asked for.
	for _, tc := range []struct{ body, want string }{
		{`{"endpoint_id":"linux-noscr"}`, "reports no screen capability"},
		{`{"endpoint_id":"win-watch","mode":"control"}`, "view-only session"},
		{`{"endpoint_id":"win-scr","mode":"drive"}`, `mode must be`},
	} {
		resp, m := open(tc.body)
		if raw, _ := json.Marshal(m); resp.StatusCode < 400 || !strings.Contains(string(raw), tc.want) {
			t.Errorf("%s: %d %v", tc.body, resp.StatusCode, m)
		}
	}

	resp, sum := open(`{"endpoint_id":"win-scr","mode":"control","max_duration_seconds":1800}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("open: %d %v", resp.StatusCode, sum)
	}
	id, _ := sum["session_id"].(string)
	opToken, _ := sum["connect_token"].(string)
	if sum["mode"] != "control" || opToken == "" {
		t.Fatalf("summary %v", sum)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatalf("a screen open set cookies: %v", resp.Cookies())
	}

	// The offer the agent gets: session, mode, its own token.
	jobs, err := srv.responseStore.ListJobs("default", "win-scr", 10)
	if err != nil || len(jobs) != 1 || jobs[0].Kind != response.ActionKindScreenSession {
		t.Fatalf("jobs %v %v", jobs, err)
	}
	var wrapped struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal([]byte(jobs[0].RequestJSON), &wrapped)
	var offer map[string]interface{}
	_ = json.Unmarshal([]byte(wrapped.Payload), &offer)
	live, _ := srv.terminalMgr.GetSession(id)
	if offer["session_id"] != id || offer["mode"] != "control" || offer["connect_token"] != live.ConnectToken || offer["operator"] != "admin" || len(offer) != 4 || live.ConnectToken == opToken {
		t.Fatalf("offer %v", offer)
	}
	if live.Grant == nil || live.Grant.ActionKind != response.ActionKindScreenSession {
		t.Fatalf("grant %+v", live.Grant)
	}
	want, _ := response.ComputeActionDigest(response.ScreenSessionPayload{Mode: "control"})
	if live.Grant.ActionDigest != want {
		t.Fatalf("grant digest %s, want sha256 of {\"mode\":\"control\"}", live.Grant.ActionDigest)
	}

	// A second screen on the same endpoint is refused (one per endpoint).
	if resp, m := open(`{"endpoint_id":"win-scr","mode":"view"}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("second screen: %d %v", resp.StatusCode, m)
	}

	toWS := func(path string, q url.Values) string {
		u, _ := url.Parse(ts.URL)
		u.Scheme, u.Path, u.RawQuery = "ws", path, q.Encode()
		return u.String()
	}
	opURL := toWS("/api/v1/screen/ws/operator", url.Values{"session_id": {id}})
	dialOp := func(origin, token string) (*websocket.Conn, *http.Response, error) {
		h := http.Header{}
		if token != "" {
			h.Set("X-Screen-Token", token)
		}
		if origin != "" {
			h.Set("Origin", origin)
		}
		return websocket.DefaultDialer.Dial(opURL, h)
	}
	// No web page may drive a screen: any Origin is refused, even this
	// hub's own, with a valid token (which is not spent by the refusal).
	for _, origin := range []string{"https://evil.example", ts.URL} {
		if c, r, err := dialOp(origin, opToken); err == nil {
			c.Close()
			t.Fatalf("origin %q attached", origin)
		} else if r == nil || r.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: %v", origin, err)
		}
	}
	// The token is a header, never a query parameter.
	if c, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/screen/ws/operator", url.Values{"session_id": {id}, "token": {opToken}}), nil); err == nil {
		c.Close()
		t.Fatal("a query token attached")
	}
	// The terminal routes never attach a screen session.
	if c, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/terminal/ws/operator", url.Values{"session_id": {id}, "token": {opToken}}), nil); err == nil {
		c.Close()
		t.Fatal("terminal route attached a screen session")
	}
	op, _, err := dialOp("", opToken)
	if err != nil {
		t.Fatalf("operator dial (no Origin, valid token): %v", err)
	}
	defer op.Close()
	// One use: the same token does not open a second attachment.
	if c, _, err := dialOp("", opToken); err == nil {
		c.Close()
		t.Fatal("the operator token opened twice")
	}
	agent, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/screen/ws/agent", url.Values{"session_id": {id}, "endpoint_id": {"win-scr"}, "token": {live.ConnectToken}}), nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agent.Close()

	tile := []byte{1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 9, 0, 0, 0, 0xff, 0xd8, 0xff, 0xd9}
	if err := agent.WriteMessage(websocket.BinaryMessage, tile); err != nil {
		t.Fatal(err)
	}
	_ = op.SetReadDeadline(time.Now().Add(3 * time.Second))
	if typ, got, err := op.ReadMessage(); err != nil || typ != websocket.BinaryMessage || !bytes.Equal(got, tile) {
		t.Fatalf("tile through the hub: %d %x %v", typ, got, err)
	}

	// The terminal list does not show it; the screen list does.
	get := func(path string) map[string]interface{} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		bearer(req)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var m map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	if l, _ := get("/api/v1/terminal/sessions")["sessions"].([]interface{}); len(l) != 0 {
		t.Fatalf("terminal list shows the screen: %v", l)
	}
	if l, _ := get("/api/v1/screen/sessions")["sessions"].([]interface{}); len(l) != 1 {
		t.Fatalf("screen list: %v", l)
	}

	// End it.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/screen/sessions?id="+id, nil)
	bearer(req)
	r, err := client.Do(req)
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("delete: %v %v", r, err)
	}
	r.Body.Close()
	if live.IsLive() {
		t.Fatal("session still live after DELETE")
	}
}

func TestServer_ScreenLaunchWatchAudit(t *testing.T) {
	t.Parallel()
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	seedScreenEndpoint(t, srv, "win-agent", `{"isolate":true,"screen":{"input":true}}`)
	seedScreenEndpoint(t, srv, "win-console", `{"isolate":true,"screen":{"input":true}}`)

	jwt, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: hubauth.RoleAdmin, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	console := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwt) }
	apiKey := func(r *http.Request) { r.Header.Set("X-API-Key", "test-admin-key-12345") }
	client := &http.Client{}
	call := func(auth func(*http.Request), method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != nil {
			auth(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	// An agent's open: the owner is told an agent with the admin key asks.
	body := `{"endpoint_id":"win-agent","mode":"control","max_duration_seconds":1800}`
	code, pending := call(apiKey, http.MethodPost, "/api/v1/screen/sessions", body)
	if code != http.StatusAccepted {
		t.Fatalf("agent open: %d %v", code, pending)
	}
	appID, _ := pending["approval_id"].(string)
	view, err := auth.GetApproval(appID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(view.Summary, "An agent (admin key) will see and control the screen on win-agent, up to 30 minutes") {
		t.Fatalf("agent approval wording: %q", view.Summary)
	}
	resp := doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/screen/sessions", body, apiKey)
	var agentSum map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&agentSum)
	resp.Body.Close()
	agentID, _ := agentSum["session_id"].(string)
	if resp.StatusCode != http.StatusCreated || agentID == "" {
		t.Fatalf("agent open: %d %v", resp.StatusCode, agentSum)
	}

	// The agent's offer names it as an agent, for the consent prompt.
	if jobs, _ := srv.responseStore.ListJobs("default", "win-agent", 10); len(jobs) != 1 || !strings.Contains(jobs[0].RequestJSON, `\"operator\":\"an agent (admin key)\"`) {
		t.Fatalf("agent offer %v", jobs)
	}

	// Launch codes are for the console only.
	if code, m := call(apiKey, http.MethodPost, "/api/v1/screen/sessions/launch", `{"session_id":"`+agentID+`"}`); code != http.StatusForbidden {
		t.Fatalf("agent launch code: %d %v", code, m)
	}

	toWS := func(path string, q url.Values) string {
		u, _ := url.Parse(ts.URL)
		u.Scheme, u.Path, u.RawQuery = "ws", path, q.Encode()
		return u.String()
	}
	dial := func(id, token string) *websocket.Conn {
		t.Helper()
		c, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/screen/ws/operator", url.Values{"session_id": {id}}), http.Header{"X-Screen-Token": {token}})
		if err != nil {
			t.Fatalf("attach %s: %v", id, err)
		}
		return c
	}

	// The agent's control attachment: its input is audited.
	op := dial(agentID, agentSum["connect_token"].(string))
	defer op.Close()
	live, _ := srv.terminalMgr.GetSession(agentID)
	ag, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/screen/ws/agent", url.Values{"session_id": {agentID}, "endpoint_id": {"win-agent"}, "token": {live.ConnectToken}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	for _, f := range []string{
		`{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{"l":true},"monitor":0}`,
		`{"type":"input","ev":"text","ch":"secret words"}`,
	} {
		if err := op.WriteMessage(websocket.TextMessage, []byte(f)); err != nil {
			t.Fatal(err)
		}
		_ = ag.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := ag.ReadMessage(); err != nil {
			t.Fatalf("input not relayed: %v", err)
		}
	}

	// The owner watches along: the admin key gets a watch token.
	code, wt := call(apiKey, http.MethodPost, "/api/v1/screen/sessions/watch", `{"session_id":"`+agentID+`"}`)
	if code != http.StatusOK || wt["mode"] != "view" || wt["token"] == "" || wt["host"] != "win-agent" || wt["expires_at"] == nil {
		t.Fatalf("watch token: %d %v", code, wt)
	}
	watcher := dial(agentID, wt["token"].(string))
	defer watcher.Close()
	tile := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 0, 0, 0xff, 0xd9}
	deadline := time.Now().Add(3 * time.Second)
	for got := false; !got; {
		if time.Now().After(deadline) {
			t.Fatal("watcher never saw a tile")
		}
		_ = ag.WriteMessage(websocket.BinaryMessage, tile)
		_ = watcher.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if typ, b, err := watcher.ReadMessage(); err == nil && typ == websocket.BinaryMessage && bytes.Equal(b, tile) {
			got = true
		}
	}

	// A console-opened session: the console gets launch codes, never a token.
	resp = doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/screen/sessions", `{"endpoint_id":"win-console"}`, console)
	var conSum map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&conSum)
	resp.Body.Close()
	conID, _ := conSum["session_id"].(string)
	launch := func(path string) string {
		t.Helper()
		code, m := call(console, http.MethodPost, path, `{"session_id":"`+conID+`"}`)
		c, _ := m["code"].(string)
		if code != http.StatusOK || c == "" || m["expires_in"] != float64(60) || m["token"] != nil || m["connect_token"] != nil {
			t.Fatalf("%s: %d %v", path, code, m)
		}
		return c
	}
	redeem := func(id, c string) (int, map[string]interface{}) {
		return call(nil, http.MethodPost, "/api/v1/screen/launch/redeem", `{"session_id":"`+id+`","code":"`+c+`"}`)
	}
	c1 := launch("/api/v1/screen/sessions/launch")
	if code, _ := redeem(agentID, c1); code != http.StatusUnauthorized {
		t.Fatalf("redeem for another session: %d", code)
	}
	if code, _ := redeem(conID, c1); code != http.StatusUnauthorized {
		t.Fatalf("a code named against the wrong session stays spent: %d", code)
	}
	c2 := launch("/api/v1/screen/sessions/launch")
	code, got := redeem(conID, c2)
	if code != http.StatusOK || got["mode"] != "control" || got["host"] != "win-console" || got["token"] == "" || got["expires_at"] == nil {
		t.Fatalf("redeem: %d %v", code, got)
	}
	if code, _ := redeem(conID, c2); code != http.StatusUnauthorized {
		t.Fatalf("second redeem: %d", code)
	}
	conOp := dial(conID, got["token"].(string))
	defer conOp.Close()
	code, got = redeem(conID, launch("/api/v1/screen/sessions/watch"))
	if code != http.StatusOK || got["mode"] != "view" || got["token"] == "" {
		t.Fatalf("watch redeem: %d %v", code, got)
	}
	// Redeems are rate limited per address (and session).
	limited := false
	for i := 0; i < 12 && !limited; i++ {
		code, _ := redeem(conID, "guess")
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("redeem never rate limited")
	}

	// The audit: attach kinds and who, the agent's input without the text,
	// redeem outcomes.
	_ = op.Close()
	_ = watcher.Close()
	want := map[string]bool{
		"SCREEN_ATTACHED:control attachment by admin (agent, admin key)": false,
		"SCREEN_ATTACHED:watch attachment by admin (agent, admin key)":   false,
		"SCREEN_AGENT_INPUT:left button down at 100,200":                 false,
		"SCREEN_AGENT_INPUT:typed text, 12 characters":                   false,
		"SCREEN_LAUNCH_REDEEMED:control launch code":                     false,
		"SCREEN_LAUNCH_REDEEMED:watch launch code":                       false,
		"SCREEN_LAUNCH_REDEEM_FAILED:invalid":                            false,
		"SCREEN_LAUNCH_REDEEM_FAILED:too many":                           false,
		"SCREEN_DETACHED:control attachment by admin (agent, admin key)": false,
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		entries, _ := store.ListAuditLogs("", 1000)
		for _, e := range entries {
			if strings.Contains(e.Details, "secret words") {
				t.Fatalf("typed text reached the audit: %s", e.Details)
			}
			for k := range want {
				parts := strings.SplitN(k, ":", 2)
				if e.Action == parts[0] && strings.Contains(e.Details, parts[1]) {
					want[k] = true
				}
			}
		}
		all := true
		for _, ok := range want {
			all = all && ok
		}
		if all {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("audit lines missing: %v", want)
}

func TestServer_ScreenAskFirst(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	seedScreenEndpoint(t, srv, "win-ask", `{"isolate":true,"screen":{"input":true}}`)
	seedScreenEndpoint(t, srv, "win-other", `{"isolate":true,"screen":{"input":true}}`)
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

	// Off by default (the hub does not know join type).
	if code, m := call(http.MethodGet, "/api/v1/screen/settings?endpoint_id=win-ask", ""); code != 200 || m["ask_first"] != false || m["source"] != "default" {
		t.Fatalf("default: %d %v", code, m)
	}
	// Turning it on applies at once.
	if code, m := call(http.MethodPut, "/api/v1/screen/settings?endpoint_id=win-ask", `{"ask_first":true}`); code != 200 || m["changed"] != true || m["approval_id"] != nil {
		t.Fatalf("on: %d %v", code, m)
	}
	if _, m := call(http.MethodGet, "/api/v1/screen/settings?endpoint_id=win-ask", ""); m["ask_first"] != true || m["source"] != "endpoint" {
		t.Fatalf("after on: %v", m)
	}
	if _, m := call(http.MethodGet, "/api/v1/screen/settings?endpoint_id=win-other", ""); m["ask_first"] != false {
		t.Fatalf("other endpoint: %v", m)
	}

	// The open: the owner is told, ask_first is digested (after mode and
	// unattended) and in the offer with the operator's name.
	body := `{"endpoint_id":"win-ask","mode":"control","unattended":true}`
	code, pending := call(http.MethodPost, "/api/v1/screen/sessions", body)
	if code != http.StatusAccepted {
		t.Fatalf("open: %d %v", code, pending)
	}
	view, err := auth.GetApproval(pending["approval_id"].(string), "")
	if err != nil || !strings.Contains(view.Summary, "; the person at the keyboard is asked to allow it first; if nobody is signed in") {
		t.Fatalf("approval %v %+v", err, view)
	}
	resp := doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/screen/sessions", body, bearer)
	var sum map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&sum)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("open: %d %v", resp.StatusCode, sum)
	}
	live, _ := srv.terminalMgr.GetSession(sum["session_id"].(string))
	canon := []byte(`{"mode":"control","unattended":true,"ask_first":true}`)
	if raw, _ := json.Marshal(response.ScreenSessionPayload{Mode: "control", Unattended: true, AskFirst: true}); !bytes.Equal(raw, canon) {
		t.Fatalf("payload bytes %s", raw)
	}
	if want, _ := response.ComputeActionDigest(response.ScreenSessionPayload{Mode: "control", Unattended: true, AskFirst: true}); live.Grant.ActionDigest != want {
		t.Fatalf("grant digest %s is not sha256(%s)", live.Grant.ActionDigest, canon)
	}
	jobs, _ := srv.responseStore.ListJobs("default", "win-ask", 10)
	var wrapped struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal([]byte(jobs[0].RequestJSON), &wrapped)
	var offer map[string]interface{}
	_ = json.Unmarshal([]byte(wrapped.Payload), &offer)
	if offer["ask_first"] != true || offer["unattended"] != true || offer["operator"] != "admin" || offer["mode"] != "control" {
		t.Fatalf("offer %v", offer)
	}

	// Turning it off loosens: the owner's tap first, nothing saved until then.
	code, m := call(http.MethodPut, "/api/v1/screen/settings?endpoint_id=win-ask", `{"ask_first":false}`)
	if code != http.StatusAccepted || m["approval_id"] == nil {
		t.Fatalf("off: %d %v", code, m)
	}
	view, _ = auth.GetApproval(m["approval_id"].(string), "")
	if view.Action != "Stop asking before screen sessions" || view.Summary != "Screen sessions on endpoint win-ask open without asking the person at the keyboard first (was: asked first)" {
		t.Fatalf("loosen approval %q %q", view.Action, view.Summary)
	}
	if srv.screenAskFirst("win-ask") != true {
		t.Fatal("ask-first turned off before the owner approved")
	}
	resp = doApproved(t, srv, client, http.MethodPut, ts.URL+"/api/v1/screen/settings?endpoint_id=win-ask", `{"ask_first":false}`, bearer)
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if resp.StatusCode != 200 || m["approval_id"] == nil || srv.screenAskFirst("win-ask") {
		t.Fatalf("off approved: %d %v", resp.StatusCode, m)
	}

	// The fleet default: on at once, covers machines without their own
	// setting; dropping an override to follow it is no loosening here.
	if code, m := call(http.MethodPut, "/api/v1/screen/settings", `{"ask_first":true}`); code != 200 || m["approval_id"] != nil {
		t.Fatalf("fleet on: %d %v", code, m)
	}
	if _, m := call(http.MethodGet, "/api/v1/screen/settings?endpoint_id=win-other", ""); m["ask_first"] != true || m["source"] != "fleet" {
		t.Fatalf("fleet default: %v", m)
	}
	if code, m := call(http.MethodPut, "/api/v1/screen/settings?endpoint_id=win-ask", `{"reset":true}`); code != 200 || !srv.screenAskFirst("win-ask") {
		t.Fatalf("reset to fleet: %d %v", code, m)
	}
	// Forgetting the fleet default (back to off) loosens.
	if code, m := call(http.MethodPut, "/api/v1/screen/settings", `{"reset":true}`); code != http.StatusAccepted {
		t.Fatalf("fleet reset: %d %v", code, m)
	}
	if code, _ := call(http.MethodPut, "/api/v1/screen/settings", `{}`); code != http.StatusBadRequest {
		t.Fatalf("empty put: %d", code)
	}
	// Admin only (an auditor may read, not change).
	op, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "op", Role: hubauth.RoleAuditor, TenantID: "default"}, "test-admin-key-12345", time.Hour)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/screen/settings", strings.NewReader(`{"ask_first":true}`))
	req.Header.Set("Authorization", "Bearer "+op)
	if r, err := client.Do(req); err != nil || r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor put: %v %v", r, err)
	}
}
