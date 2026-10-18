package screen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

func screenGrant(endpointID string) *response.EndpointGrant {
	return &response.EndpointGrant{
		Version: response.GrantVersion, GrantID: "grant-" + endpointID, TenantID: "t1", EndpointID: endpointID,
		ActionKind: response.ActionKindScreenSession, OperatorID: "alice",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
}

type harness struct {
	t   *testing.T
	mgr *terminal.Manager
	srv *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	mgr := terminal.NewManager(nil, nil, 30*time.Minute, 15*time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("/op", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.AttachOperator(w, r, r.URL.Query().Get("session_id"), r.URL.Query().Get("token")); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("/agent", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if err := mgr.AttachAgent(w, r, q.Get("session_id"), q.Get("endpoint_id"), q.Get("token")); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close(); _ = mgr.Close() })
	return &harness{t: t, mgr: mgr, srv: srv}
}

func (h *harness) dial(path string, q url.Values) *websocket.Conn {
	h.t.Helper()
	u, _ := url.Parse(h.srv.URL)
	u.Scheme, u.Path, u.RawQuery = "ws", path, q.Encode()
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		h.t.Fatalf("dial %s: %v", path, err)
	}
	return c
}

// open creates a session and attaches both sides.
func (h *harness) open(endpoint, mode string) (*terminal.TerminalSession, *websocket.Conn, *websocket.Conn) {
	h.t.Helper()
	sess, err := CreateSession(h.mgr, "t1", endpoint, "alice", mode, screenGrant(endpoint), 0)
	if err != nil {
		h.t.Fatalf("CreateSession: %v", err)
	}
	agent := h.dial("/agent", url.Values{"session_id": {sess.SessionID}, "endpoint_id": {endpoint}, "token": {sess.ConnectToken}})
	op := h.dial("/op", url.Values{"session_id": {sess.SessionID}, "token": {sess.OperatorToken}})
	h.t.Cleanup(func() { _ = agent.Close(); _ = op.Close() })
	return sess, op, agent
}

func read(t *testing.T, c *websocket.Conn) (int, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return typ, data
}

func send(t *testing.T, c *websocket.Conn, typ int, data string) {
	t.Helper()
	if err := c.WriteMessage(typ, []byte(data)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestScreenRelayPassesBinaryTilesAndControl(t *testing.T) {
	h := newHarness(t)
	sess, op, agent := h.open("win-01", response.ScreenModeControl)

	hello := `{"type":"hello","monitors":[{"id":0,"w":2560,"h":1440,"x":0,"y":0,"primary":true}],"active":0}`
	send(t, agent, websocket.TextMessage, hello)
	if typ, got := read(t, op); typ != websocket.TextMessage || string(got) != hello {
		t.Fatalf("hello: type %d %q", typ, got)
	}
	// A tile is one binary message: fixed header + JPEG, opaque to the hub.
	tile := []byte{1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 7, 0, 0, 0, 0xff, 0xd8, 0xff, 0x00, 0xfe, 0xff, 0xd9}
	if err := agent.WriteMessage(websocket.BinaryMessage, tile); err != nil {
		t.Fatal(err)
	}
	if typ, got := read(t, op); typ != websocket.BinaryMessage || !bytes.Equal(got, tile) {
		t.Fatalf("tile: type %d %x (binary must pass through unchanged)", typ, got)
	}
	frameEnd := `{"type":"frame_end","monitor":0,"frame":1,"tiles":1}`
	send(t, agent, websocket.TextMessage, frameEnd)
	if typ, got := read(t, op); typ != websocket.TextMessage || string(got) != frameEnd {
		t.Fatalf("frame_end: type %d %q", typ, got)
	}
	ack := `{"type":"ack","monitor":0,"frame":1}`
	send(t, op, websocket.TextMessage, ack)
	if typ, got := read(t, agent); typ != websocket.TextMessage || string(got) != ack {
		t.Fatalf("ack: type %d %q", typ, got)
	}

	// The agent gets the hub's canonical re-encoding, never the operator's
	// bytes: every button spelled out, the helper's field order.
	send(t, op, websocket.TextMessage, `{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{"l":true},"monitor":0}`)
	input := `{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{"l":true,"r":false,"m":false},"monitor":0}`
	if typ, got := read(t, agent); typ != websocket.TextMessage || string(got) != input {
		t.Fatalf("input in control mode: type %d %q", typ, got)
	}
	// The hub clamps quality to its caps.
	send(t, op, websocket.TextMessage, `{"type":"quality","fps":60,"jpeg_q":5}`)
	_, got := read(t, agent)
	var q struct {
		Type  string `json:"type"`
		FPS   int    `json:"fps"`
		JPEGQ int    `json:"jpeg_q"`
	}
	if err := json.Unmarshal(got, &q); err != nil || q.Type != "quality" || q.FPS != MaxFPS || q.JPEGQ != MinJPEGQuality {
		t.Fatalf("quality not clamped: %s", got)
	}

	if sum := sess.Summary(); sum["recording_state"] != "off" || sum["bundle_id"] != nil {
		t.Fatalf("a screen session records by default: %v", sum)
	}
}

func TestScreenViewModeDropsInput(t *testing.T) {
	h := newHarness(t)
	_, op, agent := h.open("win-02", response.ScreenModeView)
	send(t, op, websocket.TextMessage, `{"type":"input","ev":"key","code":30,"down":true,"ext":false}`)
	send(t, op, websocket.TextMessage, `{"type":"set_monitor","monitor":1}`)
	_, got := read(t, agent)
	if !strings.Contains(string(got), "set_monitor") {
		t.Fatalf("view mode let input through to the agent: %s", got)
	}
}

func TestScreenPolicyRefusals(t *testing.T) {
	cases := []struct {
		name   string
		side   string
		typ    int
		data   string
		reason string
	}{
		{"operator binary", "op", websocket.BinaryMessage, "x", "forbidden_operator_frame_type"},
		{"operator shell frame", "op", websocket.TextMessage, `{"type":"stdin","data":"aGk="}`, "forbidden_operator_frame_type"},
		{"operator garbage", "op", websocket.TextMessage, `not json`, "malformed_operator_frame"},
		{"operator close", "op", websocket.TextMessage, `{"type":"close"}`, "operator_requested_close"},
		{"agent stdout", "agent", websocket.TextMessage, `{"type":"stdout","data":"aGk="}`, "forbidden_agent_frame_type"},
		{"agent bye", "agent", websocket.TextMessage, `{"type":"bye","reason":"user signed out\n"}`, "agent_bye: user signed out"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			sess, op, agent := h.open("win-x", response.ScreenModeControl)
			c, other := op, agent
			if tc.side == "agent" {
				c, other = agent, op
			}
			send(t, c, tc.typ, tc.data)
			_ = other.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _, err := other.ReadMessage()
			var ce *websocket.CloseError
			if err == nil {
				t.Fatal("session stayed open")
			}
			if !asClose(err, &ce) || ce.Text != tc.reason {
				t.Fatalf("close = %v, want reason %q", err, tc.reason)
			}
			if sess.IsLive() {
				t.Fatal("session still live")
			}
		})
	}
}

func asClose(err error, ce **websocket.CloseError) bool {
	c, ok := err.(*websocket.CloseError)
	if ok {
		*ce = c
	}
	return ok
}

func TestScreenPolicyUnknownModeIsViewOnly(t *testing.T) {
	if d := newPolicy("screen:bogus", "s").Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"sas"}`)); d.Action != terminal.FrameDrop {
		t.Fatalf("unknown mode let input through: %+v", d)
	}
	if d := newPolicy(Program(response.ScreenModeView), "s").Operator(websocket.TextMessage, []byte(`{"type":"ack","frame":3}`)); d.Action != terminal.FrameForward || d.Activity {
		t.Fatalf("ack in view mode: %+v", d)
	}
}

func TestScreenPauseOnDetachResumeOnAttach(t *testing.T) {
	h := newHarness(t)
	sess, op, agent := h.open("win-03", response.ScreenModeControl)
	_ = op.Close()
	if _, got := read(t, agent); string(got) != `{"type":"pause"}` {
		t.Fatalf("detach sent %q, want pause", got)
	}
	tok, err := h.mgr.RotateOperatorToken(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	op2 := h.dial("/op", url.Values{"session_id": {sess.SessionID}, "token": {tok}})
	defer op2.Close()
	if _, got := read(t, agent); string(got) != `{"type":"resume"}` {
		t.Fatalf("reattach sent %q, want resume", got)
	}
	// The session survives the detach and still relays.
	send(t, agent, websocket.TextMessage, `{"type":"cursor_pos","x":1,"y":2,"visible":true}`)
	if _, got := read(t, op2); !strings.Contains(string(got), "cursor_pos") {
		t.Fatalf("after reattach: %s", got)
	}
}

func TestScreenOnePerEndpoint(t *testing.T) {
	mgr := terminal.NewManager(nil, nil, 30*time.Minute, 15*time.Minute)
	defer mgr.Close()
	if _, err := CreateSession(mgr, "t1", "win-04", "alice", response.ScreenModeView, screenGrant("win-04"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSession(mgr, "t1", "win-04", "alice", response.ScreenModeControl, screenGrant("win-04"), 0); err == nil || !strings.Contains(err.Error(), "screen session is already open") {
		t.Fatalf("second screen on one endpoint: %v", err)
	}
	// A shell beside it still opens (the shared cap is not lowered).
	if _, err := mgr.CreateSession("t1", "win-04", "alice", "powershell.exe", screenGrant("win-04")); err != nil {
		t.Fatalf("shell beside a screen: %v", err)
	}
	// Other endpoints are unaffected.
	if _, err := CreateSession(mgr, "t1", "win-05", "alice", response.ScreenModeControl, screenGrant("win-05"), 0); err != nil {
		t.Fatal(err)
	}
	// Wrong grant kind or mode are refused.
	g := screenGrant("win-06")
	g.ActionKind = response.ActionKindTerminalSession
	if _, err := CreateSession(mgr, "t1", "win-06", "alice", response.ScreenModeControl, g, 0); err == nil {
		t.Fatal("a terminal grant opened a screen")
	}
	if _, err := CreateSession(mgr, "t1", "win-06", "alice", "drive", screenGrant("win-06"), 0); err == nil {
		t.Fatal("an unknown mode opened a screen")
	}
}

// One control attachment plus watchers: everyone gets the agent's frames,
// watcher input never reaches the agent, a watcher's acks count only while
// it paces, and the agent pauses only once nobody is attached.
func TestScreenWatchers(t *testing.T) {
	h := newHarness(t)
	h.addWatch()
	sess, op, agent := h.open("win-w", response.ScreenModeControl)
	q := url.Values{"session_id": {sess.SessionID}}
	var watchers []*websocket.Conn
	for i := 0; i < MaxWatchers; i++ {
		watchers = append(watchers, h.dial("/watch", q))
	}
	u, _ := url.Parse(h.srv.URL)
	u.Scheme, u.Path, u.RawQuery = "ws", "/watch", q.Encode()
	if c, _, err := websocket.DefaultDialer.Dial(u.String(), nil); err == nil {
		c.Close()
		t.Fatal("watcher cap not enforced")
	}
	waitFor(t, func() bool { return h.mgr.WatcherCount(sess.SessionID) == MaxWatchers })

	tile := []byte{1, 0, 1, 0, 9, 9}
	if err := agent.WriteMessage(websocket.BinaryMessage, tile); err != nil {
		t.Fatal(err)
	}
	for _, c := range append([]*websocket.Conn{op}, watchers...) {
		if typ, got := read(t, c); typ != websocket.BinaryMessage || !bytes.Equal(got, tile) {
			t.Fatalf("fan-out: %d %x", typ, got)
		}
	}
	// Watchers: input dropped; ack ignored while control is attached.
	send(t, watchers[0], websocket.TextMessage, `{"type":"input","ev":"key","code":30,"down":true}`)
	send(t, watchers[0], websocket.TextMessage, `{"type":"ack","monitor":0,"frame":1}`)
	// The hub reads a watcher's messages in order, so its pong to a ping
	// sent after the ack says the ack was judged - while control was still
	// attached - before control leaves below.
	judged := watcherSync(t)
	judged(watchers[0])
	send(t, op, websocket.TextMessage, `{"type":"ack","monitor":0,"frame":2}`)
	if _, got := read(t, agent); !strings.Contains(string(got), `"frame":2`) {
		t.Fatalf("agent got %s, want only the control ack", got)
	}
	// Control leaves: no pause (watchers remain); the oldest watcher paces.
	// Wait until the hub has seen the control attachment go, or the acks
	// below race it and are ignored as non-pacing.
	_ = op.Close()
	waitDetached(t, sess)
	send(t, watchers[1], websocket.TextMessage, `{"type":"ack","monitor":0,"frame":3}`)
	send(t, watchers[0], websocket.TextMessage, `{"type":"ack","monitor":0,"frame":4}`)
	if _, got := read(t, agent); !strings.Contains(string(got), `"frame":4`) {
		t.Fatalf("agent got %s, want the oldest watcher's ack (no pause)", got)
	}
	// watchers[1]'s non-pacing ack must be judged before watchers[0] leaves
	// below, or it arrives after watchers[1] became the pacer and is passed on
	// where the pause is expected.
	judged(watchers[1])
	// A watcher's close detaches it alone.
	send(t, watchers[0], websocket.TextMessage, `{"type":"close"}`)
	waitFor(t, func() bool { return h.mgr.WatcherCount(sess.SessionID) == MaxWatchers-1 })
	if !sess.IsLive() {
		t.Fatal("a watcher ended the session")
	}
	for _, c := range watchers[1:] {
		_ = c.Close()
	}
	if _, got := read(t, agent); string(got) != `{"type":"pause"}` {
		t.Fatalf("after the last attachment left: %q, want pause", got)
	}
	w := h.dial("/watch", q)
	defer w.Close()
	if _, got := read(t, agent); string(got) != `{"type":"resume"}` {
		t.Fatalf("first attachment back: %q, want resume", got)
	}
}

// addWatch serves watch attachments at /watch.
func (h *harness) addWatch() {
	h.srv.Config.Handler.(*http.ServeMux).HandleFunc("/watch", func(w http.ResponseWriter, r *http.Request) {
		if err := h.mgr.AttachWatcher(w, r, r.URL.Query().Get("session_id")); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
		}
	})
}

// waitDetached waits until the hub has processed the control attachment
// leaving (the session is detached and has no operator).
func waitDetached(t *testing.T, sess *terminal.TerminalSession) {
	t.Helper()
	waitFor(t, func() bool {
		sum := sess.Summary()
		return sum["state"] == "detached" && sum["operator_connected"] == false
	})
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// Agent control input is audited by kind and coordinates; text by length.
func TestScreenInputAudit(t *testing.T) {
	var lines []string
	defer SetInputAudit("sa", func(l string) { lines = append(lines, l) })()
	p := newPolicy(Program(response.ScreenModeControl), "sa")
	for _, f := range []string{
		`{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{},"monitor":0}`,
		`{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{"l":true},"monitor":0}`,
		`{"type":"input","ev":"mouse","x":100,"y":200,"buttons":{"l":false},"monitor":0}`,
		`{"type":"input","ev":"wheel","dx":0,"dy":-120,"monitor":1}`,
		`{"type":"input","ev":"key","code":30,"down":true,"ext":false}`,
		`{"type":"input","ev":"text","ch":"hunter2"}`,
		`{"type":"input","ev":"sas"}`,
	} {
		p.Operator(websocket.TextMessage, []byte(f))
	}
	all := strings.Join(lines, "\n")
	if len(lines) != 5 || strings.Contains(all, "hunter2") || strings.Contains(all, "scancode") || strings.Contains(all, " 30 ") {
		t.Fatalf("audit:\n%s", all)
	}
	for _, want := range []string{"left button down at 100,200", "left button up", "wheel dx=0 dy=-120", "typed text, 7 characters", "Ctrl+Alt+Del", "1 mouse moves", "1 key events"} {
		if !strings.Contains(all, want) {
			t.Errorf("audit lacks %q:\n%s", want, all)
		}
	}
	// Watchers and other sessions are not audited.
	newPolicy(Program(response.ScreenModeControl), "other").Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"sas"}`))
	if len(lines) != 5 {
		t.Fatal("an unaudited session was audited")
	}
}

// What the rate limit or the counting held back is written when auditing
// stops, not lost.
func TestScreenInputAuditFlushesOnStop(t *testing.T) {
	var lines []string
	stop := SetInputAudit("sf", func(l string) { lines = append(lines, l) })
	p := newPolicy(Program(response.ScreenModeControl), "sf")
	for i := 0; i < auditBurst+5; i++ {
		p.Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"sas"}`))
	}
	p.Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"key","code":30,"down":true}`))
	p.Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"mouse","x":1,"y":2}`))
	if len(lines) != auditBurst {
		t.Fatalf("%d lines before stop, want %d", len(lines), auditBurst)
	}
	stop()
	if len(lines) != auditBurst+1 || lines[auditBurst] != "Agent screen input: 5 more inputs not logged one by one, 1 mouse moves, 1 key events since the last line" {
		t.Fatalf("flush on stop: %q", lines[auditBurst:])
	}
	stop()
	if len(lines) != auditBurst+1 {
		t.Fatal("a second stop wrote again")
	}
	// A superseding attachment's audit flushes the one it replaces.
	var first, second []string
	SetInputAudit("sg", func(l string) { first = append(first, l) })
	newPolicy(Program(response.ScreenModeControl), "sg").Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"key","code":30,"down":true}`))
	defer SetInputAudit("sg", func(l string) { second = append(second, l) })()
	if len(first) != 1 || !strings.Contains(first[0], "1 key events") || len(second) != 0 {
		t.Fatalf("superseded audit: %q / %q", first, second)
	}
}

// Frame smuggling: the hub and the helper must read every forwarded frame
// the same way, so the hub accepts only exact lower-case keys, no repeats,
// no unknown members, and forwards only its own re-encoding.
func TestScreenFrameSmuggling(t *testing.T) {
	ctl := func() terminal.FramePolicy { return newPolicy(Program(response.ScreenModeControl), "smuggle") }
	view := func() terminal.FramePolicy { return newPolicy(Program(response.ScreenModeView), "smuggle-view") }
	const (
		fwd   = terminal.FrameForward
		drop  = terminal.FrameDrop
		close = terminal.FrameCloseSession
	)
	cases := []struct {
		name    string
		policy  func() terminal.FramePolicy
		watcher bool
		frame   string
		action  terminal.FrameAction
		reason  string
		out     string
	}{
		// Case variants: an ack to a lenient Go parse, input to serde.
		{"case variant key, operator", ctl, false, `{"type":"input","ev":"text","ch":"x","Type":"ack"}`, close, "malformed_operator_frame", ""},
		{"case variant key, watcher", ctl, true, `{"type":"input","ev":"text","ch":"x","Type":"ack"}`, close, "malformed_watcher_frame", ""},
		{"case variant key on an ack, watcher", ctl, true, `{"Type":"input","type":"ack","frame":1,"ev":"text","ch":"x"}`, close, "malformed_watcher_frame", ""},
		{"case variant ev hides text from the audit", ctl, false, `{"type":"input","ev":"text","ch":"x","EV":"mouse"}`, close, "malformed_operator_frame", ""},
		{"upper-case type value", ctl, false, `{"type":"ACK","frame":1}`, close, "forbidden_operator_frame_type", ""},
		// Duplicates: last wins in Go, first in serde.
		{"duplicate type", ctl, false, `{"type":"input","ev":"text","ch":"x","type":"ack"}`, close, "malformed_operator_frame", ""},
		{"duplicate type, watcher", ctl, true, `{"type":"input","type":"ack","frame":1}`, close, "malformed_watcher_frame", ""},
		{"duplicate by escape", ctl, false, `{"type":"ack","frame":1,"typ\u0065":"input"}`, close, "malformed_operator_frame", ""},
		{"duplicate ev", ctl, false, `{"type":"input","ev":"mouse","x":1,"y":1,"ev":"text"}`, close, "malformed_operator_frame", ""},
		{"duplicate button", ctl, false, `{"type":"input","ev":"mouse","x":1,"y":1,"buttons":{"l":true,"l":false}}`, close, "malformed_operator_frame", ""},
		// Unknown members are refused, not ignored.
		{"unknown key on an ack", ctl, false, `{"type":"ack","frame":1,"ev":"text","ch":"x"}`, close, "malformed_operator_frame", ""},
		{"key from another ev", ctl, false, `{"type":"input","ev":"key","code":30,"ch":"x"}`, close, "malformed_operator_frame", ""},
		{"unknown button", ctl, false, `{"type":"input","ev":"mouse","x":1,"y":1,"buttons":{"x1":true}}`, close, "malformed_operator_frame", ""},
		{"unknown ev", ctl, false, `{"type":"input","ev":"paste","ch":"x"}`, close, "malformed_operator_frame", ""},
		{"null member", ctl, false, `{"type":"ack","frame":null}`, close, "malformed_operator_frame", ""},
		{"fractional integer", ctl, false, `{"type":"input","ev":"key","code":30.5}`, close, "malformed_operator_frame", ""},
		{"string for a number", ctl, false, `{"type":"set_monitor","monitor":"1"}`, close, "malformed_operator_frame", ""},
		{"two objects", ctl, false, `{"type":"close"}{"type":"input","ev":"sas"}`, close, "malformed_operator_frame", ""},
		// pause and resume are the hub's to send.
		{"operator pause", ctl, false, `{"type":"pause"}`, close, "forbidden_operator_frame_type", ""},
		{"operator resume", ctl, false, `{"type":"resume"}`, close, "forbidden_operator_frame_type", ""},
		{"watcher pause", ctl, true, `{"type":"pause"}`, close, "forbidden_watcher_frame_type", ""},
		// A watcher only acks; its input never reaches the agent.
		{"watcher input", ctl, true, `{"type":"input","ev":"text","ch":"x"}`, drop, "", ""},
		{"watcher set_monitor", ctl, true, `{"type":"set_monitor","monitor":1}`, drop, "", ""},
		{"watcher quality", ctl, true, `{"type":"quality","fps":5}`, drop, "", ""},
		// A view session drops input, however it is spelled.
		{"view input", view, false, `{"type":"input","ev":"text","ch":"x"}`, drop, "", ""},
		{"view input as a case variant", view, false, `{"type":"ack","frame":1,"TYPE":"input","ev":"text","ch":"x"}`, close, "malformed_operator_frame", ""},
		// What is forwarded is the canonical re-encoding.
		{"ack re-encoded", ctl, true, ` { "frame" : 7 , "type" : "ack" } `, fwd, "", `{"type":"ack","monitor":0,"frame":7}`},
		{"text re-encoded", ctl, false, `{"ch":"<é>","ev":"text","type":"input"}`, fwd, "", `{"type":"input","ev":"text","ch":"\u003cé\u003e"}`},
		{"key re-encoded", ctl, false, `{"type":"input","ev":"key","code":57416,"down":false,"ext":true}`, fwd, "", `{"type":"input","ev":"key","code":57416,"down":false,"ext":true}`},
		{"set_monitor re-encoded", ctl, false, `{"monitor":2,"type":"set_monitor"}`, fwd, "", `{"type":"set_monitor","monitor":2}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.policy()
			var d terminal.FrameDecision
			if tc.watcher {
				d = p.(terminal.WatchPolicy).Watcher(websocket.TextMessage, []byte(tc.frame))
			} else {
				d = p.Operator(websocket.TextMessage, []byte(tc.frame))
			}
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("decision %+v, want action %d reason %q", d, tc.action, tc.reason)
			}
			if tc.action == fwd && string(d.Data) != tc.out {
				t.Fatalf("forwarded %s, want %s", d.Data, tc.out)
			}
			if tc.action == fwd && d.Data == nil {
				t.Fatal("forwarded without re-encoding")
			}
		})
	}
	// The audit reads the parse that is forwarded: a smuggled frame is
	// refused before it is audited, a canonical one is audited as it is.
	var lines []string
	defer SetInputAudit("smuggle-audit", func(l string) { lines = append(lines, l) })()
	p := newPolicy(Program(response.ScreenModeControl), "smuggle-audit")
	p.Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"text","ch":"abc","EV":"mouse"}`))
	if len(lines) != 0 {
		t.Fatalf("a refused frame was audited: %q", lines)
	}
	p.Operator(websocket.TextMessage, []byte(`{"type":"input","ev":"text","ch":"abc"}`))
	if len(lines) != 1 || lines[0] != "Agent screen input: typed text, 3 characters" {
		t.Fatalf("audit: %q", lines)
	}
}

// End to end: a watch token holder pacing a control session (no controller
// attached) cannot get input to the agent by dressing it as an ack; the
// agent gets only canonical acks from a watcher.
func TestScreenWatcherCannotInjectInput(t *testing.T) {
	h := newHarness(t)
	h.addWatch()
	sess, op, agent := h.open("win-smuggle", response.ScreenModeControl)
	_ = op.Close()
	waitDetached(t, sess)
	if _, got := read(t, agent); string(got) != `{"type":"pause"}` {
		t.Fatalf("detach sent %q, want pause", got)
	}
	w := h.dial("/watch", url.Values{"session_id": {sess.SessionID}})
	defer w.Close()
	if _, got := read(t, agent); string(got) != `{"type":"resume"}` {
		t.Fatalf("watcher attach sent %q, want resume", got)
	}
	send(t, w, websocket.TextMessage, `{"frame":5,"type":"ack"}`)
	if _, got := read(t, agent); string(got) != `{"type":"ack","monitor":0,"frame":5}` {
		t.Fatalf("pacing watcher's ack reached the agent as %q", got)
	}
	send(t, w, websocket.TextMessage, `{"type":"input","ev":"text","ch":"x"}`)
	send(t, w, websocket.TextMessage, `{"type":"input","ev":"text","ch":"x","Type":"ack"}`)
	// The smuggled frame detaches the watcher; the next thing the agent
	// hears is the pause for the last attachment leaving, not input.
	if _, got := read(t, agent); string(got) != `{"type":"pause"}` {
		t.Fatalf("agent got %q, want only the pause", got)
	}
	if !sess.IsLive() {
		t.Fatal("a watcher ended the session")
	}
}

func TestLaunchCodes(t *testing.T) {
	c := NewCredentials()
	now := time.Now()
	c.now = func() time.Time { return now }
	code := c.IssueLaunchCode("s1", "owner@example", AttachControl)
	if len(code) < 40 {
		t.Fatalf("code %q is not high-entropy", code)
	}
	for k := range c.codes {
		if k == code {
			t.Fatal("code stored in the clear")
		}
	}
	if op, kind, err := c.RedeemLaunchCode("s1", code, "10.0.0.1"); err != nil || op != "owner@example" || kind != AttachControl {
		t.Fatalf("redeem: %q %q %v", op, kind, err)
	}
	if _, _, err := c.RedeemLaunchCode("s1", code, "10.0.0.1"); err != ErrCodeInvalid {
		t.Fatalf("second redeem: %v", err)
	}
	other := c.IssueLaunchCode("s1", "o", AttachWatch)
	if _, _, err := c.RedeemLaunchCode("s2", other, "10.0.0.1"); err != ErrCodeInvalid {
		t.Fatalf("code for another session: %v", err)
	}
	if _, _, err := c.RedeemLaunchCode("s1", other, "10.0.0.1"); err != ErrCodeInvalid {
		t.Fatalf("a code tried against the wrong session is spent: %v", err)
	}
	late := c.IssueLaunchCode("s3", "o", AttachControl)
	now = now.Add(LaunchCodeTTL + time.Second)
	if _, _, err := c.RedeemLaunchCode("s3", late, "10.0.0.2"); err != ErrCodeInvalid {
		t.Fatalf("expired code: %v", err)
	}
	// Bad redeems lock out their source, not the session: a third party
	// who knows the session id cannot keep its owner from redeeming.
	for i := 0; i < RedeemLimit; i++ {
		_, _, _ = c.RedeemLaunchCode("s9", "guess", "10.0.0.3")
	}
	if _, _, err := c.RedeemLaunchCode("s9", "guess", "10.0.0.3"); err != ErrRedeemLimit {
		t.Fatalf("per-source limit: %v", err)
	}
	if _, _, err := c.RedeemLaunchCode("s9", "guess", "10.0.0.4"); err != ErrCodeInvalid {
		t.Fatalf("another source was limited by someone else's guesses: %v", err)
	}
	// A live code for its own session redeems even from a limited source
	// (a shared address must not lock the owner out).
	fresh := c.IssueLaunchCode("s9", "o", AttachControl)
	if _, _, err := c.RedeemLaunchCode("s9", fresh, "10.0.0.3"); err != nil {
		t.Fatalf("a valid code was refused: %v", err)
	}
	now = now.Add(RedeemWindow)
	if _, _, err := c.RedeemLaunchCode("s9", "guess", "10.0.0.3"); err != ErrCodeInvalid {
		t.Fatalf("after the window: %v", err)
	}
	// The per-session backstop still holds against many sources.
	for i := 0; i < SessionRedeemLimit; i++ {
		_, _, _ = c.RedeemLaunchCode("s10", "guess", fmt.Sprintf("10.1.%d.%d", i/250, i%250))
	}
	if _, _, err := c.RedeemLaunchCode("s10", "guess", "10.9.9.9"); err != ErrRedeemLimit {
		t.Fatalf("per-session backstop: %v", err)
	}
	last := c.IssueLaunchCode("s10", "o", AttachControl)
	if _, _, err := c.RedeemLaunchCode("s10", last, "10.9.9.9"); err != nil {
		t.Fatalf("a valid code under the backstop: %v", err)
	}
	tok := c.IssueWatchToken("s1", "owner")
	if _, ok := c.TakeWatchToken("s2", tok); ok {
		t.Fatal("watch token for another session")
	}
	if who, ok := c.TakeWatchToken("s1", tok); !ok || who != "owner" {
		t.Fatal("watch token refused")
	}
	if _, ok := c.TakeWatchToken("s1", tok); ok {
		t.Fatal("watch token used twice")
	}
}

// watcherSync returns a function that waits until the hub has judged every
// message a watcher sent so far: the hub reads a connection's messages in
// order, so its pong to a later ping proves the earlier ones were handled.
// It takes over reading the connection (pongs are seen only while reading).
func watcherSync(t *testing.T) func(*websocket.Conn) {
	started := map[*websocket.Conn]chan struct{}{}
	return func(c *websocket.Conn) {
		t.Helper()
		pong, ok := started[c]
		if !ok {
			pong = make(chan struct{}, 1)
			started[c] = pong
			c.SetPongHandler(func(string) error {
				select {
				case pong <- struct{}{}:
				default:
				}
				return nil
			})
			go func() {
				for {
					if _, _, err := c.NextReader(); err != nil {
						return
					}
				}
			}()
		}
		if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-pong:
		case <-time.After(3 * time.Second):
			t.Fatal("the hub never answered the watcher's ping")
		}
	}
}

// TestScreenReattachGetsStateAndOpensTheWindow is the third live test:
// ominullctl attaches once per command, and the helper sends its monitor list
// and desktop only at start, so every command after the first timed out
// waiting for a monitor list. Each new attachment now gets them first, and a
// resume acks the frames the departed viewer left unacked, so the helper's
// flow-control window is open for the next picture.
func TestScreenReattachGetsStateAndOpensTheWindow(t *testing.T) {
	h := newHarness(t)
	h.addWatch()
	sess, op, agent := h.open("win-re", response.ScreenModeControl)

	hello := `{"type":"hello","monitors":[{"id":0,"w":1280,"h":800,"x":0,"y":0,"primary":true}],"active":0}`
	desktop := `{"type":"desktop","name":"user","signed_in":true}`
	send(t, agent, websocket.TextMessage, hello)
	send(t, agent, websocket.TextMessage, desktop)
	send(t, agent, websocket.TextMessage, `{"type":"frame_end","monitor":0,"frame":6,"tiles":20}`)
	for _, want := range []string{hello, desktop, `"frame_end"`} {
		if _, got := read(t, op); !strings.Contains(string(got), want) {
			t.Fatalf("first viewer got %s, want %s", got, want)
		}
	}
	// The viewer leaves without acking frame 6: the hub pauses the agent.
	_ = op.Close()
	waitDetached(t, sess)
	if _, got := read(t, agent); string(got) != `{"type":"pause"}` {
		t.Fatalf("after the viewer left: %q, want pause", got)
	}

	// The next command's viewer gets the monitor list and desktop first.
	tok, err := h.mgr.RotateOperatorToken(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	op2 := h.dial("/op", url.Values{"session_id": {sess.SessionID}, "token": {tok}})
	defer op2.Close()
	wantHello := `{"type":"hello","monitors":[{"id":0,"w":1280,"h":800,"x":0,"y":0,"primary":true}],"active":0}`
	if _, got := read(t, op2); string(got) != wantHello {
		t.Fatalf("second viewer's first message: %s, want the monitor list", got)
	}
	if _, got := read(t, op2); string(got) != desktop {
		t.Fatalf("second viewer's second message: %s, want the desktop", got)
	}
	// The agent is resumed and its window opened: two acks of frame 6.
	for _, want := range []string{`{"type":"resume"}`, `{"type":"ack","monitor":0,"frame":6}`, `{"type":"ack","monitor":0,"frame":6}`} {
		if _, got := read(t, agent); string(got) != want {
			t.Fatalf("agent after reattach: %s, want %s", got, want)
		}
	}
	// A monitor change replaces the list a later attachment gets.
	resized := `{"type":"resized","monitors":[{"id":0,"w":1920,"h":1080,"x":0,"y":0,"primary":true}],"active":0}`
	send(t, agent, websocket.TextMessage, resized)
	if _, got := read(t, op2); string(got) != resized {
		t.Fatalf("live resized: %s", got)
	}
	w := h.dial("/watch", url.Values{"session_id": {sess.SessionID}})
	defer w.Close()
	if _, got := read(t, w); !strings.Contains(string(got), `"type":"hello"`) || !strings.Contains(string(got), `"w":1920`) {
		t.Fatalf("watcher's first message: %s, want the resized monitor list as a hello", got)
	}
	if _, got := read(t, w); string(got) != desktop {
		t.Fatalf("watcher's second message: %s, want the desktop", got)
	}
}

// A session whose agent has sent nothing yet replays nothing and acks nothing.
func TestScreenReplayEmptyBeforeHello(t *testing.T) {
	p := newPolicy(Program(response.ScreenModeView), "empty").(*policy)
	if r := p.Replay(); len(r) != 0 {
		t.Fatalf("replay before hello: %q", r)
	}
	if r := p.ResumeMessages(); len(r) != 0 {
		t.Fatalf("resume acks before any frame: %q", r)
	}
	// A malformed hello is not kept.
	p.Agent(websocket.TextMessage, []byte(`{"type":"hello"}`))
	if r := p.Replay(); len(r) != 0 {
		t.Fatalf("replay after a hello without monitors: %q", r)
	}
}
