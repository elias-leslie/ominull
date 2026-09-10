package terminal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
)

// detachHarness is one manager, one httptest server carrying the two WebSocket
// routes, and the helpers to dial them. Every test below drives real sockets:
// the defect this whole feature exists to fix lives in what a *pump* does when
// a socket goes away, and a test that calls the manager directly would prove
// nothing about it.
type detachHarness struct {
	t      *testing.T
	mgr    *Manager
	server *httptest.Server
}

func newDetachHarness(t *testing.T, idleTimeout time.Duration) *detachHarness {
	t.Helper()
	mgr := NewManager(nil, nil, 30*time.Minute, idleTimeout)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/terminal/ws/operator", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.AttachOperator(w, r, r.URL.Query().Get("session_id"), r.URL.Query().Get("token")); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("/api/v1/terminal/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.AttachAgent(w, r, r.URL.Query().Get("session_id"), r.URL.Query().Get("endpoint_id"), r.URL.Query().Get("token")); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})

	h := &detachHarness{t: t, mgr: mgr, server: httptest.NewServer(mux)}
	t.Cleanup(func() {
		h.server.Close()
		_ = mgr.Close()
	})
	return h
}

func (h *detachHarness) wsURL(path string, q url.Values) string {
	u, _ := url.Parse(h.server.URL)
	u.Scheme = "ws"
	u.Path = path
	u.RawQuery = q.Encode()
	return u.String()
}

func (h *detachHarness) createSession(tenantID, endpointID string) *TerminalSession {
	h.t.Helper()
	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-" + endpointID,
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "digest-detach-test",
		OperatorID:        "operator-alice",
		ResponseSessionID: "resp-session-detach",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}
	sess, err := h.mgr.CreateSession(tenantID, endpointID, "operator-alice", "/bin/bash", grant)
	if err != nil {
		h.t.Fatalf("CreateSession failed: %v", err)
	}
	return sess
}

func (h *detachHarness) dialAgent(sess *TerminalSession) *websocket.Conn {
	h.t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL("/api/v1/terminal/ws/agent", url.Values{
		"session_id":  []string{sess.SessionID},
		"endpoint_id": []string{sess.EndpointID},
		"token":       []string{sess.ConnectToken},
	}), nil)
	if err != nil {
		h.t.Fatalf("agent dial failed: %v", err)
	}
	return conn
}

func (h *detachHarness) dialOperator(sess *TerminalSession, token string) (*websocket.Conn, *http.Response, error) {
	return websocket.DefaultDialer.Dial(h.wsURL("/api/v1/terminal/ws/operator", url.Values{
		"session_id": []string{sess.SessionID},
		"token":      []string{token},
	}), nil)
}

// waitState polls for a state rather than sleeping a fixed interval: the pumps
// are goroutines and a fixed sleep is either flaky or slow.
func (h *detachHarness) waitState(sess *TerminalSession, want SessionState) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.RLock()
		got := sess.State
		sess.mu.RUnlock()
		if got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sess.mu.RLock()
	got := sess.State
	sess.mu.RUnlock()
	h.t.Fatalf("session did not reach state %q within 3s (still %q)", want, got)
}

func (h *detachHarness) attachOperator(sess *TerminalSession) *websocket.Conn {
	h.t.Helper()
	token, err := h.mgr.RotateOperatorToken(sess.SessionID)
	if err != nil {
		h.t.Fatalf("RotateOperatorToken failed: %v", err)
	}
	conn, _, err := h.dialOperator(sess, token)
	if err != nil {
		h.t.Fatalf("operator dial failed: %v", err)
	}
	return conn
}

func writeFrame(t *testing.T, conn *websocket.Conn, f TerminalFrame) {
	t.Helper()
	b, _ := json.Marshal(f)
	if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatalf("write frame failed: %v", err)
	}
}

// TestOperatorDropDetachesRatherThanKillingTheShell is the regression for the
// whole feature: an operator socket closing used to run Close(), which sends
// the agent a WebSocket close frame, which the agent answers by killing the
// remote process group. The agent socket must survive, untouched.
func TestOperatorDropDetachesRatherThanKillingTheShell(t *testing.T) {
	h := newDetachHarness(t, 15*time.Minute)
	sess := h.createSession("tenant-alpha", "linux-agent-detach")

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()
	opWS := h.attachOperator(sess)
	h.waitState(sess, StateActive)

	// Something in the recording before the detach, so continuity is testable.
	writeFrame(t, opWS, TerminalFrame{Type: FrameStdin, Data: []byte("echo one\n")})
	if _, _, err := agentWS.ReadMessage(); err != nil {
		t.Fatalf("agent did not receive pre-detach stdin: %v", err)
	}

	sess.mu.RLock()
	framesBefore := len(sess.Frames)
	sess.mu.RUnlock()

	// The operator's tab goes away.
	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	sess.mu.RLock()
	opConnected := sess.OperatorConnected
	agConnected := sess.AgentConnected
	recState := sess.RecordingState
	closedAt := sess.ClosedAt
	sess.mu.RUnlock()

	if opConnected {
		t.Fatalf("OperatorConnected must be false while detached")
	}
	if !agConnected {
		t.Fatalf("AgentConnected must stay true across a detach")
	}
	if recState == "sealed" {
		t.Fatalf("detach must not seal the recording: a sealed session cannot be resumed")
	}
	if closedAt != nil {
		t.Fatalf("detach must not set ClosedAt, got %v", closedAt)
	}

	// The agent socket is still usable, which is the proof the hub sent it no
	// close frame. Its output keeps landing in the same, still-open recording.
	writeFrame(t, agentWS, TerminalFrame{Type: FrameStdout, Data: []byte("still alive\n")})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.RLock()
		n := len(sess.Frames)
		sess.mu.RUnlock()
		if n > framesBefore {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("frame log did not continue across the detach (still %d frames)", framesBefore)
}

// TestReattachRotatesTheTokenAndRejectsTheOld covers the attach endpoint's
// security property: the connect token is single-attach.
func TestReattachRotatesTheTokenAndRejectsTheOld(t *testing.T) {
	h := newDetachHarness(t, 15*time.Minute)
	sess := h.createSession("tenant-alpha", "linux-agent-rotate")

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()

	firstToken, err := h.mgr.RotateOperatorToken(sess.SessionID)
	if err != nil {
		t.Fatalf("first rotate failed: %v", err)
	}
	opWS, _, err := h.dialOperator(sess, firstToken)
	if err != nil {
		t.Fatalf("first operator dial failed: %v", err)
	}
	h.waitState(sess, StateActive)

	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	secondToken, err := h.mgr.RotateOperatorToken(sess.SessionID)
	if err != nil {
		t.Fatalf("second rotate failed: %v", err)
	}
	if secondToken == firstToken {
		t.Fatalf("reattach must mint a different token")
	}

	// The token that opened the first attachment must not open a second one.
	if conn, resp, err := h.dialOperator(sess, firstToken); err == nil {
		conn.Close()
		t.Fatalf("the superseded token was accepted")
	} else if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a superseded token, got %d", resp.StatusCode)
	}

	opWS2, _, err := h.dialOperator(sess, secondToken)
	if err != nil {
		t.Fatalf("reattach with the rotated token failed: %v", err)
	}
	defer opWS2.Close()
	h.waitState(sess, StateActive)

	// I/O works again after reattach.
	writeFrame(t, opWS2, TerminalFrame{Type: FrameStdin, Data: []byte("echo back\n")})
	_ = agentWS.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := agentWS.ReadMessage()
	if err != nil {
		t.Fatalf("agent did not receive stdin after reattach: %v", err)
	}
	var f TerminalFrame
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(f.Data) != "echo back\n" {
		t.Fatalf("unexpected frame after reattach: %+v", f)
	}
}

// TestDetachedSessionSurvivesMoreThanTheQueueCap is the §5.2 regression.
//
// Nothing drains agentToOp while detached. If agentReadPump kept enqueueing,
// agQueueBytes would cross MaxQueueBytes and the pump would close the session -
// a detached `tail -f` or `yes` would destroy itself inside a second. The frames
// must be recorded and dropped from the queue instead.
func TestDetachedSessionSurvivesMoreThanTheQueueCap(t *testing.T) {
	h := newDetachHarness(t, 15*time.Minute)
	sess := h.createSession("tenant-alpha", "linux-agent-chatty")
	// Recording cap out of the way: this test is about the relay queue, and a
	// bounded recording is a separate, deliberate behaviour.
	h.mgr.SetMaxRecordingBytes(64 * 1024 * 1024)

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()
	opWS := h.attachOperator(sess)
	h.waitState(sess, StateActive)

	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	// Well past MaxQueueBytes (1 MiB): 64 writes of 32 KiB is 2 MiB.
	chunk := make([]byte, 32*1024)
	for i := range chunk {
		chunk[i] = 'y'
	}
	for i := 0; i < 64; i++ {
		_ = agentWS.SetWriteDeadline(time.Now().Add(5 * time.Second))
		writeFrame(t, agentWS, TerminalFrame{Type: FrameStdout, Data: chunk})
	}

	// Observe the read pump recording every frame before reattaching. A fixed
	// sleep can reattach early on a loaded race-test runner and miss output.
	deadline := time.Now().Add(3 * time.Second)
	for {
		sess.mu.RLock()
		state, reason := sess.State, sess.CloseReason
		var recorded int
		for _, frame := range sess.Frames {
			if frame.Type == FrameStdout {
				recorded++
			}
		}
		sess.mu.RUnlock()
		if state != StateDetached {
			t.Fatalf("2 MiB of detached stdout ended the session: state=%s reason=%s", state, reason)
		}
		if recorded >= 64 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("detached read pump recorded %d of 64 stdout frames within 3s", recorded)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// And it is still reattachable and still carries the output.
	opWS2 := h.attachOperator(sess)
	defer opWS2.Close()
	h.waitState(sess, StateActive)

	frames, _, err := h.mgr.GetSessionRecording("tenant-alpha", sess.SessionID)
	if err != nil {
		t.Fatalf("GetSessionRecording failed: %v", err)
	}
	var stdout int
	for _, f := range frames {
		if f.Type == FrameStdout {
			stdout++
		}
	}
	if stdout < 64 {
		t.Fatalf("expected the detached output to be recorded, got %d stdout frames", stdout)
	}
}

// TestDetachedSessionHoldsThePerEndpointCap: if a detached session did not hold
// its slot, a second create would succeed and the operator could never get back
// to the first shell.
func TestDetachedSessionHoldsThePerEndpointCap(t *testing.T) {
	h := newDetachHarness(t, 15*time.Minute)
	sess := h.createSession("tenant-alpha", "linux-agent-cap")

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()
	opWS := h.attachOperator(sess)
	h.waitState(sess, StateActive)

	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	_, err := h.mgr.CreateSession("tenant-alpha", "linux-agent-cap", "operator-bob", "/bin/bash", nil)
	if err == nil {
		t.Fatalf("a second session was created while one was detached on the same endpoint")
	}
	if got := err.Error(); got == "" {
		t.Fatalf("expected an explanatory error")
	}

	// A different endpoint is unaffected.
	if _, err := h.mgr.CreateSession("tenant-alpha", "linux-agent-other", "operator-bob", "/bin/bash", nil); err != nil {
		t.Fatalf("an unrelated endpoint was refused: %v", err)
	}
}

// TestDetachedSessionIdlesOutOnAgentOutputAlone is the §5.4 idle rule.
//
// RecordFrame used to push IdleExpiresAt forward on every frame including agent
// stdout, so a detached process that printed anything would hold a root shell
// open until the 60-minute max duration with nobody watching it. Only operator
// frames and attaching count as activity.
func TestDetachedSessionIdlesOutOnAgentOutputAlone(t *testing.T) {
	h := newDetachHarness(t, 150*time.Millisecond)
	sess := h.createSession("tenant-alpha", "linux-agent-idle")

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()
	opWS := h.attachOperator(sess)
	h.waitState(sess, StateActive)

	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	// Observe receipt through the real socket pump before checking the deadline.
	sess.mu.RLock()
	idleAt, frames := sess.IdleExpiresAt, sess.FrameCount
	sess.mu.RUnlock()
	for i := 0; i < 3; i++ {
		writeFrame(t, agentWS, TerminalFrame{Type: FrameStdout, Data: []byte(fmt.Sprintf("tick %d\n", i))})
	}
	received := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.RLock()
		received = sess.FrameCount >= frames+3
		sess.mu.RUnlock()
		if received {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !received {
		t.Fatal("agent output was not processed")
	}
	sess.mu.RLock()
	after := sess.IdleExpiresAt
	sess.mu.RUnlock()
	if !after.Equal(idleAt) {
		t.Fatal("agent output extended the operator idle deadline")
	}

	// The background sweep runs every five seconds. Waiting exactly five
	// seconds races its tick and previously failed while reporting state closed.
	// Exercise the same production sweep directly after the unchanged deadline.
	if remaining := time.Until(idleAt); remaining > 0 {
		time.Sleep(remaining)
	}
	h.mgr.Sweep()
	sess.mu.RLock()
	st := sess.State
	sess.mu.RUnlock()
	if st != StateExpired && st != StateClosed {
		t.Fatalf("expired detached session remains %s", st)
	}

}

// TestExplicitTerminateClosesAndSeals: terminating is still terminating. The
// agent gets its close frame - which is what kills the remote process tree -
// and the recording is sealed.
func TestExplicitTerminateClosesAndSeals(t *testing.T) {
	h := newDetachHarness(t, 15*time.Minute)
	sess := h.createSession("tenant-alpha", "linux-agent-terminate")

	agentWS := h.dialAgent(sess)
	defer agentWS.Close()
	opWS := h.attachOperator(sess)
	h.waitState(sess, StateActive)

	_ = opWS.Close()
	h.waitState(sess, StateDetached)

	if err := h.mgr.CloseSession(sess.SessionID, "operator_terminated"); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}
	h.waitState(sess, StateClosed)

	sess.mu.RLock()
	closedAt := sess.ClosedAt
	reason := sess.CloseReason
	sess.mu.RUnlock()
	if closedAt == nil {
		t.Fatalf("terminate must set ClosedAt")
	}
	if reason != "operator_terminated" {
		t.Fatalf("expected the operator's reason to be recorded, got %q", reason)
	}

	// The agent's socket is closed from this side, so a write eventually fails.
	// That failing write is the close frame the agent acts on to kill the tree.
	deadline := time.Now().Add(3 * time.Second)
	var writeErr error
	for time.Now().Before(deadline) {
		_ = agentWS.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		b, _ := json.Marshal(TerminalFrame{Type: FrameStdout, Data: []byte("orphan\n")})
		if writeErr = agentWS.WriteMessage(websocket.TextMessage, b); writeErr != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if writeErr == nil {
		t.Fatalf("the agent connection was left open after an explicit terminate")
	}

	// And it cannot be attached to again.
	if _, err := h.mgr.RotateOperatorToken(sess.SessionID); err == nil {
		t.Fatalf("a closed session accepted a token rotation")
	}
}
