package terminal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
)

func TestTerminalRelay_AuthenticatedLoopback(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 15*time.Minute)
	defer mgr.Close()
	tenantID := "tenant-alpha"
	endpointID := "linux-agent-01"
	opID := "operator-alice"
	program := "/bin/bash"

	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-terminal-loopback",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "digest-0011223344",
		OperatorID:        opID,
		ResponseSessionID: "resp-session-1234",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}

	// 1. Create session and obtain plaintext token
	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	token := sess.ConnectToken
	if token == "" {
		t.Fatalf("expected non-empty connect token")
	}

	// Verify token is NOT exposed in Summary() DTO
	summary := sess.Summary()
	if _, found := summary["connect_token"]; found {
		t.Fatalf("connect_token leaked in session Summary() DTO: %+v", summary)
	}
	if _, found := summary["token_hash"]; found {
		t.Fatalf("token_hash leaked in session Summary() DTO: %+v", summary)
	}

	// 2. Set up HTTP test server with WSS routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/terminal/ws/operator", func(w http.ResponseWriter, r *http.Request) {
		sessID := r.URL.Query().Get("session_id")
		tok := r.URL.Query().Get("token")
		if err := mgr.AttachOperator(w, r, sessID, tok); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	})
	mux.HandleFunc("/api/v1/terminal/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		sessID := r.URL.Query().Get("session_id")
		epID := r.URL.Query().Get("endpoint_id")
		tok := r.URL.Query().Get("token")
		if err := mgr.AttachAgent(w, r, sessID, epID, tok); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := func(path string, query url.Values) string {
		u, _ := url.Parse(server.URL)
		u.Scheme = "ws"
		u.Path = path
		u.RawQuery = query.Encode()
		return u.String()
	}

	// 3. Test unauthenticated operator rejection
	badOpQuery := url.Values{
		"session_id": []string{sess.SessionID},
		"token":      []string{"wrong-token-invalid"},
	}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL("/api/v1/terminal/ws/operator", badOpQuery), nil)
	if err == nil {
		t.Fatalf("expected unauthenticated operator connection to be rejected")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad token, got %d", resp.StatusCode)
	}

	// 4. Test agent endpoint mismatch rejection
	badAgentQuery := url.Values{
		"session_id":  []string{sess.SessionID},
		"endpoint_id": []string{"wrong-endpoint-id"},
		"token":       []string{token},
	}
	_, resp, err = websocket.DefaultDialer.Dial(wsURL("/api/v1/terminal/ws/agent", badAgentQuery), nil)
	if err == nil {
		t.Fatalf("expected mismatched endpoint ID to be rejected")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for mismatched endpoint, got %d", resp.StatusCode)
	}

	// 5. Connect Operator with valid credentials
	validOpQuery := url.Values{
		"session_id": []string{sess.SessionID},
		"token":      []string{token},
	}
	opWS, _, err := websocket.DefaultDialer.Dial(wsURL("/api/v1/terminal/ws/operator", validOpQuery), nil)
	if err != nil {
		t.Fatalf("operator websocket dial failed: %v", err)
	}
	defer opWS.Close()

	// 6. Connect Agent with valid credentials
	validAgentQuery := url.Values{
		"session_id":  []string{sess.SessionID},
		"endpoint_id": []string{endpointID},
		"token":       []string{token},
	}
	agentWS, _, err := websocket.DefaultDialer.Dial(wsURL("/api/v1/terminal/ws/agent", validAgentQuery), nil)
	if err != nil {
		t.Fatalf("agent websocket dial failed: %v", err)
	}
	defer agentWS.Close()

	// Wait briefly for pairing and active state transition
	time.Sleep(100 * time.Millisecond)
	sess.mu.RLock()
	if sess.State != StateActive {
		t.Fatalf("expected session state to be active after pairing, got %s", sess.State)
	}
	if !sess.OperatorConnected || !sess.AgentConnected {
		t.Fatalf("expected both OperatorConnected and AgentConnected to be true")
	}
	sess.mu.RUnlock()

	// 7. Bidirectional Loopback Test:
	// a. Operator sends stdin -> Agent receives stdin
	stdinFrame := TerminalFrame{
		Type: FrameStdin,
		Data: []byte("uname -a\n"),
	}
	stdinBytes, _ := json.Marshal(stdinFrame)
	if err := opWS.WriteMessage(websocket.TextMessage, stdinBytes); err != nil {
		t.Fatalf("operator write stdin failed: %v", err)
	}

	_, rcvdByAgent, err := agentWS.ReadMessage()
	if err != nil {
		t.Fatalf("agent failed to read stdin: %v", err)
	}
	var agentFrame TerminalFrame
	if err := json.Unmarshal(rcvdByAgent, &agentFrame); err != nil {
		t.Fatalf("failed to decode agent received frame: %v", err)
	}
	if agentFrame.Type != FrameStdin || string(agentFrame.Data) != "uname -a\n" {
		t.Fatalf("unexpected frame received by agent: %+v", agentFrame)
	}

	// b. Agent sends stdout -> Operator receives stdout
	stdoutFrame := TerminalFrame{
		Type: FrameStdout,
		Data: []byte("Linux ominull-agent 6.1.0-amd64\n"),
	}
	stdoutBytes, _ := json.Marshal(stdoutFrame)
	if err := agentWS.WriteMessage(websocket.TextMessage, stdoutBytes); err != nil {
		t.Fatalf("agent write stdout failed: %v", err)
	}

	_, rcvdByOp, err := opWS.ReadMessage()
	if err != nil {
		t.Fatalf("operator failed to read stdout: %v", err)
	}
	var opFrame TerminalFrame
	if err := json.Unmarshal(rcvdByOp, &opFrame); err != nil {
		t.Fatalf("failed to decode operator received frame: %v", err)
	}
	if opFrame.Type != FrameStdout || !strings.Contains(string(opFrame.Data), "ominull-agent") {
		t.Fatalf("unexpected frame received by operator: %+v", opFrame)
	}

	// c. Operator sends resize -> Agent receives resize
	resizeFrame := TerminalFrame{
		Type: FrameResize,
		Rows: 35,
		Cols: 110,
	}
	resizeBytes, _ := json.Marshal(resizeFrame)
	if err := opWS.WriteMessage(websocket.TextMessage, resizeBytes); err != nil {
		t.Fatalf("operator write resize failed: %v", err)
	}

	_, rcvdResize, err := agentWS.ReadMessage()
	if err != nil {
		t.Fatalf("agent failed to read resize: %v", err)
	}
	var rFrame TerminalFrame
	if err := json.Unmarshal(rcvdResize, &rFrame); err != nil {
		t.Fatalf("failed to decode agent received resize: %v", err)
	}
	if rFrame.Type != FrameResize || rFrame.Rows != 35 || rFrame.Cols != 110 {
		t.Fatalf("unexpected resize frame received by agent: %+v", rFrame)
	}

	// 8. Clean Closure: Agent sends close frame
	closeFrame := TerminalFrame{
		Type: FrameClose,
	}
	closeBytes, _ := json.Marshal(closeFrame)
	_ = agentWS.WriteMessage(websocket.TextMessage, closeBytes)

	// Operator should see WebSocket close
	opWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = opWS.ReadMessage()
	if err == nil {
		t.Fatalf("expected operator connection to close after agent close")
	}

	time.Sleep(100 * time.Millisecond)
	sess.mu.RLock()
	if sess.State != StateClosed {
		t.Fatalf("expected session state to transition to closed, got %s", sess.State)
	}
	if sess.CloseReason == "" {
		t.Fatalf("expected non-empty close reason")
	}
	sess.mu.RUnlock()
}

func TestTerminalRelay_ForbiddenFrameTypes(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 15*time.Minute)
	defer mgr.Close()
	tenantID := "tenant-beta"
	endpointID := "linux-agent-02"

	grant := &response.EndpointGrant{
		Version:    response.GrantVersion,
		GrantID:    "grant-forbidden-test",
		TenantID:   tenantID,
		EndpointID: endpointID,
		ActionKind: response.ActionKindTerminalSession,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
	}

	sess, err := mgr.CreateSession(tenantID, endpointID, "admin", "/bin/sh", grant)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/operator", func(w http.ResponseWriter, r *http.Request) {
		_ = mgr.AttachOperator(w, r, sess.SessionID, sess.ConnectToken)
	})
	mux.HandleFunc("/agent", func(w http.ResponseWriter, r *http.Request) {
		_ = mgr.AttachAgent(w, r, sess.SessionID, endpointID, sess.ConnectToken)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	u.Path = "/operator"
	opWS, _, _ := websocket.DefaultDialer.Dial(u.String(), nil)
	defer opWS.Close()

	u.Path = "/agent"
	agWS, _, _ := websocket.DefaultDialer.Dial(u.String(), nil)
	defer agWS.Close()

	time.Sleep(50 * time.Millisecond)

	// Operator attempting to send FrameStdout is a protocol violation
	forbiddenFrame := TerminalFrame{
		Type: FrameStdout,
		Data: []byte("forged output from operator"),
	}
	data, _ := json.Marshal(forbiddenFrame)
	_ = opWS.WriteMessage(websocket.TextMessage, data)

	// Connection should be closed by relay due to protocol violation
	opWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = opWS.ReadMessage()
	if err == nil {
		t.Fatalf("expected operator connection to be closed after sending forbidden frame type")
	}
}
