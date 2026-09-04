package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/terminal"
)

func TestServer_TerminalAPI(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-shell-node-1"
	opID := "admin"

	// 1. Setup tenant key and response session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-shell-sess", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// 2. Operator requests terminal session with signed browser proof
	payload := response.TerminalSessionPayload{
		Program: "/bin/bash",
	}
	actionDigest, _ := response.ComputeActionDigest(payload)

	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindTerminalSession,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "554433221100",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":   endpointID,
		"program":       "/bin/bash",
		"session_id":    session.SessionID,
		"action_digest": actionDigest,
		"proof":         proof,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create terminal session returned %d: %s", w.Code, w.Body.String())
	}

	var sessionResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&sessionResp); err != nil {
		t.Fatalf("failed to decode session response: %v", err)
	}
	sessionID := sessionResp["session_id"].(string)

	// 3. Record Terminal Frames (Audit stream)
	frameBody, _ := json.Marshal(map[string]interface{}{
		"session_id": sessionID,
		"frame": terminal.TerminalFrame{
			Type: terminal.FrameStdout,
			Data: []byte("Linux shell session established\n"),
		},
	})
	reqFrame := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/frames", bytes.NewReader(frameBody))
	reqFrame.Header.Set("X-API-Key", "test-admin-key-12345")
	reqFrame.Header.Set("Content-Type", "application/json")
	wFrame := httptest.NewRecorder()
	handler.ServeHTTP(wFrame, reqFrame)

	if wFrame.Code != http.StatusOK {
		t.Fatalf("record frame returned %d: %s", wFrame.Code, wFrame.Body.String())
	}

	// 4. Close Session
	closeBody, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"reason":     "operator_disconnect",
	})
	reqClose := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions/close", bytes.NewReader(closeBody))
	reqClose.Header.Set("X-API-Key", "test-admin-key-12345")
	reqClose.Header.Set("Content-Type", "application/json")
	wClose := httptest.NewRecorder()
	handler.ServeHTTP(wClose, reqClose)

	if wClose.Code != http.StatusOK {
		t.Fatalf("close session returned %d: %s", wClose.Code, wClose.Body.String())
	}
}

func TestServer_TerminalWebSocketRelay(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tenantID := "default"
	endpointID := "ep-shell-relay-test"
	opID := "admin"

	// 1. Setup tenant key and response session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-relay-sess", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// 2. Operator requests terminal session with signed browser proof
	payload := response.TerminalSessionPayload{Program: "/bin/bash"}
	actionDigest, _ := response.ComputeActionDigest(payload)
	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindTerminalSession,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "998877665544",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":   endpointID,
		"program":       "/bin/bash",
		"session_id":    session.SessionID,
		"action_digest": actionDigest,
		"proof":         proof,
	})

	postReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/terminal/sessions", bytes.NewReader(createBody))
	postReq.Header.Set("X-API-Key", "test-admin-key-12345")
	postReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST /api/v1/terminal/sessions failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session returned status %d", resp.StatusCode)
	}

	// Verify token is NOT exposed in response body
	var bodyMap map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&bodyMap)
	if _, found := bodyMap["connect_token"]; found {
		t.Fatalf("connect_token leaked in session DTO response: %+v", bodyMap)
	}
	sessionID := bodyMap["session_id"].(string)

	// Verify HttpOnly attach cookie was delivered
	var attachCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "ominull_terminal_token" {
			attachCookie = c
			break
		}
	}
	if attachCookie == nil || attachCookie.Value == "" {
		t.Fatalf("expected ominull_terminal_token cookie to be set on response")
	}
	if !attachCookie.HttpOnly {
		t.Fatalf("expected attach cookie to have HttpOnly=true")
	}
	token := attachCookie.Value

	// Helper for ws URLs
	toWS := func(path string, query url.Values) string {
		u, _ := url.Parse(ts.URL)
		u.Scheme = "ws"
		u.Path = path
		u.RawQuery = query.Encode()
		return u.String()
	}

	// 3. Connect Operator using token
	opQuery := url.Values{"session_id": []string{sessionID}, "token": []string{token}}
	opWS, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/terminal/ws/operator", opQuery), nil)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opWS.Close()

	// 4. Connect Agent using token and endpoint_id
	agQuery := url.Values{"session_id": []string{sessionID}, "endpoint_id": []string{endpointID}, "token": []string{token}}
	agWS, _, err := websocket.DefaultDialer.Dial(toWS("/api/v1/terminal/ws/agent", agQuery), nil)
	if err != nil {
		t.Fatalf("agent dial failed: %v", err)
	}
	defer agWS.Close()

	time.Sleep(100 * time.Millisecond)

	// 5. Test Operator -> Agent stdin transmission
	inFrame := terminal.TerminalFrame{Type: terminal.FrameStdin, Data: []byte("ls -la\n")}
	inBytes, _ := json.Marshal(inFrame)
	if err := opWS.WriteMessage(websocket.TextMessage, inBytes); err != nil {
		t.Fatalf("opWS write failed: %v", err)
	}

	_, agRcvd, err := agWS.ReadMessage()
	if err != nil {
		t.Fatalf("agWS read failed: %v", err)
	}
	var rcvdFrame terminal.TerminalFrame
	_ = json.Unmarshal(agRcvd, &rcvdFrame)
	if rcvdFrame.Type != terminal.FrameStdin || string(rcvdFrame.Data) != "ls -la\n" {
		t.Fatalf("unexpected frame received by agent: %+v", rcvdFrame)
	}

	// 6. Test Agent -> Operator stdout transmission
	outFrame := terminal.TerminalFrame{Type: terminal.FrameStdout, Data: []byte("total 0\n")}
	outBytes, _ := json.Marshal(outFrame)
	if err := agWS.WriteMessage(websocket.TextMessage, outBytes); err != nil {
		t.Fatalf("agWS write failed: %v", err)
	}

	_, opRcvd, err := opWS.ReadMessage()
	if err != nil {
		t.Fatalf("opWS read failed: %v", err)
	}
	var rcvdOpFrame terminal.TerminalFrame
	_ = json.Unmarshal(opRcvd, &rcvdOpFrame)
	if rcvdOpFrame.Type != terminal.FrameStdout || string(rcvdOpFrame.Data) != "total 0\n" {
		t.Fatalf("unexpected frame received by operator: %+v", rcvdOpFrame)
	}

	// 7. Clean close: agent sends close
	clsFrame := terminal.TerminalFrame{Type: terminal.FrameClose}
	clsBytes, _ := json.Marshal(clsFrame)
	_ = agWS.WriteMessage(websocket.TextMessage, clsBytes)

	opWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = opWS.ReadMessage()
	if err == nil {
		t.Fatalf("expected operator socket to close after agent close")
	}
}

func TestTerminalSession_DeleteClose(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	endpointID := "ep-term-del-test"
	tenantID := "default"
	operatorID := "admin"

	// 1. Setup response authority session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, operatorID)
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "browser-del", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	payload := response.TerminalSessionPayload{Program: "/bin/sh"}
	actionDigest, _ := response.ComputeActionDigest(payload)

	proof := &responseauth.ActionProof{
		Version:         2,
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindTerminalSession,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "12345678123456781234567812345678",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":   endpointID,
		"program":       "/bin/sh",
		"session_id":    session.SessionID,
		"action_digest": actionDigest,
		"proof":         proof,
	})

	postReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/terminal/sessions", bytes.NewReader(createBody))
	postReq.Header.Set("X-API-Key", "test-admin-key-12345")
	postReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer resp.Body.Close()

	var bodyMap map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&bodyMap)
	sessionID := bodyMap["session_id"].(string)

	// DELETE /api/v1/terminal/sessions?id=sessionID
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/terminal/sessions?id="+sessionID, nil)
	delReq.Header.Set("X-API-Key", "test-admin-key-12345")
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	defer delResp.Body.Close()

	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from DELETE, got %d", delResp.StatusCode)
	}

	// Verify session is now in closed state
	sess, err := srv.terminalMgr.GetSession(sessionID)
	if err != nil {
		t.Fatalf("failed to get session after delete: %v", err)
	}
	if sess.State != terminal.StateClosed {
		t.Fatalf("expected session state to be closed, got %s", sess.State)
	}
}

