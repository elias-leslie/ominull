package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/terminal"
)

func TestServer_TerminalAPI(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-shell-node-1"
	opID := "admin"

	_ = auth
	seedTerminalEndpoint(t, srv, tenantID, endpointID)
	createBody, _ := json.Marshal(map[string]interface{}{"endpoint_id": endpointID, "program": "/bin/bash"})

	jwtToken, err := hubauth.GenerateJWT(hubauth.Claims{
		Username: opID,
		Role:     hubauth.RoleAdmin,
		TenantID: tenantID,
	}, "test-admin-key-12345", time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	// The static API key alone only asks: it gets an approval, not a shell.
	reqAPIKey := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", bytes.NewReader(createBody))
	reqAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	reqAPIKey.Header.Set("Content-Type", "application/json")
	wAPIKey := httptest.NewRecorder()
	handler.ServeHTTP(wAPIKey, reqAPIKey)
	if wAPIKey.Code != http.StatusAccepted {
		t.Fatalf("expected 202 (owner approval requested) for static API key, got %d: %s", wAPIKey.Code, wAPIKey.Body.String())
	}
	if srv.terminalMgr.ListSessions(tenantID) != nil && len(srv.terminalMgr.ListSessions(tenantID)) != 0 {
		t.Fatal("a session exists before the owner approved")
	}
	// A made-up approval id is refused.
	reqForged := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", bytes.NewReader(createBody))
	reqForged.Header.Set("Authorization", "Bearer "+jwtToken)
	reqForged.Header.Set(approvalHeader, "00000000000000000000000000000000")
	wForged := httptest.NewRecorder()
	handler.ServeHTTP(wForged, reqForged)
	if wForged.Code != http.StatusForbidden {
		t.Fatalf("forged approval id answered %d, want 403", wForged.Code)
	}

	// Authorized operator create request, approved by the owner
	req := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")
	w := serveApproved(t, srv, handler, req, string(createBody))

	if w.Code != http.StatusCreated {
		t.Fatalf("create terminal session returned %d: %s", w.Code, w.Body.String())
	}

	var sessionResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&sessionResp); err != nil {
		t.Fatalf("failed to decode session response: %v", err)
	}
	sessionID := sessionResp["session_id"].(string)

	// 3. External frame injection POST /api/v1/terminal/frames MUST be rejected
	frameBody, _ := json.Marshal(map[string]interface{}{
		"session_id": sessionID,
		"frame": terminal.TerminalFrame{
			Type: terminal.FrameStdout,
			Data: []byte("Linux shell session established\n"),
		},
	})
	reqFrame := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/frames", bytes.NewReader(frameBody))
	reqFrame.Header.Set("Authorization", "Bearer "+jwtToken)
	reqFrame.Header.Set("Content-Type", "application/json")
	wFrame := httptest.NewRecorder()
	handler.ServeHTTP(wFrame, reqFrame)

	if wFrame.Code != http.StatusForbidden {
		t.Fatalf("expected external frame injection to be 403 Forbidden, got %d: %s", wFrame.Code, wFrame.Body.String())
	}

	// Record frame legitimately via internal manager (as relay does)
	_ = srv.terminalMgr.RecordFrame(sessionID, terminal.TerminalFrame{
		Type:      terminal.FrameStdout,
		Data:      []byte("Linux shell session established\n"),
		Timestamp: time.Now().UTC(),
	})

	// 4. Query frames via GET /api/v1/terminal/frames while active
	// Static API key query must be rejected
	reqGetAPIKey := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/frames?session_id="+sessionID, nil)
	reqGetAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	wGetAPIKey := httptest.NewRecorder()
	handler.ServeHTTP(wGetAPIKey, reqGetAPIKey)
	if wGetAPIKey.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for static API key on frame query, got %d", wGetAPIKey.Code)
	}

	// Authorized operator query succeeds
	reqGetLive := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/frames?session_id="+sessionID, nil)
	reqGetLive.Header.Set("Authorization", "Bearer "+jwtToken)
	wGetLive := httptest.NewRecorder()
	handler.ServeHTTP(wGetLive, reqGetLive)
	if wGetLive.Code != http.StatusOK {
		t.Fatalf("live frame query failed: %d: %s", wGetLive.Code, wGetLive.Body.String())
	}
	var liveData struct {
		Metadata terminal.SessionRecordingMetadata `json:"metadata"`
		Frames   []terminal.TerminalFrame          `json:"frames"`
	}
	if err := json.NewDecoder(wGetLive.Body).Decode(&liveData); err != nil {
		t.Fatalf("decode live frames failed: %v", err)
	}
	if len(liveData.Frames) != 1 || liveData.Metadata.FrameCount != 1 {
		t.Fatalf("expected 1 frame recorded, got %d (meta %d)", len(liveData.Frames), liveData.Metadata.FrameCount)
	}
	if liveData.Metadata.RecordingState != "recording" {
		t.Fatalf("expected recording state 'recording', got %s", liveData.Metadata.RecordingState)
	}

	// 5. Close Session via POST /api/v1/terminal/sessions/close
	closeBody, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"reason":     "operator_disconnect",
	})
	reqClose := httptest.NewRequest(http.MethodPost, "/api/v1/terminal/sessions/close", bytes.NewReader(closeBody))
	reqClose.Header.Set("Authorization", "Bearer "+jwtToken)
	reqClose.Header.Set("Content-Type", "application/json")
	wClose := httptest.NewRecorder()
	handler.ServeHTTP(wClose, reqClose)

	if wClose.Code != http.StatusOK {
		t.Fatalf("close session returned %d: %s", wClose.Code, wClose.Body.String())
	}

	// 6. Query frames after session closure: must be sealed into evidence store
	reqGetSealed := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/frames?session_id="+sessionID, nil)
	reqGetSealed.Header.Set("Authorization", "Bearer "+jwtToken)
	wGetSealed := httptest.NewRecorder()
	handler.ServeHTTP(wGetSealed, reqGetSealed)
	if wGetSealed.Code != http.StatusOK {
		t.Fatalf("sealed frame query failed: %d: %s", wGetSealed.Code, wGetSealed.Body.String())
	}
	var sealedData struct {
		Metadata terminal.SessionRecordingMetadata `json:"metadata"`
		Frames   []terminal.TerminalFrame          `json:"frames"`
	}
	if err := json.NewDecoder(wGetSealed.Body).Decode(&sealedData); err != nil {
		t.Fatalf("decode sealed frames failed: %v", err)
	}
	if len(sealedData.Frames) != 1 {
		t.Fatalf("expected 1 frame in sealed store, got %d", len(sealedData.Frames))
	}
	if sealedData.Metadata.RecordingState != "sealed" {
		t.Fatalf("expected recording_state 'sealed', got %s", sealedData.Metadata.RecordingState)
	}
	if sealedData.Metadata.BundleID == "" || sealedData.Metadata.EvidenceItemID == "" {
		t.Fatalf("expected bundle_id and evidence_item_id to be populated, got bundle=%s item=%s",
			sealedData.Metadata.BundleID, sealedData.Metadata.EvidenceItemID)
	}
	if !strings.Contains(sealedData.Metadata.Encryption, "AES-256-GCM") {
		t.Fatalf("expected AES-256-GCM encryption label, got %s", sealedData.Metadata.Encryption)
	}
	if string(sealedData.Frames[0].Data) != "Linux shell session established\n" {
		t.Fatalf("unexpected decrypted frame content: %s", string(sealedData.Frames[0].Data))
	}
}

func TestServer_TerminalWebSocketRelay(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tenantID := "default"
	endpointID := "ep-shell-relay-test"
	opID := "admin"

	_ = auth
	seedTerminalEndpoint(t, srv, tenantID, endpointID)
	createBody, _ := json.Marshal(map[string]interface{}{"endpoint_id": endpointID, "program": "/bin/bash"})

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{
		Username: opID,
		Role:     hubauth.RoleAdmin,
		TenantID: tenantID,
	}, "test-admin-key-12345", time.Hour)

	client := &http.Client{}
	resp := doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/terminal/sessions", string(createBody), func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwtToken) })
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
		if c.Name == terminalCookieName(sessionID) {
			attachCookie = c
			break
		}
	}
	if attachCookie == nil || attachCookie.Value == "" {
		t.Fatalf("expected the per-session attach cookie to be set on response")
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

	// Give a moment for closing pump and evidence sealing to complete
	time.Sleep(150 * time.Millisecond)

	// 8. Query frames through evidence store
	frameReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/terminal/frames?session_id="+sessionID, nil)
	frameReq.Header.Set("Authorization", "Bearer "+jwtToken)
	frameResp, err := client.Do(frameReq)
	if err != nil {
		t.Fatalf("GET /api/v1/terminal/frames failed: %v", err)
	}
	defer frameResp.Body.Close()

	if frameResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from GET frames, got %d", frameResp.StatusCode)
	}

	var sealedResult struct {
		Metadata terminal.SessionRecordingMetadata `json:"metadata"`
		Frames   []terminal.TerminalFrame          `json:"frames"`
	}
	if err := json.NewDecoder(frameResp.Body).Decode(&sealedResult); err != nil {
		t.Fatalf("decode sealedResult failed: %v", err)
	}

	if sealedResult.Metadata.RecordingState != "sealed" {
		t.Fatalf("expected recording_state 'sealed', got %s", sealedResult.Metadata.RecordingState)
	}
	if sealedResult.Metadata.BundleID == "" {
		t.Fatalf("expected bundle_id to be present")
	}
	if len(sealedResult.Frames) < 3 {
		t.Fatalf("expected at least 3 frames (stdin, stdout, close), got %d: %+v", len(sealedResult.Frames), sealedResult.Frames)
	}
}

func TestTerminalSession_DeleteClose(t *testing.T) {
	t.Parallel()
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	endpointID := "ep-term-del-test"
	tenantID := "default"
	operatorID := "admin"

	_ = auth
	seedTerminalEndpoint(t, srv, tenantID, endpointID)
	createBody, _ := json.Marshal(map[string]interface{}{"endpoint_id": endpointID, "program": "/bin/sh"})

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{
		Username: operatorID,
		Role:     hubauth.RoleAdmin,
		TenantID: tenantID,
	}, "test-admin-key-12345", time.Hour)

	client := &http.Client{}
	resp := doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/terminal/sessions", string(createBody), func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwtToken) })
	defer resp.Body.Close()

	var bodyMap map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&bodyMap)
	sessionID := bodyMap["session_id"].(string)

	// DELETE with static API key must be rejected
	delReqAPIKey, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/terminal/sessions?id="+sessionID, nil)
	delReqAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	delRespAPIKey, err := client.Do(delReqAPIKey)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	defer delRespAPIKey.Body.Close()
	if delRespAPIKey.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for static API key DELETE, got %d", delRespAPIKey.StatusCode)
	}

	// DELETE /api/v1/terminal/sessions?id=sessionID with JWT
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/terminal/sessions?id="+sessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+jwtToken)
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

func TestServer_TerminalSecurityGates(t *testing.T) {
	t.Parallel()
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := &http.Client{}

	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"
	endpointID := "ep-sec-node-1"

	_ = auth
	seedTerminalEndpoint(t, srv, tenantA, endpointID)

	jwtAdminA, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "adminA", Role: hubauth.RoleAdmin, TenantID: tenantA}, "test-admin-key-12345", time.Hour)
	jwtAdminB, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "adminB", Role: hubauth.RoleAdmin, TenantID: tenantB}, "test-admin-key-12345", time.Hour)
	jwtAuditorA, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "auditorA", Role: hubauth.RoleAuditor, TenantID: tenantA}, "test-admin-key-12345", time.Hour)

	_ = store.UpsertOperator("auditorA@example.com", hubauth.RoleAuditor, "test")

	// 1. Static API Key Rejection on GET /api/v1/terminal/sessions
	reqGetSessionsAPIKey, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/terminal/sessions", nil)
	reqGetSessionsAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	resp, _ := client.Do(reqGetSessionsAPIKey)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on GET terminal sessions with static API key, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Create Session under Tenant A
	createBody, _ := json.Marshal(map[string]interface{}{"endpoint_id": endpointID, "program": "/bin/sh"})
	resp = doApproved(t, srv, client, http.MethodPost, ts.URL+"/api/v1/terminal/sessions", string(createBody), func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+jwtAdminA) })
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session A failed: code %d", resp.StatusCode)
	}
	var createdMap map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&createdMap)
	resp.Body.Close()
	sessionID := createdMap["session_id"].(string)

	// 3. Cross-Tenant Frame Isolation: Tenant B attempts to read Tenant A's session frames
	reqCrossFrames, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/terminal/frames?session_id="+sessionID, nil)
	reqCrossFrames.Header.Set("Authorization", "Bearer "+jwtAdminB)
	resp, _ = client.Do(reqCrossFrames)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant frame access, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Cross-Tenant Session Close: Tenant B attempts to close Tenant A's session
	closeBody, _ := json.Marshal(map[string]string{"session_id": sessionID})
	reqCrossClose, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/terminal/sessions/close", bytes.NewReader(closeBody))
	reqCrossClose.Header.Set("Authorization", "Bearer "+jwtAdminB)
	reqCrossClose.Header.Set("Content-Type", "application/json")
	resp, _ = client.Do(reqCrossClose)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant close, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. Auditor Role Permissions:
	// Auditor CAN inspect frames
	reqAuditorFrames, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/terminal/frames?session_id="+sessionID, nil)
	reqAuditorFrames.Header.Set("Authorization", "Bearer "+jwtAuditorA)
	resp, _ = client.Do(reqAuditorFrames)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for auditor reading frames, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Auditor CANNOT close session
	reqAuditorClose, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/terminal/sessions/close", bytes.NewReader(closeBody))
	reqAuditorClose.Header.Set("Authorization", "Bearer "+jwtAuditorA)
	reqAuditorClose.Header.Set("Content-Type", "application/json")
	resp, _ = client.Do(reqAuditorClose)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for auditor closing session, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. Ingress Header Spoofing: Client attempts to send forged identity headers
	reqSpoof, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/terminal/sessions", nil)
	reqSpoof.Header.Set("X-Auth-Method", "jwt")
	reqSpoof.Header.Set("X-Role", "admin")
	reqSpoof.Header.Set("X-Tenant-ID", tenantA)
	// Without actual Authorization or cookie
	resp, _ = client.Do(reqSpoof)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for forged headers without valid credential, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
