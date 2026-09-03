package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
