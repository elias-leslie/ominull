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
	"ominull/hub/pkg/scripts"
)

func TestServer_ScriptsAPI(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-script-node-1"
	opID := "admin"

	// 1. Create Script Definition
	createBody, _ := json.Marshal(map[string]string{
		"name":        "check_uptime.sh",
		"description": "Checks system uptime and kernel",
		"interpreter": "/bin/sh",
		"source":      "uptime && uname -r\n",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create script returned %d: %s", w.Code, w.Body.String())
	}

	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	if err := json.NewDecoder(w.Body).Decode(&createResp); err != nil {
		t.Fatalf("failed to decode create script response: %v", err)
	}

	// 2. Setup response session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-script-sess", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// 3. Dispatch Script Run with signed ActionProof
	actionPayload := response.ScriptExecPayload{
		ScriptID:      createResp.Script.ID,
		ScriptVersion: 1,
		ScriptDigest:  createResp.Version.DigestSHA256,
		Source:        createResp.Version.Source,
	}
	actionDigest, _ := response.ComputeActionDigest(actionPayload)

	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "1122334455aabbcc",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	runBody, _ := json.Marshal(map[string]interface{}{
		"script_id":     createResp.Script.ID,
		"version":       1,
		"endpoint_id":   endpointID,
		"session_id":    session.SessionID,
		"action_digest": actionDigest,
		"proof":         proof,
	})

	reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
	reqRun.Header.Set("X-API-Key", "test-admin-key-12345")
	reqRun.Header.Set("Content-Type", "application/json")
	wRun := httptest.NewRecorder()
	handler.ServeHTTP(wRun, reqRun)

	if wRun.Code != http.StatusCreated {
		t.Fatalf("run script returned %d: %s", wRun.Code, wRun.Body.String())
	}

	var job response.JobRecord
	if err := json.NewDecoder(wRun.Body).Decode(&job); err != nil {
		t.Fatalf("failed to decode script job response: %v", err)
	}
	if job.Kind != response.ActionKindScriptExec || job.State != response.StateQueued {
		t.Fatalf("unexpected script job: %+v", job)
	}
}
