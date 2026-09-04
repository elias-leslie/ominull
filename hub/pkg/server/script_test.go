package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

func TestServer_ScriptsAPI(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-script-node-1"
	opID := "admin"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID,
		Hostname: "script-host",
		OS:       "linux",
		TenantID: tenantID,
	})

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
		ScriptID:       createResp.Script.ID,
		ScriptVersion:  1,
		ScriptDigest:   createResp.Version.DigestSHA256,
		Interpreter:    createResp.Script.Interpreter,
		Source:         createResp.Version.Source,
		TimeoutSeconds: 60,
		MaxOutputBytes: 1048576,
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

	// Gated: static API key must be rejected with 403 Forbidden
	reqRunAPIKey := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
	reqRunAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	reqRunAPIKey.Header.Set("Content-Type", "application/json")
	wRunAPIKey := httptest.NewRecorder()
	handler.ServeHTTP(wRunAPIKey, reqRunAPIKey)

	if wRunAPIKey.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for static API key on script run, got %d: %s", wRunAPIKey.Code, wRunAPIKey.Body.String())
	}

	// Console session: JWT authenticated operator succeeds
	jwtToken, err := hubauth.GenerateJWT(hubauth.Claims{
		Username: opID,
		Role:     hubauth.RoleAdmin,
		TenantID: tenantID,
	}, "test-admin-key-12345", time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
	reqRun.Header.Set("Authorization", "Bearer "+jwtToken)
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

func TestServer_Scripts_TenantIsolation(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"
	opA := "operator-a"
	opB := "operator-b"
	epA := "ep-alpha-1"
	epB := "ep-beta-1"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       epA,
		Hostname: "alpha-host",
		OS:       "linux",
		TenantID: tenantA,
	})
	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       epB,
		Hostname: "beta-host",
		OS:       "linux",
		TenantID: tenantB,
	})

	jwtA, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opA, Role: hubauth.RoleAdmin, TenantID: tenantA}, "test-admin-key-12345", time.Hour)
	jwtB, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opB, Role: hubauth.RoleAdmin, TenantID: tenantB}, "test-admin-key-12345", time.Hour)

	// 1. Create Script in Tenant A
	createBody, _ := json.Marshal(map[string]string{
		"name":        "alpha_script.sh",
		"description": "Tenant A proprietary script",
		"interpreter": "/bin/bash",
		"source":      "echo alpha\n",
	})
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(createBody))
	reqCreate.Header.Set("Authorization", "Bearer "+jwtA)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create script in tenant A failed: %d: %s", wCreate.Code, wCreate.Body.String())
	}
	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	_ = json.NewDecoder(wCreate.Body).Decode(&createResp)
	scriptID := createResp.Script.ID

	// 2. Tenant B attempts to read Tenant A's script metadata -> 404
	reqGetB := httptest.NewRequest(http.MethodGet, "/api/v1/scripts?id="+scriptID, nil)
	reqGetB.Header.Set("Authorization", "Bearer "+jwtB)
	wGetB := httptest.NewRecorder()
	handler.ServeHTTP(wGetB, reqGetB)
	if wGetB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for tenant B reading tenant A script, got %d", wGetB.Code)
	}

	// 3. Tenant B attempts to read Tenant A's script version -> 404
	reqGetVerB := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/scripts?id=%s&version=1", scriptID), nil)
	reqGetVerB.Header.Set("Authorization", "Bearer "+jwtB)
	wGetVerB := httptest.NewRecorder()
	handler.ServeHTTP(wGetVerB, reqGetVerB)
	if wGetVerB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for tenant B reading tenant A script version, got %d", wGetVerB.Code)
	}

	// 4. Tenant B attempts to update Tenant A's script -> 404
	updateBody, _ := json.Marshal(map[string]string{
		"id":     scriptID,
		"source": "echo compromised\n",
	})
	reqUpdateB := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(updateBody))
	reqUpdateB.Header.Set("Authorization", "Bearer "+jwtB)
	reqUpdateB.Header.Set("Content-Type", "application/json")
	wUpdateB := httptest.NewRecorder()
	handler.ServeHTTP(wUpdateB, reqUpdateB)
	if wUpdateB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for tenant B updating tenant A script, got %d", wUpdateB.Code)
	}

	// 5. Tenant B attempts to retire Tenant A's script -> 404
	reqRetireB := httptest.NewRequest(http.MethodDelete, "/api/v1/scripts?id="+scriptID, nil)
	reqRetireB.Header.Set("Authorization", "Bearer "+jwtB)
	wRetireB := httptest.NewRecorder()
	handler.ServeHTTP(wRetireB, reqRetireB)
	if wRetireB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for tenant B retiring tenant A script, got %d", wRetireB.Code)
	}

	// 6. Tenant B attempts to execute Tenant A's script -> 404
	_, _, _ = auth.GetOrCreateTenantKey(tenantB)
	secretB, _ := auth.EnrollTOTP(tenantB, opB)
	bPubB, bPrivB, _ := ed25519.GenerateKey(rand.Reader)
	codeB, _ := responseauth.GenerateTOTPCode(secretB, time.Now())
	sessionB, err := auth.UnlockSessionWithTOTP(tenantB, opB, "browser-b-sess", hex.EncodeToString(bPubB), codeB)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP for tenant B failed: %v", err)
	}

	actionPayload := response.ScriptExecPayload{
		ScriptID:       scriptID,
		ScriptVersion:  1,
		ScriptDigest:   createResp.Version.DigestSHA256,
		Interpreter:    createResp.Script.Interpreter,
		Source:         createResp.Version.Source,
		TimeoutSeconds: 60,
		MaxOutputBytes: 1048576,
	}
	actionDigest, _ := response.ComputeActionDigest(actionPayload)

	proofB := &responseauth.ActionProof{
		SessionID:       sessionB.SessionID,
		TenantID:        tenantB,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{epB},
		Timestamp:       time.Now().Unix(),
		Nonce:           "aabbccddeeff0011",
	}
	sigB := ed25519.Sign(bPrivB, proofB.CanonicalBytes())
	proofB.Signature = hex.EncodeToString(sigB)

	runBodyB, _ := json.Marshal(map[string]interface{}{
		"script_id":     scriptID,
		"version":       1,
		"endpoint_id":   epB,
		"session_id":    sessionB.SessionID,
		"action_digest": actionDigest,
		"proof":         proofB,
	})
	reqRunB := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBodyB))
	reqRunB.Header.Set("Authorization", "Bearer "+jwtB)
	reqRunB.Header.Set("Content-Type", "application/json")
	wRunB := httptest.NewRecorder()
	handler.ServeHTTP(wRunB, reqRunB)
	if wRunB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for tenant B executing tenant A script, got %d: %s", wRunB.Code, wRunB.Body.String())
	}

	// 7. Tenant B list does not expose Tenant A scripts
	reqListB := httptest.NewRequest(http.MethodGet, "/api/v1/scripts", nil)
	reqListB.Header.Set("Authorization", "Bearer "+jwtB)
	wListB := httptest.NewRecorder()
	handler.ServeHTTP(wListB, reqListB)
	if wListB.Code != http.StatusOK {
		t.Fatalf("list scripts for tenant B failed: %d", wListB.Code)
	}
	var listResp struct {
		Scripts []*scripts.Script `json:"scripts"`
	}
	_ = json.NewDecoder(wListB.Body).Decode(&listResp)
	if len(listResp.Scripts) != 0 {
		t.Fatalf("expected empty script list for tenant B, got %d scripts", len(listResp.Scripts))
	}
}

func TestServer_Scripts_ParameterValidation(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-param-test-1"
	opID := "admin"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID,
		Hostname: "param-host",
		OS:       "linux",
		TenantID: tenantID,
	})

	schemaJSON := `{
		"parameters": [
			{"name": "mode", "type": "enum", "enum": ["quick", "full"], "required": true},
			{"name": "count", "type": "number", "required": true},
			{"name": "verbose", "type": "boolean", "required": false},
			{"name": "target_host", "type": "string", "pattern": "^[a-zA-Z0-9_-]+$", "required": false}
		]
	}`

	createBody, _ := json.Marshal(map[string]string{
		"name":                  "param_test_script.sh",
		"description":           "Script with strict typed parameter schema",
		"interpreter":           "/bin/sh",
		"source":                "echo mode=$mode count=$count\n",
		"parameter_schema_json": schemaJSON,
	})
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(createBody))
	reqCreate.Header.Set("X-API-Key", "test-admin-key-12345")
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create script failed: %d: %s", wCreate.Code, wCreate.Body.String())
	}

	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	_ = json.NewDecoder(wCreate.Body).Decode(&createResp)
	scriptID := createResp.Script.ID

	// Setup operator session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-param-sess", hex.EncodeToString(bPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opID, Role: hubauth.RoleAdmin, TenantID: tenantID}, "test-admin-key-12345", time.Hour)

	testCases := []struct {
		name        string
		params      map[string]string
		expectCode  int
		errContains string
	}{
		{
			name:        "missing required parameters",
			params:      map[string]string{"mode": "quick"},
			expectCode:  http.StatusBadRequest,
			errContains: "is required",
		},
		{
			name:        "invalid enum choice",
			params:      map[string]string{"mode": "extreme", "count": "5"},
			expectCode:  http.StatusBadRequest,
			errContains: "is not one of",
		},
		{
			name:        "invalid number",
			params:      map[string]string{"mode": "quick", "count": "five"},
			expectCode:  http.StatusBadRequest,
			errContains: "is not a valid number",
		},
		{
			name:        "invalid boolean",
			params:      map[string]string{"mode": "quick", "count": "5", "verbose": "maybe"},
			expectCode:  http.StatusBadRequest,
			errContains: "is not a valid boolean",
		},
		{
			name:        "regex pattern violation",
			params:      map[string]string{"mode": "quick", "count": "5", "target_host": "host; rm -rf /"},
			expectCode:  http.StatusBadRequest,
			errContains: "does not match pattern",
		},
		{
			name:        "undeclared parameter rejection",
			params:      map[string]string{"mode": "quick", "count": "5", "undeclared_param": "inject"},
			expectCode:  http.StatusBadRequest,
			errContains: "undeclared_param",
		},
		{
			name:       "valid parameters",
			params:     map[string]string{"mode": "full", "count": "42", "verbose": "true", "target_host": "server-01"},
			expectCode: http.StatusCreated,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actionPayload := response.ScriptExecPayload{
				ScriptID:       scriptID,
				ScriptVersion:  1,
				ScriptDigest:   createResp.Version.DigestSHA256,
				Interpreter:    createResp.Script.Interpreter,
				Source:         createResp.Version.Source,
				Parameters:     tc.params,
				TimeoutSeconds: 60,
				MaxOutputBytes: 1048576,
			}
			actionDigest, _ := response.ComputeActionDigest(actionPayload)

			proof := &responseauth.ActionProof{
				SessionID:       session.SessionID,
				TenantID:        tenantID,
				ActionKind:      response.ActionKindScriptExec,
				ActionDigest:    actionDigest,
				TargetEndpoints: []string{endpointID},
				Timestamp:       time.Now().Unix(),
				Nonce:           fmt.Sprintf("nonce-%d", time.Now().UnixNano()),
			}
			sig := ed25519.Sign(bPriv, proof.CanonicalBytes())
			proof.Signature = hex.EncodeToString(sig)

			runBody, _ := json.Marshal(map[string]interface{}{
				"script_id":     scriptID,
				"version":       1,
				"endpoint_id":   endpointID,
				"parameters":    tc.params,
				"session_id":    session.SessionID,
				"action_digest": actionDigest,
				"proof":         proof,
			})

			reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
			reqRun.Header.Set("Authorization", "Bearer "+jwtToken)
			reqRun.Header.Set("Content-Type", "application/json")
			wRun := httptest.NewRecorder()
			handler.ServeHTTP(wRun, reqRun)

			if wRun.Code != tc.expectCode {
				t.Fatalf("expected code %d, got %d: %s", tc.expectCode, wRun.Code, wRun.Body.String())
			}
			if tc.errContains != "" && !strings.Contains(wRun.Body.String(), tc.errContains) {
				t.Fatalf("expected error containing %q, got: %s", tc.errContains, wRun.Body.String())
			}
		})
	}
}

func TestServer_Scripts_RetirementAndConstraints(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-retire-test-1"
	opID := "admin"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID,
		Hostname: "retire-host",
		OS:       "linux",
		TenantID: tenantID,
	})

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opID, Role: hubauth.RoleAdmin, TenantID: tenantID}, "test-admin-key-12345", time.Hour)

	// 1. Rejection of unallowlisted interpreter
	badInterpBody, _ := json.Marshal(map[string]string{
		"name":        "bad_interp.py",
		"interpreter": "/usr/bin/python3",
		"source":      "print('hello')\n",
	})
	reqBadInterp := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(badInterpBody))
	reqBadInterp.Header.Set("Authorization", "Bearer "+jwtToken)
	reqBadInterp.Header.Set("Content-Type", "application/json")
	wBadInterp := httptest.NewRecorder()
	handler.ServeHTTP(wBadInterp, reqBadInterp)
	if wBadInterp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unallowlisted interpreter, got %d: %s", wBadInterp.Code, wBadInterp.Body.String())
	}

	// 2. Rejection of oversized script source (> 64 KiB)
	oversizedSource := strings.Repeat("a", 65537)
	oversizedBody, _ := json.Marshal(map[string]string{
		"name":        "oversized.sh",
		"interpreter": "/bin/sh",
		"source":      oversizedSource,
	})
	reqOversized := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(oversizedBody))
	reqOversized.Header.Set("Authorization", "Bearer "+jwtToken)
	reqOversized.Header.Set("Content-Type", "application/json")
	wOversized := httptest.NewRecorder()
	handler.ServeHTTP(wOversized, reqOversized)
	if wOversized.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized script source, got %d: %s", wOversized.Code, wOversized.Body.String())
	}

	// 3. Create valid script
	validBody, _ := json.Marshal(map[string]string{
		"name":        "retire_me.sh",
		"interpreter": "/bin/sh",
		"source":      "echo retire\n",
	})
	reqValid := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(validBody))
	reqValid.Header.Set("Authorization", "Bearer "+jwtToken)
	reqValid.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	handler.ServeHTTP(wValid, reqValid)
	if wValid.Code != http.StatusCreated {
		t.Fatalf("failed to create script: %d: %s", wValid.Code, wValid.Body.String())
	}
	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	_ = json.NewDecoder(wValid.Body).Decode(&createResp)
	scriptID := createResp.Script.ID

	// 4. Retire script
	reqRetire := httptest.NewRequest(http.MethodDelete, "/api/v1/scripts?id="+scriptID, nil)
	reqRetire.Header.Set("Authorization", "Bearer "+jwtToken)
	wRetire := httptest.NewRecorder()
	handler.ServeHTTP(wRetire, reqRetire)
	if wRetire.Code != http.StatusOK {
		t.Fatalf("failed to retire script: %d: %s", wRetire.Code, wRetire.Body.String())
	}

	// 5. Update retired script -> 400 Bad Request
	updateBody, _ := json.Marshal(map[string]string{
		"id":     scriptID,
		"source": "echo new_version\n",
	})
	reqUpdate := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(updateBody))
	reqUpdate.Header.Set("Authorization", "Bearer "+jwtToken)
	reqUpdate.Header.Set("Content-Type", "application/json")
	wUpdate := httptest.NewRecorder()
	handler.ServeHTTP(wUpdate, reqUpdate)
	if wUpdate.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 updating retired script, got %d: %s", wUpdate.Code, wUpdate.Body.String())
	}

	// 6. Run retired script -> 400 Bad Request
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, _ := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-retire-sess", hex.EncodeToString(bPub), code)

	actionPayload := response.ScriptExecPayload{
		ScriptID:       scriptID,
		ScriptVersion:  1,
		ScriptDigest:   createResp.Version.DigestSHA256,
		Interpreter:    createResp.Script.Interpreter,
		Source:         createResp.Version.Source,
		TimeoutSeconds: 60,
		MaxOutputBytes: 1048576,
	}
	actionDigest, _ := response.ComputeActionDigest(actionPayload)

	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "retired-nonce-1",
	}
	sig := ed25519.Sign(bPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	runBody, _ := json.Marshal(map[string]interface{}{
		"script_id":     scriptID,
		"version":       1,
		"endpoint_id":   endpointID,
		"session_id":    session.SessionID,
		"action_digest": actionDigest,
		"proof":         proof,
	})
	reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
	reqRun.Header.Set("Authorization", "Bearer "+jwtToken)
	reqRun.Header.Set("Content-Type", "application/json")
	wRun := httptest.NewRecorder()
	handler.ServeHTTP(wRun, reqRun)
	if wRun.Code != http.StatusBadRequest || !strings.Contains(wRun.Body.String(), "retired") {
		t.Fatalf("expected 400 Bad Request executing retired script, got %d: %s", wRun.Code, wRun.Body.String())
	}
}

func TestServer_Scripts_DigestAndSchedules(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID1 := "ep-sched-node-1"
	endpointID2 := "ep-sched-node-2"
	opID := "admin"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID1,
		Hostname: "sched-host-1",
		OS:       "linux",
		TenantID: tenantID,
	})
	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID2,
		Hostname: "sched-host-2",
		OS:       "linux",
		TenantID: tenantID,
	})

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opID, Role: hubauth.RoleAdmin, TenantID: tenantID}, "test-admin-key-12345", time.Hour)

	// 1. Create Script with Parameter Schema
	paramSchemaJSON := `{
		"parameters": [
			{"name": "env", "type": "enum", "enum": ["prod", "stage"], "required": true},
			{"name": "dry_run", "type": "boolean", "required": false}
		]
	}`
	createBody, _ := json.Marshal(map[string]string{
		"name":                  "backup_audit.sh",
		"description":           "Nightly backup audit script",
		"interpreter":           "/bin/sh",
		"source":                "echo env=$env dry_run=$dry_run\n",
		"parameter_schema_json": paramSchemaJSON,
	})
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(createBody))
	reqCreate.Header.Set("Authorization", "Bearer "+jwtToken)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create script failed: %d: %s", wCreate.Code, wCreate.Body.String())
	}

	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	_ = json.NewDecoder(wCreate.Body).Decode(&createResp)
	scriptID := createResp.Script.ID

	// 2. Test POST /api/v1/scripts/digest
	// 2a. Parameter validation error
	digestBadParams, _ := json.Marshal(map[string]interface{}{
		"script_id":  scriptID,
		"version":    1,
		"parameters": map[string]string{"env": "invalid-env"},
	})
	reqDigestBad := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/digest", bytes.NewReader(digestBadParams))
	reqDigestBad.Header.Set("Authorization", "Bearer "+jwtToken)
	reqDigestBad.Header.Set("Content-Type", "application/json")
	wDigestBad := httptest.NewRecorder()
	handler.ServeHTTP(wDigestBad, reqDigestBad)
	if wDigestBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid parameter enum in digest, got %d: %s", wDigestBad.Code, wDigestBad.Body.String())
	}

	// 2b. Valid digest calculation
	validParams := map[string]string{"env": "prod", "dry_run": "true"}
	digestReqBody, _ := json.Marshal(map[string]interface{}{
		"script_id":       scriptID,
		"version":         1,
		"parameters":      validParams,
		"timeout_seconds": 45,
		"max_output_bytes": 2048,
	})
	reqDigest := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/digest", bytes.NewReader(digestReqBody))
	reqDigest.Header.Set("Authorization", "Bearer "+jwtToken)
	reqDigest.Header.Set("Content-Type", "application/json")
	wDigest := httptest.NewRecorder()
	handler.ServeHTTP(wDigest, reqDigest)
	if wDigest.Code != http.StatusOK {
		t.Fatalf("failed to calculate digest: %d: %s", wDigest.Code, wDigest.Body.String())
	}

	var digestResp struct {
		ActionDigest string `json:"action_digest"`
		ScriptDigest string `json:"script_digest"`
	}
	if err := json.NewDecoder(wDigest.Body).Decode(&digestResp); err != nil {
		t.Fatalf("failed to decode digest response: %v", err)
	}

	expectedPayload := response.ScriptExecPayload{
		ScriptID:       scriptID,
		ScriptVersion:  1,
		ScriptDigest:   createResp.Version.DigestSHA256,
		Interpreter:    createResp.Script.Interpreter,
		Source:         createResp.Version.Source,
		Parameters:     validParams,
		TimeoutSeconds: 45,
		MaxOutputBytes: 2048,
	}
	expectedDigest, _ := response.ComputeActionDigest(expectedPayload)
	if digestResp.ActionDigest != expectedDigest {
		t.Fatalf("action digest mismatch: expected %s, got %s", expectedDigest, digestResp.ActionDigest)
	}
	if digestResp.ScriptDigest != createResp.Version.DigestSHA256 {
		t.Fatalf("script digest mismatch: expected %s, got %s", createResp.Version.DigestSHA256, digestResp.ScriptDigest)
	}

	// 3. Test POST /api/v1/scripts/schedules
	// 3a. Static API key rejection (fail-closed)
	schedBody, _ := json.Marshal(map[string]interface{}{
		"script_id":        scriptID,
		"version":          1,
		"target_endpoints": []string{endpointID1, endpointID2},
		"parameters":       validParams,
		"recurrence":       "daily",
		"start_time":       time.Now().Add(time.Hour),
		"max_runs":         30,
		"timeout_seconds":  45,
		"max_output_bytes": 2048,
	})
	reqSchedAPIKey := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/schedules", bytes.NewReader(schedBody))
	reqSchedAPIKey.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSchedAPIKey.Header.Set("Content-Type", "application/json")
	wSchedAPIKey := httptest.NewRecorder()
	handler.ServeHTTP(wSchedAPIKey, reqSchedAPIKey)
	if wSchedAPIKey.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for static API key scheduling, got %d: %s", wSchedAPIKey.Code, wSchedAPIKey.Body.String())
	}

	// 3b. Setup Response Authority Session for Console Operator
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	bPub, _, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-sched-sess", hex.EncodeToString(bPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	schedWithSessionBody, _ := json.Marshal(map[string]interface{}{
		"script_id":        scriptID,
		"version":          1,
		"target_endpoints": []string{endpointID1, endpointID2},
		"parameters":       validParams,
		"recurrence":       "daily",
		"start_time":       time.Now().Add(time.Hour),
		"max_runs":         30,
		"timeout_seconds":  45,
		"max_output_bytes": 2048,
		"session_id":       session.SessionID,
	})
	reqSched := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/schedules", bytes.NewReader(schedWithSessionBody))
	reqSched.Header.Set("Authorization", "Bearer "+jwtToken)
	reqSched.Header.Set("Content-Type", "application/json")
	wSched := httptest.NewRecorder()
	handler.ServeHTTP(wSched, reqSched)
	if wSched.Code != http.StatusCreated {
		t.Fatalf("create schedule failed: %d: %s", wSched.Code, wSched.Body.String())
	}

	var sched scripts.ScriptSchedule
	if err := json.NewDecoder(wSched.Body).Decode(&sched); err != nil {
		t.Fatalf("failed to decode schedule response: %v", err)
	}
	if sched.ID == "" || sched.ScriptDigest != createResp.Version.DigestSHA256 {
		t.Fatalf("invalid schedule record: %+v", sched)
	}
	if len(sched.TargetEndpoints) != 2 || sched.TargetEndpoints[0] != endpointID1 || sched.TargetEndpoints[1] != endpointID2 {
		t.Fatalf("frozen target endpoints mismatch: %v", sched.TargetEndpoints)
	}

	// 4. GET /api/v1/scripts/schedules (List and Get by ID)
	reqListSched := httptest.NewRequest(http.MethodGet, "/api/v1/scripts/schedules", nil)
	reqListSched.Header.Set("Authorization", "Bearer "+jwtToken)
	wListSched := httptest.NewRecorder()
	handler.ServeHTTP(wListSched, reqListSched)
	if wListSched.Code != http.StatusOK {
		t.Fatalf("list schedules failed: %d: %s", wListSched.Code, wListSched.Body.String())
	}
	var listResp struct {
		Schedules []*scripts.ScriptSchedule `json:"schedules"`
		Count     int                       `json:"count"`
	}
	_ = json.NewDecoder(wListSched.Body).Decode(&listResp)
	if listResp.Count != 1 || listResp.Schedules[0].ID != sched.ID {
		t.Fatalf("unexpected schedules list: %+v", listResp)
	}

	reqGetSched := httptest.NewRequest(http.MethodGet, "/api/v1/scripts/schedules?id="+sched.ID, nil)
	reqGetSched.Header.Set("Authorization", "Bearer "+jwtToken)
	wGetSched := httptest.NewRecorder()
	handler.ServeHTTP(wGetSched, reqGetSched)
	if wGetSched.Code != http.StatusOK {
		t.Fatalf("get schedule by id failed: %d: %s", wGetSched.Code, wGetSched.Body.String())
	}
	var singleSched scripts.ScriptSchedule
	_ = json.NewDecoder(wGetSched.Body).Decode(&singleSched)
	if singleSched.ID != sched.ID || singleSched.Status != "active" {
		t.Fatalf("unexpected single schedule: %+v", singleSched)
	}

	// 5. DELETE /api/v1/scripts/schedules?id=... (Cancel Schedule)
	reqDelSched := httptest.NewRequest(http.MethodDelete, "/api/v1/scripts/schedules?id="+sched.ID, nil)
	reqDelSched.Header.Set("Authorization", "Bearer "+jwtToken)
	wDelSched := httptest.NewRecorder()
	handler.ServeHTTP(wDelSched, reqDelSched)
	if wDelSched.Code != http.StatusOK {
		t.Fatalf("cancel schedule failed: %d: %s", wDelSched.Code, wDelSched.Body.String())
	}

	// 6. Second cancellation returns 404
	reqDelSched2 := httptest.NewRequest(http.MethodDelete, "/api/v1/scripts/schedules?id="+sched.ID, nil)
	reqDelSched2.Header.Set("Authorization", "Bearer "+jwtToken)
	wDelSched2 := httptest.NewRecorder()
	handler.ServeHTTP(wDelSched2, reqDelSched2)
	if wDelSched2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cancelling already cancelled schedule, got %d", wDelSched2.Code)
	}
}

func TestServer_ResponseJobs_SingleLookup(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-job-test-1"
	opID := "admin"

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:       endpointID,
		Hostname: "job-host",
		OS:       "linux",
		TenantID: tenantID,
	})

	jwtToken, _ := hubauth.GenerateJWT(hubauth.Claims{Username: opID, Role: hubauth.RoleAdmin, TenantID: tenantID}, "test-admin-key-12345", time.Hour)

	// Create a script
	createBody, _ := json.Marshal(map[string]string{
		"name":        "lookup_test.sh",
		"description": "Script for job lookup verification",
		"interpreter": "/bin/sh",
		"source":      "echo lookup test\n",
	})
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/scripts", bytes.NewReader(createBody))
	reqCreate.Header.Set("Authorization", "Bearer "+jwtToken)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("failed to create script: %d: %s", wCreate.Code, wCreate.Body.String())
	}
	var createResp struct {
		Script  scripts.Script        `json:"script"`
		Version scripts.ScriptVersion `json:"version"`
	}
	_ = json.NewDecoder(wCreate.Body).Decode(&createResp)

	// Create a response session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, _ := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-job-sess", hex.EncodeToString(bPub), code)

	// Dispatch a script exec job
	actionPayload := response.ScriptExecPayload{
		ScriptID:       createResp.Script.ID,
		ScriptVersion:  1,
		ScriptDigest:   createResp.Version.DigestSHA256,
		Interpreter:    createResp.Script.Interpreter,
		Source:         createResp.Version.Source,
		TimeoutSeconds: 60,
		MaxOutputBytes: 1048576,
	}
	actionDigest, _ := response.ComputeActionDigest(actionPayload)
	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "job-nonce-12345678",
	}
	sig := ed25519.Sign(bPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	runBody, _ := json.Marshal(map[string]interface{}{
		"script_id":       createResp.Script.ID,
		"version":         1,
		"endpoint_id":     endpointID,
		"session_id":      session.SessionID,
		"action_digest":   actionDigest,
		"proof":           proof,
		"timeout_seconds": 60,
		"max_output_bytes": 1048576,
	})
	reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/scripts/run", bytes.NewReader(runBody))
	reqRun.Header.Set("Authorization", "Bearer "+jwtToken)
	reqRun.Header.Set("Content-Type", "application/json")
	wRun := httptest.NewRecorder()
	handler.ServeHTTP(wRun, reqRun)
	if wRun.Code != http.StatusCreated {
		t.Fatalf("failed to create script exec job: %d: %s", wRun.Code, wRun.Body.String())
	}

	var createdJob response.JobRecord
	_ = json.NewDecoder(wRun.Body).Decode(&createdJob)
	if createdJob.ID == "" {
		t.Fatalf("empty job id returned")
	}

	// Lookup specific job by ID: GET /api/v1/response/jobs?id=...
	reqJob := httptest.NewRequest(http.MethodGet, "/api/v1/response/jobs?id="+createdJob.ID, nil)
	reqJob.Header.Set("Authorization", "Bearer "+jwtToken)
	wJob := httptest.NewRecorder()
	handler.ServeHTTP(wJob, reqJob)
	if wJob.Code != http.StatusOK {
		t.Fatalf("failed to get job by id: %d: %s", wJob.Code, wJob.Body.String())
	}

	var fetchedJob response.JobRecord
	if err := json.NewDecoder(wJob.Body).Decode(&fetchedJob); err != nil {
		t.Fatalf("failed to decode job: %v", err)
	}
	if fetchedJob.ID != createdJob.ID || fetchedJob.Kind != response.ActionKindScriptExec {
		t.Fatalf("job mismatch: %+v", fetchedJob)
	}

	// Non-existent job returns 404
	reqNonExistent := httptest.NewRequest(http.MethodGet, "/api/v1/response/jobs?id=job-does-not-exist", nil)
	reqNonExistent.Header.Set("Authorization", "Bearer "+jwtToken)
	wNonExistent := httptest.NewRecorder()
	handler.ServeHTTP(wNonExistent, reqNonExistent)
	if wNonExistent.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-existent job, got %d", wNonExistent.Code)
	}
}

