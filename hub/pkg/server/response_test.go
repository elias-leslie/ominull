package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

func setupTestServerWithResponse(t *testing.T) (*Server, *storage.Store, *responseauth.Authority, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "ominull-srv-resp-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := tempDir + "/test.db"
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}

	srv := New(store, "test-admin-key-12345", tempDir, "http://localhost:9999", "1.8.2")
	srv.SetResponseEnabled(true)

	authDir := tempDir + "/auth"
	auth, err := responseauth.NewAuthority(responseauth.Config{StateDir: authDir})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}

	// Use in-process client for testing
	srv.SetResponseAuth(responseauth.NewInProcessClient(auth))

	cleanup := func() {
		store.Close()
		os.RemoveAll(tempDir)
	}
	return srv, store, auth, cleanup
}

func TestServer_ResponseJobFlow(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	tenantID := "default"
	endpointID := "ep-linux-1"
	opID := "admin"

	// 1. Initialize tenant response key
	pubKey, keyID, err := auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed: %v", err)
	}
	_ = keyID

	// 2. Enroll TOTP and unlock session
	secret, err := auth.EnrollTOTP(tenantID, opID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	code, _ := responseauth.GenerateTOTPCode(secret, now)

	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-test-sess", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// 3. Construct action proof and create response job via API
	payload := response.ForensicCollectionPayload{
		Profile:        "diagnostic",
		MaxBytes:       5242880,
		TimeoutSeconds: 60,
	}
	actionDigest, err := response.ComputeActionDigest(payload)
	if err != nil {
		t.Fatalf("ComputeActionDigest failed: %v", err)
	}

	proof := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       now.Unix(),
		Nonce:           "9988776655443322",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":     endpointID,
		"kind":            response.ActionKindForensicCollect,
		"payload_json":    `{"profile":"diagnostic","max_bytes":5242880,"timeout_seconds":60}`,
		"idempotency_key": "idemp-test-01",
		"session_id":      session.SessionID,
		"action_digest":   actionDigest,
		"proof":           proof,
	})

	handler := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create job returned %d: %s", w.Code, w.Body.String())
	}

	var createdJob response.JobRecord
	if err := json.NewDecoder(w.Body).Decode(&createdJob); err != nil {
		t.Fatalf("failed to decode created job: %v", err)
	}
	if createdJob.ID == "" || createdJob.State != response.StateQueued {
		t.Fatalf("unexpected job record: %+v", createdJob)
	}

	// 4. Endpoint sends telemetry heartbeat and receives the offered job
	heartbeatBody, _ := json.Marshal(TelemetryBatchMessage{
		EndpointID: endpointID,
		TenantID:   tenantID,
		Hostname:   "linux-host-1",
		OS:         "Linux 6.1.0",
		IP:         "192.168.86.50",
	})
	reqHB := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(heartbeatBody))
	reqHB.Header.Set("X-API-Key", "test-admin-key-12345")
	reqHB.Header.Set("Content-Type", "application/json")
	wHB := httptest.NewRecorder()
	handler.ServeHTTP(wHB, reqHB)

	if wHB.Code != http.StatusOK {
		t.Fatalf("heartbeat returned %d: %s", wHB.Code, wHB.Body.String())
	}

	var hbResp struct {
		Status         string               `json:"status"`
		ResponseOffers []*response.JobOffer `json:"response_offers"`
	}
	if err := json.NewDecoder(wHB.Body).Decode(&hbResp); err != nil {
		t.Fatalf("failed to decode heartbeat response: %v", err)
	}
	if len(hbResp.ResponseOffers) != 1 {
		t.Fatalf("expected 1 response offer, got %d (resp: %s)", len(hbResp.ResponseOffers), wHB.Body.String())
	}

	offer := hbResp.ResponseOffers[0]
	if offer.JobID != createdJob.ID {
		t.Fatalf("offer job ID mismatch: %s vs %s", offer.JobID, createdJob.ID)
	}

	// Endpoint verifies grant signature with pinned tenant key
	if err := offer.Grant.Verify(pubKey, time.Now()); err != nil {
		t.Fatalf("endpoint verification of offered grant failed: %v", err)
	}

	// 5. Endpoint sends ACK
	ackBody, _ := json.Marshal(response.JobAck{
		JobID:    offer.JobID,
		LeaseID:  offer.LeaseID,
		Accepted: true,
	})
	reqAck := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/ack", bytes.NewReader(ackBody))
	reqAck.Header.Set("X-API-Key", "test-admin-key-12345")
	wAck := httptest.NewRecorder()
	handler.ServeHTTP(wAck, reqAck)
	if wAck.Code != http.StatusOK {
		t.Fatalf("ack returned %d: %s", wAck.Code, wAck.Body.String())
	}

	// 6. Endpoint completes job
	resBody, _ := json.Marshal(response.JobResult{
		JobID:          offer.JobID,
		LeaseID:        offer.LeaseID,
		State:          response.StateSucceeded,
		ExitCode:       0,
		DurationMs:     240,
		ManifestSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	})
	reqRes := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/result", bytes.NewReader(resBody))
	reqRes.Header.Set("X-API-Key", "test-admin-key-12345")
	wRes := httptest.NewRecorder()
	handler.ServeHTTP(wRes, reqRes)
	if wRes.Code != http.StatusOK {
		t.Fatalf("result returned %d: %s", wRes.Code, wRes.Body.String())
	}

	// 7. List jobs to verify completed state
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/response/jobs?endpoint_id="+endpointID, nil)
	reqList.Header.Set("X-API-Key", "test-admin-key-12345")
	wList := httptest.NewRecorder()
	handler.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("list jobs returned %d: %s", wList.Code, wList.Body.String())
	}

	var listResp struct {
		Jobs []*response.JobRecord `json:"jobs"`
	}
	if err := json.NewDecoder(wList.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listResp.Jobs) != 1 || listResp.Jobs[0].State != response.StateSucceeded {
		t.Fatalf("expected 1 succeeded job in list, got: %+v", listResp)
	}
}

func TestResponseJobs_DigestRecomputationAndHeaderStripping(t *testing.T) {
	srv, _, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	tenantID := "default"
	endpointID := "ep-sec-test"
	opID := "admin"

	// 1. Setup tenant key and session
	_, _, _ = auth.GetOrCreateTenantKey(tenantID)
	secret, _ := auth.EnrollTOTP(tenantID, opID)
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	code, _ := responseauth.GenerateTOTPCode(secret, time.Now())
	session, _ := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-sec-test", hex.EncodeToString(browserPub), code)

	// Valid payload and digest
	payload := response.ForensicCollectionPayload{
		Profile:        "diagnostic",
		MaxBytes:       1048576,
		TimeoutSeconds: 60,
	}
	realDigest, _ := response.ComputeActionDigest(payload)
	payloadBytes, _ := json.Marshal(payload)

	// 2. Digest Mismatch: Client sends forged digest not matching payload
	proofValid := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    realDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "sec-nonce-1",
	}
	sigValid := ed25519.Sign(browserPriv, proofValid.CanonicalBytes())
	proofValid.Signature = hex.EncodeToString(sigValid)

	forgedBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":   endpointID,
		"kind":          response.ActionKindForensicCollect,
		"payload_json":  string(payloadBytes),
		"session_id":    session.SessionID,
		"action_digest": "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad0", // forged!
		"proof":         proofValid,
	})

	reqForged := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(forgedBody))
	reqForged.Header.Set("X-API-Key", "test-admin-key-12345")
	reqForged.Header.Set("Content-Type", "application/json")
	wForged := httptest.NewRecorder()
	handler.ServeHTTP(wForged, reqForged)

	if wForged.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for forged action digest, got %d: %s", wForged.Code, wForged.Body.String())
	}

	// 3. Header Stripping: Client supplies forged X-Operator-ID header
	proofValid2 := &responseauth.ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    realDigest,
		TargetEndpoints: []string{endpointID},
		Timestamp:       time.Now().Unix(),
		Nonce:           "sec-nonce-2",
	}
	sigValid2 := ed25519.Sign(browserPriv, proofValid2.CanonicalBytes())
	proofValid2.Signature = hex.EncodeToString(sigValid2)

	validBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":   endpointID,
		"kind":          response.ActionKindForensicCollect,
		"payload_json":  string(payloadBytes),
		"session_id":    session.SessionID,
		"action_digest": realDigest,
		"proof":         proofValid2,
	})

	reqStrip := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(validBody))
	reqStrip.Header.Set("X-API-Key", "test-admin-key-12345")
	reqStrip.Header.Set("Content-Type", "application/json")
	reqStrip.Header.Set("X-Operator-ID", "impersonated-victim@example.invalid") // should be stripped!
	wStrip := httptest.NewRecorder()
	handler.ServeHTTP(wStrip, reqStrip)

	if wStrip.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201 for valid job create, got %d: %s", wStrip.Code, wStrip.Body.String())
	}

	var createdJob response.JobRecord
	_ = json.NewDecoder(wStrip.Body).Decode(&createdJob)
	if createdJob.RequestedBy == "impersonated-victim@example.invalid" {
		t.Fatalf("security violation: forged X-Operator-ID was accepted and not stripped")
	}
	if createdJob.RequestedBy != "admin" {
		t.Fatalf("expected authenticated actor 'admin', got %q", createdJob.RequestedBy)
	}
}
