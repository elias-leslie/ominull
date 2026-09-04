package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	hubauth "ominull/hub/pkg/auth"
	"ominull/hub/pkg/evidence"
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
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
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

	// Verify static API key is rejected with 403
	reqStatic := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(createBody))
	reqStatic.Header.Set("X-API-Key", "test-admin-key-12345")
	reqStatic.Header.Set("Content-Type", "application/json")
	wStatic := httptest.NewRecorder()
	handler.ServeHTTP(wStatic, reqStatic)
	if wStatic.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 when creating job with static API key, got %d: %s", wStatic.Code, wStatic.Body.String())
	}

	// Create job using active console session cookie
	consoleToken, err := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: "admin"}, "test-admin-key-12345", 12*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate console token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(createBody))
	req.AddCookie(&http.Cookie{Name: "ominull_console", Value: consoleToken})
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

	if srv.evidenceStore != nil {
		bundle, err := srv.evidenceStore.GetBundle(tenantID, createdJob.ID)
		if err != nil || bundle == nil {
			t.Fatalf("expected evidence bundle to be created for forensic job %s, got: %v", createdJob.ID, err)
		}
		if bundle.Profile != "diagnostic" {
			t.Fatalf("expected bundle profile diagnostic, got %s", bundle.Profile)
		}
	}

	// 4. Endpoint sends telemetry heartbeat and receives the offered job
	testKeyHex := strings.Repeat("0123456789abcdef", 4)
	heartbeatBody, _ := json.Marshal(TelemetryBatchMessage{
		EndpointID:         endpointID,
		TenantID:           tenantID,
		Hostname:           "linux-host-1",
		OS:                 "Linux 6.1.0",
		IP:                 "192.168.86.50",
		EvidenceSigningKey: testKeyHex,
	})
	reqHB := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(heartbeatBody))
	reqHB.Header.Set("X-API-Key", "test-admin-key-12345")
	reqHB.Header.Set("Content-Type", "application/json")
	wHB := httptest.NewRecorder()
	handler.ServeHTTP(wHB, reqHB)

	ep, err := store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		t.Fatalf("failed to fetch endpoint: %v", err)
	}
	if ep.EvidenceSigningKey != testKeyHex {
		t.Fatalf("expected endpoint evidence signing key to be persisted, got %q", ep.EvidenceSigningKey)
	}

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

	consoleToken, err := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: "admin"}, "test-admin-key-12345", 12*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate console token: %v", err)
	}

	reqForged := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(forgedBody))
	reqForged.AddCookie(&http.Cookie{Name: "ominull_console", Value: consoleToken})
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
	reqStrip.AddCookie(&http.Cookie{Name: "ominull_console", Value: consoleToken})
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

func TestServer_WindowsDiagnosticForensicFlow(t *testing.T) {
	srv, store, auth, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	tenantID := "default"
	endpointID := "win-desktop-01"
	opID := "admin"

	// 1. Initialize tenant response key
	_, _, err := auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed: %v", err)
	}

	// 2. Unlock response session
	secret, err := auth.EnrollTOTP(tenantID, opID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	code, _ := responseauth.GenerateTOTPCode(secret, now)

	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "win-test-sess", hex.EncodeToString(browserPub), code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// 3. Windows endpoint generates dedicated Ed25519 evidence keypair
	evidencePub, evidencePriv, _ := ed25519.GenerateKey(rand.Reader)
	evidencePubHex := hex.EncodeToString(evidencePub)

	handler := srv.Handler()

	// 4. Windows endpoint registers and heartbeats
	heartbeatBody, _ := json.Marshal(TelemetryBatchMessage{
		EndpointID:         endpointID,
		TenantID:           tenantID,
		Hostname:           "win-host-01",
		OS:                 "Windows 11 Pro 23H2 (Build 22631)",
		IP:                 "10.0.0.75",
		EvidenceSigningKey: evidencePubHex,
	})
	reqHB := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(heartbeatBody))
	reqHB.Header.Set("X-API-Key", "test-admin-key-12345")
	reqHB.Header.Set("Content-Type", "application/json")
	wHB := httptest.NewRecorder()
	handler.ServeHTTP(wHB, reqHB)
	if wHB.Code != http.StatusOK {
		t.Fatalf("Windows heartbeat returned %d: %s", wHB.Code, wHB.Body.String())
	}

	ep, err := store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		t.Fatalf("failed to fetch Windows endpoint: %v", err)
	}
	if ep.EvidenceSigningKey != evidencePubHex {
		t.Fatalf("expected evidence signing key %s, got %s", evidencePubHex, ep.EvidenceSigningKey)
	}

	// 5. Operator dispatches diagnostic forensic collection
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
		Nonce:           "win-proof-nonce-1",
	}
	sig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	consoleToken, _ := hubauth.GenerateJWT(hubauth.Claims{Username: "admin", Role: "admin"}, "test-admin-key-12345", 12*time.Hour)

	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id":     endpointID,
		"kind":            response.ActionKindForensicCollect,
		"payload_json":    `{"profile":"diagnostic","max_bytes":5242880,"timeout_seconds":60}`,
		"idempotency_key": "win-idemp-01",
		"session_id":      session.SessionID,
		"action_digest":   actionDigest,
		"proof":           proof,
	})

	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(createBody))
	reqCreate.AddCookie(&http.Cookie{Name: "ominull_console", Value: consoleToken})
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)

	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create Windows response job returned %d: %s", wCreate.Code, wCreate.Body.String())
	}

	var createdJob response.JobRecord
	_ = json.NewDecoder(wCreate.Body).Decode(&createdJob)
	if createdJob.ID == "" {
		t.Fatalf("expected non-empty job ID")
	}

	// 6. Windows endpoint heartbeats and receives offer
	reqHB2 := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(heartbeatBody))
	reqHB2.Header.Set("X-API-Key", "test-admin-key-12345")
	reqHB2.Header.Set("Content-Type", "application/json")
	wHB2 := httptest.NewRecorder()
	handler.ServeHTTP(wHB2, reqHB2)

	var hbResp struct {
		Status         string               `json:"status"`
		ResponseOffers []*response.JobOffer `json:"response_offers"`
	}
	_ = json.NewDecoder(wHB2.Body).Decode(&hbResp)
	if len(hbResp.ResponseOffers) != 1 {
		t.Fatalf("expected 1 offer for Windows endpoint, got %d", len(hbResp.ResponseOffers))
	}
	offer := hbResp.ResponseOffers[0]

	// 7. Windows endpoint ACKs offer
	ackBody, _ := json.Marshal(map[string]interface{}{
		"job_id":   offer.JobID,
		"lease_id": offer.LeaseID,
		"accepted": true,
	})
	reqAck := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/ack", bytes.NewReader(ackBody))
	reqAck.Header.Set("X-API-Key", "test-admin-key-12345")
	reqAck.Header.Set("Content-Type", "application/json")
	wAck := httptest.NewRecorder()
	handler.ServeHTTP(wAck, reqAck)
	if wAck.Code != http.StatusOK {
		t.Fatalf("ACK failed with %d: %s", wAck.Code, wAck.Body.String())
	}

	// 8. Windows endpoint uploads 8 diagnostic items
	itemNames := []string{
		"os_version.json",
		"network_interfaces.json",
		"routes.txt",
		"dns_config.txt",
		"resource_summary.json",
		"service_state.json",
		"system_logs.txt",
		"agent_diagnostics.json",
	}

	bundleID := createdJob.ID
	var manifestItems []evidence.ManifestItem
	for _, name := range itemNames {
		content := []byte("dummy-win-content-for-" + name)
		sum := sha256.Sum256(content)
		sumHex := hex.EncodeToString(sum[:])
		itemURL := "/api/v1/evidence/items?bundle_id=" + bundleID + "&name=" + name + "&status=collected"
		reqItem := httptest.NewRequest(http.MethodPost, itemURL, bytes.NewReader(content))
		reqItem.Header.Set("X-API-Key", "test-admin-key-12345")
		reqItem.Header.Set("Content-Type", "application/octet-stream")
		wItem := httptest.NewRecorder()
		handler.ServeHTTP(wItem, reqItem)
		if wItem.Code != http.StatusOK && wItem.Code != http.StatusCreated {
			t.Fatalf("upload item %s returned %d: %s", name, wItem.Code, wItem.Body.String())
		}
		manifestItems = append(manifestItems, evidence.ManifestItem{
			Name:            name,
			SizeBytes:       int64(len(content)),
			SHA256:          sumHex,
			CollectorStatus: "collected",
		})
	}

	// 9. Windows endpoint finalizes bundle with signed manifest
	collectedAt := time.Now().UTC().Truncate(time.Second)
	manifest := &evidence.Manifest{
		BundleID:    bundleID,
		EndpointID:  endpointID,
		TenantID:    tenantID,
		JobID:       createdJob.ID,
		Profile:     "diagnostic",
		CollectedAt: collectedAt,
		Items:       manifestItems,
	}
	canonicalBytes := manifest.CanonicalBytes()
	manifestSig := ed25519.Sign(evidencePriv, canonicalBytes)
	manifest.Signature = hex.EncodeToString(manifestSig)

	finBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundleID,
		"manifest":  manifest,
	})
	reqFin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/finalize", bytes.NewReader(finBody))
	reqFin.Header.Set("X-API-Key", "test-admin-key-12345")
	reqFin.Header.Set("Content-Type", "application/json")
	wFin := httptest.NewRecorder()
	handler.ServeHTTP(wFin, reqFin)
	if wFin.Code != http.StatusOK {
		t.Fatalf("finalize bundle returned %d: %s", wFin.Code, wFin.Body.String())
	}

	// 10. Windows endpoint reports job result
	manifestSHA := evidence.ComputeDigest(canonicalBytes)
	resBody, _ := json.Marshal(map[string]interface{}{
		"job_id":          offer.JobID,
		"lease_id":        offer.LeaseID,
		"state":           "succeeded",
		"exit_code":       0,
		"duration_ms":     150,
		"manifest_sha256": manifestSHA,
	})
	reqRes := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/result", bytes.NewReader(resBody))
	reqRes.Header.Set("X-API-Key", "test-admin-key-12345")
	reqRes.Header.Set("Content-Type", "application/json")
	wRes := httptest.NewRecorder()
	handler.ServeHTTP(wRes, reqRes)
	if wRes.Code != http.StatusOK {
		t.Fatalf("post result returned %d: %s", wRes.Code, wRes.Body.String())
	}

	// 11. Verify bundle state in evidence store
	bundle, err := srv.evidenceStore.GetBundle(tenantID, bundleID)
	if err != nil {
		t.Fatalf("GetBundle failed: %v", err)
	}
	if bundle.Status != "completed" {
		t.Fatalf("expected bundle status 'completed', got %q", bundle.Status)
	}
	if bundle.ItemCount != 8 {
		t.Fatalf("expected 8 items, got %d", bundle.ItemCount)
	}
	if bundle.ReceiptSHA256 == "" {
		t.Fatalf("expected signed receipt_sha256 on finalized bundle")
	}
}
