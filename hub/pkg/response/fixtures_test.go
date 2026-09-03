package response

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func canonicalFixtureDir(t *testing.T) string {
	candidates := []string{
		filepath.Join("..", "..", "tests", "fixtures", "response"),
		filepath.Join("tests", "fixtures", "response"),
		filepath.Join("hub", "tests", "fixtures", "response"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	p := filepath.Join("..", "..", "tests", "fixtures", "response")
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	return p
}

func TestGenerateAndValidateCrossLanguageFixtures(t *testing.T) {
	fixtureDir := canonicalFixtureDir(t)

	// Generate deterministic keypairs
	seed1 := make([]byte, 32)
	for i := range seed1 {
		seed1[i] = byte(i + 1)
	}
	privKey1 := ed25519.NewKeyFromSeed(seed1)
	pubKey1 := privKey1.Public().(ed25519.PublicKey)
	keyFP1 := sha256.Sum256(pubKey1)
	keyID1 := hex.EncodeToString(keyFP1[:])

	seed2 := make([]byte, 32)
	for i := range seed2 {
		seed2[i] = byte(i + 42)
	}
	privKey2 := ed25519.NewKeyFromSeed(seed2)

	fixedTime := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	writeJSON := func(filename string, v interface{}) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("MarshalIndent failed: %v", err)
		}
		path := filepath.Join(fixtureDir, filename)
		if err := os.WriteFile(path, b, 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	// 1. Valid baseline grant
	grantValid := EndpointGrant{
		Version:           GrantVersion,
		GrantID:           "00000000-0000-0000-0000-000000000001",
		TenantID:          "tenant-production",
		EndpointID:        "linux-ominull-target-linux",
		ActionKind:        ActionKindForensicCollect,
		ActionDigest:      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		OperatorID:        "operator-secops",
		ResponseSessionID: "sess-0000-0000-0001",
		IssuedAt:          fixedTime.Unix(),
		ExpiresAt:         fixedTime.Add(1 * time.Hour).Unix(),
		Nonce:             "0123456789abcdef0123456789abcdef",
		SignerKeyID:       keyID1,
	}
	sigValid := ed25519.Sign(privKey1, []byte(grantValid.CanonicalString()))
	grantValid.Signature = hex.EncodeToString(sigValid)
	writeJSON("grant_valid.json", grantValid)

	// 2. Valid baseline offer
	offerValid := JobOffer{
		JobID:          "job-1000-0001",
		Kind:           ActionKindForensicCollect,
		LeaseID:        "lease-2000-0001",
		LeaseExpiresAt: fixedTime.Add(5 * time.Minute).Unix(),
		Grant:          &grantValid,
		PayloadJSON:    `{"profile":"diagnostic","max_bytes":5242880,"timeout_seconds":60}`,
	}
	writeJSON("offer_valid.json", offerValid)

	// 3. Valid baseline ack
	ackValid := JobAck{
		JobID:    "job-1000-0001",
		LeaseID:  "lease-2000-0001",
		Accepted: true,
	}
	writeJSON("ack_valid.json", ackValid)

	// 4. Valid baseline result
	resultValid := JobResult{
		JobID:          "job-1000-0001",
		LeaseID:        "lease-2000-0001",
		State:          StateSucceeded,
		ExitCode:       0,
		DurationMs:     420,
		ManifestSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	writeJSON("result_valid.json", resultValid)

	// 5. Missing optional fields
	offerMissingOpt := JobOffer{
		JobID:          "job-1000-0002",
		Kind:           ActionKindForensicCollect,
		LeaseID:        "lease-2000-0002",
		LeaseExpiresAt: fixedTime.Add(5 * time.Minute).Unix(),
		Grant:          &grantValid,
		PayloadJSON:    "", // Optional omitted
	}
	writeJSON("offer_missing_optional.json", offerMissingOpt)

	ackMissingOpt := JobAck{
		JobID:           "job-1000-0002",
		LeaseID:         "lease-2000-0002",
		Accepted:        false,
		RejectionReason: "", // Optional omitted
	}
	writeJSON("ack_missing_optional.json", ackMissingOpt)

	resultMissingOpt := JobResult{
		JobID:      "job-1000-0002",
		LeaseID:    "lease-2000-0002",
		State:      StateFailed,
		ExitCode:   1,
		DurationMs: 15,
		// Optional fields omitted: ErrorCode, ResultJSON, Stdout, Stderr, ManifestSHA256
	}
	writeJSON("result_missing_optional.json", resultMissingOpt)

	// 6. Missing required fields (invalid)
	grantMissingReq := map[string]interface{}{
		"version":     1,
		"grant_id":    "00000000-0000-0000-0000-000000000001",
		"tenant_id":   "tenant-production",
		"action_kind": "forensic_collection",
		// missing endpoint_id, action_digest, operator_id, signature
	}
	writeJSON("grant_missing_required.json", grantMissingReq)

	offerMissingReq := map[string]interface{}{
		"kind":     "forensic_collection",
		"lease_id": "lease-2000-0001",
		// missing job_id, grant
	}
	writeJSON("offer_missing_required.json", offerMissingReq)

	ackMissingReq := map[string]interface{}{
		"job_id":   "job-1000-0001",
		"accepted": true,
		// missing lease_id
	}
	writeJSON("ack_missing_required.json", ackMissingReq)

	resultMissingReq := map[string]interface{}{
		"job_id":   "job-1000-0001",
		"lease_id": "lease-2000-0001",
		// missing state
	}
	writeJSON("result_missing_required.json", resultMissingReq)

	// 7. Unknown fields (forward-compatible test cases)
	grantUnknown := map[string]interface{}{
		"version":              1,
		"grant_id":             grantValid.GrantID,
		"tenant_id":            grantValid.TenantID,
		"endpoint_id":          grantValid.EndpointID,
		"action_kind":          string(grantValid.ActionKind),
		"action_digest":        grantValid.ActionDigest,
		"operator_id":          grantValid.OperatorID,
		"response_session_id":  grantValid.ResponseSessionID,
		"issued_at":            grantValid.IssuedAt,
		"expires_at":           grantValid.ExpiresAt,
		"nonce":                grantValid.Nonce,
		"signer_key_id":        grantValid.SignerKeyID,
		"signature":            grantValid.Signature,
		"future_field_xyz":     "should_be_ignored",
		"future_flags":         1024,
	}
	writeJSON("grant_unknown_fields.json", grantUnknown)

	offerUnknown := map[string]interface{}{
		"job_id":               offerValid.JobID,
		"kind":                 string(offerValid.Kind),
		"lease_id":             offerValid.LeaseID,
		"lease_expires_at":     offerValid.LeaseExpiresAt,
		"grant":                grantValid,
		"payload_json":         offerValid.PayloadJSON,
		"priority":             10,
		"retry_strategy":       "exponential_backoff",
	}
	writeJSON("offer_unknown_fields.json", offerUnknown)

	ackUnknown := map[string]interface{}{
		"job_id":               ackValid.JobID,
		"lease_id":             ackValid.LeaseID,
		"accepted":             ackValid.Accepted,
		"future_client_id":     "agent-v2-preview",
	}
	writeJSON("ack_unknown_fields.json", ackUnknown)

	resultUnknown := map[string]interface{}{
		"job_id":               resultValid.JobID,
		"lease_id":             resultValid.LeaseID,
		"state":                string(resultValid.State),
		"exit_code":            resultValid.ExitCode,
		"duration_ms":          resultValid.DurationMs,
		"manifest_sha256":      resultValid.ManifestSHA256,
		"diagnostic_metadata":  map[string]string{"collector": "v1.8.3"},
	}
	writeJSON("result_unknown_fields.json", resultUnknown)

	// 8. Cryptographic failure cases
	grantExpired := grantValid
	grantExpired.IssuedAt = fixedTime.Add(-2 * time.Hour).Unix()
	grantExpired.ExpiresAt = fixedTime.Add(-1 * time.Hour).Unix()
	sigExp := ed25519.Sign(privKey1, []byte(grantExpired.CanonicalString()))
	grantExpired.Signature = hex.EncodeToString(sigExp)
	writeJSON("grant_expired.json", grantExpired)

	grantTampered := grantValid
	grantTampered.EndpointID = "tampered-endpoint-hijack"
	// Signature remains for original endpoint
	writeJSON("grant_tampered.json", grantTampered)

	grantWrongKey := grantValid
	sigWrong := ed25519.Sign(privKey2, []byte(grantWrongKey.CanonicalString()))
	grantWrongKey.Signature = hex.EncodeToString(sigWrong)
	writeJSON("grant_wrong_key.json", grantWrongKey)

	// 9. Boundary: Maximum size within limits
	maxID := strings.Repeat("a", 64)
	maxDigest := strings.Repeat("f", 64)
	grantMax := EndpointGrant{
		Version:           GrantVersion,
		GrantID:           maxID,
		TenantID:          maxID,
		EndpointID:        maxID,
		ActionKind:        ActionKindScriptExec,
		ActionDigest:      maxDigest,
		OperatorID:        maxID,
		ResponseSessionID: maxID,
		IssuedAt:          fixedTime.Unix(),
		ExpiresAt:         fixedTime.Add(24 * time.Hour).Unix(),
		Nonce:             strings.Repeat("0", 64),
		SignerKeyID:       keyID1,
	}
	sigMax := ed25519.Sign(privKey1, []byte(grantMax.CanonicalString()))
	grantMax.Signature = hex.EncodeToString(sigMax)
	writeJSON("grant_max_size.json", grantMax)

	offerMax := JobOffer{
		JobID:          maxID,
		Kind:           ActionKindScriptExec,
		LeaseID:        maxID,
		LeaseExpiresAt: fixedTime.Add(24 * time.Hour).Unix(),
		Grant:          &grantMax,
		PayloadJSON:    `{"source":"` + strings.Repeat("echo 1;\n", 1000) + `"}`,
	}
	writeJSON("offer_max_size.json", offerMax)

	// 10. Old-agent compatibility fixture
	// Simulates what a legacy agent receives in a telemetry control response:
	// it includes quarantined_peers and agent_update (which it parses), plus response_offers (which it ignores).
	heartbeatOldAgent := map[string]interface{}{
		"status": "ok",
		"quarantined_peers": []string{"10.0.0.99", "10.0.0.100"},
		"agent_update": map[string]interface{}{
			"version": "1.8.3",
			"sha256":  "04e2be61266e7fb61c0e35999083de2d58bc442566ecdb8d8d34b3fdf178f5ae",
			"url":     "/download/ominull-agent_1.8.3_amd64.deb",
		},
		"response_offers": []interface{}{
			offerValid,
		},
	}
	writeJSON("heartbeat_response_old_agent.json", heartbeatOldAgent)

	// --- Automated Verification of All Fixtures ---

	// Valid grant verifies with correct key at issuance time
	if err := grantValid.Validate(); err != nil {
		t.Fatalf("grant_valid failed Validate: %v", err)
	}
	if err := grantValid.Verify(pubKey1, fixedTime.Add(10*time.Minute)); err != nil {
		t.Fatalf("grant_valid failed Verify: %v", err)
	}

	// Valid offer validates
	if err := offerValid.Validate(); err != nil {
		t.Fatalf("offer_valid failed Validate: %v", err)
	}

	// Valid ack validates
	if err := ackValid.Validate(); err != nil {
		t.Fatalf("ack_valid failed Validate: %v", err)
	}

	// Valid result validates
	if err := resultValid.Validate(); err != nil {
		t.Fatalf("result_valid failed Validate: %v", err)
	}

	// Missing optional validates
	if err := offerMissingOpt.Validate(); err != nil {
		t.Fatalf("offer_missing_optional failed Validate: %v", err)
	}
	if err := ackMissingOpt.Validate(); err != nil {
		t.Fatalf("ack_missing_optional failed Validate: %v", err)
	}
	if err := resultMissingOpt.Validate(); err != nil {
		t.Fatalf("result_missing_optional failed Validate: %v", err)
	}

	// Unknown fields parse and validate cleanly
	var gUnk EndpointGrant
	bGrantUnk, _ := json.Marshal(grantUnknown)
	if err := json.Unmarshal(bGrantUnk, &gUnk); err != nil || gUnk.Validate() != nil {
		t.Fatalf("grant_unknown_fields failed to unmarshal or validate: %v", err)
	}
	if err := gUnk.Verify(pubKey1, fixedTime.Add(10*time.Minute)); err != nil {
		t.Fatalf("grant_unknown_fields failed signature verification: %v", err)
	}

	// Expired grant fails Verify
	if err := grantExpired.Verify(pubKey1, fixedTime); err == nil {
		t.Fatalf("grant_expired expected verification failure, got nil")
	}

	// Tampered grant fails Verify
	if err := grantTampered.Verify(pubKey1, fixedTime.Add(10*time.Minute)); err == nil {
		t.Fatalf("grant_tampered expected verification failure, got nil")
	}

	// Wrong key fails Verify
	if err := grantWrongKey.Verify(pubKey1, fixedTime.Add(10*time.Minute)); err == nil {
		t.Fatalf("grant_wrong_key expected verification failure, got nil")
	}

	// Max size grant and offer validate and verify
	if err := grantMax.Validate(); err != nil || grantMax.Verify(pubKey1, fixedTime.Add(10*time.Minute)) != nil {
		t.Fatalf("grant_max_size failed validation or verification")
	}
	if err := offerMax.Validate(); err != nil {
		t.Fatalf("offer_max_size failed Validate: %v", err)
	}
}
