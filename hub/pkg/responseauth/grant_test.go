package responseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestSignGrant_TypedActionValidationAndTargetBinding(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-grant"
	operatorID := "ops@example.invalid"

	auth, err := NewAuthority(Config{StateDir: tempDir})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	pubKey, _, err := auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed: %v", err)
	}

	secret, err := auth.EnrollTOTP(tenantID, operatorID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	browserPubHex := hex.EncodeToString(browserPub)

	now := time.Now()
	code, _ := GenerateTOTPCode(secret, now)
	sess, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "browser-1", browserPubHex, code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}

	// Define typed action payload
	type scriptActionPayload struct {
		ScriptID   string   `json:"script_id"`
		Version    string   `json:"version"`
		Entrypoint string   `json:"entrypoint"`
		Arguments  []string `json:"arguments"`
	}
	actionObj := scriptActionPayload{
		ScriptID:   "scr-isolate-01",
		Version:    "1.0.0",
		Entrypoint: "main.py",
		Arguments:  []string{"--strict"},
	}
	actionBytes, _ := json.Marshal(actionObj)
	actionDigestBytes := sha256.Sum256(actionBytes)
	actionDigest := hex.EncodeToString(actionDigestBytes[:])

	// 1. Success case: valid typed action with target binding
	proofValid := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-prod-01", "ep-prod-02"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-valid-01",
	}
	proofSig := ed25519.Sign(browserPriv, proofValid.CanonicalBytes())
	proofValid.Signature = hex.EncodeToString(proofSig)

	grant, err := auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-prod-01",
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: actionBytes,
		TTLSeconds:    300,
		Proof:         proofValid,
	})
	if err != nil {
		t.Fatalf("SignGrant failed: %v", err)
	}
	if err := grant.Verify(pubKey, now); err != nil {
		t.Fatalf("grant verification failed: %v", err)
	}

	// 2. Target Binding: Requesting grant for endpoint NOT in proof's target list MUST FAIL
	proof2 := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-prod-01", "ep-prod-02"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-target-unauth",
	}
	proofSig2 := ed25519.Sign(browserPriv, proof2.CanonicalBytes())
	proof2.Signature = hex.EncodeToString(proofSig2)

	_, err = auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-rogue-99", // NOT in TargetEndpoints
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: actionBytes,
		TTLSeconds:    300,
		Proof:         proof2,
	})
	if err == nil {
		t.Fatalf("expected SignGrant to fail for unauthorized endpoint")
	}

	// 3. Unbounded Target Set: Proof with empty target list MUST FAIL
	proofUnbounded := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{}, // empty unbounded target set
		Timestamp:       now.Unix(),
		Nonce:           "nonce-unbounded",
	}
	proofSigUnbounded := ed25519.Sign(browserPriv, proofUnbounded.CanonicalBytes())
	proofUnbounded.Signature = hex.EncodeToString(proofSigUnbounded)

	_, err = auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-prod-01",
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: actionBytes,
		TTLSeconds:    300,
		Proof:         proofUnbounded,
	})
	if err == nil {
		t.Fatalf("expected SignGrant to fail for unbounded empty target list")
	}

	// 4. Cross-Tenant Signing Denied
	proofCrossTenant := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        "tenant-other", // cross-tenant!
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-prod-01"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-crosstenant",
	}
	proofSigCross := ed25519.Sign(browserPriv, proofCrossTenant.CanonicalBytes())
	proofCrossTenant.Signature = hex.EncodeToString(proofSigCross)

	_, err = auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID, // requested tenant
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-prod-01",
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: actionBytes,
		TTLSeconds:    300,
		Proof:         proofCrossTenant,
	})
	if err == nil {
		t.Fatalf("expected SignGrant to fail for cross-tenant proof")
	}

	// 5. Tampered Action Payload: Hub submits modified payload not matching digest
	tamperedAction := scriptActionPayload{
		ScriptID:   "scr-isolate-01",
		Version:    "1.0.0",
		Entrypoint: "malicious_backdoor.sh", // modified!
		Arguments:  []string{"--strict"},
	}
	tamperedBytes, _ := json.Marshal(tamperedAction)

	proofTamper := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest, // original digest in browser proof
		TargetEndpoints: []string{"ep-prod-01"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-tamper-check",
	}
	proofSigTamper := ed25519.Sign(browserPriv, proofTamper.CanonicalBytes())
	proofTamper.Signature = hex.EncodeToString(proofSigTamper)

	_, err = auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-prod-01",
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: tamperedBytes, // tampered payload!
		TTLSeconds:    300,
		Proof:         proofTamper,
	})
	if err == nil {
		t.Fatalf("expected SignGrant to fail when action payload is tampered")
	}

	// 6. Action Kind Mismatch
	proofKindMismatch := &ActionProof{
		Version:         2,
		SessionID:       sess.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect, // kind mismatch!
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-prod-01"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-kind-mismatch",
	}
	proofSigKind := ed25519.Sign(browserPriv, proofKindMismatch.CanonicalBytes())
	proofKindMismatch.Signature = hex.EncodeToString(proofSigKind)

	_, err = auth.SignGrant(&SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     sess.SessionID,
		EndpointID:    "ep-prod-01",
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  actionDigest,
		ActionPayload: actionBytes,
		TTLSeconds:    300,
		Proof:         proofKindMismatch,
	})
	if err == nil {
		t.Fatalf("expected SignGrant to fail on action kind mismatch")
	}
}
