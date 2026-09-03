package responseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestAuthority_FullLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ominull-auth-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	auth, err := NewAuthority(Config{
		StateDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}

	tenantID := "tenant-test-1"
	opID := "operator-alice"

	// 1. Get / create tenant key
	pubKey, keyID, err := auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed: %v", err)
	}
	if len(pubKey) != ed25519.PublicKeySize || keyID == "" {
		t.Fatalf("invalid generated public key or keyID")
	}

	// 2. Enroll TOTP
	secret, err := auth.EnrollTOTP(tenantID, opID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	// 3. Generate browser keypair (ephemeral in operator's browser)
	browserPub, browserPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey for browser failed: %v", err)
	}
	browserPubHex := hex.EncodeToString(browserPub)

	// 4. Unlock session using TOTP
	now := time.Now()
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}

	session, err := auth.UnlockSessionWithTOTP(tenantID, opID, "browser-sess-1", browserPubHex, code)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}
	if !session.IsValid(now) {
		t.Fatalf("expected unlocked session to be valid")
	}

	// 5. Operator constructs action and signs browser action proof
	actionPayload := response.ForensicCollectionPayload{
		Profile:        "live_volatile",
		MaxBytes:       1048576,
		TimeoutSeconds: 30,
	}
	actionDigest, err := response.ComputeActionDigest(actionPayload)
	if err != nil {
		t.Fatalf("ComputeActionDigest failed: %v", err)
	}

	proof := &ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"endpoint-node-1"},
		Timestamp:       now.Unix(),
		Nonce:           "1122334455667788",
	}
	proofSig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(proofSig)

	// 6. Authority validates proof and signs EndpointGrant
	req := &SignGrantRequest{
		TenantID:     tenantID,
		OperatorID:   opID,
		SessionID:    session.SessionID,
		EndpointID:   "endpoint-node-1",
		ActionKind:   response.ActionKindForensicCollect,
		ActionDigest: actionDigest,
		TTLSeconds:   300,
		Proof:        proof,
	}

	grant, err := auth.SignGrant(req)
	if err != nil {
		t.Fatalf("SignGrant failed: %v", err)
	}

	// 7. Endpoint verifies the signed grant
	if err := grant.Verify(pubKey, now); err != nil {
		t.Fatalf("endpoint verification of grant failed: %v", err)
	}

	// 8. Test lock session
	if err := auth.LockSession(session.SessionID); err != nil {
		t.Fatalf("LockSession failed: %v", err)
	}
	if session.IsValid(now) {
		t.Fatalf("expected session to be invalid after lock")
	}

	// Sign grant with locked session should fail
	_, err = auth.SignGrant(req)
	if err == nil {
		t.Fatalf("expected SignGrant to fail on locked session")
	}
}
