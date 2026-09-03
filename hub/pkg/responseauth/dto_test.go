package responseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestActionProof_Verification(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	now := time.Now()
	proof := &ActionProof{
		SessionID:       "sess-abc-123",
		TenantID:        "tenant-primary",
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TargetEndpoints: []string{"ep-1", "ep-2"},
		Timestamp:       now.Unix(),
		Nonce:           "deadbeef1234",
	}

	sig := ed25519.Sign(privKey, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(sig)

	if err := proof.Verify(pubKey, now); err != nil {
		t.Fatalf("expected proof to verify, got: %v", err)
	}

	// Test replay/expired timestamp
	oldProof := *proof
	oldProof.Timestamp = now.Add(-10 * time.Minute).Unix()
	oldSig := ed25519.Sign(privKey, oldProof.CanonicalBytes())
	oldProof.Signature = hex.EncodeToString(oldSig)
	if err := oldProof.Verify(pubKey, now); err == nil {
		t.Fatalf("expected old timestamp to fail verification")
	}

	// Test tampered targets
	tamperedProof := *proof
	tamperedProof.TargetEndpoints = []string{"ep-1", "ep-3"}
	if err := tamperedProof.Verify(pubKey, now); err == nil {
		t.Fatalf("expected tampered target list to fail verification")
	}
}

func TestResponseSession_Validation(t *testing.T) {
	now := time.Now()
	session := &ResponseSession{
		SessionID:          "sess-test",
		OperatorID:         "op-1",
		TenantID:           "tenant-1",
		AllowedActionKinds: []response.ActionKind{response.ActionKindForensicCollect},
		IssuedAt:           now,
		IdleExpiresAt:      now.Add(30 * time.Minute),
		AbsoluteExpiresAt:  now.Add(8 * time.Hour),
		Locked:             false,
		AuthMethod:         AuthMethodWebAuthn,
	}

	if !session.IsValid(now) {
		t.Fatalf("expected session to be valid now")
	}

	// Idle expired
	if session.IsValid(now.Add(31 * time.Minute)) {
		t.Fatalf("expected session to be invalid after idle expiration")
	}

	// Absolute expired
	if session.IsValid(now.Add(9 * time.Hour)) {
		t.Fatalf("expected session to be invalid after absolute expiration")
	}

	// Locked session
	session.Locked = true
	if session.IsValid(now) {
		t.Fatalf("expected locked session to be invalid")
	}
}
