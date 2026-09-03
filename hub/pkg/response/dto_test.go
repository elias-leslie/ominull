package response

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestEndpointGrant_Verification(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyFP := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyFP[:])

	now := time.Now()
	grant := &EndpointGrant{
		Version:           GrantVersion,
		GrantID:           "grant-12345",
		TenantID:          "tenant-alpha",
		EndpointID:        "linux-endpoint-1",
		ActionKind:        ActionKindForensicCollect,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        "op-admin",
		ResponseSessionID: "sess-999",
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(15 * time.Minute).Unix(),
		Nonce:             "a1b2c3d4e5f6",
		SignerKeyID:       keyID,
	}

	// Sign the canonical grant string
	canonical := []byte(grant.CanonicalString())
	sig := ed25519.Sign(privKey, canonical)
	grant.Signature = hex.EncodeToString(sig)

	// Valid verification
	if err := grant.Verify(pubKey, now); err != nil {
		t.Fatalf("expected grant to verify, got: %v", err)
	}

	// Expired grant
	if err := grant.Verify(pubKey, now.Add(20*time.Minute)); err == nil {
		t.Fatalf("expected expired grant to fail verification")
	}

	// Tampered grant field
	tamperedGrant := *grant
	tamperedGrant.EndpointID = "linux-endpoint-2"
	if err := tamperedGrant.Verify(pubKey, now); err == nil {
		t.Fatalf("expected tampered endpoint ID to fail verification")
	}

	// Wrong key
	wrongPubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := grant.Verify(wrongPubKey, now); err == nil {
		t.Fatalf("expected verification with wrong public key to fail")
	}
}

func TestComputeActionDigest(t *testing.T) {
	payload := ForensicCollectionPayload{
		Profile:        "live_volatile",
		MaxBytes:       10 * 1024 * 1024,
		TimeoutSeconds: 60,
	}
	digest, err := ComputeActionDigest(payload)
	if err != nil {
		t.Fatalf("ComputeActionDigest failed: %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("expected 64 char hex digest, got len=%d (%s)", len(digest), digest)
	}
}
