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

func TestCanonicalBytes_MatchesJSVector(t *testing.T) {
	proof := &ActionProof{
		Version:         2,
		SessionID:       "sess-123",
		TenantID:        "tenant-abc",
		ActionKind:      response.ActionKindTerminalSession,
		ActionDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TargetEndpoints: []string{"ep-win-1", "ep-linux-2"},
		Timestamp:       1725400000,
		Nonce:           "0123456789abcdef0123456789abcdef",
	}

	actualHex := hex.EncodeToString(proof.CanonicalBytes())
	expectedHex := "000000174f4d494e554c4c2d414354494f4e2d50524f4f462d56320000000200000008736573732d3132330000000a74656e616e742d616263000000107465726d696e616c5f73657373696f6e0000004065336230633434323938666331633134396166626634633839393666623932343237616534316534363439623933346361343935393931623738353262383535000000020000000865702d77696e2d310000000a65702d6c696e75782d320000000066d783c0000000203031323334353637383961626364656630313233343536373839616263646566"

	if actualHex != expectedHex {
		t.Fatalf("mismatched canonical bytes hex:\n  got:  %s\n  want: %s", actualHex, expectedHex)
	}
}

func TestCanonicalBytes_VerifyWebCryptoSignature(t *testing.T) {
	pubHex := "af2cc36ab44e073557055ce5cdc43524371742d6d10c6f095b975ebfd7b1c136"
	sigHex := "f91ed55d4422b23e5ea6f78b688e4c89a1a3de7aa4d0a4d0b0a7d4b0549d6a11cfcf911c0611e4f6bdbd39cfd8230dcb2e4b6d33f4784e31876b89905a28b603"

	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("failed to decode pubHex: %v", err)
	}

	proof := &ActionProof{
		Version:         2,
		SessionID:       "sess-node-test",
		TenantID:        "default",
		ActionKind:      response.ActionKindTerminalSession,
		ActionDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TargetEndpoints: []string{"ep-1"},
		Timestamp:       1788485075,
		Nonce:           "aabbccddeeff00112233445566778899",
		Signature:       sigHex,
	}

	if err := proof.Verify(pubBytes, time.Unix(proof.Timestamp, 0)); err != nil {
		t.Fatalf("expected real WebCrypto Ed25519 signature to verify in Go, got: %v", err)
	}
}


