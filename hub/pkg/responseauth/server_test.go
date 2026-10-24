package responseauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestUDSClientAndServer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ominull-uds-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "authority.sock")
	auth, err := NewAuthority(Config{StateDir: tempDir})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}

	server, err := NewServer(auth, sockPath)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start server failed: %v", err)
	}
	defer server.Close()

	// Wait briefly for socket to become available
	time.Sleep(50 * time.Millisecond)

	client := NewUDSClient(sockPath)
	ctx := context.Background()

	tenantID := "tenant-alpha"
	opID := "op-user"

	// 1. GetTenantPublicKey
	pubKey, keyID, err := client.GetTenantPublicKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantPublicKey failed: %v", err)
	}
	if len(pubKey) != ed25519.PublicKeySize || keyID == "" {
		t.Fatalf("invalid public key or keyID")
	}

	// 2. EnrollTOTP
	secret, err := client.EnrollTOTP(ctx, tenantID, opID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	// 3. UnlockSession
	browserPub, browserPriv, _ := ed25519.GenerateKey(rand.Reader)
	browserPubHex := hex.EncodeToString(browserPub)
	now := time.Now()
	code, _ := GenerateTOTPCode(secret, now)

	session, err := client.UnlockSession(ctx, tenantID, opID, "browser-1", browserPubHex, code)
	if err != nil {
		t.Fatalf("UnlockSession failed: %v", err)
	}
	if session.SessionID == "" {
		t.Fatalf("empty session ID")
	}

	// 4. Status
	st, err := client.Status(ctx, tenantID)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if st.ActiveSessions != 1 {
		t.Fatalf("expected 1 active session, got %d", st.ActiveSessions)
	}

	// 5. SignGrant over UDS
	proof := &ActionProof{
		SessionID:       session.SessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TargetEndpoints: []string{"ep-10"},
		Timestamp:       now.Unix(),
		Nonce:           "abcdef123456",
	}
	proofSig := ed25519.Sign(browserPriv, proof.CanonicalBytes())
	proof.Signature = hex.EncodeToString(proofSig)

	grant, err := client.SignGrant(ctx, &SignGrantRequest{
		TenantID:     tenantID,
		OperatorID:   opID,
		SessionID:    session.SessionID,
		EndpointID:   "ep-10",
		ActionKind:   response.ActionKindForensicCollect,
		ActionDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TTLSeconds:   300,
		Proof:        proof,
	})
	if err != nil {
		t.Fatalf("SignGrant failed: %v", err)
	}
	if err := grant.Verify(pubKey, now); err != nil {
		t.Fatalf("grant verification failed: %v", err)
	}

	// 6. LockSession
	if err := client.LockSession(ctx, session.SessionID); err != nil {
		t.Fatalf("LockSession failed: %v", err)
	}

	// 7. Recovery Token over UDS
	tok, err := client.GenerateRecoveryToken(ctx, tenantID, opID)
	if err != nil {
		t.Fatalf("GenerateRecoveryToken failed: %v", err)
	}
	if tok == "" {
		t.Fatalf("empty recovery token returned")
	}

	if err := client.ConsumeRecoveryToken(ctx, tenantID, opID, tok); err != nil {
		t.Fatalf("ConsumeRecoveryToken failed: %v", err)
	}
	// Consuming a second time should fail
	if err := client.ConsumeRecoveryToken(ctx, tenantID, opID, tok); err == nil {
		t.Fatalf("expected second ConsumeRecoveryToken to fail")
	}
}

// An authorization crosses the Unix socket as it does in production: the
// grants come back signed, and a refusal keeps the authority's status.
func TestUDSAuthorize(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ominull-uds-authorize-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	sockPath := filepath.Join(tempDir, "authority.sock")
	auth, err := NewAuthority(Config{StateDir: tempDir})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(auth, sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	time.Sleep(50 * time.Millisecond)
	client := NewUDSClient(sockPath)

	payload := []byte(`{"body":{"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`)
	au, err := client.Authorize(context.Background(), &AuthorizeInput{TenantID: "default", Requester: "admin", Kind: ActionKindIsolation,
		Targets: []string{"ep-1"}, Payload: payload})
	if err != nil || len(au.Grants) != 1 || au.Grants[0].EndpointID != "ep-1" {
		t.Fatalf("authorize over the socket: %+v %v", au, err)
	}
	_, err = client.Authorize(context.Background(), &AuthorizeInput{TenantID: "default", Requester: "admin", Kind: ActionKindIsolation,
		Targets: []string{"ep-1"}, Payload: []byte(`{"route":"/api/v1/nothing","body":{},"targets":["ep-1"]}`)})
	var ae *AuthorityError
	if !errors.As(err, &ae) || ae.Status < 400 {
		t.Fatalf("a refusal should carry the authority's status: %v", err)
	}
}
