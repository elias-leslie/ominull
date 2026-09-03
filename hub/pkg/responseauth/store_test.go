package responseauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestDurableStore_RestartPersistence(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-alpha"
	operatorID := "alice@example.invalid"

	// 1. Start authority with durable SQLite store
	cfg := Config{
		StateDir:          tempDir,
		SignerPartition:   "portable-local",
		DefaultSessionTTL: 4 * time.Hour,
		DefaultIdleTTL:    30 * time.Minute,
	}

	auth, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("failed to create initial authority: %v", err)
	}

	// Generate tenant response key
	pubKey1, keyID1, err := auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed: %v", err)
	}

	// Grant membership
	if err := auth.GrantMembership(tenantID, operatorID, RoleResponseAdmin); err != nil {
		t.Fatalf("GrantMembership failed: %v", err)
	}

	// Enroll TOTP
	totpSecret, err := auth.EnrollTOTP(tenantID, operatorID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	// Unlock session
	browserPub, browserPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	browserPubHex := hex.EncodeToString(browserPub)

	now := time.Now()
	totpCode, err := GenerateTOTPCode(totpSecret, now)
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}

	sess1, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "browser-1", browserPubHex, totpCode)
	if err != nil {
		t.Fatalf("UnlockSessionWithTOTP failed: %v", err)
	}
	sessionID := sess1.SessionID

	// Sign a grant
	actionDigest := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	proof1 := &ActionProof{
		Version:         2,
		SessionID:       sessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindForensicCollect,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-1"},
		Timestamp:       now.Unix(),
		Nonce:           "nonce-test-1",
	}
	proofSig1 := ed25519.Sign(browserPriv, proof1.CanonicalBytes())
	proof1.Signature = hex.EncodeToString(proofSig1)

	grant1, err := auth.SignGrant(&SignGrantRequest{
		TenantID:     tenantID,
		OperatorID:   operatorID,
		SessionID:    sessionID,
		EndpointID:   "ep-1",
		ActionKind:   response.ActionKindForensicCollect,
		ActionDigest: actionDigest,
		TTLSeconds:   300,
		Proof:        proof1,
	})
	if err != nil {
		t.Fatalf("SignGrant failed before restart: %v", err)
	}
	if err := grant1.Verify(pubKey1, now); err != nil {
		t.Fatalf("grant1 verification failed: %v", err)
	}

	// Generate emergency recovery token
	recToken, err := auth.GenerateRecoveryToken(tenantID, operatorID)
	if err != nil {
		t.Fatalf("GenerateRecoveryToken failed: %v", err)
	}

	// 2. Terminate authority (simulate restart)
	if err := auth.Close(); err != nil {
		t.Fatalf("failed to close authority: %v", err)
	}

	// 3. Reopen authority pointing to exact same state directory
	authRestarted, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("failed to reopen authority: %v", err)
	}
	defer authRestarted.Close()

	// Verify tenant key survived restart byte-for-byte
	pubKey2, keyID2, err := authRestarted.GetOrCreateTenantKey(tenantID)
	if err != nil {
		t.Fatalf("GetOrCreateTenantKey failed after restart: %v", err)
	}
	if keyID1 != keyID2 {
		t.Fatalf("key ID mismatch across restart: %s vs %s", keyID1, keyID2)
	}
	if !pubKey1.Equal(pubKey2) {
		t.Fatalf("public key changed across restart")
	}

	// Verify session survived restart and is still active & valid
	sessRestored, err := authRestarted.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession failed after restart: %v", err)
	}
	if !sessRestored.IsValid(now.Add(1 * time.Minute)) {
		t.Fatalf("restored session marked invalid prematurely")
	}
	if sessRestored.Locked {
		t.Fatalf("session became locked across restart")
	}

	// Verify that restored session can sign grants without re-authenticating
	proof2 := &ActionProof{
		Version:         2,
		SessionID:       sessionID,
		TenantID:        tenantID,
		ActionKind:      response.ActionKindScriptExec,
		ActionDigest:    actionDigest,
		TargetEndpoints: []string{"ep-2"},
		Timestamp:       now.Unix() + 10,
		Nonce:           "nonce-test-2",
	}
	proofSig2 := ed25519.Sign(browserPriv, proof2.CanonicalBytes())
	proof2.Signature = hex.EncodeToString(proofSig2)

	grant2, err := authRestarted.SignGrant(&SignGrantRequest{
		TenantID:     tenantID,
		OperatorID:   operatorID,
		SessionID:    sessionID,
		EndpointID:   "ep-2",
		ActionKind:   response.ActionKindScriptExec,
		ActionDigest: actionDigest,
		TTLSeconds:   300,
		Proof:        proof2,
	})
	if err != nil {
		t.Fatalf("SignGrant failed after restart: %v", err)
	}
	if err := grant2.Verify(pubKey2, now.Add(10*time.Second)); err != nil {
		t.Fatalf("grant2 verification failed: %v", err)
	}

	// 4. Verify Replay Protection across restart
	// Attempt to replay proof1 nonce - MUST FAIL
	_, err = authRestarted.SignGrant(&SignGrantRequest{
		TenantID:     tenantID,
		OperatorID:   operatorID,
		SessionID:    sessionID,
		EndpointID:   "ep-1",
		ActionKind:   response.ActionKindForensicCollect,
		ActionDigest: actionDigest,
		TTLSeconds:   300,
		Proof:        proof1,
	})
	if err == nil {
		t.Fatalf("expected replayed proof nonce to be rejected after restart")
	}

	// 5. Verify Recovery Token consumption across restart
	tokenHash := sha256.Sum256([]byte(recToken))
	tokenHashHex := hex.EncodeToString(tokenHash[:])
	tokRecord, err := authRestarted.store.GetRecoveryToken(context.Background(), tokenHashHex)
	if err != nil {
		t.Fatalf("GetRecoveryToken failed after restart: %v", err)
	}
	if tokRecord.Used {
		t.Fatalf("recovery token marked used before consumption")
	}
	if err := authRestarted.store.ConsumeRecoveryToken(context.Background(), tokenHashHex, time.Now()); err != nil {
		t.Fatalf("ConsumeRecoveryToken failed: %v", err)
	}
	// Second consumption must fail
	if err := authRestarted.store.ConsumeRecoveryToken(context.Background(), tokenHashHex, time.Now()); err == nil {
		t.Fatalf("expected second consumption of recovery token to fail")
	}

	// 6. Verify Signer Audit Log persisted across restart
	auditLogs, err := authRestarted.GetAuditLog(tenantID, 50)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(auditLogs) < 4 {
		t.Fatalf("expected at least 4 audit log entries, got %d", len(auditLogs))
	}

	eventTypes := make(map[string]bool)
	for _, entry := range auditLogs {
		eventTypes[entry.EventType] = true
	}
	expectedEvents := []string{"key_created", "membership_granted", "authenticator_enrolled", "session_unlocked", "grant_signed", "recovery_generated"}
	for _, ev := range expectedEvents {
		if !eventTypes[ev] {
			t.Errorf("missing expected audit event %q in persistent log", ev)
		}
	}

	// 7. Verify LockSession survives restart
	if err := authRestarted.LockSession(sessionID); err != nil {
		t.Fatalf("LockSession failed: %v", err)
	}

	// Terminate and reopen again
	_ = authRestarted.Close()
	authThird, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("reopen 3 failed: %v", err)
	}
	defer authThird.Close()

	sessThird, err := authThird.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession failed on third start: %v", err)
	}
	if !sessThird.Locked {
		t.Fatalf("session lost locked state across daemon restart")
	}
}

func TestStore_ReplayAndPolicy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_policy.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	tenantID := "tenant-beta"

	// 1. Policy test
	policy := &MethodPolicyRecord{
		TenantID:         tenantID,
		AllowedMethods:   []AuthMethod{AuthMethodWebAuthn},
		RequireStepUp:    true,
		MaxSessionTTLSec: 3600,
		MaxIdleTTLSec:    900,
		UpdatedAt:        time.Now(),
	}
	if err := store.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("SavePolicy failed: %v", err)
	}

	loadedPolicy, err := store.GetPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if !loadedPolicy.RequireStepUp || loadedPolicy.MaxSessionTTLSec != 3600 {
		t.Fatalf("policy fields mismatch: %+v", loadedPolicy)
	}

	// 2. Nonce replay test
	nonce := "unique-nonce-12345"
	exp := time.Now().Add(5 * time.Minute)
	if err := store.CheckAndRecordNonce(ctx, nonce, "test", tenantID, exp); err != nil {
		t.Fatalf("CheckAndRecordNonce first call failed: %v", err)
	}
	if err := store.CheckAndRecordNonce(ctx, nonce, "test", tenantID, exp); err == nil {
		t.Fatalf("expected second CheckAndRecordNonce to fail with ErrNonceReplayed")
	}
}
