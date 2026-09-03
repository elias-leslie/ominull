package responseauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTOTP_GenerationAndVerification(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	now := time.Now()
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	if !VerifyTOTPCode(secret, code, now) {
		t.Fatalf("expected valid code %q to verify", code)
	}

	// Verify clock skew +/- 30s
	if !VerifyTOTPCode(secret, code, now.Add(25*time.Second)) {
		t.Fatalf("expected code to verify within +25s skew")
	}
	if !VerifyTOTPCode(secret, code, now.Add(-25*time.Second)) {
		t.Fatalf("expected code to verify within -25s skew")
	}

	// Invalid code
	if VerifyTOTPCode(secret, "000000", now) && code != "000000" {
		t.Fatalf("expected random wrong code to fail")
	}

	// Expired code (+120s)
	if VerifyTOTPCode(secret, code, now.Add(120*time.Second)) {
		t.Fatalf("expected code to fail outside skew window")
	}
}

func TestTOTP_SecretEncryptionRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP"
	encrypted, err := EncryptSecret(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	if encrypted == plaintext {
		t.Fatalf("encrypted ciphertext must not equal plaintext")
	}

	decrypted, err := DecryptSecret(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted %q does not match original %q", decrypted, plaintext)
	}

	// Tampered ciphertext must fail decryption
	tampered := []byte(encrypted)
	if tampered[len(tampered)-1] == 'a' {
		tampered[len(tampered)-1] = 'b'
	} else {
		tampered[len(tampered)-1] = 'a'
	}
	if _, err := DecryptSecret(string(tampered), key); err == nil {
		t.Fatalf("expected tampered ciphertext to fail decryption")
	}
}

func TestTOTP_LockoutAndRecovery(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-lockout"
	operatorID := "bob@example.invalid"

	cfg := Config{
		StateDir:        tempDir,
		SignerPartition: "portable-local",
	}
	auth, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	secret, err := auth.EnrollTOTP(tenantID, operatorID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	browserPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	browserPubHex := hex.EncodeToString(browserPub)

	// 1. Submit 5 consecutive invalid codes -> should trigger lockout
	for i := 1; i <= 5; i++ {
		_, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "session-test", browserPubHex, "999999")
		if err == nil {
			t.Fatalf("attempt %d: expected error on wrong code", i)
		}
	}

	// 6th attempt should be rejected with ErrAuthenticatorLocked even if code is correct!
	now := time.Now()
	validCode, _ := GenerateTOTPCode(secret, now)
	_, err = auth.UnlockSessionWithTOTP(tenantID, operatorID, "session-test", browserPubHex, validCode)
	if err == nil || !errors.Is(err, ErrAuthenticatorLocked) {
		t.Fatalf("expected ErrAuthenticatorLocked on 6th attempt, got: %v", err)
	}

	// 2. Emergency Recovery: generate root recovery token
	recToken, err := auth.GenerateRecoveryToken(tenantID, operatorID)
	if err != nil {
		t.Fatalf("GenerateRecoveryToken failed: %v", err)
	}

	// Consume recovery token to reset lockout
	if err := auth.ResetLockoutWithRecovery(tenantID, operatorID, recToken); err != nil {
		t.Fatalf("ResetLockoutWithRecovery failed: %v", err)
	}

	// 3. Verify valid code succeeds now that lockout is cleared
	codeNow, err := GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}
	sess, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "session-test", browserPubHex, codeNow)
	if err != nil {
		t.Fatalf("expected successful unlock after recovery reset, got: %v", err)
	}
	if sess.SessionID == "" {
		t.Fatalf("empty session ID after unlock")
	}
}

func TestTOTP_OneUseTimeStepAntiReplay(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-replay"
	operatorID := "charlie@example.invalid"

	cfg := Config{
		StateDir:        tempDir,
		SignerPartition: "portable-local",
	}
	auth, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	secret, err := auth.EnrollTOTP(tenantID, operatorID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	browserPub, _, _ := ed25519.GenerateKey(rand.Reader)
	browserPubHex := hex.EncodeToString(browserPub)

	now := time.Now()
	validCode, _ := GenerateTOTPCode(secret, now)

	// First unlock with code succeeds
	sess1, err := auth.UnlockSessionWithTOTP(tenantID, operatorID, "browser-1", browserPubHex, validCode)
	if err != nil {
		t.Fatalf("first unlock failed: %v", err)
	}
	if sess1.SessionID == "" {
		t.Fatalf("expected session ID")
	}

	// Second unlock with EXACT SAME code (or within same 30s window) MUST FAIL with ErrTOTPReplayed
	_, err = auth.UnlockSessionWithTOTP(tenantID, operatorID, "browser-2", browserPubHex, validCode)
	if err == nil || !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed on replayed timestep, got: %v", err)
	}
}

func TestTOTP_SecurityLabeling(t *testing.T) {
	tempDir := t.TempDir()
	auth, err := NewAuthority(Config{StateDir: tempDir})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	tenantID := "tenant-label"
	operatorID := "dave@example.invalid"

	if _, err := auth.EnrollTOTP(tenantID, operatorID); err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	auths, err := auth.store.ListAuthenticators(context.Background(), tenantID, operatorID)
	if err != nil || len(auths) == 0 {
		t.Fatalf("ListAuthenticators failed: %v", err)
	}

	rec := auths[0]
	if !strings.Contains(rec.Label, "Phishing-Vulnerable") {
		t.Fatalf("expected honest security label indicating phishing vulnerability, got: %q", rec.Label)
	}
}
