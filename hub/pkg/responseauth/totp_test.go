package responseauth

import (
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
