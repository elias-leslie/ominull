package auth

import (
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	password := "sample_test_pass"
	hash, salt, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(password, hash, salt) {
		t.Errorf("expected password to match hash")
	}

	if CheckPassword("wrong_test_pass", hash, salt) {
		t.Errorf("wrong password should not match hash")
	}
}

func TestJWTTokenLifecycle(t *testing.T) {
	testKey := "test_mock_secret_key"
	claims := Claims{
		UserID:   "usr-admin-01",
		Username: "secops_lead",
		Role:     RoleAdmin,
		TenantID: "default",
	}

	token, err := GenerateJWT(claims, testKey, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	parsed, err := ValidateJWT(token, testKey)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if parsed.Username != claims.Username || parsed.Role != RoleAdmin {
		t.Errorf("claims mismatch: got %+v, want %+v", parsed, claims)
	}

	// Test invalid secret
	_, err = ValidateJWT(token, "wrong-secret-key")
	if err == nil {
		t.Errorf("expected validation to fail with wrong secret")
	}
}
