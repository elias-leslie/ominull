package responseauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

const (
	// Security labeling per Response Threat Model
	SecurityLabelTOTP     = "Phishing-Vulnerable (RFC 6238 Shared Secret)"
	SecurityLabelWebAuthn = "Phishing-Resistant (FIDO2 / WebAuthn Hardware Bound)"

	// Attempt limits and lockout parameters
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)

var (
	ErrAuthenticatorLocked = errors.New("authenticator temporarily locked due to excessive failed attempts")
	ErrTOTPReplayed        = errors.New("TOTP code already used for this 30-second window; wait for next timestep")
)

// GenerateTOTPSecret creates a new random base32 encoded secret for TOTP.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTPCode computes a 6-digit TOTP code for a secret and time.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// try with padding
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("invalid base32 secret: %w", err)
		}
	}

	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	code := truncated % uint32(math.Pow10(6))

	return fmt.Sprintf("%06d", code), nil
}

// VerifyTOTPCode verifies a 6-digit TOTP code with +/- 1 period (30s) clock skew window.
func VerifyTOTPCode(secret, code string, now time.Time) bool {
	_, ok := VerifyTOTPCodeWithStep(secret, code, now)
	return ok
}

// VerifyTOTPCodeWithStep verifies a 6-digit TOTP code and returns the matching timestep (counter).
func VerifyTOTPCodeWithStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}

	for _, offset := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		t := now.Add(offset)
		expected, err := GenerateTOTPCode(secret, t)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}

// EncryptSecret encrypts a plaintext secret using AES-256-GCM.
func EncryptSecret(secret string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a hex-encoded AES-256-GCM ciphertext.
func DecryptSecret(ciphertextHex string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("decryption key must be 32 bytes")
	}

	data, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// GetOrGenerateMasterKey retrieves or creates a 32-byte master key on disk (mode 0600).
func GetOrGenerateMasterKey(keyPath string) ([]byte, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(data))
		keyBytes, err := hex.DecodeString(key)
		if err == nil && len(keyBytes) == 32 {
			return keyBytes, nil
		}
	}

	// Generate new key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}

	keyHex := hex.EncodeToString(keyBytes)
	if err := os.WriteFile(keyPath, []byte(keyHex), 0600); err != nil {
		// Fallback: derive from hash of path if write fails (e.g. read-only)
		h := sha256.Sum256([]byte(keyPath))
		return h[:], nil
	}
	return keyBytes, nil
}
