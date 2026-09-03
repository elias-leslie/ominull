package responseauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
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
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}

	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		expected, err := GenerateTOTPCode(secret, now.Add(offset))
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}
