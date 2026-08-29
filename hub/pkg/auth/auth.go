package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleAuditor = "auditor"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Salt         string    `json:"salt"`
	Role         string    `json:"role"` // admin, analyst, auditor
	TenantID     string    `json:"tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
}

type Claims struct {
	UserID    string `json:"uid"`
	Username  string `json:"usr"`
	Role      string `json:"rol"`
	TenantID  string `json:"tid"`
	ExpiresAt int64  `json:"exp"`
}

// HashPassword derives a stored verifier from a password.
//
// It uses bcrypt, which is deliberately slow and carries its own salt. What it
// replaces was one round of SHA-256 over salt+password: a correct construction
// for a message digest and the wrong primitive for a password, because a
// commodity GPU computes billions of those a second and the salt only stops the
// attacker from doing every stolen hash at once. The salt return is kept so
// callers and the users table do not change shape; bcrypt embeds its own, so
// the value returned here is informational and CheckPassword ignores it.
func HashPassword(password string) (hash, salt string, err error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", err
	}
	salt = hex.EncodeToString(saltBytes)

	digest, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", "", err
	}
	return string(digest), salt, nil
}

// bcryptCost is the work factor. 12 is roughly a quarter-second per attempt on
// current hardware: unnoticeable on a login, ruinous on a dictionary.
const bcryptCost = 12

// CheckPassword verifies a password against a stored verifier.
//
// It accepts the legacy hex SHA-256 form as well, so a users table written by
// an older build still authenticates rather than locking everyone out; those
// rows should be rehashed on next login by whatever calls this. The legacy
// comparison stays constant-time.
func CheckPassword(password, hash, salt string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}

	h := sha256.New()
	h.Write([]byte(salt + password))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(hash))
}

// NeedsRehash reports whether a stored verifier is in the superseded format, so
// a caller that has just verified a password in the legacy form can replace it
// with a bcrypt one while it still holds the plaintext.
func NeedsRehash(hash string) bool {
	return !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$")
}

func GenerateJWT(claims Claims, secret string, ttl time.Duration) (string, error) {
	claims.ExpiresAt = time.Now().Add(ttl).Unix()

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	unsignedToken := fmt.Sprintf("%s.%s", headerB64, claimsB64)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsignedToken))
	signatureB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", unsignedToken, signatureB64), nil
}

func ValidateJWT(tokenStr, secret string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsignedToken := fmt.Sprintf("%s.%s", parts[0], parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsignedToken))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("signature verification failed")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid claims encoding")
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, errors.New("failed to parse claims")
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}
