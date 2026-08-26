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

func HashPassword(password string) (hash, salt string, err error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", err
	}
	salt = hex.EncodeToString(saltBytes)

	h := sha256.New()
	h.Write([]byte(salt + password))
	hash = hex.EncodeToString(h.Sum(nil))
	return hash, salt, nil
}

func CheckPassword(password, hash, salt string) bool {
	h := sha256.New()
	h.Write([]byte(salt + password))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(hash))
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
