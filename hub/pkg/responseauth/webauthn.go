package responseauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrWebAuthnChallengeMismatch = errors.New("webauthn challenge mismatch or expired")
	ErrWebAuthnOriginMismatch    = errors.New("webauthn origin mismatch")
	ErrWebAuthnRPIDMismatch      = errors.New("webauthn RP ID mismatch")
	ErrWebAuthnUserNotPresent    = errors.New("webauthn user presence flag not set")
	ErrWebAuthnSignatureInvalid  = errors.New("webauthn signature verification failed")
	ErrWebAuthnCloned            = errors.New("webauthn sign count not strictly incrementing; possible cloned authenticator")
)

// WebAuthnRPConfig defines Relying Party settings.
type WebAuthnRPConfig struct {
	RPID           string   `json:"rp_id"`          // e.g. "ominull.example.invalid" or "localhost"
	RPName         string   `json:"rp_name"`        // e.g. "Ominull Response Authority"
	AllowedOrigins []string `json:"allowed_origins"` // e.g. ["https://ominull.example.invalid:8443", "http://localhost:9999"]
}

// StoredWebAuthnCredential holds the public key and sign counter of a registered WebAuthn credential.
type StoredWebAuthnCredential struct {
	CredentialID string `json:"credential_id"` // base64url
	KeyType      string `json:"key_type"`      // "ES256", "Ed25519", "RS256"
	PublicKeyPEM string `json:"public_key_pem"` // PKIX PEM or hex
	SignCount    uint32 `json:"sign_count"`
	AAGUID       string `json:"aaguid,omitempty"`
}

// ClientDataJSON parses W3C WebAuthn clientDataJSON.
type ClientDataJSON struct {
	Type        string `json:"type"`      // "webauthn.create" or "webauthn.get"
	Challenge   string `json:"challenge"` // base64url
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// RegistrationOptions for navigator.credentials.create()
type RegistrationOptions struct {
	Challenge string `json:"challenge"` // base64url
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"` // base64url
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"` // -7: ES256, -8: Ed25519, -257: RS256
	} `json:"pubKeyCredParams"`
	Timeout                int    `json:"timeout"`
	Attestation            string `json:"attestation"`
	AuthenticatorSelection struct {
		UserVerification string `json:"userVerification"`
		ResidentKey      string `json:"residentKey"`
	} `json:"authenticatorSelection"`
}

// AuthenticationOptions for navigator.credentials.get()
type AuthenticationOptions struct {
	Challenge        string `json:"challenge"` // base64url
	Timeout          int    `json:"timeout"`
	RPID             string `json:"rpId"`
	AllowCredentials []struct {
		ID   string   `json:"id"` // base64url
		Type string   `json:"type"`
		X509 []string `json:"transports,omitempty"`
	} `json:"allowCredentials"`
	UserVerification string `json:"userVerification"`
}

// WebAuthnRegistrationRequest is submitted by the client after navigator.credentials.create()
type WebAuthnRegistrationRequest struct {
	TenantID        string `json:"tenant_id"`
	OperatorID      string `json:"operator_id"`
	CredentialID    string `json:"credential_id"`     // base64url
	ClientDataJSON  string `json:"client_data_json"`   // base64url
	AttestationData string `json:"attestation_data"`  // base64url
	PublicKeyPEM    string `json:"public_key_pem"`    // Optional direct PKIX PEM (or extracted from attestation)
	KeyType         string `json:"key_type"`          // "ES256", "Ed25519", "RS256"
}

// WebAuthnAuthenticationRequest is submitted by the client after navigator.credentials.get()
type WebAuthnAuthenticationRequest struct {
	TenantID          string `json:"tenant_id"`
	OperatorID        string `json:"operator_id"`
	BrowserSessionID  string `json:"browser_session_id"`
	BrowserPublicKey  string `json:"browser_public_key"` // hex
	CredentialID      string `json:"credential_id"`      // base64url
	ClientDataJSON    string `json:"client_data_json"`    // base64url
	AuthenticatorData string `json:"authenticator_data"` // base64url
	Signature         string `json:"signature"`          // base64url
}

// WebAuthnManager coordinates challenges and signature verification.
type WebAuthnManager struct {
	mu         sync.RWMutex
	cfg        WebAuthnRPConfig
	challenges map[string]*pendingChallenge // challenge (base64url) -> challenge record
}

type pendingChallenge struct {
	Challenge string
	TenantID  string
	Operator  string
	Kind      string // "create" or "get"
	ExpiresAt time.Time
}

// NewWebAuthnManager creates a WebAuthn manager.
func NewWebAuthnManager(cfg WebAuthnRPConfig) *WebAuthnManager {
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if cfg.RPName == "" {
		cfg.RPName = "Ominull Response Authority"
	}
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{
			"http://localhost:9999",
			"https://localhost:9999",
			"https://ominull.example.invalid:8443",
		}
	}
	return &WebAuthnManager{
		cfg:        cfg,
		challenges: make(map[string]*pendingChallenge),
	}
}

// GenerateChallenge creates a random 32-byte challenge and stores it in memory.
func (m *WebAuthnManager) GenerateChallenge(tenantID, operatorID, kind string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ch := base64.RawURLEncoding.EncodeToString(b)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Evict expired
	now := time.Now()
	for k, v := range m.challenges {
		if now.After(v.ExpiresAt) {
			delete(m.challenges, k)
		}
	}

	m.challenges[ch] = &pendingChallenge{
		Challenge: ch,
		TenantID:  tenantID,
		Operator:  operatorID,
		Kind:      kind,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	return ch, nil
}

// ConsumeChallenge verifies and deletes a pending challenge.
func (m *WebAuthnManager) ConsumeChallenge(ch, tenantID, operatorID, expectedKind string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, exists := m.challenges[ch]
	if !exists {
		return ErrWebAuthnChallengeMismatch
	}
	delete(m.challenges, ch)

	if time.Now().After(p.ExpiresAt) {
		return ErrWebAuthnChallengeMismatch
	}
	if p.TenantID != tenantID || p.Operator != operatorID || p.Kind != expectedKind {
		return ErrWebAuthnChallengeMismatch
	}
	return nil
}

// CreateRegistrationOptions builds options for navigator.credentials.create()
func (m *WebAuthnManager) CreateRegistrationOptions(tenantID, operatorID string) (*RegistrationOptions, error) {
	ch, err := m.GenerateChallenge(tenantID, operatorID, "create")
	if err != nil {
		return nil, err
	}

	opts := &RegistrationOptions{
		Challenge: ch,
		Timeout:   60000,
		Attestation: "none",
	}
	opts.RP.ID = m.cfg.RPID
	opts.RP.Name = m.cfg.RPName
	opts.User.ID = base64.RawURLEncoding.EncodeToString([]byte(operatorID))
	opts.User.Name = operatorID
	opts.User.DisplayName = operatorID

	opts.PubKeyCredParams = []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	}{
		{Type: "public-key", Alg: -7},   // ES256
		{Type: "public-key", Alg: -8},   // Ed25519
		{Type: "public-key", Alg: -257}, // RS256
	}

	opts.AuthenticatorSelection.UserVerification = "preferred"
	opts.AuthenticatorSelection.ResidentKey = "preferred"

	return opts, nil
}

// CreateAuthenticationOptions builds options for navigator.credentials.get()
func (m *WebAuthnManager) CreateAuthenticationOptions(tenantID, operatorID string, credIDs []string) (*AuthenticationOptions, error) {
	ch, err := m.GenerateChallenge(tenantID, operatorID, "get")
	if err != nil {
		return nil, err
	}

	opts := &AuthenticationOptions{
		Challenge:        ch,
		Timeout:          60000,
		RPID:             m.cfg.RPID,
		UserVerification: "preferred",
	}

	for _, cid := range credIDs {
		opts.AllowCredentials = append(opts.AllowCredentials, struct {
			ID   string   `json:"id"`
			Type string   `json:"type"`
			X509 []string `json:"transports,omitempty"`
		}{
			ID:   cid,
			Type: "public-key",
		})
	}

	return opts, nil
}

// VerifyRegistration verifies the clientDataJSON and extracts the credential.
func (m *WebAuthnManager) VerifyRegistration(req *WebAuthnRegistrationRequest) (*StoredWebAuthnCredential, error) {
	if req.CredentialID == "" || req.ClientDataJSON == "" {
		return nil, errors.New("missing credential ID or clientDataJSON")
	}

	rawClientData, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		rawClientData, err = base64.StdEncoding.DecodeString(req.ClientDataJSON)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 clientDataJSON: %w", err)
		}
	}

	var cd ClientDataJSON
	if err := json.Unmarshal(rawClientData, &cd); err != nil {
		return nil, fmt.Errorf("malformed clientDataJSON: %w", err)
	}

	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("unexpected clientDataJSON type: %q", cd.Type)
	}

	if err := m.ConsumeChallenge(cd.Challenge, req.TenantID, req.OperatorID, "create"); err != nil {
		return nil, err
	}

	if err := m.validateOrigin(cd.Origin); err != nil {
		return nil, err
	}

	keyType := req.KeyType
	if keyType == "" {
		keyType = "ES256"
	}

	return &StoredWebAuthnCredential{
		CredentialID: req.CredentialID,
		KeyType:      keyType,
		PublicKeyPEM: req.PublicKeyPEM,
		SignCount:    0,
	}, nil
}

// VerifyAssertion validates authenticatorData and assertion signature.
func (m *WebAuthnManager) VerifyAssertion(req *WebAuthnAuthenticationRequest, stored *StoredWebAuthnCredential) error {
	if req.CredentialID == "" || req.ClientDataJSON == "" || req.AuthenticatorData == "" || req.Signature == "" {
		return errors.New("missing required assertion fields")
	}

	// 1. Parse clientDataJSON
	rawClientData, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		rawClientData, err = base64.StdEncoding.DecodeString(req.ClientDataJSON)
		if err != nil {
			return fmt.Errorf("invalid base64 clientDataJSON: %w", err)
		}
	}

	var cd ClientDataJSON
	if err := json.Unmarshal(rawClientData, &cd); err != nil {
		return fmt.Errorf("malformed clientDataJSON: %w", err)
	}

	if cd.Type != "webauthn.get" {
		return fmt.Errorf("unexpected clientDataJSON type: %q", cd.Type)
	}

	// 2. Verify challenge
	if err := m.ConsumeChallenge(cd.Challenge, req.TenantID, req.OperatorID, "get"); err != nil {
		return err
	}

	// 3. Verify origin
	if err := m.validateOrigin(cd.Origin); err != nil {
		return err
	}

	// 4. Parse authenticatorData
	authData, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		authData, err = base64.StdEncoding.DecodeString(req.AuthenticatorData)
		if err != nil {
			return fmt.Errorf("invalid base64 authenticatorData: %w", err)
		}
	}

	if len(authData) < 37 {
		return errors.New("authenticatorData too short")
	}

	// 5. Verify RP ID hash
	expectedRPHash := sha256.Sum256([]byte(m.cfg.RPID))
	if !bytes.Equal(authData[0:32], expectedRPHash[:]) {
		// Allow origin host fallback
		u, err := url.Parse(cd.Origin)
		if err == nil {
			hostHash := sha256.Sum256([]byte(u.Hostname()))
			if !bytes.Equal(authData[0:32], hostHash[:]) {
				return ErrWebAuthnRPIDMismatch
			}
		} else {
			return ErrWebAuthnRPIDMismatch
		}
	}

	// 6. Verify User Presence (UP bit 0)
	flags := authData[32]
	if (flags & 0x01) == 0 {
		return ErrWebAuthnUserNotPresent
	}

	// 7. Verify Sign Count (anti-cloning)
	signCount := binary.BigEndian.Uint32(authData[33:37])
	if signCount > 0 && stored.SignCount > 0 && signCount <= stored.SignCount {
		return fmt.Errorf("%w: current %d <= previous %d", ErrWebAuthnCloned, signCount, stored.SignCount)
	}
	stored.SignCount = signCount

	// 8. Verify Signature over authenticatorData || sha256(clientDataJSON)
	clientDataHash := sha256.Sum256(rawClientData)
	signedData := append(authData, clientDataHash[:]...)

	sigBytes, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			return fmt.Errorf("invalid base64 signature: %w", err)
		}
	}

	return verifyWebAuthnSignature(stored, signedData, sigBytes)
}

func (m *WebAuthnManager) validateOrigin(origin string) error {
	origin = strings.TrimRight(strings.ToLower(origin), "/")
	for _, allowed := range m.cfg.AllowedOrigins {
		allowed = strings.TrimRight(strings.ToLower(allowed), "/")
		if origin == allowed {
			return nil
		}
		// Allow hostname-matching without port in dev/test
		if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "https://localhost") {
			return nil
		}
	}
	return fmt.Errorf("%w: %q not in allowed set %v", ErrWebAuthnOriginMismatch, origin, m.cfg.AllowedOrigins)
}

func verifyWebAuthnSignature(stored *StoredWebAuthnCredential, signedData, sigBytes []byte) error {
	pubBytes, err := hex.DecodeString(stored.PublicKeyPEM)
	if err != nil {
		pubBytes = []byte(stored.PublicKeyPEM)
	}

	switch stored.KeyType {
	case "Ed25519":
		if len(pubBytes) != ed25519.PublicKeySize {
			return errors.New("invalid Ed25519 public key length")
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), signedData, sigBytes) {
			return ErrWebAuthnSignatureInvalid
		}
		return nil

	case "ES256":
		// ES256: ECDSA P-256 with SHA-256
		hash := sha256.Sum256(signedData)

		var pubKey *ecdsa.PublicKey
		if p, err := x509.ParsePKIXPublicKey(pubBytes); err == nil {
			if ecPub, ok := p.(*ecdsa.PublicKey); ok {
				pubKey = ecPub
			}
		}
		if pubKey == nil && len(pubBytes) == 65 && pubBytes[0] == 0x04 {
			// Uncompressed P-256 point
			pubKey = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(pubBytes[1:33]),
				Y:     new(big.Int).SetBytes(pubBytes[33:65]),
			}
		}
		if pubKey == nil {
			return errors.New("unable to parse ES256 ECDSA public key")
		}

		// Try ASN.1 verification first
		if ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
			return nil
		}
		// Try IEEE P1363 (r || s, 64 bytes)
		if len(sigBytes) == 64 {
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:])
			if ecdsa.Verify(pubKey, hash[:], r, s) {
				return nil
			}
		}
		return ErrWebAuthnSignatureInvalid

	case "RS256":
		hash := sha256.Sum256(signedData)
		p, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		rsaPub, ok := p.(*rsa.PublicKey)
		if !ok {
			return errors.New("key is not an RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return ErrWebAuthnSignatureInvalid
		}
		return nil

	default:
		return fmt.Errorf("unsupported WebAuthn key type: %s", stored.KeyType)
	}
}
