package responseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// Config holds settings for the Response Authority.
type Config struct {
	StateDir        string        // e.g. /var/lib/ominull-response-authority
	SignerPartition string        // e.g. "portable-local" or "hsm-partition-1"
	DefaultSessionTTL time.Duration // e.g. 8h
	DefaultIdleTTL    time.Duration // e.g. 30m
}

// AuthenticatorRecord stores enrolled credentials (TOTP, WebAuthn) for an operator.
type AuthenticatorRecord struct {
	ID          string     `json:"id"`
	OperatorID  string     `json:"operator_id"`
	TenantID    string     `json:"tenant_id"`
	Type        AuthMethod `json:"type"`
	SecretOrKey string     `json:"secret_or_key"` // encrypted or public key
	EnrolledAt  time.Time  `json:"enrolled_at"`
	LastUsedAt  time.Time  `json:"last_used_at"`
}

// Authority manages tenant response keys, sessions, and endpoint grant signing.
type Authority struct {
	mu             sync.RWMutex
	cfg            Config
	tenantKeys     map[string]ed25519.PrivateKey // tenant_id -> private key
	authenticators map[string][]*AuthenticatorRecord // tenant_id:operator_id -> authenticators
	sessions       map[string]*ResponseSession // session_id -> session
	recoveryTokens map[string]*RecoveryToken   // token -> recovery token
	startedAt      time.Time
}

// NewAuthority creates a new Response Authority instance.
func NewAuthority(cfg Config) (*Authority, error) {
	if cfg.StateDir == "" {
		cfg.StateDir = "/tmp/ominull-response-authority-test"
	}
	if cfg.DefaultSessionTTL <= 0 {
		cfg.DefaultSessionTTL = 8 * time.Hour
	}
	if cfg.DefaultIdleTTL <= 0 {
		cfg.DefaultIdleTTL = 30 * time.Minute
	}
	if cfg.SignerPartition == "" {
		cfg.SignerPartition = "portable-local"
	}

	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "keys"), 0700); err != nil {
		return nil, fmt.Errorf("failed to create authority key dir: %w", err)
	}

	auth := &Authority{
		cfg:            cfg,
		tenantKeys:     make(map[string]ed25519.PrivateKey),
		authenticators: make(map[string][]*AuthenticatorRecord),
		sessions:       make(map[string]*ResponseSession),
		recoveryTokens: make(map[string]*RecoveryToken),
		startedAt:      time.Now(),
	}

	if err := auth.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing tenant keys: %w", err)
	}

	return auth, nil
}

func (a *Authority) loadKeys() error {
	keyDir := filepath.Join(a.cfg.StateDir, "keys")
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		tenantID := strings.TrimSuffix(entry.Name(), ".key")
		keyPath := filepath.Join(keyDir, entry.Name())
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		rawHex := strings.TrimSpace(string(data))
		keyBytes, err := hex.DecodeString(rawHex)
		if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
			continue
		}
		a.tenantKeys[tenantID] = ed25519.PrivateKey(keyBytes)
	}
	return nil
}

// GetOrCreateTenantKey returns or generates the Ed25519 response keypair for a tenant.
func (a *Authority) GetOrCreateTenantKey(tenantID string) (ed25519.PublicKey, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if tenantID == "" {
		return nil, "", errors.New("empty tenant ID")
	}

	privKey, exists := a.tenantKeys[tenantID]
	if !exists {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("generate ed25519 key failed: %w", err)
		}
		privKey = priv
		a.tenantKeys[tenantID] = privKey

		keyPath := filepath.Join(a.cfg.StateDir, "keys", tenantID+".key")
		keyHex := hex.EncodeToString(priv)
		if err := os.WriteFile(keyPath, []byte(keyHex), 0600); err != nil {
			return nil, "", fmt.Errorf("failed to persist tenant key: %w", err)
		}
		pubKey := pub
		fp := sha256.Sum256(pubKey)
		return pubKey, hex.EncodeToString(fp[:]), nil
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pubKey)
	return pubKey, hex.EncodeToString(fp[:]), nil
}

// EnrollTOTP registers a new TOTP authenticator for an operator in a tenant.
func (a *Authority) EnrollTOTP(tenantID, operatorID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s:%s", tenantID, operatorID)
	rec := &AuthenticatorRecord{
		ID:          uuid.New().String(),
		OperatorID:  operatorID,
		TenantID:    tenantID,
		Type:        AuthMethodTOTP,
		SecretOrKey: secret,
		EnrolledAt:  time.Now(),
	}
	a.authenticators[key] = append(a.authenticators[key], rec)
	return secret, nil
}

// UnlockSessionWithTOTP verifies a TOTP code and issues an 8-hour browser-bound response session.
func (a *Authority) UnlockSessionWithTOTP(tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode string) (*ResponseSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	key := fmt.Sprintf("%s:%s", tenantID, operatorID)
	recs := a.authenticators[key]

	var validSecret string
	for _, rec := range recs {
		if rec.Type == AuthMethodTOTP && VerifyTOTPCode(rec.SecretOrKey, totpCode, now) {
			validSecret = rec.SecretOrKey
			rec.LastUsedAt = now
			break
		}
	}
	if validSecret == "" {
		return nil, errors.New("invalid or expired TOTP code")
	}

	// Validate browser public key hex
	pubBytes, err := hex.DecodeString(browserPubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid browser public key encoding or length")
	}

	session := &ResponseSession{
		SessionID:        uuid.New().String(),
		OperatorID:       operatorID,
		TenantID:         tenantID,
		BrowserSessionID: browserSessionID,
		BrowserPublicKey: browserPubKeyHex,
		AllowedActionKinds: []response.ActionKind{
			response.ActionKindForensicCollect,
			response.ActionKindScriptExec,
			response.ActionKindTerminalSession,
		},
		IssuedAt:          now,
		IdleExpiresAt:     now.Add(a.cfg.DefaultIdleTTL),
		AbsoluteExpiresAt: now.Add(a.cfg.DefaultSessionTTL),
		Locked:            false,
		AuthMethod:        AuthMethodTOTP,
	}

	a.sessions[session.SessionID] = session
	return session, nil
}

// SignGrant validates an action proof and creates a signed endpoint grant.
func (a *Authority) SignGrant(req *SignGrantRequest) (*response.EndpointGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if req == nil || req.Proof == nil {
		return nil, errors.New("missing sign grant request or proof")
	}

	session, exists := a.sessions[req.SessionID]
	if !exists || !session.IsValid(now) {
		return nil, errors.New("invalid or expired response session")
	}
	if session.TenantID != req.TenantID || session.OperatorID != req.OperatorID {
		return nil, errors.New("session tenant or operator mismatch")
	}

	// Verify action kind allowed
	kindAllowed := false
	for _, k := range session.AllowedActionKinds {
		if k == req.ActionKind {
			kindAllowed = true
			break
		}
	}
	if !kindAllowed {
		return nil, fmt.Errorf("action kind %q not permitted by response session", req.ActionKind)
	}

	// Verify browser action proof
	browserPubBytes, err := hex.DecodeString(session.BrowserPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid browser public key: %w", err)
	}
	if err := req.Proof.Verify(ed25519.PublicKey(browserPubBytes), now); err != nil {
		return nil, fmt.Errorf("action proof verification failed: %w", err)
	}
	if !strings.EqualFold(req.Proof.ActionDigest, req.ActionDigest) {
		return nil, errors.New("proof action digest does not match requested action digest")
	}

	// Update session idle deadline on successful action
	session.IdleExpiresAt = now.Add(a.cfg.DefaultIdleTTL)

	privKey, exists := a.tenantKeys[req.TenantID]
	if !exists {
		return nil, fmt.Errorf("no response signing key found for tenant %q", req.TenantID)
	}
	pubKey := privKey.Public().(ed25519.PublicKey)
	keyFP := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyFP[:])

	ttl := req.TTLSeconds
	if ttl <= 0 || ttl > 3600 {
		ttl = 300 // default 5 minutes
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}

	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           uuid.New().String(),
		TenantID:          req.TenantID,
		EndpointID:        req.EndpointID,
		ActionKind:        req.ActionKind,
		ActionDigest:      req.ActionDigest,
		OperatorID:        req.OperatorID,
		ResponseSessionID: session.SessionID,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Unix() + ttl,
		Nonce:             hex.EncodeToString(nonceBytes),
		SignerKeyID:       keyID,
	}

	sig := ed25519.Sign(privKey, grant.CanonicalBytes())
	grant.Signature = hex.EncodeToString(sig)

	return grant, nil
}

// LockSession explicitly locks a response session.
func (a *Authority) LockSession(sessionID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	session, exists := a.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}
	session.Locked = true
	return nil
}

// GenerateRecoveryToken creates a short-lived single-use root recovery token.
func (a *Authority) GenerateRecoveryToken(tenantID, operatorID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	a.recoveryTokens[token] = &RecoveryToken{
		Token:      token,
		TenantID:   tenantID,
		OperatorID: operatorID,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
		Used:       false,
	}
	return token, nil
}

// Status returns summary health metrics for the authority.
func (a *Authority) Status(tenantID string) ResponseAuthorityStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var keyID, pubHex string
	if priv, exists := a.tenantKeys[tenantID]; exists {
		pub := priv.Public().(ed25519.PublicKey)
		fp := sha256.Sum256(pub)
		keyID = hex.EncodeToString(fp[:])
		pubHex = hex.EncodeToString(pub)
	}

	activeCount := 0
	now := time.Now()
	for _, s := range a.sessions {
		if s.IsValid(now) {
			activeCount++
		}
	}

	return ResponseAuthorityStatus{
		Healthy:             true,
		SignerPartition:     a.cfg.SignerPartition,
		TenantKeyID:         keyID,
		TenantPublicKey:     pubHex,
		AuthenticatorsCount: len(a.authenticators),
		ActiveSessions:      activeCount,
		StartedAt:           a.startedAt,
	}
}
