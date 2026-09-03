package responseauth

import (
	"context"
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
	StateDir          string        // e.g. /var/lib/ominull-response-authority
	SignerPartition   string        // e.g. "portable-local" or "hsm-partition-1"
	DefaultSessionTTL time.Duration // e.g. 8h
	DefaultIdleTTL    time.Duration // e.g. 30m
}

// AuthenticatorRecord stores enrolled credentials (TOTP, WebAuthn) for an operator.
type AuthenticatorRecord struct {
	ID           string     `json:"id"`
	OperatorID   string     `json:"operator_id"`
	TenantID     string     `json:"tenant_id"`
	Type         AuthMethod `json:"type"`
	Label        string     `json:"label"`
	SecretOrKey  string     `json:"secret_or_key"` // encrypted or public key
	Status       string     `json:"status"`        // "active", "disabled", "revoked"
	EnrolledAt   time.Time  `json:"enrolled_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	FailureCount int        `json:"failure_count"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
}

// Authority manages tenant response keys, sessions, and endpoint grant signing.
type Authority struct {
	mu         sync.RWMutex
	cfg        Config
	store      Store
	tenantKeys map[string]ed25519.PrivateKey // tenant_id -> cached in-memory signing key
	masterKey  []byte                        // 32-byte master key for encrypting secrets at rest
	startedAt  time.Time
}

// NewAuthority creates a new Response Authority instance backed by SQLite.
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

	dbPath := filepath.Join(cfg.StateDir, "authority.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sqlite store: %w", err)
	}

	return NewAuthorityWithStore(cfg, store)
}

// NewAuthorityWithStore creates an Authority with a specific Store implementation.
func NewAuthorityWithStore(cfg Config, store Store) (*Authority, error) {
	if cfg.DefaultSessionTTL <= 0 {
		cfg.DefaultSessionTTL = 8 * time.Hour
	}
	if cfg.DefaultIdleTTL <= 0 {
		cfg.DefaultIdleTTL = 30 * time.Minute
	}
	if cfg.SignerPartition == "" {
		cfg.SignerPartition = "portable-local"
	}

	var masterKey []byte
	if cfg.StateDir != "" {
		keyPath := filepath.Join(cfg.StateDir, "secret.key")
		if mk, err := GetOrGenerateMasterKey(keyPath); err == nil {
			masterKey = mk
		}
	}
	if len(masterKey) != 32 {
		h := sha256.Sum256([]byte("ominull-response-authority:" + cfg.SignerPartition))
		masterKey = h[:]
	}

	auth := &Authority{
		cfg:        cfg,
		store:      store,
		tenantKeys: make(map[string]ed25519.PrivateKey),
		masterKey:  masterKey,
		startedAt:  time.Now(),
	}

	// 1. Load keys from durable store
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := store.ListTenantKeys(ctx)
	if err == nil {
		for _, rec := range records {
			keyBytes, err := hex.DecodeString(rec.PrivateKey)
			if err == nil && len(keyBytes) == ed25519.PrivateKeySize {
				auth.tenantKeys[rec.TenantID] = ed25519.PrivateKey(keyBytes)
			}
		}
	}

	// 2. Import any legacy file keys from keys/ directory into store
	if cfg.StateDir != "" {
		_ = auth.importLegacyFileKeys(ctx)
	}

	return auth, nil
}

func (a *Authority) importLegacyFileKeys(ctx context.Context) error {
	keyDir := filepath.Join(a.cfg.StateDir, "keys")
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		tenantID := strings.TrimSuffix(entry.Name(), ".key")
		if _, exists := a.tenantKeys[tenantID]; exists {
			continue
		}
		data, err := os.ReadFile(filepath.Join(keyDir, entry.Name()))
		if err != nil {
			continue
		}
		rawHex := strings.TrimSpace(string(data))
		keyBytes, err := hex.DecodeString(rawHex)
		if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
			continue
		}
		priv := ed25519.PrivateKey(keyBytes)
		pub := priv.Public().(ed25519.PublicKey)
		fp := sha256.Sum256(pub)
		keyID := hex.EncodeToString(fp[:])

		rec := &TenantKeyRecord{
			TenantID:   tenantID,
			KeyID:      keyID,
			PublicKey:  hex.EncodeToString(pub),
			PrivateKey: rawHex,
			Partition:  a.cfg.SignerPartition,
			Status:     "active",
			CreatedAt:  time.Now(),
		}
		_ = a.store.SaveTenantKey(ctx, rec)
		a.tenantKeys[tenantID] = priv
	}
	return nil
}

// Close closes the authority and its underlying durable store.
func (a *Authority) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}

// GetOrCreateTenantKey returns or generates the Ed25519 response keypair for a tenant.
func (a *Authority) GetOrCreateTenantKey(tenantID string) (ed25519.PublicKey, string, error) {
	if tenantID == "" {
		return nil, "", errors.New("empty tenant ID")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if privKey, exists := a.tenantKeys[tenantID]; exists {
		pubKey := privKey.Public().(ed25519.PublicKey)
		fp := sha256.Sum256(pubKey)
		return pubKey, hex.EncodeToString(fp[:]), nil
	}

	// Check store
	rec, err := a.store.GetTenantKey(ctx, tenantID)
	if err == nil && rec.Status == "active" {
		keyBytes, err := hex.DecodeString(rec.PrivateKey)
		if err == nil && len(keyBytes) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(keyBytes)
			a.tenantKeys[tenantID] = priv
			pub := priv.Public().(ed25519.PublicKey)
			return pub, rec.KeyID, nil
		}
	}

	// Generate new key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key failed: %w", err)
	}
	fp := sha256.Sum256(pub)
	keyID := hex.EncodeToString(fp[:])
	keyHex := hex.EncodeToString(priv)

	newRec := &TenantKeyRecord{
		TenantID:   tenantID,
		KeyID:      keyID,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: keyHex,
		Partition:  a.cfg.SignerPartition,
		Status:     "active",
		CreatedAt:  time.Now(),
	}
	if err := a.store.SaveTenantKey(ctx, newRec); err != nil {
		return nil, "", fmt.Errorf("failed to persist tenant key: %w", err)
	}

	// Maintain file key for legacy backwards compatibility
	if a.cfg.StateDir != "" {
		keyPath := filepath.Join(a.cfg.StateDir, "keys", tenantID+".key")
		_ = os.WriteFile(keyPath, []byte(keyHex), 0600)
	}

	a.tenantKeys[tenantID] = priv
	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  time.Now(),
		TenantID:   tenantID,
		OperatorID: "system",
		EventType:  "key_created",
		GrantID:    keyID,
		Status:     "success",
		Details:    fmt.Sprintf("Partition: %s", a.cfg.SignerPartition),
	})

	return pub, keyID, nil
}

// GrantMembership adds or updates an operator's membership in a tenant.
func (a *Authority) GrantMembership(tenantID, operatorID string, role MembershipRole) error {
	if tenantID == "" || operatorID == "" {
		return errors.New("empty tenant ID or operator ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	rec := &MembershipRecord{
		TenantID:   tenantID,
		OperatorID: operatorID,
		Role:       role,
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := a.store.SaveMembership(ctx, rec); err != nil {
		return err
	}
	return a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "membership_granted",
		Status:     "success",
		Details:    fmt.Sprintf("Role: %s", role),
	})
}

// RevokeMembership revokes an operator's response authority membership.
func (a *Authority) RevokeMembership(tenantID, operatorID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.store.RevokeMembership(ctx, tenantID, operatorID); err != nil {
		return err
	}
	return a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  time.Now(),
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "membership_revoked",
		Status:     "success",
	})
}

// EnrollTOTP registers a new TOTP authenticator for an operator in a tenant.
func (a *Authority) EnrollTOTP(tenantID, operatorID string) (string, error) {
	if tenantID == "" || operatorID == "" {
		return "", errors.New("empty tenant ID or operator ID")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check response membership: if memberships exist for tenant, operator must be active member
	members, err := a.store.ListMemberships(ctx, tenantID)
	if err == nil && len(members) > 0 {
		mem, err := a.store.GetMembership(ctx, tenantID, operatorID)
		if err != nil || mem.Status != "active" {
			_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
				Timestamp:  time.Now(),
				TenantID:   tenantID,
				OperatorID: operatorID,
				EventType:  "auth_failed",
				Status:     "denied",
				Details:    "operator not an active member of tenant response authority",
			})
			return "", errors.New("operator is not an active member of tenant response authority")
		}
	} else {
		// Bootstrap initial administrator membership
		_ = a.store.SaveMembership(ctx, &MembershipRecord{
			TenantID:   tenantID,
			OperatorID: operatorID,
			Role:       RoleResponseAdmin,
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		})
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", err
	}

	storedSecret := secret
	if len(a.masterKey) == 32 {
		if enc, err := EncryptSecret(secret, a.masterKey); err == nil {
			storedSecret = enc
		}
	}

	now := time.Now()
	rec := &AuthenticatorRecord{
		ID:          uuid.New().String(),
		OperatorID:  operatorID,
		TenantID:    tenantID,
		Type:        AuthMethodTOTP,
		Label:       SecurityLabelTOTP,
		SecretOrKey: storedSecret,
		Status:      "active",
		EnrolledAt:  now,
	}

	if err := a.store.SaveAuthenticator(ctx, rec); err != nil {
		return "", err
	}

	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "authenticator_enrolled",
		Status:     "success",
		Details:    fmt.Sprintf("Method: TOTP, Label: %s", SecurityLabelTOTP),
	})

	return secret, nil
}

// UnlockSessionWithTOTP verifies a TOTP code and issues an 8-hour browser-bound response session.
func (a *Authority) UnlockSessionWithTOTP(tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode string) (*ResponseSession, error) {
	if tenantID == "" || operatorID == "" {
		return nil, errors.New("empty tenant ID or operator ID")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	recs, err := a.store.ListAuthenticators(ctx, tenantID, operatorID)
	if err != nil || len(recs) == 0 {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   tenantID,
			OperatorID: operatorID,
			EventType:  "auth_failed",
			Status:     "denied",
			Details:    "no active authenticators enrolled",
		})
		return nil, errors.New("no authenticators enrolled for operator")
	}

	// Validate browser public key hex
	pubBytes, err := hex.DecodeString(browserPubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid browser public key encoding or length")
	}

	var matchedAuth *AuthenticatorRecord
	var matchedStep int64
	for _, rec := range recs {
		if rec.Type != AuthMethodTOTP || rec.Status != "active" {
			continue
		}
		if rec.LockedUntil != nil && now.Before(*rec.LockedUntil) {
			_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
				Timestamp:  now,
				TenantID:   tenantID,
				OperatorID: operatorID,
				EventType:  "auth_failed",
				Status:     "denied",
				Details:    fmt.Sprintf("authenticator locked until %s", rec.LockedUntil.Format(time.RFC3339)),
			})
			return nil, fmt.Errorf("%w until %s", ErrAuthenticatorLocked, rec.LockedUntil.Format(time.RFC3339))
		}

		// Decrypt secret if encrypted
		rawSecret := rec.SecretOrKey
		if len(a.masterKey) == 32 {
			if dec, err := DecryptSecret(rec.SecretOrKey, a.masterKey); err == nil {
				rawSecret = dec
			}
		}

		if step, ok := VerifyTOTPCodeWithStep(rawSecret, totpCode, now); ok {
			matchedAuth = rec
			matchedStep = step
			break
		}
	}

	if matchedAuth == nil {
		// Increment failure count on first active totp authenticator
		for _, rec := range recs {
			if rec.Type == AuthMethodTOTP && rec.Status == "active" {
				newCount := rec.FailureCount + 1
				var lockUntil *time.Time
				if newCount >= MaxFailedAttempts {
					t := now.Add(LockoutDuration)
					lockUntil = &t
				}
				_ = a.store.UpdateAuthenticatorUsage(ctx, rec.ID, now, newCount, lockUntil)
				break
			}
		}
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   tenantID,
			OperatorID: operatorID,
			EventType:  "auth_failed",
			Status:     "denied",
			Details:    "invalid TOTP code",
		})
		return nil, errors.New("invalid or expired TOTP code")
	}

	// Enforce single-use timestep replay protection
	nonce := fmt.Sprintf("totp:%s:%s:%d", tenantID, operatorID, matchedStep)
	if err := a.store.CheckAndRecordNonce(ctx, nonce, "totp_timestep", tenantID, now.Add(90*time.Second)); err != nil {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   tenantID,
			OperatorID: operatorID,
			EventType:  "auth_failed",
			Status:     "denied",
			Details:    "replayed TOTP code within same timestep",
		})
		return nil, ErrTOTPReplayed
	}

	// Reset failure count on success
	_ = a.store.UpdateAuthenticatorUsage(ctx, matchedAuth.ID, now, 0, nil)

	policy, _ := a.store.GetPolicy(ctx, tenantID)
	sessionTTL := a.cfg.DefaultSessionTTL
	if policy != nil && policy.MaxSessionTTLSec > 0 {
		sessionTTL = time.Duration(policy.MaxSessionTTLSec) * time.Second
	}
	idleTTL := a.cfg.DefaultIdleTTL
	if policy != nil && policy.MaxIdleTTLSec > 0 {
		idleTTL = time.Duration(policy.MaxIdleTTLSec) * time.Second
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
		IdleExpiresAt:     now.Add(idleTTL),
		AbsoluteExpiresAt: now.Add(sessionTTL),
		Locked:            false,
		AuthMethod:        AuthMethodTOTP,
	}

	if err := a.store.SaveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to save response session: %w", err)
	}

	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "session_unlocked",
		GrantID:    session.SessionID,
		Status:     "success",
		Details:    "Method: TOTP",
	})

	return session, nil
}

// SignGrant validates an action proof and creates a signed endpoint grant.
func (a *Authority) SignGrant(req *SignGrantRequest) (*response.EndpointGrant, error) {
	if req == nil || req.Proof == nil {
		return nil, errors.New("missing sign grant request or proof")
	}

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := a.store.GetSession(ctx, req.SessionID)
	if err != nil || !session.IsValid(now) {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   req.TenantID,
			OperatorID: req.OperatorID,
			EventType:  "grant_denied",
			ActionKind: string(req.ActionKind),
			EndpointID: req.EndpointID,
			Status:     "denied",
			Details:    "invalid or expired response session",
		})
		return nil, errors.New("invalid or expired response session")
	}

	if session.TenantID != req.TenantID || session.OperatorID != req.OperatorID {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   req.TenantID,
			OperatorID: req.OperatorID,
			EventType:  "grant_denied",
			ActionKind: string(req.ActionKind),
			EndpointID: req.EndpointID,
			Status:     "denied",
			Details:    "session tenant or operator mismatch",
		})
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
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   req.TenantID,
			OperatorID: req.OperatorID,
			EventType:  "grant_denied",
			ActionKind: string(req.ActionKind),
			EndpointID: req.EndpointID,
			Status:     "denied",
			Details:    fmt.Sprintf("proof verification failed: %v", err),
		})
		return nil, fmt.Errorf("action proof verification failed: %w", err)
	}

	if !strings.EqualFold(req.Proof.ActionDigest, req.ActionDigest) {
		return nil, errors.New("proof action digest does not match requested action digest")
	}

	// Replay protection: verify and record proof nonce
	proofNonceKey := fmt.Sprintf("proof:%s:%s", req.TenantID, req.Proof.Nonce)
	if err := a.store.CheckAndRecordNonce(ctx, proofNonceKey, "action_proof", req.TenantID, now.Add(10*time.Minute)); err != nil {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   req.TenantID,
			OperatorID: req.OperatorID,
			EventType:  "grant_denied",
			ActionKind: string(req.ActionKind),
			EndpointID: req.EndpointID,
			Status:     "denied",
			Details:    "proof nonce replayed",
		})
		return nil, errors.New("action proof nonce already used")
	}

	// Update session idle deadline on successful action
	policy, _ := a.store.GetPolicy(ctx, req.TenantID)
	idleTTL := a.cfg.DefaultIdleTTL
	if policy != nil && policy.MaxIdleTTLSec > 0 {
		idleTTL = time.Duration(policy.MaxIdleTTLSec) * time.Second
	}
	session.IdleExpiresAt = now.Add(idleTTL)
	_ = a.store.UpdateSession(ctx, session)

	// Fetch tenant signing key
	a.mu.RLock()
	privKey, exists := a.tenantKeys[req.TenantID]
	a.mu.RUnlock()

	if !exists {
		// Try load from store
		rec, err := a.store.GetTenantKey(ctx, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("no response signing key found for tenant %q", req.TenantID)
		}
		keyBytes, err := hex.DecodeString(rec.PrivateKey)
		if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
			return nil, errors.New("corrupted tenant private key in store")
		}
		privKey = ed25519.PrivateKey(keyBytes)
		a.mu.Lock()
		a.tenantKeys[req.TenantID] = privKey
		a.mu.Unlock()
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

	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   req.TenantID,
		OperatorID: req.OperatorID,
		EventType:  "grant_signed",
		ActionKind: string(req.ActionKind),
		EndpointID: req.EndpointID,
		GrantID:    grant.GrantID,
		Status:     "success",
		Details:    fmt.Sprintf("TTL: %ds, Nonce: %s", ttl, grant.Nonce),
	})

	return grant, nil
}

// LockSession explicitly locks a response session.
func (a *Authority) LockSession(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.store.LockSession(ctx, sessionID); err != nil {
		return err
	}
	sess, err := a.store.GetSession(ctx, sessionID)
	if err == nil {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  time.Now(),
			TenantID:   sess.TenantID,
			OperatorID: sess.OperatorID,
			EventType:  "session_locked",
			GrantID:    sessionID,
			Status:     "success",
		})
	}
	return nil
}

// GenerateRecoveryToken creates a short-lived single-use root recovery token.
func (a *Authority) GenerateRecoveryToken(tenantID, operatorID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	now := time.Now()
	rec := &RecoveryTokenRecord{
		TokenHash:  hashHex,
		TenantID:   tenantID,
		OperatorID: operatorID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(15 * time.Minute),
		Used:       false,
	}

	if err := a.store.SaveRecoveryToken(ctx, rec); err != nil {
		return "", err
	}

	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "recovery_generated",
		Status:     "success",
	})

	return token, nil
}

// ResetLockoutWithRecovery consumes a recovery token to clear authenticator lockouts for an operator.
func (a *Authority) ResetLockoutWithRecovery(tenantID, operatorID, recoveryToken string) error {
	if tenantID == "" || operatorID == "" || recoveryToken == "" {
		return errors.New("missing parameters")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte(recoveryToken))
	hashHex := hex.EncodeToString(hash[:])
	now := time.Now()

	if err := a.store.ConsumeRecoveryToken(ctx, hashHex, now); err != nil {
		_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
			Timestamp:  now,
			TenantID:   tenantID,
			OperatorID: operatorID,
			EventType:  "recovery_failed",
			Status:     "denied",
			Details:    fmt.Sprintf("consume error: %v", err),
		})
		return fmt.Errorf("invalid or expired recovery token: %w", err)
	}

	// Clear lockouts on authenticators
	auths, err := a.store.ListAuthenticators(ctx, tenantID, operatorID)
	if err == nil {
		for _, rec := range auths {
			if rec.FailureCount > 0 || rec.LockedUntil != nil {
				_ = a.store.UpdateAuthenticatorUsage(ctx, rec.ID, now, 0, nil)
			}
		}
	}

	return a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  now,
		TenantID:   tenantID,
		OperatorID: operatorID,
		EventType:  "recovery_consumed",
		Status:     "success",
		Details:    "lockout reset via root emergency recovery token",
	})
}

// GetSession retrieves a response session from the durable store.
func (a *Authority) GetSession(sessionID string) (*ResponseSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.store.GetSession(ctx, sessionID)
}

// Status returns summary health metrics for the authority.
func (a *Authority) Status(tenantID string) ResponseAuthorityStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a.mu.RLock()
	var keyID, pubHex string
	if priv, exists := a.tenantKeys[tenantID]; exists {
		pub := priv.Public().(ed25519.PublicKey)
		fp := sha256.Sum256(pub)
		keyID = hex.EncodeToString(fp[:])
		pubHex = hex.EncodeToString(pub)
	}
	a.mu.RUnlock()

	activeSessions := 0
	authCount := 0
	now := time.Now()
	if a.store != nil {
		if c, err := a.store.CountActiveSessions(ctx, tenantID, now); err == nil {
			activeSessions = c
		}
		if c, err := a.store.CountAuthenticators(ctx, tenantID); err == nil {
			authCount = c
		}
	}

	return ResponseAuthorityStatus{
		Healthy:             true,
		SignerPartition:     a.cfg.SignerPartition,
		TenantKeyID:         keyID,
		TenantPublicKey:     pubHex,
		AuthenticatorsCount: authCount,
		ActiveSessions:      activeSessions,
		StartedAt:           a.startedAt,
	}
}

// GetAuditLog queries the audit log for a tenant.
func (a *Authority) GetAuditLog(tenantID string, limit int) ([]*SignerAuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.store.QueryAudit(ctx, tenantID, limit)
}
