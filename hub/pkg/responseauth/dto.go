package responseauth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"ominull/hub/pkg/response"
)

// AuthMethod represents the authentication method used to unlock a response session.
type AuthMethod string

const (
	AuthMethodWebAuthn AuthMethod = "webauthn"
	AuthMethodTOTP     AuthMethod = "totp"
	AuthMethodRecovery AuthMethod = "recovery"
)

// ResponseSession represents an authenticated, browser-bound response session for an operator.
type ResponseSession struct {
	SessionID          string                `json:"session_id"`
	OperatorID         string                `json:"operator_id"`
	TenantID           string                `json:"tenant_id"`
	BrowserSessionID   string                `json:"browser_session_id"`
	BrowserPublicKey   string                `json:"browser_public_key"` // hex ed25519 public key
	AllowedActionKinds []response.ActionKind `json:"allowed_action_kinds"`
	IssuedAt           time.Time             `json:"issued_at"`
	IdleExpiresAt      time.Time             `json:"idle_expires_at"`
	AbsoluteExpiresAt  time.Time             `json:"absolute_expires_at"`
	Locked             bool                  `json:"locked"`
	AuthMethod         AuthMethod            `json:"auth_method"`
}

// IsValid checks if the session is currently active and unlocked.
func (s *ResponseSession) IsValid(now time.Time) bool {
	if s.Locked {
		return false
	}
	if now.After(s.AbsoluteExpiresAt) {
		return false
	}
	if now.After(s.IdleExpiresAt) {
		return false
	}
	return true
}

// ProofVersion is the current version of the action proof protocol.
const ProofVersion = 2

// ActionProof is sent from the operator's browser to prove authorization for a specific action.
type ActionProof struct {
	Version         int                 `json:"version"`
	SessionID       string              `json:"session_id"`
	TenantID        string              `json:"tenant_id"`
	ActionKind      response.ActionKind `json:"action_kind"`
	ActionDigest    string              `json:"action_digest"`
	TargetEndpoints []string            `json:"target_endpoints"`
	Timestamp       int64               `json:"timestamp"` // unix seconds
	Nonce           string              `json:"nonce"`
	Signature       string              `json:"signature"` // hex ed25519 signature over canonical proof bytes
}

// CanonicalBytes returns the deterministic length-prefixed bytes for browser proof verification.
func (p *ActionProof) CanonicalBytes() []byte {
	v := p.Version
	if v == 0 {
		v = ProofVersion
	}
	enc := response.NewCanonicalEncoder("OMINULL-ACTION-PROOF-V2")
	enc.WriteUint32(uint32(v))
	enc.WriteString(p.SessionID)
	enc.WriteString(p.TenantID)
	enc.WriteString(string(p.ActionKind))
	enc.WriteHexNormalized(p.ActionDigest)
	enc.WriteStringSlice(p.TargetEndpoints)
	enc.WriteInt64(p.Timestamp)
	enc.WriteHexNormalized(p.Nonce)
	return enc.Bytes()
}

// CanonicalString returns a diagnostic string representation of the action proof.
func (p *ActionProof) CanonicalString() string {
	targets := strings.Join(p.TargetEndpoints, ",")
	v := p.Version
	if v == 0 {
		v = ProofVersion
	}
	return fmt.Sprintf("OMINULL-PROOF-V%d:%s:%s:%s:%s:%s:%d:%s",
		v,
		p.SessionID,
		p.TenantID,
		string(p.ActionKind),
		strings.ToLower(p.ActionDigest),
		targets,
		p.Timestamp,
		strings.ToLower(p.Nonce),
	)
}

// Verify verifies the action proof against the browser's public key.
func (p *ActionProof) Verify(browserPubKey ed25519.PublicKey, now time.Time) error {
	if p.SessionID == "" || p.TenantID == "" || p.ActionDigest == "" {
		return errors.New("missing required proof fields")
	}
	nowSec := now.Unix()
	if nowSec < p.Timestamp-60 || nowSec > p.Timestamp+300 {
		return errors.New("proof timestamp out of valid time window")
	}
	sigBytes, err := hex.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d (expected %d)", len(sigBytes), ed25519.SignatureSize)
	}
	if !ed25519.Verify(browserPubKey, p.CanonicalBytes(), sigBytes) {
		return errors.New("browser proof signature verification failed")
	}
	return nil
}

// SignGrantRequest is sent to the response authority to request an endpoint grant.
type SignGrantRequest struct {
	TenantID      string              `json:"tenant_id"`
	OperatorID    string              `json:"operator_id"`
	SessionID     string              `json:"session_id"`
	EndpointID    string              `json:"endpoint_id"`
	ActionKind    response.ActionKind `json:"action_kind"`
	ActionDigest  string              `json:"action_digest"`
	ActionPayload json.RawMessage     `json:"action_payload,omitempty"`
	TTLSeconds    int64               `json:"ttl_seconds"`
	Proof         *ActionProof        `json:"proof"`
}

// SignGrantResponse is returned by the response authority.
type SignGrantResponse struct {
	Grant *response.EndpointGrant `json:"grant"`
}

// ResponseAuthorityStatus reports the status of the response authority and tenant signing keys.
type ResponseAuthorityStatus struct {
	Healthy           bool      `json:"healthy"`
	SignerPartition   string    `json:"signer_partition"`
	TenantKeyID       string    `json:"tenant_key_id"`
	TenantPublicKey   string    `json:"tenant_public_key"` // hex ed25519 public key
	AuthenticatorsCount int     `json:"authenticators_count"`
	ActiveSessions    int       `json:"active_sessions"`
	StartedAt         time.Time `json:"started_at"`
}

// RecoveryToken represents a single-use root-issued token for emergency authenticator enrollment.
type RecoveryToken struct {
	Token      string    `json:"token"`
	TenantID   string    `json:"tenant_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Used       bool      `json:"used"`
	OperatorID string    `json:"operator_id"`
}
