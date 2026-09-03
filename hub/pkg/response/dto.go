package response

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// JobState represents the lifecycle state of a response job.
type JobState string

const (
	StateQueued          JobState = "queued"
	StateOffered         JobState = "offered"
	StateAcknowledged    JobState = "acknowledged"
	StateRunning         JobState = "running"
	StateSucceeded       JobState = "succeeded"
	StateFailed          JobState = "failed"
	StateCancelRequested JobState = "cancel_requested"
	StateCancelled       JobState = "cancelled"
)

// ActionKind specifies the typed operation a grant authorizes.
type ActionKind string

const (
	ActionKindForensicCollect ActionKind = "forensic_collection"
	ActionKindScriptExec      ActionKind = "script_exec"
	ActionKindTerminalSession ActionKind = "terminal_session"
)

// GrantVersion is the current version of the endpoint grant protocol.
const GrantVersion = 2

// EndpointGrant is an immutable, cryptographically signed authorization token
// issued by a tenant's response authority. The endpoint verifies this grant before
// executing any action.
type EndpointGrant struct {
	Version           int        `json:"version"`
	GrantID           string     `json:"grant_id"`
	TenantID          string     `json:"tenant_id"`
	EndpointID        string     `json:"endpoint_id"`
	ActionKind        ActionKind `json:"action_kind"`
	ActionDigest      string     `json:"action_digest"` // hex sha256 of canonical action payload
	OperatorID        string     `json:"operator_id"`
	ResponseSessionID string     `json:"response_session_id"`
	IssuedAt          int64      `json:"issued_at"`  // unix seconds
	ExpiresAt         int64      `json:"expires_at"` // unix seconds
	Nonce             string     `json:"nonce"`      // hex random nonce
	SignerKeyID       string     `json:"signer_key_id"` // hex sha256 fingerprint of public key
	Signature         string     `json:"signature"`  // hex ed25519 signature
}

// CanonicalBytes returns the deterministic length-prefixed bytes for signature verification.
func (g *EndpointGrant) CanonicalBytes() []byte {
	enc := NewCanonicalEncoder("OMINULL-ENDPOINT-GRANT-V2")
	enc.WriteUint32(uint32(g.Version))
	enc.WriteString(g.GrantID)
	enc.WriteString(g.TenantID)
	enc.WriteString(g.EndpointID)
	enc.WriteString(string(g.ActionKind))
	enc.WriteHexNormalized(g.ActionDigest)
	enc.WriteString(g.OperatorID)
	enc.WriteString(g.ResponseSessionID)
	enc.WriteInt64(g.IssuedAt)
	enc.WriteInt64(g.ExpiresAt)
	enc.WriteHexNormalized(g.Nonce)
	enc.WriteHexNormalized(g.SignerKeyID)
	return enc.Bytes()
}

// CanonicalString returns a diagnostic string representation of the grant.
func (g *EndpointGrant) CanonicalString() string {
	return fmt.Sprintf("OMINULL-GRANT-V%d:%s:%s:%s:%s:%s:%s:%s:%d:%d:%s:%s",
		g.Version,
		g.GrantID,
		g.TenantID,
		g.EndpointID,
		string(g.ActionKind),
		strings.ToLower(g.ActionDigest),
		g.OperatorID,
		g.ResponseSessionID,
		g.IssuedAt,
		g.ExpiresAt,
		strings.ToLower(g.Nonce),
		strings.ToLower(g.SignerKeyID),
	)
}

// CanonicalDigest returns the SHA-256 digest of the grant's canonical bytes.
func (g *EndpointGrant) CanonicalDigest() [32]byte {
	return sha256.Sum256(g.CanonicalBytes())
}

// Verify checks the signature against the provided tenant response Ed25519 public key.
func (g *EndpointGrant) Verify(pubKey ed25519.PublicKey, now time.Time) error {
	if g.Version != GrantVersion {
		return fmt.Errorf("unsupported grant version: %d (expected %d)", g.Version, GrantVersion)
	}
	if g.GrantID == "" || g.TenantID == "" || g.EndpointID == "" {
		return errors.New("missing required grant identifiers")
	}
	if g.IssuedAt <= 0 || g.ExpiresAt <= 0 || g.ExpiresAt < g.IssuedAt {
		return errors.New("invalid grant timestamp window")
	}
	nowSec := now.Unix()
	if nowSec < g.IssuedAt-60 { // allow 60s clock skew
		return errors.New("grant not yet valid")
	}
	if nowSec > g.ExpiresAt+60 {
		return errors.New("grant has expired")
	}

	// Verify key ID matches public key
	keyFingerprint := sha256.Sum256(pubKey)
	expectedKeyID := hex.EncodeToString(keyFingerprint[:])
	if !strings.EqualFold(g.SignerKeyID, expectedKeyID) {
		return fmt.Errorf("signer key id mismatch: got %s, expected %s", g.SignerKeyID, expectedKeyID)
	}

	sigBytes, err := hex.DecodeString(g.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d (expected %d)", len(sigBytes), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pubKey, g.CanonicalBytes(), sigBytes) {
		return errors.New("grant signature verification failed")
	}
	return nil
}

// Validate checks that all required fields of the grant are present and well-formed.
func (g *EndpointGrant) Validate() error {
	if g.Version != GrantVersion {
		return fmt.Errorf("unsupported grant version: %d (expected %d)", g.Version, GrantVersion)
	}
	if g.GrantID == "" {
		return errors.New("missing grant_id")
	}
	if g.TenantID == "" {
		return errors.New("missing tenant_id")
	}
	if g.EndpointID == "" {
		return errors.New("missing endpoint_id")
	}
	switch g.ActionKind {
	case ActionKindForensicCollect, ActionKindScriptExec, ActionKindTerminalSession:
	default:
		return fmt.Errorf("unsupported action_kind: %q", g.ActionKind)
	}
	if len(g.ActionDigest) != 64 {
		return fmt.Errorf("invalid action_digest length: %d (expected 64)", len(g.ActionDigest))
	}
	if g.OperatorID == "" {
		return errors.New("missing operator_id")
	}
	if g.ResponseSessionID == "" {
		return errors.New("missing response_session_id")
	}
	if g.IssuedAt <= 0 || g.ExpiresAt <= 0 || g.ExpiresAt <= g.IssuedAt {
		return errors.New("invalid grant timestamp window")
	}
	if g.Nonce == "" {
		return errors.New("missing nonce")
	}
	if len(g.SignerKeyID) != 64 {
		return fmt.Errorf("invalid signer_key_id length: %d (expected 64)", len(g.SignerKeyID))
	}
	if len(g.Signature) != hex.EncodedLen(ed25519.SignatureSize) {
		return fmt.Errorf("invalid signature length: %d (expected %d)", len(g.Signature), hex.EncodedLen(ed25519.SignatureSize))
	}
	return nil
}

// Validate checks that all required fields of the job offer are present and valid.
func (o *JobOffer) Validate() error {
	if o.JobID == "" {
		return errors.New("missing job_id")
	}
	switch o.Kind {
	case ActionKindForensicCollect, ActionKindScriptExec, ActionKindTerminalSession:
	default:
		return fmt.Errorf("unsupported offer kind: %q", o.Kind)
	}
	if o.LeaseID == "" {
		return errors.New("missing lease_id")
	}
	if o.LeaseExpiresAt <= 0 {
		return errors.New("invalid lease_expires_at")
	}
	if o.Grant == nil {
		return errors.New("missing grant in offer")
	}
	return o.Grant.Validate()
}

// Validate checks that all required fields of the job ack are present.
func (a *JobAck) Validate() error {
	if a.JobID == "" {
		return errors.New("missing job_id")
	}
	if a.LeaseID == "" {
		return errors.New("missing lease_id")
	}
	return nil
}

// Validate checks that all required fields of the job result are present.
func (r *JobResult) Validate() error {
	if r.JobID == "" {
		return errors.New("missing job_id")
	}
	if r.LeaseID == "" {
		return errors.New("missing lease_id")
	}
	switch r.State {
	case StateSucceeded, StateFailed, StateCancelled:
	default:
		return fmt.Errorf("invalid result state: %q", r.State)
	}
	return nil
}

// ComputeActionDigest computes the lowercase hex SHA-256 digest of a JSON-serializable action payload.
func ComputeActionDigest(payload interface{}) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}

// JobOffer is the offer payload bundled in heartbeat responses for endpoints.
type JobOffer struct {
	JobID          string         `json:"job_id"`
	Kind           ActionKind     `json:"kind"`
	LeaseID        string         `json:"lease_id"`
	LeaseExpiresAt int64          `json:"lease_expires_at"` // unix seconds
	Grant          *EndpointGrant `json:"grant"`
	PayloadJSON    string         `json:"payload_json"`
}

// JobAck represents an endpoint's acknowledgement or rejection of an offered job.
type JobAck struct {
	JobID           string `json:"job_id"`
	LeaseID         string `json:"lease_id"`
	Accepted        bool   `json:"accepted"`
	RejectionReason string `json:"rejection_reason,omitempty"`
}

// JobProgress represents incremental progress reported by an endpoint.
type JobProgress struct {
	JobID       string `json:"job_id"`
	LeaseID     string `json:"lease_id"`
	ProgressPct int    `json:"progress_pct"`
	Message     string `json:"message,omitempty"`
}

// JobResult represents the final execution outcome reported by an endpoint.
type JobResult struct {
	JobID          string   `json:"job_id"`
	LeaseID        string   `json:"lease_id"`
	State          JobState `json:"state"` // StateSucceeded, StateFailed, or StateCancelled
	ErrorCode      string   `json:"error_code,omitempty"`
	ResultJSON     string   `json:"result_json,omitempty"`
	Stdout         string   `json:"stdout,omitempty"`
	Stderr         string   `json:"stderr,omitempty"`
	ExitCode       int      `json:"exit_code"`
	DurationMs     int64    `json:"duration_ms"`
	ManifestSHA256 string   `json:"manifest_sha256,omitempty"` // For forensic collections
}

// ForensicCollectionPayload defines parameters for a forensic snapshot.
type ForensicCollectionPayload struct {
	Profile        string            `json:"profile"` // diagnostic, live_volatile, ir_standard
	Options        map[string]string `json:"options,omitempty"`
	MaxBytes       int64             `json:"max_bytes"`
	TimeoutSeconds int               `json:"timeout_seconds"`
}

// ScriptExecPayload defines parameters for executing a versioned script.
type ScriptExecPayload struct {
	ScriptID       string            `json:"script_id"`
	ScriptVersion  int               `json:"script_version"`
	ScriptDigest   string            `json:"script_digest"` // sha256 of source
	Interpreter    string            `json:"interpreter"`   // /bin/sh, /bin/bash, powershell.exe, cmd.exe
	Source         string            `json:"source"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	MaxOutputBytes int64             `json:"max_output_bytes"`
}

// TerminalSessionPayload defines parameters for establishing an interactive pseudoterminal.
type TerminalSessionPayload struct {
	SessionID          string `json:"session_id"`
	Program            string `json:"program"` // /bin/sh, /bin/bash, powershell.exe, cmd.exe
	RelayURL           string `json:"relay_url"`
	ConnectToken       string `json:"connect_token"`
	MaxDurationSeconds int    `json:"max_duration_seconds"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
}
