package responseauth

// Owner approval: one passkey tap from the owner's phone authorizes one
// high-impact action (an isolation change, an agent update, a terminal
// session). The hub asks; the authority writes and signs the statement the
// owner is shown, derives the WebAuthn challenge from it, and later verifies
// the owner's assertion itself against an approver key that only root on the
// authority host can pin. Nothing the hub, the relay that carries the push, or
// the approval page says can turn into a grant without that signature.
//
// The approval page is Nightshift's approve origin (one passkey, one approval
// surface for the owner). Nightshift verifies the same assertion for its own
// bookkeeping, but this package never trusts that verdict: it checks the raw
// assertion with its own pinned copy of the public key.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// Action kinds that only an owner approval can authorize.
const (
	ActionKindIsolation   response.ActionKind = "isolation_change"
	ActionKindAgentUpdate response.ActionKind = "agent_update"
	ActionKindMesh        response.ActionKind = "mesh_quarantine"
)

// ApprovalState is the lifecycle of one owner approval.
type ApprovalState string

const (
	ApprovalPending  ApprovalState = "pending"
	ApprovalApproved ApprovalState = "approved"
	ApprovalDenied   ApprovalState = "denied"
	ApprovalExpired  ApprovalState = "expired"
	ApprovalConsumed ApprovalState = "consumed"
)

const (
	approvalStatementPrefix = "OMINULL-OWNER-APPROVAL-V1\n"
	approvalDefaultTTL      = 10 * time.Minute
	approvalMaxTTL          = 15 * time.Minute
	approvalUseWindow       = 10 * time.Minute // an approved request must be used this soon
	approvalMaxPending      = 3                // per tenant
	approvalMaxPerHour      = 30               // per tenant
	approvalKeep            = time.Hour        // finished approvals stay readable this long
	approvalMaxTargets      = 50
	approvalMaxSummary      = 300
	approvalMaxPayload      = 16 * 1024
)

// DefaultApproversPath is where root pins the owner's approver keys.
const DefaultApproversPath = "/etc/ominull/response-approvers.json"

// ApprovalStatement is exactly what the owner is shown and what the
// authority signs. Its JSON encoding (struct field order) is the signed form.
type ApprovalStatement struct {
	V         int      `json:"v"`
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant"`
	Requester string   `json:"requester"`
	Kind      string   `json:"kind"`
	Action    string   `json:"action"`
	Summary   string   `json:"summary"`
	Targets   []string `json:"targets"`
	Digest    string   `json:"digest"`
	Created   int64    `json:"created"`
	Expires   int64    `json:"expires"`
}

// ApprovalRequestInput is what the hub asks for.
type ApprovalRequestInput struct {
	TenantID   string              `json:"tenant_id"`
	Requester  string              `json:"requester"`
	Kind       response.ActionKind `json:"kind"`
	Action     string              `json:"action"`
	Summary    string              `json:"summary"`
	Targets    []string            `json:"targets"`
	Payload    json.RawMessage     `json:"payload"`
	TTLSeconds int64               `json:"ttl_seconds,omitempty"`
}

// ApprovalView is the readable state of an approval. Statement and Signature
// let a relay show the owner the authority's own words, verifiably.
type ApprovalView struct {
	ID         string        `json:"id"`
	TenantID   string        `json:"tenant_id"`
	State      ApprovalState `json:"state"`
	Kind       string        `json:"kind"`
	Action     string        `json:"action"`
	Summary    string        `json:"summary"`
	Targets    []string      `json:"targets"`
	Requester  string        `json:"requester"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	DecidedAt  *time.Time    `json:"decided_at,omitempty"`
	UseBy      *time.Time    `json:"use_by,omitempty"`
	Statement  string        `json:"statement"` // base64 of the signed statement JSON
	Signature  string        `json:"signature"` // hex ed25519 by the tenant response key
	Challenge  string        `json:"challenge"` // hex sha256 of prefix || statement
	SignerKey  string        `json:"signer_key_id"`
	ApproverID string        `json:"approver_id,omitempty"`
	Method     string        `json:"method,omitempty"`
}

// ApprovalAssertion is the owner's WebAuthn assertion, all base64url.
type ApprovalAssertion struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// ApprovalAnswer carries the owner's decision.
type ApprovalAnswer struct {
	ID        string             `json:"id"`
	Decision  string             `json:"decision"` // approve | deny
	Assertion *ApprovalAssertion `json:"assertion,omitempty"`
}

// ApprovalConsumeRequest turns an approved request into grants, once.
type ApprovalConsumeRequest struct {
	ID         string              `json:"id"`
	TenantID   string              `json:"tenant_id"`
	Kind       response.ActionKind `json:"kind"`
	Digest     string              `json:"digest"`
	Targets    []string            `json:"targets"`
	TTLSeconds int64               `json:"ttl_seconds,omitempty"`
}

// Approver is one pinned owner passkey (ES256, raw P-256 coordinates).
type Approver struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	RPID         string `json:"rp_id"`
	Origin       string `json:"origin"`
	CredentialID string `json:"credential_id"`
	X            string `json:"x"`
	Y            string `json:"y"`
}

type approverFile struct {
	Approvers []Approver `json:"approvers"`
}

// Approval errors a caller can act on.
var (
	ErrApprovalNotFound  = errors.New("approval not found")
	ErrApprovalNotUsable = errors.New("approval is not approved or no longer usable")
	ErrApprovalMismatch  = errors.New("approval does not cover this action")
	ErrApprovalRateLimit = errors.New("too many owner approval requests; wait for the pending ones")
	ErrApprovalAssertion = errors.New("owner assertion rejected")
	ErrNoApprovers       = errors.New("no owner approver is pinned on the authority host")
)

type approvalRecord struct {
	view      ApprovalView
	stmt      ApprovalStatement
	kind      response.ActionKind
	digest    string
	createdAt time.Time
}

type approvalBook struct {
	mu        sync.Mutex
	items     map[string]*approvalRecord
	created   map[string][]time.Time // tenant -> creation times in the last hour
	counters  map[string]uint32      // approver id -> last sign count
	approvers string                 // path of the pinned approver file
}

func newApprovalBook(path string) *approvalBook {
	if path == "" {
		path = DefaultApproversPath
	}
	return &approvalBook{
		items:     map[string]*approvalRecord{},
		created:   map[string][]time.Time{},
		counters:  map[string]uint32{},
		approvers: path,
	}
}

// SetApproversPath points the authority at a different pinned approver file
// (tests, alternative layouts). Root owns the default one.
func (a *Authority) SetApproversPath(path string) {
	a.approvals.mu.Lock()
	a.approvals.approvers = path
	a.approvals.mu.Unlock()
}

func (b *approvalBook) loadApprovers() ([]Approver, error) {
	raw, err := os.ReadFile(b.approvers)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoApprovers
		}
		return nil, fmt.Errorf("read approvers: %w", err)
	}
	var f approverFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse approvers: %w", err)
	}
	if len(f.Approvers) == 0 {
		return nil, ErrNoApprovers
	}
	return f.Approvers, nil
}

func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func approvalKindAllowed(k response.ActionKind) bool {
	switch k {
	case ActionKindIsolation, ActionKindAgentUpdate, ActionKindMesh, response.ActionKindTerminalSession:
		return true
	}
	return false
}

// RequestApproval records a pending approval and signs its statement.
func (a *Authority) RequestApproval(in *ApprovalRequestInput) (*ApprovalView, error) {
	if in == nil {
		return nil, errors.New("missing approval request")
	}
	if in.TenantID == "" {
		in.TenantID = "default"
	}
	if !approvalKindAllowed(in.Kind) {
		return nil, fmt.Errorf("action kind %q does not take an owner approval", in.Kind)
	}
	targets := sortedUnique(in.Targets)
	if len(targets) == 0 {
		return nil, errors.New("an owner approval names its targets explicitly")
	}
	if len(targets) > approvalMaxTargets {
		return nil, fmt.Errorf("an owner approval covers at most %d targets", approvalMaxTargets)
	}
	for _, t := range targets {
		if len(t) > 128 || cleanText(t, 128) != t {
			return nil, fmt.Errorf("invalid target %q", t)
		}
	}
	if len(in.Payload) == 0 || len(in.Payload) > approvalMaxPayload || !json.Valid(in.Payload) {
		return nil, errors.New("approval payload must be valid JSON up to 16 KiB")
	}
	if _, err := a.approvalsReady(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(in.Payload)
	ttl := approvalDefaultTTL
	if in.TTLSeconds > 0 {
		ttl = time.Duration(in.TTLSeconds) * time.Second
	}
	if ttl > approvalMaxTTL {
		ttl = approvalMaxTTL
	}
	now := time.Now()
	b := a.approvals
	b.mu.Lock()
	b.sweepLocked(now)
	pending := 0
	for _, r := range b.items {
		if r.view.TenantID == in.TenantID && r.view.State == ApprovalPending {
			pending++
		}
	}
	recent := b.created[in.TenantID]
	if pending >= approvalMaxPending || len(recent) >= approvalMaxPerHour {
		b.mu.Unlock()
		a.auditApproval(in.TenantID, in.Requester, "approval_refused", string(in.Kind), "", "", "denied", ErrApprovalRateLimit.Error())
		return nil, ErrApprovalRateLimit
	}
	b.mu.Unlock()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	stmt := ApprovalStatement{
		V:         1,
		ID:        hex.EncodeToString(idBytes),
		TenantID:  in.TenantID,
		Requester: cleanText(in.Requester, 80),
		Kind:      string(in.Kind),
		Action:    cleanText(in.Action, 60),
		Summary:   cleanText(in.Summary, approvalMaxSummary),
		Targets:   targets,
		Digest:    hex.EncodeToString(digest[:]),
		Created:   now.Unix(),
		Expires:   now.Add(ttl).Unix(),
	}
	if stmt.Action == "" {
		stmt.Action = string(in.Kind)
	}
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	signed := append([]byte(approvalStatementPrefix), stmtJSON...)
	priv, keyID, err := a.tenantSigningKey(in.TenantID)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signed)
	ch := sha256.Sum256(signed)
	rec := &approvalRecord{
		stmt:      stmt,
		kind:      in.Kind,
		digest:    stmt.Digest,
		createdAt: now,
		view: ApprovalView{
			ID:        stmt.ID,
			TenantID:  stmt.TenantID,
			State:     ApprovalPending,
			Kind:      stmt.Kind,
			Action:    stmt.Action,
			Summary:   stmt.Summary,
			Targets:   stmt.Targets,
			Requester: stmt.Requester,
			CreatedAt: time.Unix(stmt.Created, 0).UTC(),
			ExpiresAt: time.Unix(stmt.Expires, 0).UTC(),
			Statement: base64.StdEncoding.EncodeToString(stmtJSON),
			Signature: hex.EncodeToString(sig),
			Challenge: hex.EncodeToString(ch[:]),
			SignerKey: keyID,
		},
	}
	b.mu.Lock()
	b.items[stmt.ID] = rec
	b.created[in.TenantID] = append(b.created[in.TenantID], now)
	view := rec.view
	b.mu.Unlock()
	a.auditApproval(in.TenantID, in.Requester, "approval_requested", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success", stmt.Action+": "+stmt.Summary)
	return &view, nil
}

// approvalsReady reports whether an owner approver is pinned. Requests are
// refused up front when none is, so nobody waits on a tap that cannot verify.
func (a *Authority) approvalsReady() (int, error) {
	list, err := a.approvals.loadApprovers()
	if err != nil {
		return 0, err
	}
	return len(list), nil
}

func (a *Authority) tenantSigningKey(tenantID string) (ed25519.PrivateKey, string, error) {
	if _, _, err := a.GetOrCreateTenantKey(tenantID); err != nil {
		return nil, "", err
	}
	a.mu.RLock()
	priv, ok := a.tenantKeys[tenantID]
	a.mu.RUnlock()
	if !ok {
		return nil, "", fmt.Errorf("no response signing key for tenant %q", tenantID)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	return priv, hex.EncodeToString(fp[:]), nil
}

func (b *approvalBook) sweepLocked(now time.Time) {
	for id, r := range b.items {
		switch r.view.State {
		case ApprovalPending:
			if now.After(r.view.ExpiresAt) {
				r.view.State = ApprovalExpired
			}
		case ApprovalApproved:
			if r.view.UseBy != nil && now.After(*r.view.UseBy) {
				r.view.State = ApprovalExpired
			}
		}
		if now.Sub(r.createdAt) > approvalMaxTTL+approvalUseWindow+approvalKeep {
			delete(b.items, id)
		}
	}
	for t, times := range b.created {
		kept := times[:0]
		for _, at := range times {
			if now.Sub(at) < time.Hour {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(b.created, t)
		} else {
			b.created[t] = kept
		}
	}
}

// GetApproval returns one approval's state. An empty tenant reads any tenant
// (the relay); otherwise the tenant must match.
func (a *Authority) GetApproval(id, tenantID string) (*ApprovalView, error) {
	b := a.approvals
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(time.Now())
	r, ok := b.items[id]
	if !ok || (tenantID != "" && r.view.TenantID != tenantID) {
		return nil, ErrApprovalNotFound
	}
	v := r.view
	return &v, nil
}

// PendingApprovals lists every pending approval, oldest first.
func (a *Authority) PendingApprovals() []ApprovalView {
	b := a.approvals
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(time.Now())
	out := []ApprovalView{}
	for _, r := range b.items {
		if r.view.State == ApprovalPending {
			out = append(out, r.view)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// DecisionChallenge is what the owner's passkey signs for one decision:
// sha256(challenge_hex ":" decision), so a signed deny is never an approval.
func DecisionChallenge(challengeHex, decision string) []byte {
	h := sha256.Sum256([]byte(challengeHex + ":" + decision))
	return h[:]
}

func unb64url(s string) ([]byte, error) {
	if len(s) > 8192 {
		return nil, errors.New("field too long")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// verifyOwnerAssertion checks a WebAuthn assertion strictly against one of
// the pinned approvers and returns that approver and the new sign count.
func verifyOwnerAssertion(approvers []Approver, counters map[string]uint32, challengeHex, decision string, as *ApprovalAssertion) (*Approver, uint32, error) {
	if as == nil || as.AuthenticatorData == "" || as.ClientDataJSON == "" || as.Signature == "" || as.CredentialID == "" {
		return nil, 0, errors.New("incomplete assertion")
	}
	var ap *Approver
	for i := range approvers {
		if approvers[i].CredentialID == as.CredentialID {
			ap = &approvers[i]
			break
		}
	}
	if ap == nil {
		return nil, 0, errors.New("credential is not a pinned approver")
	}
	cdRaw, err := unb64url(as.ClientDataJSON)
	if err != nil {
		return nil, 0, errors.New("bad clientDataJSON encoding")
	}
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin *bool  `json:"crossOrigin"`
	}
	if err := json.Unmarshal(cdRaw, &cd); err != nil {
		return nil, 0, errors.New("malformed clientDataJSON")
	}
	if cd.Type != "webauthn.get" {
		return nil, 0, errors.New("not an assertion")
	}
	want := base64.RawURLEncoding.EncodeToString(DecisionChallenge(challengeHex, decision))
	if cd.Challenge != want {
		return nil, 0, errors.New("challenge does not match this approval and decision")
	}
	if cd.Origin != ap.Origin {
		return nil, 0, errors.New("origin is not the pinned approval origin")
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return nil, 0, errors.New("cross-origin assertion")
	}
	authData, err := unb64url(as.AuthenticatorData)
	if err != nil || len(authData) < 37 {
		return nil, 0, errors.New("bad authenticatorData")
	}
	rp := sha256.Sum256([]byte(ap.RPID))
	if !bytes.Equal(authData[:32], rp[:]) {
		return nil, 0, errors.New("rpIdHash mismatch")
	}
	if authData[32]&0x01 == 0 || authData[32]&0x04 == 0 {
		return nil, 0, errors.New("user presence and verification are required")
	}
	count := binary.BigEndian.Uint32(authData[33:37])
	if prev := counters[ap.ID]; (count != 0 || prev != 0) && count <= prev {
		return nil, 0, errors.New("signature counter did not advance")
	}
	x, errX := unb64url(ap.X)
	y, errY := unb64url(ap.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, 0, errors.New("pinned approver key is malformed")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, 0, errors.New("pinned approver key is not on P-256")
	}
	sig, err := unb64url(as.Signature)
	if err != nil {
		return nil, 0, errors.New("bad signature encoding")
	}
	cdHash := sha256.Sum256(cdRaw)
	msg := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	if !ecdsa.VerifyASN1(pub, msg[:], sig) {
		return nil, 0, errors.New("signature does not verify with the pinned approver key")
	}
	return ap, count, nil
}

// AnswerApproval records the owner's decision. Approve needs a valid
// assertion; deny is accepted with or without one (it only refuses).
func (a *Authority) AnswerApproval(ans *ApprovalAnswer) (*ApprovalView, error) {
	if ans == nil || ans.ID == "" {
		return nil, ErrApprovalNotFound
	}
	if ans.Decision != "approve" && ans.Decision != "deny" {
		return nil, errors.New("decision must be approve or deny")
	}
	approvers, aErr := a.approvals.loadApprovers()
	now := time.Now()
	b := a.approvals
	b.mu.Lock()
	b.sweepLocked(now)
	r, ok := b.items[ans.ID]
	if !ok {
		b.mu.Unlock()
		return nil, ErrApprovalNotFound
	}
	if r.view.State != ApprovalPending {
		v := r.view
		b.mu.Unlock()
		return &v, fmt.Errorf("approval is already %s", v.State)
	}
	method := "unverified"
	var approverID string
	if ans.Decision == "approve" || ans.Assertion != nil {
		if aErr != nil {
			b.mu.Unlock()
			return nil, aErr
		}
		ap, count, err := verifyOwnerAssertion(approvers, b.counters, r.view.Challenge, ans.Decision, ans.Assertion)
		if err != nil {
			tenant, req, kind := r.view.TenantID, r.view.Requester, r.view.Kind
			b.mu.Unlock()
			a.auditApproval(tenant, req, "approval_assertion_rejected", kind, "", ans.ID, "denied", err.Error())
			return nil, fmt.Errorf("%w: %v", ErrApprovalAssertion, err)
		}
		b.counters[ap.ID] = count
		method = "passkey"
		approverID = ap.ID
	}
	t := now.UTC()
	r.view.DecidedAt = &t
	r.view.Method = method
	r.view.ApproverID = approverID
	if ans.Decision == "approve" {
		r.view.State = ApprovalApproved
		useBy := t.Add(approvalUseWindow)
		r.view.UseBy = &useBy
	} else {
		r.view.State = ApprovalDenied
	}
	v := r.view
	b.mu.Unlock()
	a.auditApproval(v.TenantID, v.Requester, "approval_"+string(v.State), v.Kind, strings.Join(v.Targets, ","), v.ID, "success", "method="+method+" approver="+approverID)
	return &v, nil
}

// ConsumeApproval spends an approved request exactly once and signs one
// grant per target. The kind, payload digest and target set must equal what
// the owner approved.
func (a *Authority) ConsumeApproval(req *ApprovalConsumeRequest) ([]*response.EndpointGrant, error) {
	if req == nil || req.ID == "" {
		return nil, ErrApprovalNotFound
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}
	now := time.Now()
	b := a.approvals
	b.mu.Lock()
	b.sweepLocked(now)
	r, ok := b.items[req.ID]
	if !ok || r.view.TenantID != req.TenantID {
		b.mu.Unlock()
		return nil, ErrApprovalNotFound
	}
	if r.view.State != ApprovalApproved {
		st := r.view.State
		b.mu.Unlock()
		a.auditApproval(req.TenantID, "", "approval_consume_refused", string(req.Kind), "", req.ID, "denied", "state "+string(st))
		return nil, ErrApprovalNotUsable
	}
	targets := sortedUnique(req.Targets)
	if r.kind != req.Kind || !strings.EqualFold(r.digest, req.Digest) || strings.Join(targets, "\x00") != strings.Join(r.stmt.Targets, "\x00") {
		b.mu.Unlock()
		a.auditApproval(req.TenantID, "", "approval_consume_refused", string(req.Kind), strings.Join(targets, ","), req.ID, "denied", "action differs from the approved one")
		return nil, ErrApprovalMismatch
	}
	r.view.State = ApprovalConsumed
	requester, stmt := r.stmt.Requester, r.stmt
	b.mu.Unlock()

	priv, keyID, err := a.tenantSigningKey(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := req.TTLSeconds
	if ttl <= 0 || ttl > 3600 {
		ttl = 300
	}
	grants := make([]*response.EndpointGrant, 0, len(targets))
	for _, ep := range targets {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		g := &response.EndpointGrant{
			Version:           response.GrantVersion,
			GrantID:           uuid.New().String(),
			TenantID:          req.TenantID,
			EndpointID:        ep,
			ActionKind:        req.Kind,
			ActionDigest:      stmt.Digest,
			OperatorID:        requester,
			ResponseSessionID: "approval:" + stmt.ID,
			IssuedAt:          now.Unix(),
			ExpiresAt:         now.Unix() + ttl,
			Nonce:             hex.EncodeToString(nonce),
			SignerKeyID:       keyID,
		}
		g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
		grants = append(grants, g)
		a.auditApproval(req.TenantID, requester, "grant_signed", string(req.Kind), ep, stmt.ID, "success", "owner approval "+stmt.ID+" grant "+g.GrantID)
	}
	return grants, nil
}

// ApproverStatus reports how many owner approvers are pinned (never keys).
func (a *Authority) ApproverStatus() (int, string) {
	n, err := a.approvalsReady()
	if err != nil {
		return 0, err.Error()
	}
	return n, ""
}

func (a *Authority) auditApproval(tenant, operator, event, kind, endpoint, approvalID, status, details string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  time.Now(),
		TenantID:   tenant,
		OperatorID: operator,
		EventType:  event,
		ActionKind: kind,
		EndpointID: endpoint,
		GrantID:    approvalID,
		Status:     status,
		Details:    details,
	})
}
