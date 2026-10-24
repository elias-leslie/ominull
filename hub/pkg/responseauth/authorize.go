package responseauth

// Authorizing an action. The hub asks the authority to sign the grants for one
// high-impact action (an isolation change, an agent update, a terminal or
// screen session, a package run, a mesh quarantine, a capability or detection
// policy change). The authority checks what it can read for itself (the
// payload, its targets, the release it installs), puts the action in its own
// words for the audit, signs one grant per target with the tenant response key
// and returns them. Nobody is asked: this authority decides by the checks
// below and the hub's own, and an action it cannot read is refused with the
// reason. Agents still accept only grants this authority signed, verify them
// themselves, and enforce their own lock and capability limits.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// Action kinds the authority signs grants for on the hub's request.
const (
	ActionKindIsolation   = response.ActionKindIsolationChange
	ActionKindAgentUpdate = response.ActionKindAgentUpdate
	ActionKindMesh        = response.ActionKindMeshQuarantine
	ActionKindCapability  = response.ActionKindCapability
	ActionKindDetection   = response.ActionKindDetectionPolicy
)

const (
	authorizeMaxTargets = 50
	approvalMaxSummary  = 300
	authorizeMaxPayload = 16 * 1024
)

// AuthorizeInput is what the hub asks.
type AuthorizeInput struct {
	TenantID   string              `json:"tenant_id"`
	Requester  string              `json:"requester"`
	Kind       response.ActionKind `json:"kind"`
	Targets    []string            `json:"targets"`
	Payload    json.RawMessage     `json:"payload"`
	TTLSeconds int64               `json:"ttl_seconds,omitempty"`
	// Release is the signed agent packages an agent update installs; the
	// authority reads it to tell a release signed with a routine key (which
	// rolls out canaries first).
	Release []ReleaseEvidence `json:"release,omitempty"`
	// RoutineKeys: the routine release keys the hub holds, as the pinned
	// release key signed them; the authority verifies the list itself.
	RoutineKeys *response.RoutineKeys `json:"routine_keys,omitempty"`
	// SessionSeconds is the longest a requested terminal or screen session
	// may run, as the hub will hold it. Audited, not part of the digest:
	// agents check a terminal grant against the program alone.
	SessionSeconds int64 `json:"session_seconds,omitempty"`
	// AskFirst says the person at the endpoint's keyboard is asked to allow a
	// screen session before it goes live. Audited, not digested.
	AskFirst bool `json:"ask_first,omitempty"`
	// AgentLabel is the name an agent using the hub admin key gives itself
	// (the hub's X-Ominull-Agent header). Self-declared: audited as a claim,
	// never as an identity. Only an admin-key requester may carry one.
	AgentLabel string `json:"agent_label,omitempty"`
	// StewardRun is the stuck maintenance run (job id) a steward screen
	// request is for: audited, not digested.
	StewardRun string `json:"steward_run,omitempty"`
}

// Authorization is the authority's answer: the action in its words, and the
// grants it signed (none for a hub-side change that no agent acts on).
type Authorization struct {
	ID        string                    `json:"id"`
	TenantID  string                    `json:"tenant_id"`
	Kind      string                    `json:"kind"`
	Action    string                    `json:"action"`
	Summary   string                    `json:"summary"`
	Targets   []string                  `json:"targets"`
	Requester string                    `json:"requester"`
	CreatedAt time.Time                 `json:"created_at"`
	Grants    []*response.EndpointGrant `json:"grants,omitempty"`
}

// authorized is one checked action, ready to be signed.
type authorized struct {
	ID         string
	TenantID   string
	Requester  string
	Kind       response.ActionKind
	Digest     string
	Payload    []byte
	Targets    []string
	TTLSeconds int64
}

// ErrNotAuthorized refuses an action the authority cannot read or does not
// sign; the message says why.
var ErrNotAuthorized = errors.New("the authority does not sign this action")

func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
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

func authorizeKindAllowed(k response.ActionKind) bool {
	switch k {
	case ActionKindIsolation, ActionKindAgentUpdate, ActionKindMesh, ActionKindCapability, ActionKindDetection, response.ActionKindTerminalSession,
		response.ActionKindScreenSession, response.ActionKindScriptExec:
		return true
	}
	return false
}

// Authorize checks one action and signs its grants.
func (a *Authority) Authorize(in *AuthorizeInput) (*Authorization, error) {
	if in == nil {
		return nil, errors.New("missing authorize request")
	}
	if in.TenantID == "" {
		in.TenantID = "default"
	}
	if !authorizeKindAllowed(in.Kind) {
		return nil, fmt.Errorf("action kind %q is not signed on the hub's request", in.Kind)
	}
	targets := sortedUnique(in.Targets)
	if len(targets) == 0 {
		return nil, errors.New("an authorization names its targets explicitly")
	}
	if len(targets) > authorizeMaxTargets {
		return nil, fmt.Errorf("an authorization covers at most %d targets", authorizeMaxTargets)
	}
	for _, t := range targets {
		if len(t) > 128 || cleanText(t, 128) != t {
			return nil, fmt.Errorf("invalid target %q", t)
		}
	}
	maxPayload := authorizeMaxPayload
	if in.Kind == response.ActionKindScriptExec {
		// A package run carries the script sources the agents will run.
		maxPayload = packageMaxPayload
	}
	if len(in.Payload) == 0 || len(in.Payload) > maxPayload || !json.Valid(in.Payload) {
		return nil, fmt.Errorf("the payload must be valid JSON up to %d KiB", maxPayload/1024)
	}
	if in.Kind == ActionKindAgentUpdate {
		// A release signed in the owner's session with a routine key always
		// rolls out canaries first.
		if _, _, routine, canary, err := a.rolloutEvidence(in); err == nil && routine && len(targets) > 1 && len(canary) == 0 {
			return nil, errors.New("a release signed with a routine key rolls out canaries first: name the canaries")
		}
	}
	if strings.Contains(in.TenantID, "#") {
		return nil, errors.New("invalid tenant ID")
	}
	// Agents act on these payloads themselves, so the authority holds them to
	// one canonical reading, no case-variant keys. A package run's items are
	// the exact bytes agents digest (the hub's field order, not sorted), so it
	// is held to lower-case, unique keys (plainKeys) instead of the canonical
	// form. A screen payload's one form is the hub's field order (mode,
	// unattended, ask_first), which describeScreen holds it to byte for byte.
	if in.Kind != response.ActionKindTerminalSession && in.Kind != response.ActionKindScriptExec && in.Kind != response.ActionKindScreenSession {
		if err := strictPayload(in.Payload); err != nil {
			return nil, fmt.Errorf("payload refused: %w", err)
		}
	}
	requester := cleanText(in.Requester, 80)
	if in.AgentLabel != "" {
		if !ValidAgentLabel(in.AgentLabel) {
			return nil, errors.New("an agent label is 1 to 64 printable characters, without quotes or backslashes")
		}
		if !strings.HasSuffix(requester, "(api-key)") {
			return nil, errors.New("only a request made with the hub admin key carries an agent label")
		}
	}
	if in.StewardRun != "" {
		if in.Kind != response.ActionKindScreenSession || !IsStewardRequester(requester) {
			return nil, errors.New("only the steward's screen request names a maintenance run")
		}
		if len(in.StewardRun) > stewardRunMax || cleanText(in.StewardRun, stewardRunMax) != in.StewardRun {
			return nil, errors.New("invalid maintenance run id")
		}
	}
	action, summary, err := describeApproval(in.Kind, in.Payload, targets, requester)
	if err == nil && in.Kind == response.ActionKindTerminalSession {
		action, summary, err = describeTerminal(in.Payload, targets, requester, in.SessionSeconds, in.AgentLabel)
	}
	if err == nil && in.Kind == response.ActionKindScreenSession {
		action, summary, err = describeScreen(in.Payload, targets, requester, in.SessionSeconds, in.AskFirst, in.AgentLabel)
		if err == nil && in.StewardRun != "" {
			summary += "; to unstick maintenance run " + in.StewardRun
		}
	}
	if err != nil {
		a.auditAction(in.TenantID, in.Requester, "action_refused", string(in.Kind), strings.Join(targets, ","), "", "denied", err.Error())
		return nil, fmt.Errorf("%w: %v", ErrNotAuthorized, err)
	}
	if in.Kind == ActionKindAgentUpdate {
		// The release the update installs, as far as the authority can verify
		// it. A release it cannot verify is still signed (agents check the
		// package signature themselves before installing); the audit says so.
		if what, _, _, _, rerr := a.rolloutEvidence(in); rerr == nil {
			summary += "; " + what
		} else {
			summary += "; release signature not verified by the authority (" + rerr.Error() + ")"
		}
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(in.Payload)
	now := time.Now()
	au := &authorized{
		ID: hex.EncodeToString(idBytes), TenantID: in.TenantID, Requester: requester, Kind: in.Kind,
		Digest: hex.EncodeToString(digest[:]), Payload: append([]byte(nil), in.Payload...), Targets: targets, TTLSeconds: in.TTLSeconds,
	}
	out := &Authorization{
		ID: au.ID, TenantID: au.TenantID, Kind: string(in.Kind), Action: action, Summary: cleanText(summary, approvalMaxSummary),
		Targets: targets, Requester: requester, CreatedAt: now.UTC(),
	}
	a.auditAction(au.TenantID, in.Requester, "action_authorized", string(in.Kind), strings.Join(targets, ","), au.ID, "success", action+": "+out.Summary)
	grants, err := a.signAuthorized(au, now)
	if err != nil {
		a.auditAction(au.TenantID, in.Requester, "action_refused", string(in.Kind), strings.Join(targets, ","), au.ID, "denied", err.Error())
		return nil, err
	}
	out.Grants = grants
	return out, nil
}

// signAuthorized signs the grants of a checked action.
func (a *Authority) signAuthorized(au *authorized, now time.Time) ([]*response.EndpointGrant, error) {
	switch {
	case au.Kind == response.ActionKindScriptExec:
		return a.signPackageGrants(au, now)
	case au.Kind == ActionKindDetection:
		// The hub applies a detection-policy change itself; no agent acts on
		// it, so there is nothing to sign.
		a.auditAction(au.TenantID, au.Requester, "detection_policy_authorized", string(au.Kind), strings.Join(au.Targets, ","), au.ID, "success", "digest "+au.Digest)
		return nil, nil
	}
	priv, keyID, err := a.tenantSigningKey(au.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := grantTTL(au.Kind, au.TTLSeconds)
	issued := now.Unix()
	if enforcementKind(au.Kind) {
		if issued, err = a.enfClock.next(au.TenantID, now); err != nil {
			return nil, err
		}
	}
	// The manifest changes only once the key and clock are in hand, so a
	// failure above leaves the authority's manifest as it was.
	if changesManifest(au.Kind, au.Payload) {
		if err := a.applyCapabilityChange(au); err != nil {
			a.auditAction(au.TenantID, au.Requester, "manifest_refused", string(au.Kind), strings.Join(au.Targets, ","), au.ID, "denied", err.Error())
			return nil, err
		}
	}
	grants := make([]*response.EndpointGrant, 0, len(au.Targets))
	for _, ep := range au.Targets {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		g := &response.EndpointGrant{
			Version:           response.GrantVersion,
			GrantID:           uuid.New().String(),
			TenantID:          au.TenantID,
			EndpointID:        ep,
			ActionKind:        au.Kind,
			ActionDigest:      au.Digest,
			OperatorID:        au.Requester,
			ResponseSessionID: "approval:" + au.ID,
			IssuedAt:          issued,
			ExpiresAt:         issued + ttl,
			Nonce:             hex.EncodeToString(nonce),
			SignerKeyID:       keyID,
		}
		g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
		grants = append(grants, g)
		a.auditAction(au.TenantID, au.Requester, "grant_signed", string(au.Kind), ep, au.ID, "success", "authorization "+au.ID+" grant "+g.GrantID)
	}
	return grants, nil
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

func (a *Authority) auditAction(tenant, operator, event, kind, endpoint, id, status, details string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.store.RecordAudit(ctx, &SignerAuditEntry{
		Timestamp:  time.Now(),
		TenantID:   tenant,
		OperatorID: operator,
		EventType:  event,
		ActionKind: kind,
		EndpointID: endpoint,
		GrantID:    id,
		Status:     status,
		Details:    details,
	})
}
