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
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// Action kinds that only an owner approval can authorize.
const (
	ActionKindIsolation   = response.ActionKindIsolationChange
	ActionKindAgentUpdate = response.ActionKindAgentUpdate
	ActionKindMesh        = response.ActionKindMeshQuarantine
	ActionKindCapability  = response.ActionKindCapability
	ActionKindDetection   = response.ActionKindDetectionPolicy
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
// The directory is root:ominull-authority 0750 (the hub package creates it);
// the file is root-owned and not group/world-writable.
const DefaultApproversPath = "/etc/ominull-response-authority/approvers.json"

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
	// Offer "rollouts": the owner may answer "rule" (Approve all like this)
	// and approve later rollouts of owner-signed releases without asking
	// (rollout_rule.go). Only an agent update of an owner-signed release
	// carries it.
	Offer string `json:"offer,omitempty"`
	// Row is the owner's Approvals row this ask follows (approval_rows.go),
	// with what picked it; AskReason, when set, says why it always asks.
	Row       string     `json:"row,omitempty"`
	RowInputs *RowInputs `json:"row_inputs,omitempty"`
	AskReason string     `json:"ask_reason,omitempty"`
	// Blast is the ask's blast radius (approval_blast.go).
	Blast *Blast `json:"blast,omitempty"`
	// Rows, Session and Lab are exactly what an approval_rules tap saves.
	Rows    map[string]string `json:"rows,omitempty"`
	Session *RowSession       `json:"session,omitempty"`
	Lab     []string          `json:"lab,omitempty"`
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
	// Release is the signed agent packages an agent update installs; it is
	// read only to decide whether a rollout rule covers the request.
	Release []ReleaseEvidence `json:"release,omitempty"`
	// RoutineKeys: the routine release keys the hub holds, as the pinned
	// release key signed them; the authority verifies the list itself.
	RoutineKeys *response.RoutineKeys `json:"routine_keys,omitempty"`
	// RuleOnly asks for a package run that a live package rule covers and
	// nothing else: an uncovered request is refused (ErrRuleNotCovered)
	// without recording or asking anyone. The hub's schedule uses it.
	RuleOnly bool `json:"rule_only,omitempty"`
	// SessionSeconds is the longest a requested terminal session may run, as
	// the hub will hold it. It is shown to the owner and not digested: agents
	// check a terminal grant against the program alone.
	SessionSeconds int64 `json:"session_seconds,omitempty"`
	// AskFirst says the person at the endpoint's keyboard is asked to allow a
	// screen session before it goes live (the machine's "ask the person
	// first" setting). Shown to the owner, not digested, like SessionSeconds.
	AskFirst bool `json:"ask_first,omitempty"`
	// AgentLabel is the name an agent using the hub admin key gives itself
	// (the hub's X-Ominull-Agent header). Self-declared: it is shown to the
	// owner as a claim, never as an identity. Only an admin-key requester
	// may carry one.
	AgentLabel string `json:"agent_label,omitempty"`
	// StewardRun is the stuck maintenance run (job id) a steward screen
	// request is for: shown to the owner and audited, not digested, and
	// required for a steward screen rule to approve it.
	StewardRun string `json:"steward_run,omitempty"`
	// StewardRule raises a machine's "Steward remote screen" setting: the
	// owner's tap stores a steward screen rule and signs nothing
	// (steward_screen_rule.go).
	StewardRule *StewardScreenAsk `json:"steward_rule,omitempty"`
	// StewardRuleToken is the owner's steward screen rule for the target, as
	// Nightshift keeps it (a token this authority signed when the owner
	// tapped), and StewardNarrow Nightshift's narrowing of it. Read only to
	// decide whether the rule covers a steward session.
	StewardRuleToken string               `json:"steward_rule_token,omitempty"`
	StewardNarrow    *StewardScreenNarrow `json:"steward_narrow,omitempty"`
	// Facts are the hub's reading of the targets' trust reports, used only to
	// pick the Approvals row (approval_rows.go).
	Facts *ApprovalFacts `json:"facts,omitempty"`
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
	Method     string        `json:"method,omitempty"` // passkey | rule | row | session | learned | baseline | unverified
	Row        string        `json:"row,omitempty"`    // the Approvals row the ask follows ("" when it always asks)
	Blast      *Blast        `json:"blast,omitempty"`  // its blast radius, as signed in the statement
	Offer      string        `json:"offer,omitempty"`
	// StewardRule is the signed rule token an approved steward screen rule
	// ask yields, for Nightshift to keep (steward_screen_rule.go).
	StewardRule string `json:"steward_rule,omitempty"`
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
	Decision  string             `json:"decision"` // approve | deny | rule (approve, and approve all like this)
	Assertion *ApprovalAssertion `json:"assertion,omitempty"`
}

// ApprovalConsumeRequest turns an approved request into grants, once.
type ApprovalConsumeRequest struct {
	ID         string              `json:"id"`
	TenantID   string              `json:"tenant_id"`
	Requester  string              `json:"requester"`
	Kind       response.ActionKind `json:"kind"`
	Digest     string              `json:"digest"`
	Targets    []string            `json:"targets"`
	TTLSeconds int64               `json:"ttl_seconds,omitempty"`
	// SessionSeconds, AskFirst and AgentLabel must equal what the request
	// that was approved carried: the owner was shown them, so a second
	// request cannot change the session length, the ask-first wording or
	// the agent's name under the same approval.
	SessionSeconds int64  `json:"session_seconds,omitempty"`
	AskFirst       bool   `json:"ask_first,omitempty"`
	AgentLabel     string `json:"agent_label,omitempty"`
	StewardRun     string `json:"steward_run,omitempty"`
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
	payload   []byte
	createdAt time.Time
	// What the owner was shown beside the digest; ConsumeApproval requires
	// the same values.
	sessionSeconds int64
	askFirst       bool
	agentLabel     string
	stewardRun     string
	stewardRule    *StewardScreenAsk
	// shape is the job's shape for learning; "" when it never learns (core,
	// the steward's screen).
	shape string
}

type approvalBook struct {
	mu        sync.Mutex
	items     map[string]*approvalRecord
	created   map[string][]time.Time // tenant -> creation times in the last hour
	reserved  map[string]int         // tenant -> requests between the cap check and insertion
	counters  map[string]uint32      // approver id -> last sign count
	approvers string                 // path of the pinned approver file
}

func (b *approvalBook) unreserveLocked(tenant string) {
	b.reserved[tenant]--
	if b.reserved[tenant] <= 0 {
		delete(b.reserved, tenant)
	}
}

func newApprovalBook(path string) *approvalBook {
	if path == "" {
		path = DefaultApproversPath
	}
	return &approvalBook{
		items:     map[string]*approvalRecord{},
		created:   map[string][]time.Time{},
		reserved:  map[string]int{},
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
	b.mu.Lock()
	path := b.approvers
	b.mu.Unlock()
	f0, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoApprovers
		}
		return nil, fmt.Errorf("read approvers: %w", err)
	}
	defer f0.Close()
	info, err := f0.Stat()
	if err != nil {
		return nil, fmt.Errorf("read approvers: %w", err)
	}
	// Whoever can write this file can approve: only root (or, in tests, the
	// authority's own user) may own it, and nobody else may write it.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || info.Size() > 64*1024 {
		return nil, errors.New("approver file must be a root-owned regular file, not group or world writable")
	}
	raw, err := io.ReadAll(io.LimitReader(f0, 64*1024))
	if err != nil {
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
	case ActionKindIsolation, ActionKindAgentUpdate, ActionKindMesh, ActionKindCapability, ActionKindDetection, response.ActionKindTerminalSession,
		response.ActionKindScreenSession, response.ActionKindScriptExec:
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
	maxPayload := approvalMaxPayload
	if in.Kind == response.ActionKindScriptExec {
		// A package run carries the script sources the agents will run.
		maxPayload = packageMaxPayload
	}
	if len(in.Payload) == 0 || len(in.Payload) > maxPayload || !json.Valid(in.Payload) {
		return nil, fmt.Errorf("approval payload must be valid JSON up to %d KiB", maxPayload/1024)
	}
	if in.Kind == ActionKindAgentUpdate {
		// A release signed in the owner's session always rolls out
		// canaries first, whoever approves it.
		if _, _, routine, canary, err := a.rolloutEvidence(in); err == nil && routine && len(targets) > 1 && len(canary) == 0 {
			return nil, errors.New("a release signed with a routine key rolls out canaries first: name the canaries")
		}
	}
	if in.RuleOnly && in.Kind != response.ActionKindScriptExec {
		return nil, errors.New("only a package run can be asked for under a rule alone")
	}
	if strings.Contains(in.TenantID, "#") {
		return nil, errors.New("invalid tenant ID")
	}
	// Agents act on these payloads themselves, so the owner must see what
	// the agent will read: one canonical reading, no case-variant keys.
	// A package run's items are the exact bytes agents digest (the hub's
	// field order, not sorted), so it is held to lower-case, unique keys
	// (plainKeys) instead of the canonical form.
	// A screen payload's one form is the hub's field order (mode,
	// unattended, ask_first), which describeScreen holds it to byte for byte.
	if in.Kind != response.ActionKindTerminalSession && in.Kind != response.ActionKindScriptExec && in.Kind != response.ActionKindScreenSession {
		if err := strictPayload(in.Payload); err != nil {
			return nil, fmt.Errorf("approval payload refused: %w", err)
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
	var stewardAsk response.ScreenSessionPayload
	if in.StewardRule != nil {
		p, err := a.stewardScreenAskCheck(in, targets)
		if err != nil {
			return nil, err
		}
		stewardAsk = p
	}
	action, summary, err := describeApproval(in.Kind, in.Payload, targets, requester)
	if err == nil && in.Kind == response.ActionKindTerminalSession {
		action, summary, err = describeTerminal(in.Payload, targets, requester, in.SessionSeconds, in.AgentLabel)
	}
	if err == nil && in.Kind == response.ActionKindScreenSession {
		action, summary, err = describeScreen(in.Payload, targets, requester, in.SessionSeconds, in.AskFirst, in.AgentLabel)
		if err == nil && in.StewardRule != nil {
			action, summary = describeStewardScreenAsk(stewardAsk, in.AskFirst || stewardAsk.AskFirst, targets, in.StewardRule)
		} else if err == nil && in.StewardRun != "" {
			summary += "; to unstick maintenance run " + in.StewardRun
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err := a.approvalsReady(); err != nil {
		return nil, err
	}
	// A package run of safe packages: approved now under a live package rule
	// (no rate limit: the owner already approved exactly these runs), or
	// offered one.
	// A baseline run (safe released packages, audit, default settings) needs
	// no tap at all.
	// Once the owner's Approvals rows were accepted they decide, and the old
	// approve-all rules are neither consulted nor offered.
	rowsLive := a.rows.stored(in.TenantID)
	pkgDigests, pkgLabels, pkgErr := packageRuleCovers(in, targets)
	pkgRuleID, pkgAuto := "", false
	pkgBaseline := pkgErr == nil && packageBaseline(in, targets)
	if pkgBaseline {
		pkgAuto = true
	} else if pkgErr == nil && !rowsLive {
		pkgRuleID, pkgAuto = a.packages.match(in.TenantID, pkgDigests, targets, time.Now())
	}
	// A steward session for a stuck run under the machine's steward screen
	// rule: approved now, no rate limit (the owner already allowed it).
	stewardRule, stewardPayload, stewardAuto := a.stewardScreenMatch(in, targets, time.Now())
	// The owner's Approvals row for this ask (approval_rows.go): auto, or
	// session while the owner's session is open, approves it now.
	row, askReason, rowIn := a.rowFor(in, targets, time.Now())
	// Nightshift's approvals model (approval_blast.go, approval_learned.go):
	// the blast radius is signed into every ask; core always asks the owner.
	// Otherwise the owner's open work session approves it, or a job shape
	// the owner approved three times with no denial, or its row.
	blast := a.blastFor(in, targets, rowIn)
	modelOn := a.rows.enabled()
	core := modelOn && blast.Verdict == BlastCore
	shape := ""
	if modelOn && !core && in.StewardRule == nil && in.StewardRun == "" {
		shape = approvalShape(in, targets)
	}
	rowAuto, rowChoice := false, ""
	if row != "" && !pkgAuto && !stewardAuto && !core {
		rowChoice, rowAuto = a.rows.allows(in.TenantID, row, time.Now())
	}
	sessionAuto := false
	if modelOn && !core && !pkgAuto && !stewardAuto && !rowAuto {
		sessionAuto = a.rows.sessionAllows(in.TenantID, time.Now())
	}
	var learned LearnedShape
	learnedAuto := false
	if shape != "" && !pkgAuto && !stewardAuto && !rowAuto && !sessionAuto {
		if l, ok := a.learned.match(in.TenantID, shape); ok && a.rows.spendAuto(in.TenantID, time.Now()) {
			learned, learnedAuto = l, true
		}
	}
	freeAuto := rowAuto || sessionAuto || learnedAuto
	if in.RuleOnly && !pkgAuto && !freeAuto {
		return nil, ErrRuleNotCovered
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
	pending += b.reserved[in.TenantID]
	if !pkgAuto && !stewardAuto && !freeAuto && (pending >= approvalMaxPending || len(recent) >= approvalMaxPerHour) {
		b.mu.Unlock()
		a.auditApproval(in.TenantID, in.Requester, "approval_refused", string(in.Kind), "", "", "denied", ErrApprovalRateLimit.Error())
		return nil, ErrApprovalRateLimit
	}
	// Take both slots now, under the same lock as the check: concurrent
	// callers must not all pass on the same stale counts. The hourly slot is
	// spent even if signing fails below; the pending slot is handed back.
	reserved := !pkgAuto && !stewardAuto && !freeAuto
	if reserved {
		b.created[in.TenantID] = append(recent, now)
		b.reserved[in.TenantID]++
	}
	b.mu.Unlock()
	inserted := false
	defer func() {
		if !inserted && reserved {
			b.mu.Lock()
			b.unreserveLocked(in.TenantID)
			b.mu.Unlock()
		}
	}()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	// A rollout of an owner-signed release: approved now under the tenant's
	// rule, or offered one.
	evidence, covered := "", false
	ev, version, err := a.rolloutRuleCovers(in, targets)
	if err == nil {
		evidence, covered = ev, true
	}
	var rule RolloutRule
	auto := false
	if covered && !rowsLive && !freeAuto {
		rule, auto = a.rollouts.use(in.TenantID, version, now)
	}
	var pkgRule PackageRule
	if pkgBaseline {
		evidence = "baseline audit " + strings.Join(pkgLabels, ", ")
	} else if pkgAuto {
		var ok bool
		if pkgRule, ok = a.packages.use(in.TenantID, pkgRuleID, pkgDigests, targets, now); !ok {
			// The rule ended or could not record its use between match
			// and here. Nothing was reserved, so nothing is asked either.
			return nil, ErrRuleNotCovered
		}
		evidence = "packages " + strings.Join(pkgLabels, ", ")
	}
	stmt := ApprovalStatement{
		V:         1,
		ID:        hex.EncodeToString(idBytes),
		TenantID:  in.TenantID,
		Requester: requester,
		Kind:      string(in.Kind),
		Action:    action,
		Summary:   cleanText(summary, approvalMaxSummary),
		Targets:   targets,
		Digest:    hex.EncodeToString(digest[:]),
		Created:   now.Unix(),
		Expires:   now.Add(ttl).Unix(),
		Row:       row,
		RowInputs: &rowIn,
		AskReason: askReason,
		Blast:     &blast,
	}
	if covered && !auto && !rowsLive && !freeAuto {
		stmt.Offer = rolloutRuleOffer
	}
	if pkgErr == nil && !pkgAuto && !rowsLive && !freeAuto {
		stmt.Offer = packageRuleOffer
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
		payload:   append([]byte(nil), in.Payload...),
		createdAt: now,
		// Only what describeTerminal/describeScreen showed the owner.
		sessionSeconds: in.SessionSeconds,
		askFirst:       in.AskFirst,
		agentLabel:     in.AgentLabel,
		stewardRun:     in.StewardRun,
		stewardRule:    in.StewardRule,
		shape:          shape,
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
			Offer:     stmt.Offer,
			Row:       row,
			Blast:     &blast,
		},
	}
	if freeAuto && !auto {
		t := now.UTC()
		useBy := t.Add(approvalUseWindow)
		rec.view.State, rec.view.DecidedAt, rec.view.UseBy = ApprovalApproved, &t, &useBy
		rec.view.Method, rec.view.ApproverID = "row", a.rows.approver(in.TenantID)
		if sessionAuto {
			rec.view.Method = "session"
		} else if learnedAuto {
			rec.view.Method, rec.view.ApproverID = "learned", learned.Approver
		}
	} else if auto || pkgAuto || stewardAuto {
		t := now.UTC()
		useBy := t.Add(approvalUseWindow)
		rec.view.State, rec.view.DecidedAt, rec.view.UseBy = ApprovalApproved, &t, &useBy
		rec.view.Method, rec.view.ApproverID = "rule", rule.ApproverID
		if pkgAuto {
			rec.view.ApproverID = pkgRule.ApproverID
		}
		if pkgBaseline {
			rec.view.Method, rec.view.ApproverID = "baseline", ""
		}
		if stewardAuto {
			rec.view.ApproverID = stewardRule.ApproverID
		}
	}
	b.mu.Lock()
	b.items[stmt.ID] = rec
	if reserved {
		b.unreserveLocked(in.TenantID)
	}
	inserted = true
	view := rec.view
	b.mu.Unlock()
	a.auditApproval(in.TenantID, in.Requester, "approval_requested", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success", stmt.Action+": "+stmt.Summary)
	if auto {
		_, spike := ruleWeek(&rule, now)
		note := ""
		if spike {
			note = "; busy week: far more rollouts than usual"
		}
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			fmt.Sprintf("approved without asking under the approve-all rule the owner made %s (approval %s, approver %s): %s%s",
				time.Unix(rule.Created, 0).UTC().Format(time.RFC3339), rule.ApprovalID, rule.ApproverID, evidence, note))
	}
	if sessionAuto && !auto {
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			fmt.Sprintf("approved without asking: the owner's work session is open and this is %s, not core (%s: %s)", blast.Verdict, blast.Class, blast.Why))
	}
	if learnedAuto && !auto {
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			fmt.Sprintf("approved without asking: the owner approved this exact job %d times with no denial (shape %s, last by %s)", learned.Approvals, shape, learned.Approver))
	}
	if rowAuto && !auto {
		why := "auto"
		if rowChoice == RowChoiceSession {
			why = "session, and the owner's session is open"
		}
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			fmt.Sprintf("approved without asking under the owner's Approvals row %s (%s; rows from %s)", row, why, a.rows.approver(in.TenantID)))
	}
	if pkgBaseline {
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			"approved without asking: released safe packages in audit mode with their default settings ("+evidence+")")
	} else if pkgAuto {
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), strings.Join(targets, ","), stmt.ID, "success",
			fmt.Sprintf("approved without asking under the package rule the owner made %s (approval %s, approver %s): %s",
				time.Unix(pkgRule.Created, 0).UTC().Format(time.RFC3339), pkgRule.ID, pkgRule.ApproverID, evidence))
	}
	if stewardAuto {
		a.auditApproval(in.TenantID, in.Requester, "approval_auto_approved", string(in.Kind), targets[0], stmt.ID, "success",
			fmt.Sprintf("approved without asking under the steward screen rule the owner made %s (approval %s, approver %s): %s session up to %s for maintenance run %s",
				time.Unix(stewardRule.Created, 0).UTC().Format(time.RFC3339), stewardRule.ApprovalID, stewardRule.ApproverID, stewardPayload.Mode, spanText(in.SessionSeconds), in.StewardRun))
	}
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

// NightshiftDesktopOrigin is the clientDataJSON origin Nightshift's desktop
// approver uses for the approve host rpID: it asks the security key directly
// over USB (CTAP2), with no browser in between. Accepting it weakens nothing:
// the origin check only stops another web page from asking for this rpID, and
// a browser never lets a page claim a non-https origin, while any native CTAP
// client could put the web origin into clientDataJSON just as easily. The
// pinned credential, rpIdHash, UP+UV, sign count and the decision-bound
// challenge still decide.
func NightshiftDesktopOrigin(rpID string) string {
	if rpID == "" {
		return ""
	}
	return "nightshift-desktop://" + rpID
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
	if cd.Origin != ap.Origin && cd.Origin != NightshiftDesktopOrigin(ap.RPID) {
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
	if ans.Decision != "approve" && ans.Decision != "deny" && ans.Decision != "rule" {
		return nil, errors.New("decision must be approve, deny or rule")
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
	if ans.Decision == "rule" && r.stmt.Offer != rolloutRuleOffer && r.stmt.Offer != packageRuleOffer {
		b.mu.Unlock()
		return nil, errors.New("this approval offers no approve-all rule")
	}
	method := "unverified"
	var approverID string
	if ans.Decision != "deny" || ans.Assertion != nil {
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
	if ans.Decision != "deny" {
		r.view.State = ApprovalApproved
		useBy := t.Add(approvalUseWindow)
		r.view.UseBy = &useBy
	} else {
		r.view.State = ApprovalDenied
	}
	v, payload := r.view, r.payload
	stewardRec := r.stewardRule != nil
	shape := r.shape
	b.mu.Unlock()
	a.auditApproval(v.TenantID, v.Requester, "approval_"+string(v.State), v.Kind, strings.Join(v.Targets, ","), v.ID, "success", "method="+method+" approver="+approverID)
	a.learnFrom(v, shape, method, approverID, now)
	if stewardRec && ans.Decision != "deny" {
		// The owner's tap: the rule token Nightshift keeps.
		if token := a.mintStewardRule(v, r, approverID, t); token != "" {
			b.mu.Lock()
			r.view.StewardRule = token
			v = r.view
			b.mu.Unlock()
		}
	} else if ans.Decision == "rule" && r.stmt.Offer == packageRuleOffer {
		a.createPackageRule(v, r.stmt.Targets, payload, approverID, t)
	} else if ans.Decision == "rule" {
		// The owner's one tap: this rollout is approved either way; the rule
		// covers later rollouts of owner-signed releases (rollout_rule.go).
		rule := &RolloutRule{TenantID: v.TenantID, Created: t.Unix(), ApproverID: approverID, ApprovalID: v.ID, Version: rolloutVersion(payload)}
		if err := a.rollouts.create(rule); err != nil {
			a.auditApproval(v.TenantID, v.Requester, "rollout_rule_not_saved", v.Kind, "", v.ID, "error", err.Error())
		} else {
			a.auditApproval(v.TenantID, v.Requester, "rollout_rule_created", v.Kind, "", v.ID, "success",
				"approve-all rule: agent rollouts of releases signed with the pinned release key, staged canaries first, approved without asking; ends 90 days after its last use; approver "+approverID)
		}
	}
	return &v, nil
}

// ConsumeApproval spends an approved request exactly once and signs one
// grant per target. The kind, payload digest, target set, requester and
// what the owner was shown beside them (session length, ask-first, agent
// label) must equal what the owner approved.
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
	if r.kind == ApprovalKindRules || r.kind != req.Kind || !strings.EqualFold(r.digest, req.Digest) || strings.Join(targets, "\x00") != strings.Join(r.stmt.Targets, "\x00") ||
		cleanText(req.Requester, 80) != r.stmt.Requester ||
		req.SessionSeconds != r.sessionSeconds || req.AskFirst != r.askFirst || req.AgentLabel != r.agentLabel || req.StewardRun != r.stewardRun {
		b.mu.Unlock()
		a.auditApproval(req.TenantID, "", "approval_consume_refused", string(req.Kind), strings.Join(targets, ","), req.ID, "denied", "action differs from the approved one")
		return nil, ErrApprovalMismatch
	}
	r.view.State = ApprovalConsumed
	requester, stmt, payload := r.stmt.Requester, r.stmt, r.payload
	stewardRec := r.stewardRule != nil
	b.mu.Unlock()

	if stewardRec {
		// The owner's tap stored the steward screen rule; there is no
		// session to sign for.
		a.auditApproval(req.TenantID, requester, "approval_consumed", string(req.Kind), strings.Join(targets, ","), stmt.ID, "success", "steward screen rule "+stmt.Digest)
		return nil, nil
	}

	if req.Kind == response.ActionKindScriptExec {
		return a.signPackageGrants(req, requester, stmt, payload, targets, now)
	}
	if req.Kind == ActionKindDetection {
		// The hub applies a detection-policy change itself; no agent acts on
		// it, so there is nothing to sign beyond spending the approval.
		a.auditApproval(req.TenantID, requester, "approval_consumed", string(req.Kind), strings.Join(targets, ","), stmt.ID, "success", "detection policy change "+stmt.Digest)
		return nil, nil
	}
	if manifestApproval(req.Kind, payload) {
		if err := a.applyCapabilityApproval(req.TenantID, stmt, payload); err != nil {
			a.auditApproval(req.TenantID, requester, "manifest_refused", string(req.Kind), strings.Join(targets, ","), stmt.ID, "denied", err.Error())
			return nil, err
		}
	}
	priv, keyID, err := a.tenantSigningKey(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := grantTTL(req.Kind, req.TTLSeconds)
	issued := now.Unix()
	if enforcementKind(req.Kind) {
		if issued, err = a.enfClock.next(req.TenantID, now); err != nil {
			return nil, err
		}
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
			IssuedAt:          issued,
			ExpiresAt:         issued + ttl,
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

// learnFrom counts the owner's passkey approval of a job shape, or forgets
// the shape on any denial (approval_learned.go).
func (a *Authority) learnFrom(v ApprovalView, shape, method, approverID string, now time.Time) {
	if shape == "" {
		return
	}
	if v.State == ApprovalDenied {
		if forgot, err := a.learned.forget(v.TenantID, shape); err != nil {
			a.auditApproval(v.TenantID, v.Requester, "approval_learned_not_saved", v.Kind, "", v.ID, "error", err.Error())
		} else if len(forgot) > 0 {
			a.auditApproval(v.TenantID, v.Requester, "approval_learned_forgotten", v.Kind, strings.Join(v.Targets, ","), v.ID, "success",
				"the owner denied a job shape that was approved without asking; it asks again (shape "+shape+")")
		}
		return
	}
	if method != "passkey" {
		return
	}
	became, err := a.learned.approve(v.TenantID, LearnedShape{Shape: shape, Kind: v.Kind, Action: v.Action, Targets: v.Targets, Approver: approverID}, now)
	if err != nil {
		a.auditApproval(v.TenantID, v.Requester, "approval_learned_not_saved", v.Kind, "", v.ID, "error", err.Error())
	} else if became {
		a.auditApproval(v.TenantID, v.Requester, "approval_learned", v.Kind, strings.Join(v.Targets, ","), v.ID, "success",
			fmt.Sprintf("the owner approved this exact job %d times with no denial; it runs without asking from now on (shape %s; any denial or the owner's undo ends it)", learnedAfter, shape))
	}
}
