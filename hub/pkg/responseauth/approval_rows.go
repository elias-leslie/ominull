package responseauth

// Approval rows: the owner's choices on Nightshift's Approvals page for
// OmniNull's asks (auto | session | ask, one per row). Nightshift is the one
// place the owner edits them and pushes them here; the authority keeps only
// the last set it accepted, to decide by, and its built-in defaults until it
// has one. A save that loosens anything against what the authority holds
// needs the owner's tap on an approval of kind approval_rules, which this
// authority signs with the rows, session and lab list it binds (Nightshift's
// root checks the signed fields before the owner signs), spent once by the
// save it names. Neither the hub nor a replayed save can loosen them.
// Tightening needs nothing. Some asks never follow a row
// (rowFor: locked always-ask).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
)

const (
	RowAuto          = "auto"
	RowChoiceSession = "session"
	RowAsk           = "ask"

	// ApprovalKindRules is the statement kind of a rows save the owner taps.
	ApprovalKindRules = "approval_rules"
	rowsTarget        = "approval-rules"
	rowsAskTTL        = 15 * time.Minute
	rowsMaxLab        = 64
	rowsMaxSession    = 7 * 24 * time.Hour
	// rowsAutoPerHour bounds what rows approve without asking, per tenant: a
	// runaway caller falls back to asking (and its rate limit) past it.
	rowsAutoPerHour = 120
)

// approvalRowDefaults are the rows before the owner saves any: the same
// defaults as Nightshift's Approvals page.
var approvalRowDefaults = map[string]string{
	"ominull.agent_update":    RowAuto,
	"ominull.maintenance.in":  RowAuto,
	"ominull.maintenance.out": RowChoiceSession,
	"ominull.security.in":     RowAuto,
	"ominull.security.out":    RowChoiceSession,
	"ominull.reboot.in":       RowAuto,
	"ominull.reboot.out":      RowChoiceSession,
	"ominull.remote.lab":      RowAuto,
	"ominull.remote.people":   RowAsk,
	"ominull.capability":      RowAsk,
	"ominull.isolation":       RowAsk,
	"ominull.other":           RowAsk,
}

var rowRank = map[string]int{RowAsk: 0, RowChoiceSession: 1, RowAuto: 2}

// RowSession is the owner's open session on Nightshift: "session" rows are
// auto while it is open.
type RowSession struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (s *RowSession) open(now time.Time) bool {
	return s != nil && !now.Before(s.Start) && now.Before(s.End)
}

// ApprovalRowsInput is a save pushed by Nightshift (and the body of an ask
// for the owner's tap, without approval_id).
type ApprovalRowsInput struct {
	TenantID   string            `json:"tenant_id"`
	Rows       map[string]string `json:"rows"`
	Session    *RowSession       `json:"session"`
	Lab        []string          `json:"lab"`
	SavedAt    string            `json:"saved_at,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"` // the approved approval_rules ask this save spends
}

// ApprovalRows is the set the authority holds.
type ApprovalRows struct {
	Rows       map[string]string `json:"rows"` // every row id
	Session    *RowSession       `json:"session,omitempty"`
	Lab        []string          `json:"lab,omitempty"`
	SavedAt    string            `json:"saved_at,omitempty"`
	AcceptedAt time.Time         `json:"accepted_at"`
	ApproverID string            `json:"approver_id,omitempty"` // whose assertion last loosened them
}

// ApprovalRowsView is what the authority holds, for Nightshift's page.
type ApprovalRowsView struct {
	Rows        map[string]string `json:"rows"`
	Session     *RowSession       `json:"session,omitempty"`
	SessionOpen bool              `json:"session_open"`
	Lab         []string          `json:"lab"`
	SavedAt     string            `json:"saved_at,omitempty"`
	AcceptedAt  *time.Time        `json:"accepted_at,omitempty"`
	ApproverID  string            `json:"approver_id,omitempty"`
	Stored      bool              `json:"stored"` // false: the built-in defaults
	Defaults    map[string]string `json:"defaults"`
	Error       string            `json:"error,omitempty"`
}

// ApprovalRowsAsk is the owner's tap a loosening save needs: a pending
// approval of kind approval_rules (nil when the save loosens nothing).
type ApprovalRowsAsk struct {
	Approval *ApprovalView `json:"approval,omitempty"`
	Looser   []string      `json:"looser"`
}

// ApprovalRowsResult answers a save.
type ApprovalRowsResult struct {
	Accepted bool             `json:"accepted"`
	Looser   []string         `json:"looser"`
	Rows     ApprovalRowsView `json:"rows"`
}

// ErrInvalidRows: the save or ask names an unknown row, choice, session or
// lab entry.
var ErrInvalidRows = errors.New("invalid approval rules")

// ErrRowsNeedApproval: the save loosens rows and names no approved
// approval_rules ask for exactly it.
var ErrRowsNeedApproval = errors.New("this save loosens approval rules: it needs the owner's tap on an approval_rules ask for exactly these rows (POST the challenge step, then save with its approval_id once approved)")

type approvalRowsBook struct {
	mu    sync.Mutex
	path  string
	items map[string]*ApprovalRows // tenant -> accepted rows
	err   error
	spent map[string][]time.Time // tenant -> row approvals this hour
	off   bool                   // rows switched off (UseApprovalRows): asks behave as before rows
}

// UseApprovalRows switches the rows on (the default) or off; off, asks are
// decided as before rows existed (tests of the approve-all rules).
func (a *Authority) UseApprovalRows(on bool) {
	a.rows.mu.Lock()
	a.rows.off = !on
	a.rows.mu.Unlock()
}

func newApprovalRowsBook(stateDir string) *approvalRowsBook {
	b := &approvalRowsBook{items: map[string]*ApprovalRows{}, spent: map[string][]time.Time{}}
	if stateDir == "" {
		return b
	}
	b.path = filepath.Join(stateDir, "approval_rows.json")
	raw, err := os.ReadFile(b.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		b.err = fmt.Errorf("approval rows unreadable: %w", err)
	default:
		if json.Unmarshal(raw, &b.items) != nil || b.items == nil {
			// Unreadable rows approve nothing: every ask goes to the owner
			// until a new save replaces the file.
			b.err = fmt.Errorf("approval rows file %s is corrupt", b.path)
			b.items = map[string]*ApprovalRows{}
		}
	}
	return b
}

func tenantOrDefault(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// heldLocked is what decides now: the accepted rows, the defaults when none
// were saved, or nothing at all (every row ask) when the file is unreadable.
func (b *approvalRowsBook) heldLocked(tenant string) (ApprovalRows, bool) {
	if r, ok := b.items[tenant]; ok && r != nil {
		return *r, true
	}
	rows := map[string]string{}
	for id, c := range approvalRowDefaults {
		rows[id] = c
		if b.err != nil {
			rows[id] = RowAsk
		}
	}
	return ApprovalRows{Rows: rows}, false
}

// stored says rows were accepted for the tenant: the old approve-all rules
// are no longer consulted or offered.
func (b *approvalRowsBook) stored(tenant string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.off {
		return false
	}
	_, ok := b.items[tenantOrDefault(tenant)]
	return ok || b.err != nil
}

// normalizeRows checks a save and fills the rows it leaves out with their
// defaults.
func normalizeRows(in *ApprovalRowsInput) (ApprovalRows, error) {
	out := ApprovalRows{Rows: map[string]string{}, SavedAt: cleanText(in.SavedAt, 40)}
	for id, c := range in.Rows {
		if _, ok := approvalRowDefaults[id]; !ok {
			return out, fmt.Errorf("unknown approval row %q", cleanText(id, 48))
		}
		if _, ok := rowRank[c]; !ok {
			return out, fmt.Errorf("approval row %s: choice must be auto, session or ask", id)
		}
		out.Rows[id] = c
	}
	for id, c := range approvalRowDefaults {
		if _, ok := out.Rows[id]; !ok {
			out.Rows[id] = c
		}
	}
	if s := in.Session; s != nil {
		if s.Start.IsZero() || s.End.IsZero() || !s.End.After(s.Start) || s.End.Sub(s.Start) > rowsMaxSession {
			return out, errors.New("session needs a start before its end, at most 7 days apart")
		}
		out.Session = &RowSession{Start: s.Start.UTC().Truncate(time.Second), End: s.End.UTC().Truncate(time.Second)}
	}
	lab := sortedUnique(in.Lab)
	if len(lab) > rowsMaxLab {
		return out, fmt.Errorf("at most %d lab machines", rowsMaxLab)
	}
	for _, id := range lab {
		if id == "" || len(id) > 128 || cleanText(id, 128) != id {
			return out, fmt.Errorf("invalid lab machine %q", cleanText(id, 48))
		}
	}
	out.Lab = lab
	return out, nil
}

// canonRows is the exact content a challenge binds.
func canonRows(tenant string, r ApprovalRows) string {
	ids := make([]string, 0, len(r.Rows))
	for id := range r.Rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var sb strings.Builder
	sb.WriteString("tenant=" + tenant + "\n")
	for _, id := range ids {
		sb.WriteString(id + "=" + r.Rows[id] + "\n")
	}
	if r.Session != nil {
		sb.WriteString("session=" + r.Session.Start.Format(time.RFC3339) + "/" + r.Session.End.Format(time.RFC3339) + "\n")
	} else {
		sb.WriteString("session=none\n")
	}
	sb.WriteString("lab=" + strings.Join(r.Lab, ",") + "\n")
	return sb.String()
}

// rowsLooser lists what next allows that cur does not: rows ranked higher,
// a session opened or lengthened, lab machines added while lab rows are
// looser than people rows.
func rowsLooser(cur, next ApprovalRows) []string {
	var out []string
	for id, c := range next.Rows {
		if rowRank[c] > rowRank[cur.Rows[id]] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if s := next.Session; s != nil && (cur.Session == nil || s.Start.Before(cur.Session.Start) || s.End.After(cur.Session.End)) {
		out = append(out, "session")
	}
	if rowRank[next.Rows["ominull.remote.lab"]] > rowRank[next.Rows["ominull.remote.people"]] {
		had := map[string]bool{}
		for _, id := range cur.Lab {
			had[id] = true
		}
		for _, id := range next.Lab {
			if !had[id] {
				out = append(out, "lab")
				break
			}
		}
	}
	return out
}

// AskApprovalRows asks the owner to approve a save that loosens rows: a
// pending approval of kind approval_rules whose signed statement carries the
// rows, session and lab list, relayed like any approval. A save that loosens
// nothing needs no ask (Approval nil).
func (a *Authority) AskApprovalRows(in *ApprovalRowsInput) (*ApprovalRowsAsk, error) {
	if in == nil {
		return nil, errors.New("missing rows")
	}
	tenant := tenantOrDefault(in.TenantID)
	next, err := normalizeRows(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRows, err)
	}
	a.rows.mu.Lock()
	cur, _ := a.rows.heldLocked(tenant)
	a.rows.mu.Unlock()
	looser := rowsLooser(cur, next)
	if len(looser) == 0 {
		return &ApprovalRowsAsk{Looser: []string{}}, nil
	}
	if _, err := a.approvalsReady(); err != nil {
		return nil, err
	}
	canon := canonRows(tenant, next)
	digest := sha256.Sum256([]byte(canon))
	parts := make([]string, 0, len(looser))
	for _, id := range looser {
		switch id {
		case "session":
			parts = append(parts, "session open "+next.Session.Start.Format("Jan 2 15:04")+" to "+next.Session.End.Format("Jan 2 15:04")+" UTC")
		case "lab":
			parts = append(parts, "lab machines "+strings.Join(next.Lab, ", "))
		default:
			parts = append(parts, strings.TrimPrefix(id, "ominull.")+": "+next.Rows[id])
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	now := time.Now()
	stmt := ApprovalStatement{
		V: 1, ID: hex.EncodeToString(idBytes), TenantID: tenant, Requester: "nightshift (approval rules)", Kind: ApprovalKindRules,
		Action:  "Change OmniNull approval rules",
		Summary: cleanText("Runs without asking from now on: "+strings.Join(parts, "; "), approvalMaxSummary),
		Targets: []string{rowsTarget}, Digest: hex.EncodeToString(digest[:]),
		Created: now.Unix(), Expires: now.Add(rowsAskTTL).Unix(),
		Rows: next.Rows, Session: next.Session, Lab: append([]string{}, next.Lab...),
	}
	v, err := a.recordAsk(stmt, []byte(canon), now)
	if err != nil {
		return nil, err
	}
	a.auditApproval(tenant, stmt.Requester, "approval_requested", ApprovalKindRules, rowsTarget, stmt.ID, "success", stmt.Action+": "+stmt.Summary)
	return &ApprovalRowsAsk{Approval: v, Looser: looser}, nil
}

// SetApprovalRows accepts a save: at once when it loosens nothing, else only
// by spending the approved approval_rules ask for exactly it.
func (a *Authority) SetApprovalRows(in *ApprovalRowsInput) (*ApprovalRowsResult, error) {
	if in == nil {
		return nil, errors.New("missing rows")
	}
	tenant := tenantOrDefault(in.TenantID)
	next, err := normalizeRows(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRows, err)
	}
	now := time.Now()
	b := a.rows
	b.mu.Lock()
	cur, _ := b.heldLocked(tenant)
	b.mu.Unlock()
	looser := rowsLooser(cur, next)
	approverID := cur.ApproverID
	if len(looser) > 0 {
		id, err := a.spendRowsApproval(tenant, in.ApprovalID, canonRows(tenant, next), now)
		if err != nil {
			return &ApprovalRowsResult{Looser: looser, Rows: a.ApprovalRowsView(tenant)}, err
		}
		approverID = id
	}
	next.AcceptedAt = now.UTC().Truncate(time.Second)
	next.ApproverID = approverID
	b.mu.Lock()
	items := make(map[string]*ApprovalRows, len(b.items)+1)
	for t, r := range b.items {
		items[t] = r
	}
	saved := next
	items[tenant] = &saved
	if b.path != "" {
		raw, err := json.Marshal(items)
		if err == nil {
			err = writeDurable(b.path, raw)
		}
		if err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("approval rows not saved: %w", err)
		}
	}
	b.items, b.err = items, nil
	b.mu.Unlock()
	stricter := rowsLooser(next, cur)
	if looser == nil {
		looser = []string{}
	}
	if len(looser) > 0 || len(stricter) > 0 {
		a.auditApproval(tenant, "nightshift", "approval_rows_saved", ApprovalKindRules, rowsTarget, in.ApprovalID, "success",
			fmt.Sprintf("approval rules saved by Nightshift (saved %s): looser %v (owner %s), stricter %v", next.SavedAt, looser, approverID, stricter))
	}
	return &ApprovalRowsResult{Accepted: true, Looser: looser, Rows: a.ApprovalRowsView(tenant)}, nil
}

// ApprovalRowsView shows what decides now.
func (a *Authority) ApprovalRowsView(tenant string) ApprovalRowsView {
	tenant = tenantOrDefault(tenant)
	b := a.rows
	b.mu.Lock()
	defer b.mu.Unlock()
	r, stored := b.heldLocked(tenant)
	v := ApprovalRowsView{Rows: r.Rows, Session: r.Session, SessionOpen: r.Session.open(time.Now()), Lab: r.Lab, SavedAt: r.SavedAt,
		ApproverID: r.ApproverID, Stored: stored, Defaults: approvalRowDefaults}
	if v.Lab == nil {
		v.Lab = []string{}
	}
	if stored {
		t := r.AcceptedAt
		v.AcceptedAt = &t
	}
	if b.err != nil {
		v.Error = b.err.Error() + "; every ask goes to the owner until Nightshift saves the rows again"
	}
	return v
}

// allows says the row lets an ask through without the owner now, and spends
// one of the hour's row approvals if so.
func (b *approvalRowsBook) allows(tenant, row string, now time.Time) (string, bool) {
	tenant = tenantOrDefault(tenant)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.off {
		return "", false
	}
	r, _ := b.heldLocked(tenant)
	choice := r.Rows[row]
	if choice != RowAuto && !(choice == RowChoiceSession && r.Session.open(now)) {
		return choice, false
	}
	recent := b.spent[tenant][:0]
	for _, t := range b.spent[tenant] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rowsAutoPerHour {
		b.spent[tenant] = recent
		return choice, false
	}
	b.spent[tenant] = append(recent, now)
	return choice, true
}

func (b *approvalRowsBook) approver(tenant string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, stored := b.heldLocked(tenantOrDefault(tenant))
	if !stored {
		return "defaults"
	}
	return r.ApproverID
}

func (b *approvalRowsBook) lab(tenant string) map[string]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, _ := b.heldLocked(tenantOrDefault(tenant))
	out := map[string]bool{}
	for _, id := range r.Lab {
		out[id] = true
	}
	return out
}

// ApprovalFacts are what the hub knows about the targets from their agents'
// trust reports, for picking a row: each one's clock offset (maintenance
// windows are in machine time) and which carry a lock set on the host.
type ApprovalFacts struct {
	UTCOffsets map[string]int `json:"utc_offsets,omitempty"` // minutes east of UTC
	Locked     []string       `json:"locked,omitempty"`
}

// RowInputs are what picked an ask's row, signed into its statement so
// Nightshift can name the row: every target on the lab list, the packages'
// category, a restart step, and every target inside its maintenance window.
type RowInputs struct {
	Lab      bool   `json:"lab"`
	Category string `json:"category,omitempty"` // maintenance | security (package runs)
	Reboot   bool   `json:"reboot"`
	InWindow bool   `json:"in_window"`
}

// rowFor names the row an ask follows, or "" with the reason when it always
// asks the owner, and what picked it.
func (a *Authority) rowFor(in *ApprovalRequestInput, targets []string, now time.Time) (string, string, RowInputs) {
	var ri RowInputs
	labSet := a.rows.lab(in.TenantID)
	ri.Lab = len(targets) > 0
	for _, t := range targets {
		ri.Lab = ri.Lab && labSet[t]
	}
	row, why := a.rowForKind(in, targets, now, &ri)
	return row, why, ri
}

func (a *Authority) rowForKind(in *ApprovalRequestInput, targets []string, now time.Time, ri *RowInputs) (string, string) {
	locked := map[string]bool{}
	if in.Facts != nil {
		for _, id := range in.Facts.Locked {
			locked[id] = true
		}
	}
	anyLocked := false
	for _, t := range targets {
		anyLocked = anyLocked || locked[t]
	}
	if in.Kind == ActionKindAgentUpdate {
		if _, _, err := a.rolloutRuleCovers(in, targets); err == nil {
			return "ominull.agent_update", ""
		}
		if anyLocked {
			return "", "an agent update that is not an owner-signed release, on a host-locked machine"
		}
		return "ominull.other", ""
	}
	if anyLocked {
		return "", "a host-locked machine always asks"
	}
	remote := func() string {
		if ri.Lab {
			return "ominull.remote.lab"
		}
		return "ominull.remote.people"
	}
	switch in.Kind {
	case response.ActionKindTerminalSession:
		return remote(), ""
	case response.ActionKindScreenSession:
		if in.StewardRule != nil || in.StewardRun != "" || IsStewardRequester(cleanText(in.Requester, 80)) {
			return "", "the steward's screen follows its own rule"
		}
		return remote(), ""
	case response.ActionKindScriptExec:
		return rowForRun(in, targets, now, remote, ri)
	case ActionKindIsolation, ActionKindMesh:
		var p routedPayload
		if json.Unmarshal(in.Payload, &p) == nil && p.Route == "/api/v1/endpoints/allow-isolation" {
			return "ominull.capability", ""
		}
		return "ominull.isolation", ""
	case ActionKindCapability:
		return "ominull.capability", ""
	case ActionKindDetection:
		var p detectionPolicyPayload
		if json.Unmarshal(in.Payload, &p) != nil {
			return "", "unreadable detection change"
		}
		if p.Drill != nil && len(*p.Drill) > 0 {
			return "", "the change blinds a floor case, or its drill could not run"
		}
		switch p.Policy {
		case "enrolment_window":
			return "", "opening LAN self-enrolment lets a new agent onto a person's machine"
		case "terminal_limits", "screen_ask_first", "remote_access", "software_catalog":
			return "ominull.capability", ""
		}
		return "ominull.other", ""
	}
	return "ominull.other", ""
}

// rowForRun: released packages by category and restart, in or out of every
// target's window; anything else is remote code.
func rowForRun(in *ApprovalRequestInput, targets []string, now time.Time, remote func() string, ri *RowInputs) (string, string) {
	if oneOffOf(in.Payload) != nil {
		return remote(), ""
	}
	items, _, err := parsePackageRunPayload(in.Payload, targets)
	if err != nil || len(items) == 0 {
		return "", "unreadable package run"
	}
	kind, auditOnly, in_ := "maintenance", true, true
	for _, it := range items {
		if it.Header == nil {
			return remote(), ""
		}
		if it.Risk == "careful" && it.Header.Role != scripts.RoleReboot {
			return "", "careful packages and careful steps always ask"
		}
	}
	for _, it := range items {
		mode := it.Exec.Parameters["mode"]
		if mode != "audit" {
			auditOnly = false
		}
		if it.Header.Role == scripts.RoleReboot && mode == "enforce" {
			kind = "reboot"
		} else if it.Header.Category == "security" && kind != "reboot" {
			kind = "security"
		}
		if mode == "audit" {
			continue
		}
		w := it.Exec.Parameters["window"]
		for _, t := range targets {
			var off *int
			if in.Facts != nil {
				if o, ok := in.Facts.UTCOffsets[t]; ok && o >= -14*60 && o <= 14*60 {
					off = &o
				}
			}
			if !windowOpen(w, now, off) {
				in_ = false
			}
		}
	}
	if auditOnly {
		in_ = true
	}
	ri.Category, ri.Reboot, ri.InWindow = "maintenance", kind == "reboot", in_
	if kind == "security" {
		ri.Category = "security"
	}
	for _, it := range items {
		if it.Header.Category == "security" {
			ri.Category = "security"
		}
	}
	if in_ {
		return "ominull." + kind + ".in", ""
	}
	return "ominull." + kind + ".out", ""
}

// windowOpen reads a package run's window param (1-4 HH:MM-HH:MM ranges,
// machine time, or UTC with a trailing Z) against now. Machine time needs the
// machine's offset; unknown counts as closed.
func windowOpen(w string, now time.Time, offsetMin *int) bool {
	if w == "" {
		return false
	}
	t := now.UTC()
	if strings.HasSuffix(w, "Z") {
		w = strings.TrimSuffix(w, "Z")
	} else if offsetMin == nil {
		return false
	} else {
		t = t.Add(time.Duration(*offsetMin) * time.Minute)
	}
	ranges := strings.Split(w, ",")
	if len(ranges) > 4 {
		return false
	}
	n := t.Hour()*60 + t.Minute()
	for _, r := range ranges {
		s, e, ok := parseRange(r)
		if !ok {
			return false
		}
		if (s <= e && n >= s && n < e) || (s > e && (n >= s || n < e)) {
			return true
		}
	}
	return false
}

func parseRange(r string) (int, int, bool) {
	if len(r) != 11 || r[2] != ':' || r[5] != '-' || r[8] != ':' {
		return 0, 0, false
	}
	num := func(s string, max int) (int, bool) {
		v, err := strconv.Atoi(s)
		return v, err == nil && v >= 0 && v <= max && len(s) == 2
	}
	sh, ok1 := num(r[0:2], 23)
	sm, ok2 := num(r[3:5], 59)
	eh, ok3 := num(r[6:8], 23)
	em, ok4 := num(r[9:11], 59)
	if !(ok1 && ok2 && ok3 && ok4) {
		return 0, 0, false
	}
	return sh*60 + sm, eh*60 + em, true
}

// recordAsk signs and records a pending ask the authority makes itself (an
// approval_rules save), under the same pending and hourly limits as the
// hub's asks.
func (a *Authority) recordAsk(stmt ApprovalStatement, payload []byte, now time.Time) (*ApprovalView, error) {
	b := a.approvals
	b.mu.Lock()
	b.sweepLocked(now)
	pending := b.reserved[stmt.TenantID]
	for _, r := range b.items {
		if r.view.TenantID == stmt.TenantID && r.view.State == ApprovalPending {
			pending++
		}
	}
	if pending >= approvalMaxPending || len(b.created[stmt.TenantID]) >= approvalMaxPerHour {
		b.mu.Unlock()
		return nil, ErrApprovalRateLimit
	}
	b.created[stmt.TenantID] = append(b.created[stmt.TenantID], now)
	b.mu.Unlock()
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	signed := append([]byte(approvalStatementPrefix), stmtJSON...)
	priv, keyID, err := a.tenantSigningKey(stmt.TenantID)
	if err != nil {
		return nil, err
	}
	sig := ed25519Sign(priv, signed)
	ch := sha256.Sum256(signed)
	rec := &approvalRecord{
		stmt: stmt, kind: response.ActionKind(stmt.Kind), digest: stmt.Digest, payload: append([]byte(nil), payload...), createdAt: now,
		view: ApprovalView{
			ID: stmt.ID, TenantID: stmt.TenantID, State: ApprovalPending, Kind: stmt.Kind, Action: stmt.Action, Summary: stmt.Summary,
			Targets: stmt.Targets, Requester: stmt.Requester, CreatedAt: time.Unix(stmt.Created, 0).UTC(), ExpiresAt: time.Unix(stmt.Expires, 0).UTC(),
			Statement: base64Std(stmtJSON), Signature: hex.EncodeToString(sig), Challenge: hex.EncodeToString(ch[:]), SignerKey: keyID,
		},
	}
	b.mu.Lock()
	b.items[stmt.ID] = rec
	v := rec.view
	b.mu.Unlock()
	return &v, nil
}

// spendRowsApproval spends the approved approval_rules ask a save names,
// once, when it binds exactly the save's rows; it returns the approver.
func (a *Authority) spendRowsApproval(tenant, id, canon string, now time.Time) (string, error) {
	b := a.approvals
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(now)
	r, ok := b.items[id]
	if id == "" || !ok || r.view.TenantID != tenant || r.kind != ApprovalKindRules {
		return "", ErrRowsNeedApproval
	}
	sum := sha256.Sum256([]byte(canon))
	if !strings.EqualFold(r.digest, hex.EncodeToString(sum[:])) {
		return "", fmt.Errorf("%w: the approved rules differ from this save", ErrRowsNeedApproval)
	}
	switch r.view.State {
	case ApprovalApproved:
	case ApprovalPending:
		return "", fmt.Errorf("%w: the owner has not approved it yet", ErrRowsNeedApproval)
	default:
		return "", fmt.Errorf("%w: that ask is %s", ErrRowsNeedApproval, r.view.State)
	}
	if r.view.Method != "passkey" {
		return "", fmt.Errorf("%w: approved without the owner's passkey", ErrRowsNeedApproval)
	}
	r.view.State = ApprovalConsumed
	return r.view.ApproverID, nil
}

func ed25519Sign(priv ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(priv, msg) }

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
