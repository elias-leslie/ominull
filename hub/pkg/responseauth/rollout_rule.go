package responseauth

// "Approve all like this" for agent rollouts. One owner passkey tap on an
// agent update ask, with the decision "rule" (the passkey signs
// sha256(challenge ":rule"), never valid as a plain approve), stores a
// standing rule for that tenant. While it lives, an agent update request is
// approved here without asking, but only when:
//
//   - it is the /api/v1/agents/update route (kind agent_update) and nothing else;
//   - every agent package of the version it installs (the Linux deb and the
//     Windows MSI) carries a release statement (OMINULL-RELEASE-V1, package,
//     version, sha256) whose signature verifies under the release key compiled
//     into this authority, the same key agents pin: the owner signed it. A
//     release signed with any other key (a rotation release, signed with the
//     outgoing key) or unsigned is asked for as before;
//   - it is staged: a request covering more than one endpoint names canaries,
//     so the hub still installs on those first and halts on a bad canary.
//   - its version is not older than the newest the rule already approved;
//     only a newer one counts as use (keeps the rule alive), so requests that
//     install nothing new cannot extend it.
//
// Canaries guard against a bad release, not against a hostile hub (it may ask
// for one endpoint at a time, and it releases held grants itself); against
// the hub the bound is that agents install only packages signed with the
// release key. A rotation release is not covered because the authority ships
// in the same hub package as the agents it serves and so already pins the new
// key when one is installed.
//
// Signing, trust bundles, key rotation, detection-policy changes, isolation,
// mesh quarantine, capabilities, terminals and enrolment are never covered:
// their kinds never match and are never offered a rule.
//
// Like Nightshift's learned rules (executor/budget.py, quiet.idle_until), a
// rule ends rolloutRuleIdle after it was made or last used, a week with far
// more rollouts than usual is flagged, every rollout it approves leaves an
// audit row here (approval_auto_approved) and on the hub
// (OWNER_APPROVAL_AUTO), and anyone with the hub's admin key may remove it
// (removing only narrows).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/response"
)

const (
	rolloutRuleIdle  = 90 * 24 * time.Hour
	rolloutRuleOffer = "rollouts" // ApprovalStatement.Offer: the ask offers the rule
	rolloutRoute     = "/api/v1/agents/update"
	// A week counts as busy at five times the usual weekly rollouts and at
	// least this many (releases are rare; Nightshift's floor of ten fits
	// commands, not releases).
	rolloutSpikeRatio   = 5.0
	rolloutSpikeMinimum = 3
)

var releaseVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ReleaseEvidence is one signed agent package of the release an agent update
// installs, as the hub publishes it: name, digest and the release signature
// over the statement that binds them to the version.
type ReleaseEvidence struct {
	Package string `json:"package"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"` // base64 DER ECDSA P-256 / SHA-256
}

// RolloutRule is one tenant's standing approval for owner-signed rollouts.
type RolloutRule struct {
	TenantID   string `json:"tenant_id"`
	Created    int64  `json:"created"`
	LastUsed   int64  `json:"last_used,omitempty"`
	ApproverID string `json:"approver_id"`
	ApprovalID string `json:"approval_id"`
	// Version is the newest release the rule approved. An older one is
	// asked for, and only a newer one counts as use, so requests that
	// install nothing new cannot keep the rule alive.
	Version string         `json:"version,omitempty"`
	Days    map[string]int `json:"days,omitempty"` // UTC day -> rollouts approved
}

// RolloutRuleView is a rule as the hub shows it.
type RolloutRuleView struct {
	TenantID   string    `json:"tenant_id"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	EndsAt     time.Time `json:"ends_at"`
	Week       int       `json:"week"`
	Spike      bool      `json:"spike"`
	ApproverID string    `json:"approver_id"`
}

const rolloutRuleLabel = "Agent rollouts of releases the owner signed (canaries first)"

type rolloutRules struct {
	mu    sync.Mutex
	path  string
	items map[string]*RolloutRule
	err   error
}

func newRolloutRules(stateDir string) *rolloutRules {
	b := &rolloutRules{items: map[string]*RolloutRule{}}
	if stateDir == "" {
		return b
	}
	b.path = filepath.Join(stateDir, "rollout_rules.json")
	raw, err := os.ReadFile(b.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		b.err = fmt.Errorf("rollout rules unreadable: %w", err)
	default:
		if json.Unmarshal(raw, &b.items) != nil || b.items == nil {
			// Unreadable rules approve nothing: every rollout asks.
			b.err = fmt.Errorf("rollout rules file %s is corrupt", b.path)
			b.items = map[string]*RolloutRule{}
		}
	}
	return b
}

func (b *rolloutRules) saveLocked(items map[string]*RolloutRule) error {
	if b.path == "" {
		return nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return writeDurable(b.path, raw)
}

func ruleEnds(r *RolloutRule) time.Time {
	last := r.Created
	if r.LastUsed > last {
		last = r.LastUsed
	}
	return time.Unix(last, 0).Add(rolloutRuleIdle)
}

func ruleLive(r *RolloutRule, now time.Time) bool {
	return r != nil && now.Before(ruleEnds(r))
}

// cloneRules copies the map with r replacing tenant's entry (nil removes it),
// so a failed write leaves the live set unchanged.
func (b *rolloutRules) cloneWith(tenant string, r *RolloutRule) map[string]*RolloutRule {
	out := make(map[string]*RolloutRule, len(b.items)+1)
	for k, v := range b.items {
		out[k] = v
	}
	if r == nil {
		delete(out, tenant)
	} else {
		out[tenant] = r
	}
	return out
}

// use records that tenant's live rule approved a rollout of version now. It
// reports false (ask instead) when there is no live rule, the version is
// older than one the rule already approved, or the use cannot be saved. The
// same version again (hosts that were offline) is approved without counting.
func (b *rolloutRules) use(tenant, version string, now time.Time) (RolloutRule, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.items[tenant]
	if b.err != nil || !ruleLive(cur, now) {
		return RolloutRule{}, false
	}
	switch c := compareRelease(version, cur.Version); {
	case c < 0:
		return RolloutRule{}, false
	case c == 0:
		return *cur, true
	}
	next := *cur
	next.Version = version
	next.LastUsed = now.Unix()
	next.Days = map[string]int{}
	for d, n := range cur.Days {
		next.Days[d] = n
	}
	next.Days[now.UTC().Format("2006-01-02")]++
	days := make([]string, 0, len(next.Days))
	for d := range next.Days {
		days = append(days, d)
	}
	sort.Strings(days)
	for len(days) > 35 { // this week and the four the spike flag compares it with
		delete(next.Days, days[0])
		days = days[1:]
	}
	items := b.cloneWith(tenant, &next)
	if err := b.saveLocked(items); err != nil {
		return RolloutRule{}, false
	}
	b.items = items
	return next, true
}

func (b *rolloutRules) create(r *RolloutRule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	items := b.cloneWith(r.TenantID, r)
	if err := b.saveLocked(items); err != nil {
		return err
	}
	b.items = items
	return nil
}

func (b *rolloutRules) live(tenant string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err == nil && ruleLive(b.items[tenant], now)
}

// spike: this week's rollouts at least rolloutSpikeRatio times the weekly
// average of up to four weeks before it (only weeks the rule existed), and
// at least rolloutSpikeMinimum (Nightshift quiet.spike).
func ruleWeek(r *RolloutRule, now time.Time) (int, bool) {
	day := func(n int) string { return now.Add(-time.Duration(n) * 24 * time.Hour).UTC().Format("2006-01-02") }
	week := 0
	for n := 0; n < 7; n++ {
		week += r.Days[day(n)]
	}
	weeksBefore := int(now.Sub(time.Unix(r.Created, 0))/(7*24*time.Hour)) - 1
	if weeksBefore > 4 {
		weeksBefore = 4
	}
	if week < rolloutSpikeMinimum || weeksBefore < 1 {
		return week, false
	}
	before := 0
	for n := 7; n < 7+7*weeksBefore; n++ {
		before += r.Days[day(n)]
	}
	avg := float64(before) / float64(weeksBefore)
	if avg < 1 {
		avg = 1
	}
	return week, float64(week) >= rolloutSpikeRatio*avg
}

func ruleView(r *RolloutRule, now time.Time) RolloutRuleView {
	week, spike := ruleWeek(r, now)
	v := RolloutRuleView{TenantID: r.TenantID, Label: rolloutRuleLabel, CreatedAt: time.Unix(r.Created, 0).UTC(),
		EndsAt: ruleEnds(r).UTC(), Week: week, Spike: spike, ApproverID: r.ApproverID}
	if r.LastUsed > 0 {
		v.LastUsedAt = time.Unix(r.LastUsed, 0).UTC()
	}
	return v
}

// RolloutRules lists the live rules (one tenant's, or every tenant's for "").
// Rules past their idle end are dropped.
func (a *Authority) RolloutRules(tenantID string) ([]RolloutRuleView, error) {
	b := a.rollouts
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return nil, b.err
	}
	out := []RolloutRuleView{}
	var gone []string
	for t, r := range b.items {
		if !ruleLive(r, now) {
			gone = append(gone, t)
			continue
		}
		if tenantID == "" || t == tenantID {
			out = append(out, ruleView(r, now))
		}
	}
	if len(gone) > 0 {
		items := b.cloneWith("", nil)
		for _, t := range gone {
			delete(items, t)
		}
		if b.saveLocked(items) == nil {
			b.items = items
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

// ForgetRolloutRule removes a tenant's rule. Removing only narrows, so the
// hub's admin key is enough; it reports whether there was one.
func (a *Authority) ForgetRolloutRule(tenantID, by string) (bool, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	b := a.rollouts
	b.mu.Lock()
	_, had := b.items[tenantID]
	if !had {
		b.mu.Unlock()
		return false, nil
	}
	items := b.cloneWith(tenantID, nil)
	if err := b.saveLocked(items); err != nil {
		b.mu.Unlock()
		return false, err
	}
	b.items = items
	b.mu.Unlock()
	a.auditApproval(tenantID, cleanText(by, 80), "rollout_rule_removed", string(ActionKindAgentUpdate), "", "", "success", "approve-all rule for owner-signed agent rollouts removed")
	return true, nil
}

// SetReleaseKey replaces the pinned release public key (tests).
func (a *Authority) SetReleaseKey(pem []byte) {
	a.mu.Lock()
	a.releaseKey = append([]byte(nil), pem...)
	a.mu.Unlock()
}

func (a *Authority) releasePublicKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.releaseKey) > 0 {
		return a.releaseKey
	}
	return []byte(response.ReleasePublicKeyPEM)
}

// ReleaseStatement is what the release key signs for one package
// (scripts/sign-release.sh; agents rebuild it byte for byte).
func ReleaseStatement(pkg, version, sha string) string {
	return fmt.Sprintf("OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n", pkg, version, sha)
}

// compareRelease orders X.Y.Z versions; an empty or malformed one is lowest.
func compareRelease(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		if !releaseVersionRE.MatchString(v) {
			return [3]int{-1, -1, -1}
		}
		_, _ = fmt.Sscanf(v, "%d.%d.%d", &out[0], &out[1], &out[2])
		return out
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// rolloutVersion is the release version an agent update payload installs.
func rolloutVersion(payload []byte) string {
	var p routedPayload
	var body struct {
		Version string `json:"version"`
	}
	if decodeJSON(payload, &p) != nil || p.Route != rolloutRoute || decodeJSON(p.Body, &body) != nil {
		return ""
	}
	return body.Version
}

// rolloutRuleCovers says why an approval request is not one a rollout rule
// may approve, or returns the evidence note and version when it is: an agent
// update of an owner-signed release, staged when it covers more than one
// endpoint. Only kind, payload and release evidence are read; the summary the
// hub wrote is not.
func (a *Authority) rolloutRuleCovers(in *ApprovalRequestInput, targets []string) (string, string, error) {
	if in.Kind != ActionKindAgentUpdate {
		return "", "", errors.New("not an agent rollout")
	}
	var p routedPayload
	if err := decodeJSON(in.Payload, &p); err != nil || p.Route != rolloutRoute {
		return "", "", errors.New("not the agent rollout route")
	}
	var body struct {
		Version string   `json:"version"`
		Canary  []string `json:"canary"`
	}
	if err := decodeJSON(p.Body, &body); err != nil || !releaseVersionRE.MatchString(body.Version) {
		return "", "", errors.New("the rollout names no release version")
	}
	if len(targets) > 1 && len(sortedUnique(body.Canary)) == 0 {
		return "", "", errors.New("a rollout to more than one endpoint must be staged with canaries")
	}
	want := map[string]bool{
		"ominull-agent_" + body.Version + "_amd64.deb":   false,
		"ominull-agent-windows-" + body.Version + ".msi": false,
	}
	if len(in.Release) != len(want) {
		return "", "", errors.New("the release evidence must cover every agent package of the version")
	}
	pub := a.releasePublicKey()
	var parts []string
	for _, ev := range in.Release {
		seen, ok := want[ev.Package]
		if !ok || seen {
			return "", "", fmt.Errorf("release evidence names an unexpected package %q", cleanText(ev.Package, 80))
		}
		want[ev.Package] = true
		sha := strings.ToLower(ev.SHA256)
		if b, err := hex.DecodeString(sha); err != nil || len(b) != sha256.Size {
			return "", "", fmt.Errorf("%s: digest is not SHA-256", ev.Package)
		}
		der, err := base64.StdEncoding.DecodeString(ev.Sig)
		if err != nil || len(der) == 0 || len(der) > 512 {
			return "", "", fmt.Errorf("%s: release signature unreadable", ev.Package)
		}
		if err := response.VerifyReleaseSignature(pub, []byte(ReleaseStatement(ev.Package, body.Version, sha)), der); err != nil {
			return "", "", fmt.Errorf("%s %s is not signed with the pinned release key", ev.Package, body.Version)
		}
		parts = append(parts, ev.Package+"="+sha[:16])
	}
	sort.Strings(parts)
	return "release " + body.Version + " owner-signed (" + strings.Join(parts, ", ") + ")", body.Version, nil
}
