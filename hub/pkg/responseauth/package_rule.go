package responseauth

// Maintenance package runs (kind script_exec) under owner approval, and the
// owner's "approve all like this" rule for them.
//
// The hub asks with a PackageRunPayload: the exact script payloads the agents
// will receive (each item is the JSON string an agent digests), the named
// endpoints, and the route. The authority reads everything the owner sees from
// those bytes: the package name and risk come from line 1 of each script's own
// source ("# ominull-package: {...}"), which the script digest binds. On use it
// signs one grant per endpoint and item, each bound to that item's own digest.
//
// One passkey tap with the decision "rule" on an ask that offers it stores a
// package rule. While it lives, a later request is approved here without
// asking when every item's digest is one the rule names (so the script source,
// interpreter, parameters, timeout and output bound are all the same bytes) and
// every endpoint is one the rule names. A new script version, another mode, a
// longer timeout or another host is a new digest or target and asks again.
// Only packages whose header says risk "safe" are ever offered or covered;
// "careful" packages and scripts without a package header ask every time.
//
// Like the rollout rule, a package rule ends packageRuleIdle after it was made
// or last used, every run it approves leaves an audit row here
// (approval_auto_approved) and on the hub (OWNER_APPROVAL_AUTO), and anyone
// with the hub's admin key may remove it (removing only narrows).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

const (
	// PackageRunRoute is the hub route a package run approval belongs to.
	PackageRunRoute    = "/api/v1/maintenance/run"
	packageRuleOffer   = "packages" // ApprovalStatement.Offer
	packageRuleIdle    = 90 * 24 * time.Hour
	packageMaxItems    = 10
	packageMaxGrants   = 100
	packageMaxPayload  = 512 * 1024
	packageRulesKept   = 20 // per tenant
	packageHeaderMagic = "# ominull-package:"
)

// ErrRuleNotCovered refuses a rule-only request (the hub's schedule) that no
// live package rule covers. Nothing is recorded and nobody is asked.
var ErrRuleNotCovered = errors.New("no approve-all rule covers this package run")

var packageInterpreters = map[string]bool{"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "/bin/sh": true, "/bin/bash": true}

// PackageRunPayload is what the owner approves for a script_exec run.
type PackageRunPayload struct {
	Route   string   `json:"route"`
	Items   []string `json:"items"` // each the exact ScriptExecPayload JSON an agent receives
	Targets []string `json:"targets"`
}

// PackageItem is one script payload of a run as the authority read it.
type PackageItem struct {
	Raw    string
	Digest string // sha256 of Raw: the grant's action digest
	Exec   response.ScriptExecPayload
	Name   string // package name from the source header, or the script id
	Risk   string // "safe" | "careful" | "" (no package header)
}

// Label names the item for the owner: package (mode).
func (it PackageItem) Label() string {
	if m := it.Exec.Parameters["mode"]; m != "" {
		return it.Name + " (" + m + ")"
	}
	return it.Name
}

// ItemDigest is the action digest of one script payload.
func ItemDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// packageHeader reads line 1 of a package script.
func packageHeader(source string) (name, risk string) {
	line, _, _ := strings.Cut(source, "\n")
	rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), packageHeaderMagic)
	if !ok {
		return "", ""
	}
	var h struct {
		Name string `json:"name"`
		Risk string `json:"risk"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(rest)), &h) != nil {
		return "", ""
	}
	return cleanText(h.Name, 64), h.Risk
}

// plainKeys requires one JSON value whose object keys are all lower case and
// unique within their object, so the agent and the authority cannot read
// different members out of the same bytes.
func plainKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next string token in this object is a key
	}
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(stack) == 0 {
			if values++; values > 1 {
				return errors.New("trailing data")
			}
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{object: d == '{', keys: map[string]bool{}, key: d == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top != nil && top.object && top.key {
			k, _ := tok.(string)
			if strings.ToLower(k) != k {
				return fmt.Errorf("key %q is not lower case", k)
			}
			if top.keys[k] {
				return fmt.Errorf("key %q appears twice", k)
			}
			top.keys[k] = true
			top.key = false
			continue
		}
		if top != nil && top.object {
			top.key = true
		}
	}
	if len(stack) != 0 {
		return errors.New("unterminated JSON")
	}
	return nil
}

func parsePackageItem(raw string) (PackageItem, error) {
	it := PackageItem{Raw: raw, Digest: ItemDigest(raw)}
	if err := plainKeys([]byte(raw)); err != nil {
		return it, fmt.Errorf("script payload refused: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&it.Exec); err != nil {
		return it, errors.New("script payload unreadable")
	}
	p := &it.Exec
	if p.ScriptID == "" || p.ScriptVersion <= 0 || p.Source == "" {
		return it, errors.New("script payload names no script, version or source")
	}
	if sum := sha256.Sum256([]byte(p.Source)); !strings.EqualFold(p.ScriptDigest, hex.EncodeToString(sum[:])) {
		return it, errors.New("script digest does not match its source")
	}
	if !packageInterpreters[p.Interpreter] {
		return it, fmt.Errorf("interpreter %q is not allowed", cleanText(p.Interpreter, 40))
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 3600 {
		return it, errors.New("script timeout must be 1-3600 seconds")
	}
	if p.MaxOutputBytes < 1 || p.MaxOutputBytes > 5*1024*1024 {
		return it, errors.New("script output bound must be 1 byte to 5 MiB")
	}
	for k, v := range p.Parameters {
		if cleanText(k, 64) != k || len(v) > 256 {
			return it, errors.New("script parameters are malformed")
		}
	}
	it.Name, it.Risk = packageHeader(p.Source)
	if it.Name == "" {
		it.Name = cleanText(p.ScriptID, 64)
	}
	return it, nil
}

// ParsePackageRun reads a package run payload; targets is the approval's
// sorted, de-duplicated target list.
func ParsePackageRun(payload []byte, targets []string) ([]PackageItem, error) {
	if err := plainKeys(payload); err != nil {
		return nil, fmt.Errorf("package run payload refused: %w", err)
	}
	var p PackageRunPayload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, errors.New("package run payload must carry route, items and targets")
	}
	if p.Route != PackageRunRoute {
		return nil, fmt.Errorf("route %q is not a package run", cleanText(p.Route, 80))
	}
	if strings.Join(sortedUnique(p.Targets), "\x00") != strings.Join(targets, "\x00") {
		return nil, errors.New("payload targets differ from the approval's targets")
	}
	if len(p.Items) == 0 || len(p.Items) > packageMaxItems {
		return nil, fmt.Errorf("a package run carries 1-%d scripts", packageMaxItems)
	}
	if len(p.Items)*len(targets) > packageMaxGrants {
		return nil, fmt.Errorf("a package run covers at most %d script runs", packageMaxGrants)
	}
	items := make([]PackageItem, 0, len(p.Items))
	seen := map[string]bool{}
	for _, raw := range p.Items {
		it, err := parsePackageItem(raw)
		if err != nil {
			return nil, err
		}
		if seen[it.Digest] {
			return nil, errors.New("a package run names the same script payload twice")
		}
		seen[it.Digest] = true
		items = append(items, it)
	}
	return items, nil
}

func describePackageRun(payload []byte, targets []string) (string, string, error) {
	items, err := ParsePackageRun(payload, targets)
	if err != nil {
		return "", "", err
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		s := fmt.Sprintf("%s, up to %d min", it.Label(), (it.Exec.TimeoutSeconds+59)/60)
		if it.Risk != "safe" {
			if it.Risk == "" {
				s += ", not a package"
			} else {
				s += ", " + cleanText(it.Risk, 16)
			}
		}
		parts = append(parts, s)
	}
	lead := "Run as SYSTEM on " + listTargets(targets) + ": "
	full := lead + strings.Join(parts, "; ")
	if len([]rune(full)) <= approvalMaxSummary {
		return "Run maintenance", full, nil
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Label())
	}
	return "Run maintenance", fmt.Sprintf("Run %d scripts as SYSTEM on %d host(s): %s", len(items), len(targets), strings.Join(names, ", ")), nil
}

// packageRuleCovers says whether a request is one a package rule may cover
// (every item a safe package) and returns its item digests and labels.
func packageRuleCovers(in *ApprovalRequestInput, targets []string) ([]string, []string, error) {
	if in.Kind != response.ActionKindScriptExec {
		return nil, nil, errors.New("not a package run")
	}
	items, err := ParsePackageRun(in.Payload, targets)
	if err != nil {
		return nil, nil, err
	}
	digests := make([]string, 0, len(items))
	labels := make([]string, 0, len(items))
	for _, it := range items {
		if it.Risk != "safe" {
			return nil, nil, fmt.Errorf("%s is not a safe package", it.Name)
		}
		digests = append(digests, it.Digest)
		labels = append(labels, it.Label())
	}
	sort.Strings(digests)
	return digests, labels, nil
}

// PackageRule is the owner's standing approval for runs of exact package
// payloads on named endpoints.
type PackageRule struct {
	ID         string         `json:"id"` // the approval the owner tapped
	TenantID   string         `json:"tenant_id"`
	Created    int64          `json:"created"`
	LastUsed   int64          `json:"last_used,omitempty"`
	ApproverID string         `json:"approver_id"`
	Items      []string       `json:"items"`  // item digests
	Labels     []string       `json:"labels"` // package (mode), for the owner
	Endpoints  []string       `json:"endpoints"`
	Days       map[string]int `json:"days,omitempty"`
}

func packageRuleEnds(r *PackageRule) time.Time {
	last := max(r.Created, r.LastUsed)
	return time.Unix(last, 0).Add(packageRuleIdle)
}

func (r *PackageRule) covers(digests, targets []string, now time.Time) bool {
	if !now.Before(packageRuleEnds(r)) {
		return false
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, d := range digests {
		if !has(r.Items, d) {
			return false
		}
	}
	for _, t := range targets {
		if !has(r.Endpoints, t) {
			return false
		}
	}
	return true
}

type packageRules struct {
	mu    sync.Mutex
	path  string
	items map[string][]*PackageRule
	err   error
}

func newPackageRules(stateDir string) *packageRules {
	b := &packageRules{items: map[string][]*PackageRule{}}
	if stateDir == "" {
		return b
	}
	b.path = filepath.Join(stateDir, "package_rules.json")
	raw, err := os.ReadFile(b.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		b.err = fmt.Errorf("package rules unreadable: %w", err)
	default:
		if json.Unmarshal(raw, &b.items) != nil || b.items == nil {
			// Unreadable rules approve nothing: every run asks.
			b.err = fmt.Errorf("package rules file %s is corrupt", b.path)
			b.items = map[string][]*PackageRule{}
		}
	}
	return b
}

// replaceLocked saves tenant's list and swaps it in only if the write held.
func (b *packageRules) replaceLocked(tenant string, list []*PackageRule) error {
	next := make(map[string][]*PackageRule, len(b.items)+1)
	for k, v := range b.items {
		next[k] = v
	}
	if len(list) == 0 {
		delete(next, tenant)
	} else {
		next[tenant] = list
	}
	if b.path != "" {
		raw, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := writeDurable(b.path, raw); err != nil {
			return err
		}
	}
	b.items = next
	return nil
}

// match returns the id of a live rule covering the run, without using it.
func (b *packageRules) match(tenant string, digests, targets []string, now time.Time) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return "", false
	}
	for _, r := range b.items[tenant] {
		if r.covers(digests, targets, now) {
			return r.ID, true
		}
	}
	return "", false
}

// use records that rule id approved a run now (keeps it alive).
func (b *packageRules) use(tenant, id string, digests, targets []string, now time.Time) (PackageRule, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return PackageRule{}, false
	}
	list := b.items[tenant]
	for i, r := range list {
		if r.ID != id || !r.covers(digests, targets, now) {
			continue
		}
		next := *r
		next.LastUsed = now.Unix()
		next.Days = map[string]int{}
		for d, n := range r.Days {
			next.Days[d] = n
		}
		next.Days[now.UTC().Format("2006-01-02")]++
		days := make([]string, 0, len(next.Days))
		for d := range next.Days {
			days = append(days, d)
		}
		sort.Strings(days)
		for len(days) > 35 {
			delete(next.Days, days[0])
			days = days[1:]
		}
		out := append(append([]*PackageRule{}, list[:i]...), list[i+1:]...)
		out = append(out, &next)
		if b.replaceLocked(tenant, out) != nil {
			return PackageRule{}, false
		}
		return next, true
	}
	return PackageRule{}, false
}

func (b *packageRules) create(r *PackageRule, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	out := []*PackageRule{}
	for _, x := range b.items[r.TenantID] {
		if now.Before(packageRuleEnds(x)) {
			out = append(out, x)
		}
	}
	out = append(out, r)
	sort.SliceStable(out, func(i, j int) bool { return packageRuleEnds(out[i]).Before(packageRuleEnds(out[j])) })
	if len(out) > packageRulesKept {
		out = out[len(out)-packageRulesKept:]
	}
	return b.replaceLocked(r.TenantID, out)
}

// PackageRuleView is a package rule as the hub shows it.
type PackageRuleView struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Label      string    `json:"label"`
	Packages   []string  `json:"packages"`
	Endpoints  []string  `json:"endpoints"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	EndsAt     time.Time `json:"ends_at"`
	ApproverID string    `json:"approver_id"`
}

// PackageRules lists the live package rules (one tenant's, or all for "").
func (a *Authority) PackageRules(tenantID string) ([]PackageRuleView, error) {
	b := a.packages
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return nil, b.err
	}
	out := []PackageRuleView{}
	for t, list := range b.items {
		if tenantID != "" && t != tenantID {
			continue
		}
		for _, r := range list {
			if !now.Before(packageRuleEnds(r)) {
				continue
			}
			v := PackageRuleView{ID: r.ID, TenantID: r.TenantID, Packages: r.Labels, Endpoints: r.Endpoints,
				Label:     "Maintenance packages " + strings.Join(r.Labels, ", ") + " on " + listTargets(r.Endpoints),
				CreatedAt: time.Unix(r.Created, 0).UTC(), EndsAt: packageRuleEnds(r).UTC(), ApproverID: r.ApproverID}
			if r.LastUsed > 0 {
				v.LastUsedAt = time.Unix(r.LastUsed, 0).UTC()
			}
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// ForgetPackageRule removes one package rule, or every one of the tenant's
// for id "". Removing only narrows, so the hub's admin key is enough.
func (a *Authority) ForgetPackageRule(tenantID, id, by string) (int, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	b := a.packages
	b.mu.Lock()
	list := b.items[tenantID]
	kept := []*PackageRule{}
	for _, r := range list {
		if id != "" && r.ID != id {
			kept = append(kept, r)
		}
	}
	removed := len(list) - len(kept)
	if removed == 0 {
		b.mu.Unlock()
		return 0, nil
	}
	if err := b.replaceLocked(tenantID, kept); err != nil {
		b.mu.Unlock()
		return 0, err
	}
	b.mu.Unlock()
	a.auditApproval(tenantID, cleanText(by, 80), "package_rule_removed", string(response.ActionKindScriptExec), "", id, "success",
		fmt.Sprintf("%d approve-all rule(s) for maintenance packages removed", removed))
	return removed, nil
}

// createPackageRule stores the rule the owner's "rule" tap made for an
// approved package run: exactly its item digests on exactly its endpoints.
func (a *Authority) createPackageRule(v ApprovalView, targets []string, payload []byte, approverID string, now time.Time) {
	items, err := ParsePackageRun(payload, targets)
	if err != nil {
		a.auditApproval(v.TenantID, v.Requester, "package_rule_not_saved", v.Kind, "", v.ID, "error", err.Error())
		return
	}
	rule := &PackageRule{ID: v.ID, TenantID: v.TenantID, Created: now.Unix(), ApproverID: approverID, Endpoints: append([]string(nil), targets...)}
	for _, it := range items {
		rule.Items = append(rule.Items, it.Digest)
		rule.Labels = append(rule.Labels, it.Label())
	}
	sort.Strings(rule.Items)
	if err := a.packages.create(rule, now); err != nil {
		a.auditApproval(v.TenantID, v.Requester, "package_rule_not_saved", v.Kind, "", v.ID, "error", err.Error())
		return
	}
	a.auditApproval(v.TenantID, v.Requester, "package_rule_created", v.Kind, strings.Join(targets, ","), v.ID, "success",
		"approve-all rule: "+strings.Join(rule.Labels, ", ")+" with these exact scripts on these hosts run without asking; ends 90 days after its last use; approver "+approverID)
}

// signPackageGrants spends a package run approval: one grant per endpoint
// and script payload, each bound to that payload's own digest.
func (a *Authority) signPackageGrants(req *ApprovalConsumeRequest, requester string, stmt ApprovalStatement, payload []byte, targets []string, now time.Time) ([]*response.EndpointGrant, error) {
	items, err := ParsePackageRun(payload, targets)
	if err != nil {
		return nil, err
	}
	priv, keyID, err := a.tenantSigningKey(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := grantTTL(req.Kind, req.TTLSeconds)
	grants := make([]*response.EndpointGrant, 0, len(items)*len(targets))
	for _, ep := range targets {
		for _, it := range items {
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
				ActionDigest:      it.Digest,
				OperatorID:        requester,
				ResponseSessionID: "approval:" + stmt.ID,
				IssuedAt:          now.Unix(),
				ExpiresAt:         now.Unix() + ttl,
				Nonce:             hex.EncodeToString(nonce),
				SignerKeyID:       keyID,
			}
			g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
			grants = append(grants, g)
			a.auditApproval(req.TenantID, requester, "grant_signed", string(req.Kind), ep, stmt.ID, "success", "owner approval "+stmt.ID+" grant "+g.GrantID+" "+it.Label())
		}
	}
	return grants, nil
}
