package responseauth

// Maintenance package runs (kind script_exec) under owner approval, and the
// owner's "approve all like this" rule for them.
//
// The hub asks with a PackageRunPayload: the exact script payloads the agents
// will receive (each item is the JSON string an agent digests), the named
// endpoints, and the route. The authority reads everything the owner sees from
// those bytes, and the hub cannot vouch for a package: a script counts as a
// package only when its source digest is one this authority was released with
// (released_packages.json, generated from packages/windows and checked against
// it by the tests), run by powershell.exe. Its header (line 1 of that released
// source) then declares its category, risk and typed parameters; a run must
// carry mode and exactly those parameters, each within its declared bounds,
// and the owner is shown every value that differs from its default. Anything
// else is shown as "not a released package", asks every time and never gets a
// rule. The hub's own copy of package metadata is never trusted.
//
// A run whose every item is a safe released package in audit mode with every
// parameter at its default is approved without asking ("baseline"): audit
// changes nothing and the released defaults are what the owner shipped.
// Each item must be exactly the bytes json.Marshal makes of it (field order,
// no duplicates or stray members), so an agent's field search and this parse
// cannot read different values. On use the authority signs one grant per
// endpoint and item, each bound to that item's own digest.
//
// One passkey tap with the decision "rule" on an ask that offers it stores a
// package rule. While it lives, a later request is approved here without
// asking when every item's digest is one the rule names (so the script source,
// interpreter, parameters, timeout and output bound are all the same bytes) and
// every endpoint is one the rule names. A new script version, another mode, a
// longer timeout, other settings or another host is a new digest or target and
// asks again. A rule that covers an enforce run also covers the same run in
// audit mode, so switching back to audit never asks.
// Only packages whose header says risk "safe" are ever offered or covered;
// "careful" packages and scripts that are not released packages ask every time.
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
	_ "embed"
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
	"ominull/hub/pkg/scripts"
)

const (
	// PackageRunRoute is the hub route a package run approval belongs to.
	PackageRunRoute = "/api/v1/maintenance/run"
	// PlaybookRunRoute is the route of a playbook run: the same items, run
	// one after another on each host within the approved window.
	PlaybookRunRoute  = "/api/v1/maintenance/playbooks/run"
	PlaybookMaxWindow = 24 * 60 * 60
	playbookMinWindow = 10 * 60
	packageRuleOffer  = "packages" // ApprovalStatement.Offer
	packageRuleIdle   = 90 * 24 * time.Hour
	packageMaxItems   = 10
	packageMaxGrants  = 100
	packageMaxPayload = 512 * 1024
	packageRulesKept  = 20 // per tenant
)

// ErrRuleNotCovered refuses a rule-only request (the hub's schedule) that no
// live package rule covers. Nothing is recorded and nobody is asked.
var ErrRuleNotCovered = errors.New("no approve-all rule covers this package run")

var packageInterpreters = map[string]bool{"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "/bin/sh": true, "/bin/bash": true}

// releasedPackages maps the sha256 of each package source shipped with this
// release to its name and risk.
//
//go:embed released_packages.json
var releasedPackagesJSON []byte

type releasedPackage struct {
	Name string `json:"name"`
	Risk string `json:"risk"`
}

var releasedPackages = func() map[string]releasedPackage {
	m := map[string]releasedPackage{}
	if err := json.Unmarshal(releasedPackagesJSON, &m); err != nil {
		panic("released_packages.json: " + err.Error())
	}
	return m
}()

// ReleasedPackages is the embedded list (for the tests that keep it in step
// with packages/windows).
func ReleasedPackages() map[string]string {
	out := make(map[string]string, len(releasedPackages))
	for d, p := range releasedPackages {
		out[d] = p.Name + " " + p.Risk
	}
	return out
}

// reservedParams are payload field names a parameter may not take.
var reservedParams = map[string]bool{"script_id": true, "script_version": true, "script_digest": true, "interpreter": true,
	"source": true, "parameters": true, "timeout_seconds": true, "max_output_bytes": true}

// PackageRunPayload is what the owner approves for a script_exec run.
type PackageRunPayload struct {
	Route   string   `json:"route"`
	Items   []string `json:"items"` // each the exact ScriptExecPayload JSON an agent receives
	Targets []string `json:"targets"`
	// Playbook is set for a playbook run: the items run in this order, one at
	// a time on each host, and their grants live for the window the owner
	// approved (the hub holds a step back until the one before it ends).
	Playbook *PlaybookRun `json:"playbook,omitempty"`
}

// PlaybookRun names a playbook run and how long it may take.
type PlaybookRun struct {
	Name          string `json:"name"`
	WindowSeconds int64  `json:"window_seconds"`
}

// PackageItem is one script payload of a run as the authority read it.
type PackageItem struct {
	Raw    string
	Digest string // sha256 of Raw: the grant's action digest
	Exec   response.ScriptExecPayload
	Name   string                 // released package name, or the script id
	Risk   string                 // "safe" | "careful" | "" (not a released package)
	Header *scripts.PackageHeader // the released source's header; nil otherwise
	Steps  []string               // careful steps this run turns on
}

// Baseline: a safe released package in audit mode with every parameter at
// its default. A catalog parameter is hub data an audit only reads by, so
// any valid catalog keeps an audit a baseline run.
func (it PackageItem) Baseline() bool {
	if it.Header == nil || it.Risk != "safe" || it.Exec.Parameters["mode"] != "audit" {
		return false
	}
	for k, v := range it.Header.Defaults() {
		if p := it.Header.Param(k); p != nil && p.Type == "catalog" {
			continue
		}
		if it.Exec.Parameters[k] != v {
			return false
		}
	}
	return true
}

// auditTwin is the digest of the same run in audit mode: a rule that covers
// an enforce run also covers auditing with the same settings.
func (it PackageItem) auditTwin() (string, bool) {
	if it.Exec.Parameters["mode"] != "enforce" {
		return "", false
	}
	p := it.Exec
	p.Parameters = make(map[string]string, len(it.Exec.Parameters))
	for k, v := range it.Exec.Parameters {
		p.Parameters[k] = v
	}
	p.Parameters["mode"] = "audit"
	raw, err := json.Marshal(p)
	if err != nil {
		return "", false
	}
	return ItemDigest(string(raw)), true
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
	if again, err := json.Marshal(it.Exec); err != nil || string(again) != raw {
		return it, errors.New("script payload is not in its canonical form")
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
	// A value is at most 1 KiB, except a catalog param of a released
	// package (checked below against its trusted header): up to 12 KiB, all
	// params together within what agents take.
	var long []string
	total := 0
	for k, v := range p.Parameters {
		total += len(k) + len(v)
		if !paramName(k) || reservedParams[k] || len(v) > 12*1024 {
			return it, errors.New("script parameters are malformed")
		}
		if len(v) > 1024 {
			long = append(long, k)
		}
	}
	if total > 15*1024 {
		return it, errors.New("script parameters are malformed")
	}
	malformedUnlessCatalog := func(h *scripts.PackageHeader) error {
		for _, k := range long {
			if h == nil || h.Param(k) == nil || h.Param(k).Type != "catalog" {
				return errors.New("script parameters are malformed")
			}
		}
		return nil
	}
	it.Name = cleanText(p.ScriptID, 64)
	rp, ok := releasedPackages[strings.ToLower(p.ScriptDigest)]
	if !ok {
		return it, malformedUnlessCatalog(nil)
	}
	// The released header names the platform, and so the one interpreter its
	// runs may use (powershell.exe on Windows, /bin/sh on Linux).
	h, err := scripts.ParsePackageHeader(p.Source)
	if err != nil || h.Name != rp.Name || h.Risk != rp.Risk || p.Interpreter != h.Interpreter() {
		return it, malformedUnlessCatalog(nil)
	}
	if err := malformedUnlessCatalog(h); err != nil {
		return it, err
	}
	if err := h.CheckRun(p.Parameters); err != nil {
		return it, fmt.Errorf("%s: %v", h.Name, err)
	}
	it.Name, it.Risk, it.Header = h.Name, h.Risk, h
	// Turning on a careful step makes the run careful: asked every time,
	// never covered by a rule.
	if it.Steps = h.CarefulSteps(p.Parameters); len(it.Steps) > 0 {
		it.Risk = "careful"
	}
	return it, nil
}

// ParsePackageRun reads a package run payload; targets is the approval's
// sorted, de-duplicated target list.
func ParsePackageRun(payload []byte, targets []string) ([]PackageItem, error) {
	items, _, err := parsePackageRunPayload(payload, targets)
	return items, err
}

// parsePackageRunPayload also returns the playbook part, if any.
func parsePackageRunPayload(payload []byte, targets []string) ([]PackageItem, *PlaybookRun, error) {
	if err := plainKeys(payload); err != nil {
		return nil, nil, fmt.Errorf("package run payload refused: %w", err)
	}
	var p PackageRunPayload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, errors.New("package run payload must carry route, items and targets")
	}
	if p.Playbook == nil && p.Route != PackageRunRoute || p.Playbook != nil && p.Route != PlaybookRunRoute {
		return nil, nil, fmt.Errorf("route %q is not a package run", cleanText(p.Route, 80))
	}
	if pb := p.Playbook; pb != nil {
		if pb.Name == "" || cleanText(pb.Name, 80) != pb.Name {
			return nil, nil, errors.New("a playbook run names its playbook in up to 80 plain characters")
		}
		if pb.WindowSeconds < playbookMinWindow || pb.WindowSeconds > PlaybookMaxWindow {
			return nil, nil, errors.New("a playbook run takes 10 minutes to 24 hours")
		}
	}
	if strings.Join(sortedUnique(p.Targets), "\x00") != strings.Join(targets, "\x00") {
		return nil, nil, errors.New("payload targets differ from the approval's targets")
	}
	if len(p.Items) == 0 || len(p.Items) > packageMaxItems {
		return nil, nil, fmt.Errorf("a package run carries 1-%d scripts", packageMaxItems)
	}
	if len(p.Items)*len(targets) > packageMaxGrants {
		return nil, nil, fmt.Errorf("a package run covers at most %d script runs", packageMaxGrants)
	}
	items := make([]PackageItem, 0, len(p.Items))
	seen := map[string]bool{}
	for _, raw := range p.Items {
		it, err := parsePackageItem(raw)
		if err != nil {
			return nil, nil, err
		}
		if seen[it.Digest] {
			return nil, nil, errors.New("a package run names the same script payload twice")
		}
		seen[it.Digest] = true
		items = append(items, it)
	}
	return items, p.Playbook, nil
}

// paramName is a lower-case identifier of at most 32 characters.
func paramName(k string) bool {
	if k == "" || len(k) > 32 || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for _, c := range k {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// riskNote is what the owner is told about an item that is not a safe package.
func (it PackageItem) riskNote() string {
	switch it.Risk {
	case "safe":
		return ""
	case "":
		return ", not a released package"
	}
	if len(it.Steps) > 0 && it.Header != nil && it.Header.Risk == "safe" {
		return ", careful steps " + strings.Join(it.Steps, ", ")
	}
	return ", " + cleanText(it.Risk, 16)
}

// settingsNote names the parameters that differ from the package defaults.
func (it PackageItem) settingsNote(short bool) string {
	if it.Header == nil {
		return ""
	}
	if ch := it.Header.Changes(it.Exec.Parameters, short); len(ch) > 0 {
		return ", settings " + strings.Join(ch, ", ")
	}
	return ""
}

// packageBaseline says whether every item of a run is a baseline run.
func packageBaseline(in *ApprovalRequestInput, targets []string) bool {
	if in.Kind != response.ActionKindScriptExec {
		return false
	}
	items, pb, err := parsePackageRunPayload(in.Payload, targets)
	if err != nil || pb != nil { // a playbook asks every time
		return false
	}
	for _, it := range items {
		if !it.Baseline() {
			return false
		}
	}
	return true
}

func describePackageRun(payload []byte, targets []string) (string, string, error) {
	items, pb, err := parsePackageRunPayload(payload, targets)
	if err != nil {
		return "", "", err
	}
	if pb != nil {
		return describePlaybookRun(pb, items, targets)
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%s, up to %d min%s%s", it.Label(), (it.Exec.TimeoutSeconds+59)/60, it.riskNote(), it.settingsNote(false)))
	}
	lead := "Run as SYSTEM on " + listTargets(targets) + ": "
	full := lead + strings.Join(parts, "; ")
	if len([]rune(full)) <= approvalMaxSummary {
		return "Run maintenance", full, nil
	}
	// Shorter, but still every script, every risk note and every changed
	// value in full (two runs that differ must never read the same); a run
	// that cannot be shown whole is refused rather than cut.
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Label()+it.riskNote()+it.settingsNote(false))
	}
	short := fmt.Sprintf("Run %d scripts as SYSTEM on %d host(s): %s", len(items), len(targets), strings.Join(names, "; "))
	if len([]rune(short)) > approvalMaxSummary {
		return "", "", errors.New("too much to show in one approval; run fewer packages at once or change fewer settings at a time")
	}
	return "Run maintenance", short, nil
}

// describePlaybookRun: the steps in order, each with its time limit, risk
// and changed settings, and the window the grants live for.
func describePlaybookRun(pb *PlaybookRun, items []PackageItem, targets []string) (string, string, error) {
	lead := fmt.Sprintf("Playbook %q as SYSTEM on %s, one step after another, all within %s: ", pb.Name, listTargets(targets), spanText(pb.WindowSeconds))
	for _, short := range []bool{false, true} {
		parts := make([]string, 0, len(items))
		for i, it := range items {
			step := fmt.Sprintf("%d. %s", i+1, it.Label())
			if !short {
				step += fmt.Sprintf(", up to %d min", (it.Exec.TimeoutSeconds+59)/60)
			}
			parts = append(parts, step+it.riskNote()+it.settingsNote(false))
		}
		if full := lead + strings.Join(parts, "; "); len([]rune(full)) <= approvalMaxSummary {
			return "Run playbook", full, nil
		}
	}
	return "", "", errors.New("too much to show in one approval; give the playbook fewer steps or change fewer settings")
}

// packageRuleCovers says whether a request is one a package rule may cover
// (every item a safe package) and returns its item digests and labels.
func packageRuleCovers(in *ApprovalRequestInput, targets []string) ([]string, []string, error) {
	if in.Kind != response.ActionKindScriptExec {
		return nil, nil, errors.New("not a package run")
	}
	items, pb, err := parsePackageRunPayload(in.Payload, targets)
	if err != nil {
		return nil, nil, err
	}
	if pb != nil {
		return nil, nil, errors.New("a playbook run asks every time")
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
	seen := map[string]bool{}
	for _, it := range items {
		if !seen[it.Digest] {
			seen[it.Digest] = true
			rule.Items = append(rule.Items, it.Digest)
		}
		if twin, ok := it.auditTwin(); ok && !seen[twin] {
			seen[twin] = true
			rule.Items = append(rule.Items, twin)
		}
		rule.Labels = append(rule.Labels, it.Label()+it.settingsNote(true))
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
	items, pb, err := parsePackageRunPayload(payload, targets)
	if err != nil {
		return nil, err
	}
	priv, keyID, err := a.tenantSigningKey(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := grantTTL(req.Kind, req.TTLSeconds)
	if pb != nil {
		// The hub starts each step when the one before it ends, so every
		// grant lives for the window the owner approved.
		ttl = pb.WindowSeconds
	}
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
