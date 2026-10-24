package responseauth

// Maintenance package runs (kind script_exec).
//
// The hub asks with a PackageRunPayload: the exact script payloads the agents
// will receive (each item is the JSON string an agent digests), the named
// endpoints, and the route. The authority reads everything from those bytes,
// and the hub cannot vouch for a package: a script counts as a package only
// when its source digest is one this authority was released with
// (released_packages.json, generated from packages/windows and checked against
// it by the tests). Its header (line 1 of that released source) then declares
// its category, risk and typed parameters; a run must carry mode and exactly
// those parameters, each within its declared bounds, and the audit shows every
// value that differs from its default. Anything else is recorded as "not a
// released package". The hub's own copy of package metadata is never trusted.
//
// Each item must be exactly the bytes json.Marshal makes of it (field order,
// no duplicates or stray members), so an agent's field search and this parse
// cannot read different values. The authority signs one grant per endpoint and
// item, each bound to that item's own digest.

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
	"strings"
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
	PlaybookRunRoute = "/api/v1/maintenance/playbooks/run"
	// OneOffScriptRoute is an agent's or operator's one-off script: one
	// script, not a package, asked every time and never a rule.
	OneOffScriptRoute = "/api/v1/maintenance/script"
	// OneOffPrefix starts a one-off script's id: "adhoc-" + 12 hex of its digest.
	OneOffPrefix      = "adhoc-"
	PlaybookMaxWindow = 24 * 60 * 60
	playbookMinWindow = 10 * 60
	packageMaxItems   = 10
	packageMaxGrants  = 100
	packageMaxPayload = 512 * 1024
)

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

// PackageRunPayload is what the authority signs for a script_exec run.
type PackageRunPayload struct {
	Route   string   `json:"route"`
	Items   []string `json:"items"` // each the exact ScriptExecPayload JSON an agent receives
	Targets []string `json:"targets"`
	// Playbook is set for a playbook run: the items run in this order, one at
	// a time on each host, and their grants live for the window the owner
	// approved (the hub holds a step back until the one before it ends).
	Playbook *PlaybookRun `json:"playbook,omitempty"`
	// OneOff is set for a one-off script run (OneOffScriptRoute).
	OneOff *OneOffScript `json:"one_off,omitempty"`
}

// OneOffScript names a one-off script run and says why it runs.
type OneOffScript struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// OneOffID is the script id of a one-off script with this source digest.
func OneOffID(digest string) string {
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return OneOffPrefix + strings.ToLower(digest)
}

// oneOffOf returns the one-off part of a payload parsePackageRunPayload
// accepted, or nil.
func oneOffOf(payload []byte) *OneOffScript {
	var p PackageRunPayload
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	return p.OneOff
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

// Label names the item in the audit: package (mode).
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
	switch {
	case p.OneOff != nil:
		if p.Route != OneOffScriptRoute || p.Playbook != nil {
			return nil, nil, fmt.Errorf("route %q is not a one-off script run", cleanText(p.Route, 80))
		}
	case p.Playbook == nil && p.Route != PackageRunRoute || p.Playbook != nil && p.Route != PlaybookRunRoute:
		return nil, nil, fmt.Errorf("route %q is not a package run", cleanText(p.Route, 80))
	}
	if oo := p.OneOff; oo != nil {
		if oo.Name == "" || len(oo.Name) > 60 || cleanText(oo.Name, 60) != oo.Name {
			return nil, nil, errors.New("a one-off script is named in up to 60 plain characters")
		}
		if oo.Reason == "" || len(oo.Reason) > 160 || cleanText(oo.Reason, 160) != oo.Reason {
			return nil, nil, errors.New("a one-off script says why it runs in up to 160 plain characters")
		}
		if len(p.Items) != 1 {
			return nil, nil, errors.New("a one-off script run carries exactly one script")
		}
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
		if p.OneOff != nil && (it.Exec.ScriptID != OneOffID(it.Exec.ScriptDigest) || it.Exec.ScriptVersion != 1 || len(it.Exec.Parameters) > 0) {
			return nil, nil, errors.New("a one-off script is named by its digest, version 1, with no parameters")
		}
		if p.OneOff == nil && strings.HasPrefix(it.Exec.ScriptID, OneOffPrefix) {
			return nil, nil, errors.New("a one-off script runs through its own route")
		}
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
	return it.changesNote(short) + it.optionsNote()
}

func (it PackageItem) changesNote(short bool) string {
	if it.Header == nil {
		return ""
	}
	if ch := it.Header.Changes(it.Exec.Parameters, short); len(ch) > 0 {
		return ", settings " + strings.Join(ch, ", ")
	}
	return ""
}

// optionsNote: the run options (when_busy, window) in the owner's words.
func (it PackageItem) optionsNote() string {
	if it.Header == nil {
		return ""
	}
	if t := scripts.RunOptionText(it.Exec.Parameters); len(t) > 0 {
		return "; " + strings.Join(t, "; ")
	}
	return ""
}

func describePackageRun(payload []byte, targets []string) (string, string, error) {
	items, pb, err := parsePackageRunPayload(payload, targets)
	if err != nil {
		return "", "", err
	}
	if pb != nil {
		return describePlaybookRun(pb, items, targets)
	}
	if oo := oneOffOf(payload); oo != nil {
		return describeOneOff(oo, items[0], targets)
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
	// value in full (two runs that differ must never read the same).
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Label()+it.riskNote()+it.settingsNote(false))
	}
	short := fmt.Sprintf("Run %d scripts as SYSTEM on %d host(s): %s", len(items), len(targets), strings.Join(names, "; "))
	return "Run maintenance", short, nil
}

// describeOneOff: what the script is (name, shell, size, the start of its
// digest), where it runs, its time limit and why. The full text is kept with
// the run on the hub.
func describeOneOff(oo *OneOffScript, it PackageItem, targets []string) (string, string, error) {
	shell := map[string]string{"powershell.exe": "PowerShell", "pwsh.exe": "PowerShell", "cmd.exe": "cmd", "/bin/sh": "sh", "/bin/bash": "bash"}[it.Exec.Interpreter]
	lines := strings.Count(strings.TrimRight(it.Exec.Source, "\n"), "\n") + 1
	summary := fmt.Sprintf("One-off script %q as SYSTEM on %s: %d lines of %s (sha256 %s), up to %d min. Why: %s",
		oo.Name, listTargets(targets), lines, shell, it.Exec.ScriptDigest[:12], (it.Exec.TimeoutSeconds+59)/60, oo.Reason)
	return "Run a one-off script", summary, nil
}

// describePlaybookRun: the steps in order, each with its risk and changed
// settings, the window the grants live for, and the run options (said once
// when every step that has them agrees). A long playbook is shown in a
// compact form (no time limits, short names, the mode only when it is not
// enforce).
func describePlaybookRun(pb *PlaybookRun, items []PackageItem, targets []string) (string, string, error) {
	common, same := "", true
	for _, it := range items {
		if n := it.optionsNote(); n != "" {
			if common != "" && n != common {
				same = false
			}
			common = n
		}
	}
	lastFull := ""
	for _, compact := range []bool{false, true} {
		lead := fmt.Sprintf("Playbook %q as SYSTEM on %s, one step after another, all within %s", pb.Name, listTargets(targets), spanText(pb.WindowSeconds))
		if compact {
			lead = fmt.Sprintf("Playbook %q on %s, in order within %s, enforce unless marked", pb.Name, listTargets(targets), spanText(pb.WindowSeconds))
		}
		parts := make([]string, 0, len(items))
		for i, it := range items {
			note := it.settingsNote(false)
			if same {
				note = it.changesNote(false)
			}
			if compact {
				parts = append(parts, it.shortLabel()+it.riskNote()+note)
				continue
			}
			parts = append(parts, fmt.Sprintf("%d. %s, up to %d min", i+1, it.Label(), (it.Exec.TimeoutSeconds+59)/60)+it.riskNote()+note)
		}
		tail := ""
		if same && common != "" {
			tail = ". Steps that change something: " + strings.TrimPrefix(common, "; ")
		}
		full := lead + ": " + strings.Join(parts, "; ") + tail
		if len([]rune(full)) <= approvalMaxSummary {
			return "Run playbook", full, nil
		}
		lastFull = full
	}
	// Neither form fits the summary cap: the last (compact) one is cut.
	return "Run playbook", cleanText(lastFull, approvalMaxSummary), nil
}

// shortLabel: the package without its platform prefix ("keep awake" for
// maintenance mode), and the mode unless it is enforce.
func (it PackageItem) shortLabel() string {
	mode := it.Exec.Parameters["mode"]
	if it.Header == nil {
		return it.Label()
	}
	name := strings.TrimPrefix(strings.TrimPrefix(it.Name, "windows-"), "linux-")
	if it.Header.Role == scripts.RoleMaintenanceMode {
		if mode == "revert" {
			return "keep awake off"
		}
		if mode == "enforce" {
			return "keep awake on"
		}
	}
	if mode != "enforce" {
		name += " (" + mode + ")"
	}
	return name
}

// signPackageGrants signs a package run: one grant per endpoint and script
// payload, each bound to that payload's own digest.
func (a *Authority) signPackageGrants(au *authorized, now time.Time) ([]*response.EndpointGrant, error) {
	targets := au.Targets
	items, pb, err := parsePackageRunPayload(au.Payload, targets)
	if err != nil {
		return nil, err
	}
	priv, keyID, err := a.tenantSigningKey(au.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := grantTTL(au.Kind, au.TTLSeconds)
	if pb != nil {
		// The hub starts each step when the one before it ends, so every
		// grant lives for the window the run names.
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
				TenantID:          au.TenantID,
				EndpointID:        ep,
				ActionKind:        au.Kind,
				ActionDigest:      it.Digest,
				OperatorID:        au.Requester,
				ResponseSessionID: "approval:" + au.ID,
				IssuedAt:          now.Unix(),
				ExpiresAt:         now.Unix() + ttl,
				Nonce:             hex.EncodeToString(nonce),
				SignerKeyID:       keyID,
			}
			g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
			grants = append(grants, g)
			a.auditAction(au.TenantID, au.Requester, "grant_signed", string(au.Kind), ep, au.ID, "success", "authorization "+au.ID+" grant "+g.GrantID+" "+it.Label())
		}
	}
	return grants, nil
}
