package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// The expected rules are data in the tuning row. This file is their API: list,
// save one, delete one, and "mark as expected" on a finding, which writes the
// narrowest rule that would have made that finding expected. None needs a
// release. A write that covers more than before goes through the response
// authority like any loosening (policyAuthorized); deleting a rule or
// narrowing it only tightens and asks nobody.

// vendorRangesOwned refuses a rule whose maker prefix has an end the hub's
// network attribution places on a shared CDN or rented compute: any site can
// be fronted from there, so the range would prove nothing about the maker.
func vendorRangesOwned(t storage.DetectionTuning) error {
	for _, rule := range t.ExpectedRules {
		if len(rule.Domains) == 0 {
			continue
		}
		for _, raw := range rule.Prefixes {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			for _, a := range []netip.Addr{p.Masked().Addr(), lastAddr(p)} {
				geo := threatintel.ResolveGeoIP(a.String())
				if geo.Tenancy == storage.TenancySharedCDN || geo.Tenancy == storage.TenancyHosting {
					return fmt.Errorf("%w: rule %s prefix %s holds %s address space of %q, which any site can be served from",
						storage.ErrInvalidDetectionTuning, rule.ID, raw, geo.Tenancy, geo.Org)
				}
			}
		}
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		bit := i * 8
		switch {
		case bit >= p.Bits():
			b[i] = 0xff
		case bit+8 > p.Bits():
			b[i] |= 0xff >> uint(p.Bits()-bit)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// handleExpectedRules lists, saves and deletes expected rules. Reading is open
// to any authenticated operator (an analyst has to see why a finding did not
// fire); writing is an administrator's action.
func (s *Server) handleExpectedRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "changing what is expected is an administrator action")
		return
	}
	switch r.Method {
	case http.MethodGet:
		t := s.store.GetDetectionTuning()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rules":    t.ExpectedRules,
			"findings": storage.ExpectableKinds(),
			"explicit": storage.ExplicitKinds(),
			"now":      time.Now().UTC().Format(time.RFC3339),
		})

	case http.MethodPost, http.MethodPut:
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<18))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		var rule storage.ExpectedRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.policyMu.Lock()
		defer s.policyMu.Unlock()
		before := s.store.GetDetectionTuning()
		rules := make([]storage.ExpectedRule, 0, len(before.ExpectedRules)+1)
		replaced := false
		for _, old := range before.ExpectedRules {
			if old.ID == strings.TrimSpace(rule.ID) {
				rules, replaced = append(rules, rule), true
				continue
			}
			rules = append(rules, old)
		}
		if !replaced {
			rules = append(rules, rule)
		}
		next := before
		next.ExpectedRules = rules
		after, err := s.prepareRules(before, next)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.applyTuning(w, r, tuningChange("rule_save", before, after), "EXPECTED_RULE_SAVED")

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		s.policyMu.Lock()
		defer s.policyMu.Unlock()
		before := s.store.GetDetectionTuning()
		next := before
		next.ExpectedRules = slices.DeleteFunc(slices.Clone(before.ExpectedRules), func(x storage.ExpectedRule) bool { return x.ID == id })
		if len(next.ExpectedRules) == len(before.ExpectedRules) {
			writeJSONError(w, http.StatusNotFound, "no expected rule with that id")
			return
		}
		after, err := storage.PrepareDetectionTuning(next)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.applyTuning(w, r, tuningChange("rule_delete", before, after), "EXPECTED_RULE_DELETED")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// prepareRules validates a tuning whose rules were edited: expiry bounds on
// new workload rules, the shared validation, and the maker-range check.
func (s *Server) prepareRules(before, next storage.DetectionTuning) (storage.DetectionTuning, error) {
	if err := storage.CheckNewRuleExpiry(before.ExpectedRules, next.ExpectedRules, time.Now()); err != nil {
		return storage.DetectionTuning{}, err
	}
	after, err := storage.PrepareDetectionTuning(next)
	if err != nil {
		return storage.DetectionTuning{}, err
	}
	if err := vendorRangesOwned(after); err != nil {
		return storage.DetectionTuning{}, err
	}
	return after, nil
}

// versionSegment is a path segment that is a release number: 2.1.5, v0.9,
// 1.0.0-beta.2. A program that updates itself installs each release under a
// new one.
var versionSegment = regexp.MustCompile(`^v?\d+(\.\d+)+([-+][0-9a-z.]+)?$`)

// generalisePath replaces the release-number segments of an installed path
// with "*", so a program that updates itself in place stays expected after
// its next update. The first two segments stay literal.
func generalisePath(path string) string {
	segs := strings.Split(path, "/")
	for i := 2; i < len(segs); i++ {
		if versionSegment.MatchString(segs[i]) {
			segs[i] = "*"
		}
	}
	return strings.Join(segs, "/")
}

// markRequest is the body of mark-as-expected.
type markRequest struct {
	ID       string `json:"id"`
	Reason   string `json:"reason,omitempty"`
	AllHosts bool   `json:"all_hosts,omitempty"`
	// Days is how long the rule lasts; 0 is until removed.
	Days int `json:"days,omitempty"`
}

// handleMarkExpected turns one finding into the narrowest expected rule that
// would have made it expected: this program (any release of it, for one that
// updates itself), as the account it ran as, on this host, reaching this
// network, for this one kind of finding.
//
// What it will not do is as important. It never rules on a destination alone
// (a CDN or cloud allowlist is exactly where an implant wants to be) and never
// on rented compute, where anyone can buy a machine inside a reputable range;
// it refuses a process nothing attributed, one whose file differs from its
// path, and findings the floor raises. Cloud storage uploads and lateral
// sweeps are written as rules by hand, not from a click.
func (s *Server) handleMarkExpected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "marking a finding expected is an administrator action")
		return
	}
	var req markRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeJSONError(w, http.StatusBadRequest, "which finding?")
		return
	}
	finding, err := s.store.GetAnomalyAlert(strings.TrimSpace(req.ID))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no such finding")
		return
	}
	rule, status, msg := markRule(finding, req, time.Now().UTC())
	if msg != "" {
		writeJSONError(w, status, msg)
		return
	}

	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	before := s.store.GetDetectionTuning()
	// The rule this would write, rebuilt from the finding, is what must cover
	// it, whether it is new or already stored.
	c := detector.FindingExpectCtx(finding, "")
	c.Kind = rule.Findings[0]
	if stored, ok := before.RuleByID(rule.ID); ok {
		// Already expected: this only dismisses the finding, so it is
		// recorded and counted on the Aico push like any other. A rule
		// of that id that was edited, narrowed or has lapsed may no longer
		// cover it, and dismissing would hide a finding that fires again.
		if _, covered := before.Expected(c); !covered {
			writeJSONError(w, http.StatusConflict, "a rule with this id ("+stored.ID+") already exists but does not cover this finding any more, so nothing was dismissed; edit that rule, or delete it and mark again")
			return
		}
		if err := s.acknowledgeFinding(r, finding.ID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeMarked(w, rule, finding, false)
		return
	}
	next := before
	next.ExpectedRules = append(slices.Clone(before.ExpectedRules), rule)
	after, err := s.prepareRules(before, next)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The rule must cover the finding it came from, or marking would dismiss
	// something that fires again an hour later.
	if _, ok := after.Expected(c); !ok {
		writeJSONError(w, http.StatusBadRequest, "the rule this would write does not cover the finding it came from, so it was not saved; write the rule by hand")
		return
	}
	change := tuningChange("mark_expected", before, after)
	approvalID, ok := s.policyAuthorized(w, r, change)
	if !ok {
		return
	}
	if _, err := s.store.SaveDetectionTuning(after, operatorName(r)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	s.notePolicyChange(r, change, approvalID)
	if err := s.acknowledgeFinding(r, finding.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "EXPECTED_RULE_MARKED", "detection",
		fmt.Sprintf("marked %s expected from finding %s on %s", ruleSummary(rule), finding.AnomalyType, finding.EndpointID))
	s.writeMarked(w, rule, finding, true)
}

// markRule builds the rule for one finding, or says why none can be: the
// message and HTTP status.
func markRule(f storage.AnomalyAlert, req markRequest, now time.Time) (storage.ExpectedRule, int, string) {
	none := storage.ExpectedRule{}
	kinds := detector.FindingKinds(f)
	if len(kinds) == 0 {
		return none, http.StatusBadRequest, "this is a finding the detection floor raises, and nothing can make it expected"
	}
	kind := kinds[0]
	switch kind {
	case storage.KindCloudStorage:
		return none, http.StatusBadRequest, "uploads to a cloud storage service are never marked expected from a click: anyone can rent a bucket there. Write a rule for the program and the one bucket by hand"
	case storage.KindLateralSweep:
		return none, http.StatusBadRequest, "a lateral sweep is made expected by a rule that names the hosts, the program and the one port; write that rule by hand"
	}
	proc := storage.ProcessPathKey(f.ProcessPath)
	if proc == "" || proc == "unknown" {
		return none, http.StatusBadRequest, "this finding has no attributed process, so there is no program to vouch for"
	}
	if evidenceText(f.Evidence, "attribution_status") == storage.AttributionPathMismatch {
		return none, http.StatusBadRequest, "the agent found this process running a different file from the one at its reported path, so that path cannot vouch for it"
	}
	if !strings.HasPrefix(proc, "/") && !(len(proc) > 2 && proc[1] == ':') {
		return none, http.StatusBadRequest, "this finding names the program only by its name, not where it is installed, and a name is something any program can take"
	}
	owner := evidenceText(f.Evidence, "destination_asn")
	if owner == "" {
		owner = evidenceText(f.Evidence, "destination_owner")
	}
	if owner == "" {
		return none, http.StatusBadRequest, "nothing has named this destination's network, and an address on its own is not a counterparty worth silencing"
	}
	if evidenceText(f.Evidence, "destination_tenancy") == storage.TenancyHosting {
		return none, http.StatusBadRequest, "that destination is rented compute, which anyone can buy inside; mark the program and the network it should be talking to instead"
	}

	prog := storage.ExpectedProgram{Path: generalisePath(proc)}
	if user := strings.TrimSpace(evidenceText(f.Evidence, "user_identity")); user != "" {
		prog.RunAs = user
		if storage.IsServiceAccount(user, "") {
			prog.RunAs = "system"
		}
	}
	if storage.SharedWritable(proc) {
		// Where it sits proves nothing: the build the finding saw is the
		// program.
		sha := strings.ToLower(strings.TrimSpace(evidenceText(f.Evidence, "executable_sha256")))
		if sha == "" {
			return none, http.StatusBadRequest, "this program is in a folder any account can write to, and the agent did not record which build it was, so there is nothing safe to vouch for"
		}
		prog.Path, prog.SHA256 = proc, sha
	}
	if storage.ValidExpectedProgram(prog) != "" {
		prog.RunAs = ""
	}
	if msg := storage.ValidExpectedProgram(prog); msg != "" {
		return none, http.StatusBadRequest, msg
	}

	rule := storage.ExpectedRule{
		Findings: []string{kind},
		Programs: []storage.ExpectedProgram{prog},
		Networks: []string{owner},
		Reason:   strings.TrimSpace(req.Reason),
	}
	if !req.AllHosts {
		rule.Hosts = []string{strings.ToLower(f.EndpointID)}
	}
	if req.Days > 0 {
		rule.ExpiresAt = now.AddDate(0, 0, req.Days)
	}
	if rule.Reason == "" {
		rule.Reason = fmt.Sprintf("marked expected from finding %s (%s on %s)", f.ID, f.AnomalyType, f.EndpointID)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{kind, prog.Path, prog.RunAs, owner, strings.Join(rule.Hosts, ",")}, "|")))
	base := proc[strings.LastIndex(proc, "/")+1:]
	rule.ID = "marked-" + truncate(storage.RuleSlug(base), 24) + "-" + hex.EncodeToString(sum[:4])
	rule.Name = base + " to " + owner
	return rule, 0, ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) writeMarked(w http.ResponseWriter, rule storage.ExpectedRule, finding storage.AnomalyAlert, added bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"rule":         rule,
		"added":        added,
		"acknowledged": finding.ID,
		"endpoint_id":  finding.EndpointID,
		"anomaly_type": finding.AnomalyType,
	})
}
