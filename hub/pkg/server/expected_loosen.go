package server

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Expected rules silence findings, so the response authority judges every
// write to them. A rule loosens detection when it covers more than it did: a
// new rule, a kind it did not cover, an entry in a list that restricts it, a
// restriction taken away or changed, an exception taken away, a higher host
// bound, or a later expiry. Removing a rule, narrowing it or ending it sooner
// tightens. A changed name, reason or vendor label matches nothing.

func ruleList(v any) []storage.ExpectedRule {
	var out []storage.ExpectedRule
	raw, _ := json.Marshal(v)
	_ = json.Unmarshal(raw, &out)
	return out
}

func ruleMap(list []storage.ExpectedRule) map[string]storage.ExpectedRule {
	m := make(map[string]storage.ExpectedRule, len(list))
	for _, r := range list {
		m[r.ID] = r
	}
	return m
}

// laterExpiry reports an expiry that lets a rule live longer; no expiry is
// the longest.
func laterExpiry(was, now time.Time) bool {
	switch {
	case was.IsZero():
		return false
	case now.IsZero():
		return true
	}
	return now.After(was)
}

// addsToList reports a restricting list that admits something it did not: an
// entry that was not there, or the list emptied (no restriction at all).
func addsToList(was, now []string) bool {
	if len(was) > 0 && len(now) == 0 {
		return true
	}
	return len(was) > 0 && gainsEntry(was, now)
}

func gainsEntry(was, now []string) bool {
	for _, x := range now {
		if !slices.Contains(was, x) {
			return true
		}
	}
	return false
}

// scalarWidens reports a single-valued restriction that now admits more than
// before: lifted, or changed to something else. Setting one that was empty
// narrows.
func scalarWidens(was, now string) bool { return was != "" && was != now }

func programsWiden(was, now []storage.ExpectedProgram) bool {
	if len(was) == 0 {
		return false
	}
	if len(now) == 0 {
		return true
	}
	for _, p := range now {
		if !slices.ContainsFunc(was, func(q storage.ExpectedProgram) bool { return programWithin(p, q) }) {
			return true
		}
	}
	return false
}

// programWithin reports that everything p matches, q matches too: the same
// path, q pinned to no build or the same one, q open to any account or the
// same one (an account name also admits the system accounts).
func programWithin(p, q storage.ExpectedProgram) bool {
	if !strings.EqualFold(p.Path, q.Path) {
		return false
	}
	if q.SHA256 != "" && !strings.EqualFold(q.SHA256, p.SHA256) {
		return false
	}
	return q.RunAs == "" || q.RunAs == p.RunAs || (p.RunAs == "system" && q.RunAs != "system")
}

// ruleLoosens reports whether now covers anything old did not.
func ruleLoosens(old, now storage.ExpectedRule) bool {
	if gainsEntry(old.Kinds(), now.Kinds()) {
		return true
	}
	if laterExpiry(old.ExpiresAt, now.ExpiresAt) || now.MaxHosts > old.MaxHosts {
		return true
	}
	if programsWiden(old.Programs, now.Programs) {
		return true
	}
	if scalarWidens(old.Runtime, now.Runtime) || scalarWidens(old.Workload, now.Workload) || tenancyRank(now.Tenancy) > tenancyRank(old.Tenancy) ||
		scalarWidens(old.Protocol, now.Protocol) || scalarWidens(old.Direction, now.Direction) ||
		(old.Port != 0 && old.Port != now.Port) {
		return true
	}
	if addsToList(old.Hosts, now.Hosts) {
		return true
	}
	// Domains, prefixes and networks are alternatives of one destination
	// clause: it widens when any of them gains an entry or when it is taken
	// away entirely.
	hadDest := len(old.Domains)+len(old.Prefixes)+len(old.Networks) > 0
	// Domains restrict a network match to the names under them, so taking
	// them away opens the whole network.
	if len(old.Domains) > 0 && len(now.Domains) == 0 {
		return true
	}
	if hadDest {
		if len(now.Domains)+len(now.Prefixes)+len(now.Networks) == 0 ||
			gainsEntry(old.Domains, now.Domains) || gainsEntry(old.Prefixes, now.Prefixes) || gainsEntry(old.Networks, now.Networks) {
			return true
		}
	}
	// An exception taken away admits the names it kept out.
	for _, x := range old.ExceptDomains {
		if !slices.Contains(now.ExceptDomains, x) {
			return true
		}
	}
	return false
}

// rulesLoosen reports a change to the rules that covers more than before.
func rulesLoosen(before, after any) bool {
	was := ruleMap(ruleList(before))
	for _, r := range ruleList(after) {
		old, ok := was[r.ID]
		if !ok || ruleLoosens(old, r) {
			return true
		}
	}
	return false
}

// keptRules is the rules before as the change leaves them once everything
// that loosens is held back: a rule the change removes goes, a rule that only
// narrows takes its new form, and a rule that would cover more stays as it
// was. A new rule is not part of the tightening half.
func keptRules(before, after any) any {
	next := ruleMap(ruleList(after))
	kept := []storage.ExpectedRule{}
	for _, r := range ruleList(before) {
		n, ok := next[r.ID]
		switch {
		case !ok:
		case ruleLoosens(r, n):
			kept = append(kept, r)
		default:
			kept = append(kept, n)
		}
	}
	return kept
}

// tenancyRank orders a rule's network tenancy by how much it covers: only a
// published maker range, then any non-rented network, then rented compute and
// unnamed addresses too.
func tenancyRank(t string) int {
	switch t {
	case storage.ExpectedTenancyVendor:
		return 0
	case storage.ExpectedTenancyAny:
		return 2
	}
	return 1
}

// ruleSummary is one line for an audit entry.
func ruleSummary(r storage.ExpectedRule) string {
	what := strings.Join(r.Kinds(), ", ")
	if what == "" {
		what = "nothing"
	}
	return r.ID + " (" + what + ")"
}
