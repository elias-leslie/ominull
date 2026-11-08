package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/trustfabric"
)

// Trust fabric routes: author the destinations an isolated endpoint may still
// reach, see an endpoint's effective policy, and choose per isolation whether
// the fabric applies at all.
//
// Isolation modes:
//
//   - full: the endpoint reaches only the hub. The fabric is not consulted and
//     no exception may be named. Detector isolation is always full.
//   - selective: the endpoint's effective policy is expanded into allow_ips
//     before the hub signs, so the signed grant carries exactly what was
//     authorized; a rule changed later does not reach an isolation in force.
//   - omitted: the request's own allow_ips only, as before modes existed.
//
// Agents that report allow_prefixes enforce address ranges (no wider than /8
// for IPv4 or /32 for IPv6). An older agent takes single addresses only, and a
// list naming a range cuts nothing off at all on the ones that predate grants,
// so it gets a small range spelled out as addresses; a bigger one is reported as
// not enforced rather than opened, so selective isolation errs closed.
//
// A name rule (kind fqdn) is resolved by the hub, which signs the addresses:
// the agent never trusts a name. See trust_names.go.

const (
	isolationModeFull      = "full"
	isolationModeSelective = "selective"
	// isolatedRuleTTL bounds an endpoint allow rule written while that
	// endpoint is isolated, so a hole opened mid-incident closes by itself.
	isolatedRuleTTL = 4 * time.Hour
)

func parseIsolationMode(raw string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(raw)); m {
	case "", isolationModeFull, isolationModeSelective:
		return m, nil
	default:
		return "", fmt.Errorf("mode must be full or selective")
	}
}

// Narrowest prefix lengths an allow list may carry, as the agents check them
// (Trust_IsAllowEntry): the list is a pinhole through a default deny.
const (
	allowMinBitsV4 = 8
	allowMinBitsV6 = 32
	// maxAllowEntries is what an agent holds (TRUST_MAX_ALLOW, agent_trust.h).
	// It refuses a grant naming more, and that isolation would not apply.
	maxAllowEntries = 32
	// allowPrefixesAgentVersion is the first agent that enforces ranges.
	allowPrefixesAgentVersion = "1.8.65"
	// addressOnlyMaxRange is the biggest range spelled out as addresses for an
	// agent that takes no ranges; the agent's list holds few more than this.
	addressOnlyMaxRange = 16
)

// validateAllowEntry accepts an address or a bounded address range and
// returns it canonical: a range is masked, a one-address range is the
// address.
func validateAllowEntry(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "/") {
		return validateIP(v)
	}
	pre, err := netip.ParsePrefix(v)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address or range", v)
	}
	if pre.Addr().Is4In6() {
		return "", fmt.Errorf("%q: write an IPv4 range as IPv4", v)
	}
	pre = pre.Masked()
	if s := allowPrefixProblem(pre); s != "" {
		return "", fmt.Errorf("%q %s", v, s)
	}
	if pre.IsSingleIP() {
		return pre.Addr().String(), nil
	}
	return pre.String(), nil
}

// IPv6 ranges an allow list may open: global unicast and unique local, but
// not Teredo or 6to4. Link-local and translation prefixes (64:ff9b::/96
// reaches all of IPv4 through NAT64) stay closed. The agents check the same.
var (
	allowV6Within = []netip.Prefix{netip.MustParsePrefix("2000::/3"), netip.MustParsePrefix("fc00::/7")}
	allowV6Never  = []netip.Prefix{netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2002::/16")}
)

func allowPrefixProblem(pre netip.Prefix) string {
	if pre.Addr().Is4() {
		if pre.Bits() < allowMinBitsV4 {
			return fmt.Sprintf("is wider than /%d", allowMinBitsV4)
		}
		return ""
	}
	if pre.Bits() < allowMinBitsV6 {
		return fmt.Sprintf("is wider than /%d", allowMinBitsV6)
	}
	if pre.IsSingleIP() {
		return ""
	}
	within := false
	for _, w := range allowV6Within {
		within = within || w.Contains(pre.Addr())
	}
	for _, n := range allowV6Never {
		if n.Overlaps(pre) {
			within = false
		}
	}
	if !within {
		return "is not a global unicast or unique local IPv6 range (link-local, Teredo, 6to4 and translation prefixes stay closed)"
	}
	return ""
}

// takesAllowRanges reports whether the endpoint's agent enforces address
// ranges in its isolation allow list. The version is checked as well as the
// capability: a capability outlives the agent that reported it when a host goes
// back to an older one (a restored VM did, live: its 1.8.40 agent still showed
// allow_prefixes, took a range, and applied no isolation at all).
func (s *Server) takesAllowRanges(endpointID string) bool {
	ep, err := s.store.GetEndpoint(endpointID)
	return err == nil && ep != nil && agentTakesAllowRanges(ep)
}

func agentTakesAllowRanges(ep *storage.Endpoint) bool {
	if ep.DriverVersion != "" && compareVersions(ep.DriverVersion, allowPrefixesAgentVersion) < 0 {
		return false
	}
	return parseResponseCapabilities(ep.ResponseCapabilities).AllowPrefixes
}

// allowRangesProblem refuses ranges for an agent that would reject the grant.
func (s *Server) allowRangesProblem(endpointID string, allow []string) string {
	for _, a := range allow {
		if strings.Contains(a, "/") && !s.takesAllowRanges(endpointID) {
			return "allow_ips: " + a + " is a range, and the agent on " + endpointID + " enforces single addresses only; update the agent or name addresses"
		}
	}
	return ""
}

// fabricPolicy is an endpoint's compiled trust and the part of it its agent
// can enforce.
type fabricPolicy struct {
	trustfabric.Policy
	Enforced    []string `json:"enforced"`
	NotEnforced []string `json:"not_enforced,omitempty"`
	// Names are the applicable name rules and what the hub resolved them to.
	Names []storage.TrustNameAnswer `json:"names,omitempty"`
}

func (s *Server) fabricPolicyFor(endpointID string, now time.Time) (fabricPolicy, error) {
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		return fabricPolicy{}, err
	}
	if ep == nil {
		return fabricPolicy{}, fmt.Errorf("endpoint %s not found", endpointID)
	}
	rules, err := s.store.TrustRules()
	if err != nil {
		return fabricPolicy{}, err
	}
	answers, err := s.store.TrustNameAnswers()
	if err != nil {
		return fabricPolicy{}, err
	}
	return compileFabric(ep, rules, answers, now), nil
}

func fabricEndpoint(ep *storage.Endpoint) trustfabric.Endpoint {
	return trustfabric.Endpoint{ID: ep.ID, TenantID: ep.TenantID, LocationID: ep.LocationID, Role: ep.RoleTag}
}

// compileFabric is an endpoint's policy under the given rules and name answers.
func compileFabric(ep *storage.Endpoint, rules []trustfabric.Rule, answers map[string]storage.TrustNameAnswer, now time.Time) fabricPolicy {
	return compileFabricFor(fabricEndpoint(ep), agentTakesAllowRanges(ep), rules, answers, now)
}

func compileFabricFor(fe trustfabric.Endpoint, ranges bool, rules []trustfabric.Rule, answers map[string]storage.TrustNameAnswer, now time.Time) fabricPolicy {
	p := fabricPolicy{Policy: trustfabric.Compile(fe, trustfabric.ExpandNames(fe, rules, answerAddrs(answers), now), now)}
	listed := map[string]bool{}
	for _, r := range rules {
		if r.Kind == trustfabric.KindFQDN && r.Active(now) && r.AppliesTo(fe) && !listed[r.Value] {
			listed[r.Value] = true
			a, ok := answers[r.Value]
			if !ok {
				a = storage.TrustNameAnswer{Name: r.Value}
			}
			p.Names = append(p.Names, a)
		}
	}
	p.Enforced, p.NotEnforced = allowEntries(p.Policy, ranges, nameAddressRanks(rules, p.Names, fe, now))
	for _, w := range p.Withheld {
		p.NotEnforced = append(p.NotEnforced, w.Reason)
	}
	return p
}

// nameAddressRanks orders the addresses that only a name put on the list: every
// name's newest answer first, then every name's second newest, and so on, so
// one name's old addresses cannot push out another name's current one. An
// address a rule also names outright is not here.
func nameAddressRanks(rules []trustfabric.Rule, names []storage.TrustNameAnswer, fe trustfabric.Endpoint, now time.Time) map[netip.Addr]int {
	ranks := map[netip.Addr]int{}
	for _, n := range names {
		for i, entry := range n.Addrs {
			a, err := netip.ParseAddr(entry.Addr)
			if err != nil {
				continue
			}
			if have, ok := ranks[a]; !ok || i+1 < have {
				ranks[a] = i + 1
			}
		}
	}
	for _, r := range rules {
		if r.Kind == trustfabric.KindFQDN || !r.Active(now) || !r.AppliesTo(fe) {
			continue
		}
		if pre := r.Prefix(); pre.IsSingleIP() {
			delete(ranks, pre.Addr())
		}
	}
	return ranks
}

// allowEntries turns a compiled policy into the list an agent can hold: what a
// rule names outright first (single addresses, then ranges, widest first), then
// what only a name put there, by rank. What does not fit stays closed and is
// reported.
func allowEntries(pol trustfabric.Policy, ranges bool, ranks map[netip.Addr]int) (enforced, notEnforced []string) {
	enforced = []string{}
	seen := map[netip.Addr]bool{}
	var addrs []netip.Addr
	var wide []netip.Prefix
	addAddr := func(a netip.Addr) {
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	for _, a := range pol.Addresses {
		addAddr(a)
	}
	for _, pre := range pol.Allow {
		hostBits := pre.Addr().BitLen() - pre.Bits()
		switch {
		case pre.IsSingleIP():
			addAddr(pre.Addr())
		case ranges && allowPrefixProblem(pre) == "":
			wide = append(wide, pre)
		case !ranges && hostBits < 31 && 1<<hostBits <= addressOnlyMaxRange:
			for a := pre.Addr(); pre.Contains(a); a = a.Next() {
				addAddr(a)
			}
		default:
			notEnforced = append(notEnforced, pre.String())
		}
	}
	if ranges {
		// A named address inside a range the list already carries needs no entry.
		kept := addrs[:0]
		for _, a := range addrs {
			covered := false
			for _, pre := range wide {
				covered = covered || pre.Contains(a)
			}
			if !covered {
				kept = append(kept, a)
			}
		}
		addrs = kept
	}
	type namedEntry struct {
		rank int
		addr netip.Addr
		text string
	}
	var ruleAddrs []netip.Addr
	var ruleWide []netip.Prefix
	var named []namedEntry
	for _, a := range addrs {
		if r := ranks[a]; r != 0 {
			named = append(named, namedEntry{r, a, a.String()})
		} else {
			ruleAddrs = append(ruleAddrs, a)
		}
	}
	for _, pre := range wide {
		// Compile merges neighbouring addresses; a range made only of what names
		// answered is still only as important as those names' answers.
		if r := namedRangeRank(pre, ranks); r != 0 {
			named = append(named, namedEntry{r, pre.Addr(), pre.String()})
		} else {
			ruleWide = append(ruleWide, pre)
		}
	}
	sort.Slice(ruleAddrs, func(i, j int) bool { return ruleAddrs[i].Less(ruleAddrs[j]) })
	sort.SliceStable(ruleWide, func(i, j int) bool { return ruleWide[i].Bits() < ruleWide[j].Bits() })
	sort.Slice(named, func(i, j int) bool {
		if named[i].rank != named[j].rank {
			return named[i].rank < named[j].rank
		}
		return named[i].addr.Less(named[j].addr)
	})
	for _, a := range ruleAddrs {
		enforced = append(enforced, a.String())
	}
	for _, pre := range ruleWide {
		enforced = append(enforced, pre.String())
	}
	for _, n := range named {
		enforced = append(enforced, n.text)
	}
	enforced, over := capAllowList(enforced)
	return enforced, append(notEnforced, over...)
}

// namedRangeRank is the best rank in a range every address of which came only
// from a name, or 0 if a rule has a part in it.
func namedRangeRank(pre netip.Prefix, ranks map[netip.Addr]int) int {
	hostBits := pre.Addr().BitLen() - pre.Bits()
	if hostBits >= 31 || 1<<hostBits > len(ranks) {
		return 0
	}
	count, best := 0, 0
	for a, r := range ranks {
		if pre.Contains(a) {
			count++
			if best == 0 || r < best {
				best = r
			}
		}
	}
	if count != 1<<hostBits {
		return 0
	}
	return best
}

// capAllowList keeps what an agent holds; the rest stays closed.
func capAllowList(list []string) (kept, over []string) {
	if len(list) <= maxAllowEntries {
		return list, nil
	}
	return list[:maxAllowEntries], list[maxAllowEntries:]
}

// unionAddrs merges address lists, first occurrence kept.
func unionAddrs(lists ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range lists {
		for _, a := range l {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// handleTrustRules lists (GET), creates (POST) and deletes (DELETE ?id=) rules.
func (s *Server) handleTrustRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.TrustRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rules == nil {
			rules = []trustfabric.Rule{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
	case http.MethodPost:
		var rule trustfabric.Rule
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
			return
		}
		rule.CreatedBy = r.Header.Get("X-Username")
		rule.Source = "operator"
		now := time.Now().UTC()
		if rule.ExpiresAt != nil && !rule.ExpiresAt.After(now) {
			writeJSONError(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		isolated, err := s.store.IsolatedEndpoints()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if strings.EqualFold(strings.TrimSpace(rule.ScopeType), trustfabric.ScopeEndpoint) &&
			strings.EqualFold(strings.TrimSpace(rule.Action), trustfabric.Allow) && rule.ExpiresAt == nil {
			for _, iso := range isolated {
				if iso.EndpointID == strings.TrimSpace(rule.ScopeID) {
					exp := now.Add(isolatedRuleTTL)
					rule.ExpiresAt = &exp
					break
				}
			}
		}
		created, err := s.store.CreateTrustRule(rule)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(r, "TRUST_RULE_CREATED", created.ID, describeRule(created))
		if created.Kind == trustfabric.KindFQDN {
			s.lookupTrustName(r.Context(), created.Value, now)
		}
		s.auditRuleDuringIsolation(r, isolated, created, "created")
		writeJSON(w, http.StatusCreated, created)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "id is required")
			return
		}
		isolated, err := s.store.IsolatedEndpoints()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		deleted, err := s.store.DeleteTrustRule(id)
		if errors.Is(err, storage.ErrTrustRuleNotFound) {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r, "TRUST_RULE_DELETED", deleted.ID, describeRule(deleted))
		s.auditRuleDuringIsolation(r, isolated, deleted, "deleted")
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "rule": deleted})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// auditRuleDuringIsolation records a rule change against every isolation in
// force that the rule applies to. The change does not alter that isolation's
// approved allow list; the record says what the fabric now says differently.
func (s *Server) auditRuleDuringIsolation(r *http.Request, isolated []storage.IsolationRecord, rule trustfabric.Rule, verb string) {
	for _, iso := range isolated {
		ep := trustfabric.Endpoint{ID: iso.EndpointID, TenantID: iso.TenantID, LocationID: iso.LocationID, Role: iso.Role}
		if !rule.AppliesTo(ep) {
			continue
		}
		id := iso.ID
		if id == "" {
			id = "unrecorded"
		}
		s.audit(r, "TRUST_RULE_DURING_ISOLATION", iso.EndpointID, fmt.Sprintf(
			"isolation %s (%s): rule %s %s: %s; takes effect at the next isolation", id, iso.Mode, rule.ID, verb, describeRule(rule)))
	}
}

func describeRule(r trustfabric.Rule) string {
	scope := r.ScopeType
	if r.ScopeID != "" {
		scope += " " + r.ScopeID
	}
	d := fmt.Sprintf("%s %s %s at %s", r.Action, r.Kind, r.Value, scope)
	if r.Port != 0 {
		d += fmt.Sprintf(" %s/%d", r.Proto, r.Port)
	} else if r.Proto != trustfabric.ProtoAny {
		d += " " + r.Proto
	}
	if r.Direction != trustfabric.DirBoth {
		d += " " + r.Direction
	}
	if r.Locked {
		d += " (locked)"
	}
	if r.ExpiresAt != nil {
		d += " until " + r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if r.Justification != "" {
		d += ": " + r.Justification
	}
	return d
}

// handleTrustEffective answers GET ?endpoint_id= with the endpoint's compiled
// policy, or with one decision when addr (and optionally port, proto,
// direction) is given.
func (s *Server) handleTrustEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	id := strings.TrimSpace(q.Get("endpoint_id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return
	}
	now := time.Now().UTC()
	p, err := s.fabricPolicyFor(id, now)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	resp := map[string]any{"endpoint_id": id, "policy": p}
	if raw := strings.TrimSpace(q.Get("addr")); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "addr is not an IP address")
			return
		}
		t := trustfabric.Target{Addr: addr.Unmap(), Proto: q.Get("proto"), Direction: q.Get("direction")}
		if ps := q.Get("port"); ps != "" {
			if _, err := fmt.Sscanf(ps, "%d", &t.Port); err != nil || t.Port < 0 || t.Port > 65535 {
				writeJSONError(w, http.StatusBadRequest, "port must be 0 to 65535")
				return
			}
		}
		ep, _ := s.store.GetEndpoint(id)
		rules, err := s.store.TrustRules()
		answers, aerr := s.store.TrustNameAnswers()
		if err != nil || aerr != nil || ep == nil {
			writeJSONError(w, http.StatusInternalServerError, "trust rules unavailable")
			return
		}
		resp["decision"] = trustfabric.Decide(fabricEndpoint(ep), trustfabric.ExpandNames(fabricEndpoint(ep), rules, answerAddrs(answers), now), t, now)
	}
	writeJSON(w, http.StatusOK, resp)
}

// recordIsolationSnapshot writes what the fabric said when an isolation began,
// under that isolation's id.
func (s *Server) recordIsolationSnapshot(r *http.Request, endpointID, mode string) {
	var rec *storage.IsolationRecord
	if all, err := s.store.IsolatedEndpoints(); err == nil {
		for i := range all {
			if all[i].EndpointID == endpointID {
				rec = &all[i]
				break
			}
		}
	}
	if rec == nil {
		return
	}
	if mode == isolationModeSelective {
		if err := s.store.SetIsolationMode(endpointID, mode); err == nil {
			rec.Mode = mode
		}
	}
	snap := map[string]any{"isolation_id": rec.ID, "mode": rec.Mode, "allow_ips": rec.AllowIPs}
	if p, err := s.fabricPolicyFor(endpointID, time.Now().UTC()); err == nil {
		snap["fabric"] = p
	}
	b, _ := json.Marshal(snap)
	s.audit(r, "ISOLATION_FABRIC_SNAPSHOT", endpointID, string(b))
}
