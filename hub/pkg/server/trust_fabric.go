package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
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
//     before the owner approves, so the signed grant carries exactly what was
//     approved; a rule changed later does not reach an isolation in force.
//   - omitted: the request's own allow_ips only, as before modes existed.
//
// Agents that report allow_prefixes enforce address ranges (no wider than /8
// for IPv4 or /32 for IPv6); older agents take single addresses and refuse a
// grant naming a range. For those, a fabric range wider than one address is
// reported as not enforced rather than opened, so selective isolation errs
// closed.

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
// ranges in its isolation allow list.
func (s *Server) takesAllowRanges(endpointID string) bool {
	ep, err := s.store.GetEndpoint(endpointID)
	return err == nil && ep != nil && parseResponseCapabilities(ep.ResponseCapabilities).AllowPrefixes
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
	p := fabricPolicy{Policy: trustfabric.Compile(trustfabric.Endpoint{
		ID: ep.ID, TenantID: ep.TenantID, LocationID: ep.LocationID, Role: ep.RoleTag,
	}, rules, now)}
	p.Enforced = []string{}
	if parseResponseCapabilities(ep.ResponseCapabilities).AllowPrefixes {
		for _, pre := range p.Allow {
			switch {
			case allowPrefixProblem(pre) != "":
				p.NotEnforced = append(p.NotEnforced, pre.String())
			case pre.IsSingleIP():
				p.Enforced = append(p.Enforced, pre.Addr().String())
			default:
				p.Enforced = append(p.Enforced, pre.String())
			}
		}
		return p, nil
	}
	named := map[netip.Addr]bool{}
	for _, a := range p.Addresses {
		named[a] = true
		p.Enforced = append(p.Enforced, a.String())
	}
	for _, pre := range p.Allow {
		if !pre.IsSingleIP() || !named[pre.Addr()] {
			p.NotEnforced = append(p.NotEnforced, pre.String())
		}
	}
	return p, nil
}

// fabricPin is a selective isolation's expanded fabric, kept under its
// approval id until the approved request returns. In memory: a hub restart
// in between means the request is expanded again, and an approval whose
// list then differs is refused (fails closed) and must be asked for again.
type fabricPin struct {
	endpointID  string
	enforced    []string
	notEnforced []string
	at          time.Time
}

type fabricPinStore struct {
	mu   sync.Mutex
	pins map[string]fabricPin
}

const (
	fabricPinTTL = 24 * time.Hour
	fabricPinMax = 1024
)

func (ps *fabricPinStore) put(approvalID string, p fabricPin) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.pins == nil {
		ps.pins = map[string]fabricPin{}
	}
	now := time.Now()
	for id, old := range ps.pins {
		if now.Sub(old.at) > fabricPinTTL || len(ps.pins) >= fabricPinMax {
			delete(ps.pins, id)
		}
	}
	p.at = now
	ps.pins[approvalID] = p
}

func (ps *fabricPinStore) get(approvalID, endpointID string) (fabricPin, bool) {
	if approvalID == "" {
		return fabricPin{}, false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.pins[approvalID]
	if !ok || p.endpointID != endpointID || time.Since(p.at) > fabricPinTTL {
		return fabricPin{}, false
	}
	return p, true
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
		if err != nil || ep == nil {
			writeJSONError(w, http.StatusInternalServerError, "trust rules unavailable")
			return
		}
		resp["decision"] = trustfabric.Decide(trustfabric.Endpoint{
			ID: ep.ID, TenantID: ep.TenantID, LocationID: ep.LocationID, Role: ep.RoleTag,
		}, rules, t, now)
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
