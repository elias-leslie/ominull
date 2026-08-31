package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The baseline isolation policy.
//
// Isolation is a default-deny with a small set of permits under it. Until now
// two of those permits were written into the agents: DNS to any resolver and
// DHCP to any server. Both were holes with a justification attached rather than
// policy - an isolated host could still reach every resolver on the internet
// over UDP/53 - and neither was visible to the person clicking Isolate.
//
// A baseline policy names the infrastructure an isolated host is still allowed
// to reach, by service and by destination. It is authored in the console, it is
// resolved by the hub, and the agents enforce exactly what they are given and
// nothing more. Only the hub pinhole and loopback remain compiled in: those two
// are what make an isolation reversible, so they are not the operator's to
// remove by accident.
//
// An empty baseline is legal and means exactly what it says - hub and loopback
// only. It is not a footgun, because the readiness gate refuses to isolate a
// host whose observed services the baseline does not cover.

// ServiceSpec is what a named service resolves to on the wire. The catalogue is
// deliberately short: three services people actually name, plus "custom" for
// everything else. A longer shipped catalogue is a list of guesses about
// somebody else's network.
type ServiceSpec struct {
	Service  string `json:"service"`
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	// Ports are remote ports. For DHCP that is the *server* port in both
	// directions: a renewal is a request out and a reply in, and the reply is a
	// new inbound flow rather than part of the outbound one.
	Ports []int `json:"ports"`
	// Broadcast destinations are permitted alongside whatever the operator
	// names. DHCP only: a renewal is unicast to the server, but a REBIND or a
	// DISCOVER after a failed renewal is a broadcast, and a baseline that
	// permitted only the server address would hold the lease right up until the
	// moment the host actually needed to fall back. These addresses are
	// link-local by construction and cannot be routed off the segment.
	Broadcast []string `json:"broadcast,omitempty"`
	Why       string   `json:"why"`
}

var baselineCatalogue = []ServiceSpec{
	{
		Service: "dns", Label: "DNS", Protocol: "udp", Ports: []int{53},
		Why: "Name resolution. UDP only - TCP/53 to an arbitrary host is a general-purpose tunnel, not a lookup.",
	},
	{
		Service: "dhcp", Label: "DHCP", Protocol: "udp", Ports: []int{67, 547},
		Broadcast: []string{"255.255.255.255", "ff02::1:2"},
		Why:       "Lease renewal. Without it the lease expires and the host loses the address the hub reaches it on.",
	},
	{
		Service: "ntp", Label: "NTP", Protocol: "udp", Ports: []int{123},
		Why: "Clock synchronisation. A host whose clock drifts far enough stops being able to verify the hub's certificate.",
	},
	{
		Service: "custom", Label: "Custom", Protocol: "", Ports: nil,
		Why: "Anything else this network needs: a domain controller, a management VLAN, a licence server. Name the protocol and port yourself.",
	},
}

// BaselineCatalogue returns the shipped service catalogue. It lives in the repo
// rather than being served from an endpoint: versioned with the hub, reviewable
// in a pull request, and it works on an airgapped deployment.
func BaselineCatalogue() []ServiceSpec { return baselineCatalogue }

func serviceSpec(name string) (ServiceSpec, bool) {
	for _, s := range baselineCatalogue {
		if s.Service == name {
			return s, true
		}
	}
	return ServiceSpec{}, false
}

// BaselineRule is one permitted destination for one named service.
type BaselineRule struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Service     string    `json:"service"`
	Destination string    `json:"destination"`
	Protocol    string    `json:"protocol,omitempty"`
	Port        int       `json:"port,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// BaselinePolicy is a named set of rules bound to a scope.
type BaselinePolicy struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Scope      string         `json:"scope"`
	ScopeValue string         `json:"scope_value"`
	Enabled    bool           `json:"enabled"`
	Rules      []BaselineRule `json:"rules"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ObservedService is one service an endpoint reports actually using, with the
// destination it uses it against. This is what the baseline is checked against.
type ObservedService struct {
	Service     string `json:"service"`
	Destination string `json:"destination"`
	// Source names where the agent read it - "resolv.conf", "dhcp lease",
	// "scutil" - so a surprising entry can be chased rather than argued about.
	Source string `json:"source,omitempty"`
}

// Readiness is the endpoint's own answer to "can I still be released after
// this?", reported on every heartbeat.
type Readiness struct {
	// EnforcementEngine is "ok" or a named reason. Required.
	EnforcementEngine string `json:"enforcement_engine"`
	// HubLiteral is the address the pinhole will be written for. Required: an
	// agent that cannot reduce its hub to an address cannot write the one rule
	// that makes the isolation reversible.
	HubLiteral string `json:"hub_literal"`
	// AddressOrigin is "dhcp" or "static" - whether the DHCP permit is on the
	// critical path for this host at all.
	AddressOrigin string `json:"address_origin,omitempty"`
	// LastApplied is what the agent read back out of the kernel, not what it
	// believes it wrote. The distinction is the whole point of the check.
	LastApplied string    `json:"last_applied,omitempty"`
	ReportedAt  time.Time `json:"reported_at"`
}

// Ready reports whether the two required checks passed.
func (r Readiness) Ready() (bool, string) {
	if r.EnforcementEngine != "ok" {
		reason := r.EnforcementEngine
		if reason == "" {
			reason = "the endpoint has not reported whether it can apply rules at all"
		}
		return false, "enforcement_engine: " + reason
	}
	if r.HubLiteral == "" {
		return false, "hub_literal: the endpoint could not reduce its hub URL to an address, so the pinhole that makes this reversible cannot be written"
	}
	return true, ""
}

func (s *Store) initBaselineSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS baseline_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		scope TEXT NOT NULL DEFAULT 'global',
		scope_value TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS baseline_rules (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL REFERENCES baseline_policies(id) ON DELETE CASCADE,
		service TEXT NOT NULL,
		destination TEXT NOT NULL,
		protocol TEXT NOT NULL DEFAULT '',
		port INTEGER NOT NULL DEFAULT 0,
		note TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_baseline_rules_policy ON baseline_rules(policy_id);
	CREATE INDEX IF NOT EXISTS idx_baseline_policies_scope ON baseline_policies(scope, scope_value);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	for _, m := range []string{
		"ALTER TABLE endpoints ADD COLUMN observed_services TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN readiness TEXT DEFAULT ''",
	} {
		if err := runAdditiveMigration(s.db, m); err != nil {
			return err
		}
	}
	return nil
}

// ValidateBaselineRule checks a rule before it is stored. The destination
// reaches an agent's firewall layer, so only addresses belong in it.
func ValidateBaselineRule(r *BaselineRule) error {
	spec, ok := serviceSpec(r.Service)
	if !ok {
		names := make([]string, 0, len(baselineCatalogue))
		for _, s := range baselineCatalogue {
			names = append(names, s.Service)
		}
		return fmt.Errorf("service: %q is not one of %s", r.Service, strings.Join(names, ", "))
	}

	r.Destination = strings.TrimSpace(r.Destination)
	if r.Destination == "" {
		return fmt.Errorf("destination: required - a baseline rule names one host, never a range and never \"any\"")
	}
	ip := net.ParseIP(r.Destination)
	if ip == nil {
		return fmt.Errorf("destination: %q is not an IP address", r.Destination)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("destination: %q means \"any host\", which is the hole this policy exists to close", r.Destination)
	}
	r.Destination = ip.String()

	if r.Service == "custom" {
		switch strings.ToLower(strings.TrimSpace(r.Protocol)) {
		case "udp":
			r.Protocol = "udp"
		case "tcp":
			r.Protocol = "tcp"
		default:
			return fmt.Errorf("protocol: a custom rule must name udp or tcp")
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("port: a custom rule must name a port between 1 and 65535")
		}
	} else {
		// The catalogue decides the wire details for a named service. Letting a
		// rule override them would mean "DNS" in the console and something else
		// in the kernel.
		r.Protocol = spec.Protocol
		r.Port = 0
	}
	r.Note = strings.TrimSpace(r.Note)
	return nil
}

func validScope(scope string) bool {
	switch scope {
	case "global", "tenant", "location", "endpoint":
		return true
	}
	return false
}

// SaveBaselinePolicy creates or replaces a policy and its whole rule set. The
// rules are written as a set rather than patched one at a time: a half-applied
// allow-list is the failure this design exists to avoid.
func (s *Store) SaveBaselinePolicy(p *BaselinePolicy) error {
	if p.Name = strings.TrimSpace(p.Name); p.Name == "" {
		return fmt.Errorf("name: required")
	}
	if p.Scope == "" {
		p.Scope = "global"
	}
	if !validScope(p.Scope) {
		return fmt.Errorf("scope: %q is not one of global, tenant, location, endpoint", p.Scope)
	}
	if p.Scope != "global" && strings.TrimSpace(p.ScopeValue) == "" {
		return fmt.Errorf("scope_value: required when scope is %q", p.Scope)
	}
	if p.Scope == "global" {
		p.ScopeValue = ""
	}
	for i := range p.Rules {
		if err := ValidateBaselineRule(&p.Rules[i]); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if p.ID == "" {
		p.ID = "baseline-" + uuid.New().String()
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO baseline_policies (id, name, scope, scope_value, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, scope=excluded.scope, scope_value=excluded.scope_value,
			enabled=excluded.enabled, updated_at=excluded.updated_at`,
		p.ID, p.Name, p.Scope, p.ScopeValue, boolToInt(p.Enabled), p.CreatedAt, p.UpdatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM baseline_rules WHERE policy_id = ?", p.ID); err != nil {
		return err
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			r.ID = "brule-" + uuid.New().String()
		}
		r.PolicyID = p.ID
		if r.CreatedAt.IsZero() {
			r.CreatedAt = now
		}
		if _, err := tx.Exec(`
			INSERT INTO baseline_rules (id, policy_id, service, destination, protocol, port, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.PolicyID, r.Service, r.Destination, r.Protocol, r.Port, r.Note, r.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ListBaselinePolicies returns every policy with its rules, newest scope first.
func (s *Store) ListBaselinePolicies() ([]BaselinePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listBaselinePoliciesLocked("", "")
}

// listBaselinePoliciesLocked is the unlocked body. Every caller already holds
// the lock: this package's convention is that a method never calls another
// locking method, because sync.RWMutex is not reentrant and a writer queueing
// between the two acquisitions deadlocks the whole hub.
func (s *Store) listBaselinePoliciesLocked(where string, arg string) ([]BaselinePolicy, error) {
	q := "SELECT id, name, scope, scope_value, enabled, created_at, updated_at FROM baseline_policies"
	var rows *sql.Rows
	var err error
	if where != "" {
		rows, err = s.db.Query(q+" "+where, arg)
	} else {
		rows, err = s.db.Query(q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := []BaselinePolicy{}
	byID := map[string]int{}
	for rows.Next() {
		var p BaselinePolicy
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.Scope, &p.ScopeValue, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.Rules = []BaselineRule{}
		byID[p.ID] = len(policies)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return policies, nil
	}

	rrows, err := s.db.Query("SELECT id, policy_id, service, destination, protocol, port, note, created_at FROM baseline_rules ORDER BY service, destination")
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var r BaselineRule
		if err := rrows.Scan(&r.ID, &r.PolicyID, &r.Service, &r.Destination, &r.Protocol, &r.Port, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		if idx, ok := byID[r.PolicyID]; ok {
			policies[idx].Rules = append(policies[idx].Rules, r)
		}
	}
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Scope != policies[j].Scope {
			return scopeRank(policies[i].Scope) < scopeRank(policies[j].Scope)
		}
		return policies[i].Name < policies[j].Name
	})
	return policies, rrows.Err()
}

func scopeRank(scope string) int {
	switch scope {
	case "global":
		return 0
	case "tenant":
		return 1
	case "location":
		return 2
	case "endpoint":
		return 3
	}
	return 4
}

// DeleteBaselinePolicy removes a policy and its rules.
func (s *Store) DeleteBaselinePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM baseline_rules WHERE policy_id = ?", id); err != nil {
		return err
	}
	res, err := s.db.Exec("DELETE FROM baseline_policies WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking deleted baseline policy %q: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("no baseline policy %q", id)
	}
	return nil
}

// SetEndpointObservations records what an endpoint reports about itself: the
// services it actually uses, and whether it believes it could still be released
// after an isolation. Both arrive on the heartbeat the agent already sends.
func (s *Store) SetEndpointObservations(endpointID string, services []ObservedService, r Readiness) error {
	if services == nil {
		services = []ObservedService{}
	}
	cleaned := make([]ObservedService, 0, len(services))
	seen := map[string]bool{}
	for _, o := range services {
		o.Service = strings.ToLower(strings.TrimSpace(o.Service))
		o.Destination = strings.TrimSpace(o.Destination)
		if o.Service == "" || o.Destination == "" {
			continue
		}
		// An endpoint is not a trusted author. It reports what it observes and
		// the hub stores it for a person to look at; anything that is not an
		// address cannot be compared against a rule, so it is dropped rather
		// than kept as something that will never match.
		ip := net.ParseIP(o.Destination)
		if ip == nil {
			continue
		}
		o.Destination = ip.String()
		key := o.Service + "|" + o.Destination
		if seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, o)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].Service != cleaned[j].Service {
			return cleaned[i].Service < cleaned[j].Service
		}
		return cleaned[i].Destination < cleaned[j].Destination
	})

	svcJSON, err := json.Marshal(cleaned)
	if err != nil {
		return err
	}
	r.ReportedAt = time.Now().UTC()
	rdyJSON, err := json.Marshal(r)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec("UPDATE endpoints SET observed_services = ?, readiness = ? WHERE id = ?",
		string(svcJSON), string(rdyJSON), endpointID)
	return err
}

// BaselineResolution is everything a person needs to decide whether isolating
// this host is safe, and everything an agent needs to enforce it.
type BaselineResolution struct {
	EndpointID string         `json:"endpoint_id"`
	Rules      []BaselineRule `json:"rules"`
	// Policies names the policies that contributed, so a surprising rule can be
	// traced back to the thing that authored it.
	Policies  []string          `json:"policies"`
	Observed  []ObservedService `json:"observed"`
	Uncovered []ObservedService `json:"uncovered"`
	Readiness Readiness         `json:"readiness"`
	// ReadinessReported is false when the endpoint has never answered - an
	// agent too old to report, or one that has not checked in since the hub
	// learned to ask.
	ReadinessReported bool `json:"readiness_reported"`
}

// ResolveBaseline computes the effective baseline for one endpoint together
// with what that endpoint reports about itself.
//
// Scopes union rather than override. An allow-list where a narrow policy
// silently replaced a broad one would let someone remove the DNS rule for a
// whole site by writing an unrelated endpoint policy, and they would find out
// when the site went quiet.
func (s *Store) ResolveBaseline(endpointID string) (BaselineResolution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := BaselineResolution{EndpointID: endpointID, Rules: []BaselineRule{}, Policies: []string{}, Observed: []ObservedService{}, Uncovered: []ObservedService{}}

	var tenantID, locationID, observed, readiness string
	err := s.db.QueryRow(
		"SELECT tenant_id, COALESCE(location_id,''), COALESCE(observed_services,''), COALESCE(readiness,'') FROM endpoints WHERE id = ?",
		endpointID).Scan(&tenantID, &locationID, &observed, &readiness)
	if err != nil {
		return res, err
	}
	if observed != "" {
		_ = json.Unmarshal([]byte(observed), &res.Observed)
	}
	if readiness != "" && readiness != "null" {
		if err := json.Unmarshal([]byte(readiness), &res.Readiness); err == nil {
			res.ReadinessReported = true
		}
	}

	policies, err := s.listBaselinePoliciesLocked("", "")
	if err != nil {
		return res, err
	}

	seen := map[string]bool{}
	for _, p := range policies {
		if !p.Enabled || !p.appliesTo(endpointID, tenantID, locationID) {
			continue
		}
		res.Policies = append(res.Policies, p.Name)
		for _, r := range p.Rules {
			key := r.Service + "|" + r.Destination + "|" + r.Protocol + "|" + fmt.Sprint(r.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			res.Rules = append(res.Rules, r)
		}
	}
	sort.Slice(res.Rules, func(i, j int) bool {
		if res.Rules[i].Service != res.Rules[j].Service {
			return res.Rules[i].Service < res.Rules[j].Service
		}
		return res.Rules[i].Destination < res.Rules[j].Destination
	})

	covered := map[string]bool{}
	for _, r := range res.Rules {
		covered[r.Service+"|"+r.Destination] = true
	}
	for _, o := range res.Observed {
		if covered[o.Service+"|"+o.Destination] || alwaysPermitted(o.Destination) {
			continue
		}
		res.Uncovered = append(res.Uncovered, o)
	}
	return res, nil
}

// alwaysPermitted reports whether a destination is already reachable under an
// isolation without any policy naming it.
//
// Loopback is compiled into every agent and cannot be removed from the console,
// so a service on a loopback address is covered whatever the baseline says. This
// is not a corner case: systemd-resolved puts the resolver on 127.0.0.53, so
// without this every modern Linux host would sit permanently "not ready" over a
// flow that was never going to be cut - and a gate that cries wolf is a gate
// people learn to click past.
func alwaysPermitted(destination string) bool {
	ip := net.ParseIP(strings.TrimSpace(destination))
	return ip != nil && ip.IsLoopback()
}

func (p BaselinePolicy) appliesTo(endpointID, tenantID, locationID string) bool {
	switch p.Scope {
	case "global":
		return true
	case "tenant":
		return p.ScopeValue == tenantID
	case "location":
		return p.ScopeValue == locationID
	case "endpoint":
		return p.ScopeValue == endpointID
	}
	return false
}

// ProposeBaselineRules turns what an endpoint observed into rules an operator
// can look at, edit and approve. It proposes; it never applies. That split is
// the whole point: the agent knows what the host talks to, and only a person
// knows whether it should.
func ProposeBaselineRules(observed []ObservedService) []BaselineRule {
	out := []BaselineRule{}
	now := time.Now().UTC()
	seen := map[string]bool{}
	for _, o := range observed {
		if _, ok := serviceSpec(o.Service); !ok {
			continue
		}
		// Proposing a rule for a loopback resolver would put a row in the policy
		// that permits something already permitted, and invite an operator to
		// wonder what it is for.
		if alwaysPermitted(o.Destination) {
			continue
		}
		key := o.Service + "|" + o.Destination
		if seen[key] {
			continue
		}
		seen[key] = true
		r := BaselineRule{
			Service:     o.Service,
			Destination: o.Destination,
			Note:        "proposed from what the endpoint reported",
			CreatedAt:   now,
		}
		if err := ValidateBaselineRule(&r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// BaselineWireRule is one permit as an agent enforces it: a destination, a
// protocol and a remote port, with nothing left to interpret. The hub expands
// the named services here rather than shipping the catalogue to three agents in
// three languages, because a catalogue that has to agree across four codebases
// is a catalogue that will eventually disagree.
type BaselineWireRule struct {
	Service     string `json:"service"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
}

// BaselineWireRules expands resolved rules into what the agents enforce.
// BaselineWireLimit is how many expanded rules an agent can actually hold:
// OMINULL_MAX_BASELINE_RULES in agent/include/agent.h and MAX_BASELINE_RULES in
// agent/linux/main.c, which are the same number. Past it the agent reads the
// first N and drops the rest, and the heartbeat reply starts crowding the
// agent's 16KB response buffer - so an over-large policy would quietly become a
// *subset* of itself on an isolated host, which is the one failure mode this
// whole design exists to prevent. The hub trims to this number and refuses to
// isolate while it is doing so.
const BaselineWireLimit = 64

// CapBaselineWireRules trims an expansion to what an agent can hold, and says
// whether it had to. The input is already in a deterministic order, so the same
// policy always trims to the same rules rather than to whatever the map
// iteration produced this time.
func CapBaselineWireRules(rules []BaselineWireRule) ([]BaselineWireRule, bool) {
	if len(rules) <= BaselineWireLimit {
		return rules, false
	}
	return rules[:BaselineWireLimit], true
}

func BaselineWireRules(rules []BaselineRule) []BaselineWireRule {
	out := []BaselineWireRule{}
	seen := map[string]bool{}
	add := func(service, dest, proto string, port int) {
		key := fmt.Sprintf("%s|%s|%s|%d", service, dest, proto, port)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, BaselineWireRule{Service: service, Destination: dest, Protocol: proto, Port: port})
	}

	haveDHCP := false
	for _, r := range rules {
		spec, ok := serviceSpec(r.Service)
		if !ok {
			continue
		}
		if r.Service == "custom" {
			add(r.Service, r.Destination, r.Protocol, r.Port)
			continue
		}
		if r.Service == "dhcp" {
			haveDHCP = true
		}
		// A named service's ports are per address family where the families
		// disagree. DHCP is the one that does: the v4 server listens on 67 and
		// the v6 server on 547, and sending a host a permit for the other
		// family's port is a rule that can never match.
		isV6 := strings.Contains(r.Destination, ":")
		for _, port := range spec.Ports {
			if r.Service == "dhcp" {
				if isV6 != (port == 547) {
					continue
				}
			}
			add(r.Service, r.Destination, spec.Protocol, port)
		}
	}

	// The broadcast destinations ride along with DHCP and only when the
	// operator has permitted DHCP at all. A renewal is unicast to the server,
	// but a REBIND or a DISCOVER after a failed renewal is a broadcast - so a
	// baseline naming only the server address would hold the lease right up to
	// the moment the host actually needed the fallback. These addresses are
	// link-local by construction and cannot be routed off the segment.
	if haveDHCP {
		spec, _ := serviceSpec("dhcp")
		for _, b := range spec.Broadcast {
			if strings.Contains(b, ":") {
				add("dhcp", b, spec.Protocol, 547)
			} else {
				add("dhcp", b, spec.Protocol, 67)
			}
		}
	}
	return out
}
