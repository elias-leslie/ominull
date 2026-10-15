// Package trustfabric decides which destinations an isolated endpoint may
// still reach, from rules written at five scopes.
//
// Scopes follow the hub's existing hierarchy, so no separate scope table is
// kept: provider (the whole hub), client (tenant), site (location), group
// (role tag) and endpoint. A rule applies to an endpoint when its scope names
// the endpoint's tenant, location, role or id, or is the provider scope.
//
// Precedence, strongest first:
//
//  1. The floor: the hub's own addresses, loopback and DHCP. Compiled in,
//     never overridable, so no rule can cut an endpoint off from the hub that
//     must release it.
//  2. Locked rules. A locked rule cannot be overridden from below: among the
//     locked rules that match, the least specific scope wins, so a provider
//     lock beats everything. Deny beats allow at the same scope.
//  3. Otherwise the most specific match wins: scope first (endpoint, group,
//     site, client, provider), then the longer prefix, then a rule naming a
//     port or protocol over one that does not. Deny beats allow on a tie.
//  4. No match: not trusted.
//
// Allows from different scopes therefore add up unless a deny at a more
// specific scope (or a locked deny above) takes the target back out.
//
// Everything here is pure: callers pass the rules and the time.
package trustfabric

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Scope types, least specific first.
const (
	ScopeProvider = "provider"
	ScopeClient   = "client"
	ScopeSite     = "site"
	ScopeGroup    = "group"
	ScopeEndpoint = "endpoint"
)

var scopeLevel = map[string]int{ScopeProvider: 0, ScopeClient: 1, ScopeSite: 2, ScopeGroup: 3, ScopeEndpoint: 4}

// Actions, directions and protocols.
const (
	Allow = "allow"
	Deny  = "deny"

	DirBoth = "both"
	DirIn   = "in"
	DirOut  = "out"

	ProtoAny = "any"
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// Decision bases.
const (
	BasisFloor    = "floor"
	BasisLocked   = "locked"
	BasisSpecific = "most_specific"
	BasisDefault  = "default"
)

// Rule is one trust rule. Kind is "ip" (a single address) or "cidr".
type Rule struct {
	ID            string     `json:"id"`
	ScopeType     string     `json:"scope_type"`
	ScopeID       string     `json:"scope_id"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	Action        string     `json:"action"`
	Direction     string     `json:"direction"`
	Port          int        `json:"port"`
	Proto         string     `json:"proto"`
	Locked        bool       `json:"locked"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Justification string     `json:"justification"`
	CreatedBy     string     `json:"created_by"`
	Source        string     `json:"source"`
	CreatedAt     time.Time  `json:"created_at"`

	prefix netip.Prefix
}

// Endpoint is what scope matching needs to know about an endpoint, plus the
// hub addresses its floor keeps open.
type Endpoint struct {
	ID         string
	TenantID   string
	LocationID string
	Role       string
	HubAddrs   []netip.Addr
}

// Target is one destination question. Port 0, an empty protocol or an empty
// direction ask about the address as a whole.
type Target struct {
	Addr      netip.Addr
	Port      int
	Proto     string
	Direction string
}

// Decision is the answer for one target and the rule that gave it.
type Decision struct {
	Action string `json:"action"`
	Basis  string `json:"basis"`
	RuleID string `json:"rule_id,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

var errRule = errors.New("invalid trust rule")

// Normalize validates a rule and fills defaults (direction both, protocol
// any, a cidr value masked to its prefix). It returns the rule as stored.
func Normalize(r Rule) (Rule, error) {
	bad := func(format string, a ...any) (Rule, error) {
		return Rule{}, fmt.Errorf("%w: %s", errRule, fmt.Sprintf(format, a...))
	}
	r.ScopeType = strings.ToLower(strings.TrimSpace(r.ScopeType))
	r.ScopeID = strings.TrimSpace(r.ScopeID)
	if _, ok := scopeLevel[r.ScopeType]; !ok {
		return bad("scope_type must be provider, client, site, group or endpoint")
	}
	if r.ScopeType == ScopeProvider {
		r.ScopeID = ""
	} else if r.ScopeID == "" || len(r.ScopeID) > 128 {
		return bad("scope_id is required for a %s rule", r.ScopeType)
	}
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	if r.Action != Allow && r.Action != Deny {
		return bad("action must be allow or deny")
	}
	r.Direction = strings.ToLower(strings.TrimSpace(r.Direction))
	if r.Direction == "" {
		r.Direction = DirBoth
	}
	if r.Direction != DirBoth && r.Direction != DirIn && r.Direction != DirOut {
		return bad("direction must be both, in or out")
	}
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	if r.Proto == "" {
		r.Proto = ProtoAny
	}
	if r.Proto != ProtoAny && r.Proto != ProtoTCP && r.Proto != ProtoUDP {
		return bad("proto must be any, tcp or udp")
	}
	if r.Port < 0 || r.Port > 65535 {
		return bad("port must be 0 (any) to 65535")
	}
	if r.Port != 0 && r.Proto == ProtoAny {
		return bad("a port needs a protocol")
	}
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	value := strings.TrimSpace(r.Value)
	switch r.Kind {
	case "ip":
		a, err := netip.ParseAddr(value)
		if err != nil || a.Zone() != "" {
			return bad("value is not an IP address")
		}
		a = a.Unmap()
		r.Value, r.prefix = a.String(), netip.PrefixFrom(a, a.BitLen())
	case "cidr":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return bad("value is not a CIDR prefix")
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return bad("an IPv4-mapped prefix must be /96 or longer")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if p.Bits() == 0 && r.Action == Allow {
			return bad("an allow rule may not cover a whole address family")
		}
		r.Value, r.prefix = p.String(), p
	default:
		return bad("kind must be ip or cidr")
	}
	if len(r.Justification) > 512 {
		return bad("justification is longer than 512 characters")
	}
	return r, nil
}

// Prefix is the address range a normalized rule covers.
func (r Rule) Prefix() netip.Prefix {
	if !r.prefix.IsValid() {
		if n, err := Normalize(r); err == nil {
			return n.prefix
		}
	}
	return r.prefix
}

// Active reports whether the rule is in force at now.
func (r Rule) Active(now time.Time) bool { return r.ExpiresAt == nil || now.Before(*r.ExpiresAt) }

// AppliesTo reports whether the rule's scope covers the endpoint.
func (r Rule) AppliesTo(ep Endpoint) bool {
	switch r.ScopeType {
	case ScopeProvider:
		return true
	case ScopeClient:
		return r.ScopeID == ep.TenantID
	case ScopeSite:
		return r.ScopeID == ep.LocationID
	case ScopeGroup:
		return r.ScopeID == ep.Role
	case ScopeEndpoint:
		return r.ScopeID == ep.ID
	}
	return false
}

func (r Rule) matches(t Target) bool {
	if !r.Prefix().Contains(t.Addr.Unmap()) {
		return false
	}
	if t.Port != 0 && r.Port != 0 && r.Port != t.Port {
		return false
	}
	if t.Port == 0 && r.Port != 0 {
		return false
	}
	if t.Proto != "" && t.Proto != ProtoAny && r.Proto != ProtoAny && r.Proto != t.Proto {
		return false
	}
	if (t.Proto == "" || t.Proto == ProtoAny) && r.Proto != ProtoAny {
		return false
	}
	if t.Direction != "" && t.Direction != DirBoth && r.Direction != DirBoth && r.Direction != t.Direction {
		return false
	}
	if (t.Direction == "" || t.Direction == DirBoth) && r.Direction != DirBoth {
		return false
	}
	return true
}

// IsFloor reports whether the floor keeps the target open whatever the rules
// say: the hub's addresses, loopback, and DHCP (UDP 67/68).
func IsFloor(ep Endpoint, t Target) bool {
	a := t.Addr.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, h := range ep.HubAddrs {
		if h.Unmap() == a {
			return true
		}
	}
	return t.Proto == ProtoUDP && (t.Port == 67 || t.Port == 68)
}

// stronger reports whether a outranks b when no lock is involved.
func stronger(a, b Rule) bool {
	if la, lb := scopeLevel[a.ScopeType], scopeLevel[b.ScopeType]; la != lb {
		return la > lb
	}
	if pa, pb := a.Prefix().Bits(), b.Prefix().Bits(); pa != pb {
		return pa > pb
	}
	if (a.Port != 0) != (b.Port != 0) {
		return a.Port != 0
	}
	if (a.Proto != ProtoAny) != (b.Proto != ProtoAny) {
		return a.Proto != ProtoAny
	}
	if (a.Direction != DirBoth) != (b.Direction != DirBoth) {
		return a.Direction != DirBoth
	}
	return a.Action == Deny && b.Action == Allow
}

// strongerLocked: the least specific lock wins, deny over allow at a level.
func strongerLocked(a, b Rule) bool {
	if la, lb := scopeLevel[a.ScopeType], scopeLevel[b.ScopeType]; la != lb {
		return la < lb
	}
	return a.Action == Deny && b.Action == Allow
}

// Decide answers one target for one endpoint.
func Decide(ep Endpoint, rules []Rule, t Target, now time.Time) Decision {
	if IsFloor(ep, t) {
		return Decision{Action: Allow, Basis: BasisFloor}
	}
	var best, bestLocked *Rule
	for i := range rules {
		r := &rules[i]
		if !r.Active(now) || !r.AppliesTo(ep) || !r.matches(t) {
			continue
		}
		if r.Locked {
			if bestLocked == nil || strongerLocked(*r, *bestLocked) {
				bestLocked = r
			}
			continue
		}
		if best == nil || stronger(*r, *best) {
			best = r
		}
	}
	switch {
	case bestLocked != nil:
		return Decision{Action: bestLocked.Action, Basis: BasisLocked, RuleID: bestLocked.ID, Scope: bestLocked.ScopeType}
	case best != nil:
		return Decision{Action: best.Action, Basis: BasisSpecific, RuleID: best.ID, Scope: best.ScopeType}
	}
	return Decision{Action: Deny, Basis: BasisDefault}
}

// Entry is one compiled range and the decision behind it.
type Entry struct {
	Prefix netip.Prefix `json:"prefix"`
	Decision
}

// Withheld is a rule the address-only allow list cannot carry.
type Withheld struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// Policy is an endpoint's effective trust as an address allow list.
type Policy struct {
	// Allow is what an isolated endpoint may reach, as merged prefixes.
	Allow []netip.Prefix `json:"allow"`
	// Entries explain every range a rule decided, allowed or denied.
	Entries []Entry `json:"entries"`
	// Withheld lists port-, protocol- or direction-scoped allow rules: the
	// isolation allow list names addresses only, so they are not in Allow.
	Withheld []Withheld `json:"withheld,omitempty"`
	// Addresses are the single addresses an allow rule names and the policy
	// allows: what an agent that takes only literal addresses may be given.
	// An address that is merely inside an allowed range is not one of them,
	// so a deny elsewhere in a range never opens a neighbour nobody named.
	Addresses []netip.Addr `json:"addresses"`
}

// Compile turns the rules that apply to an endpoint into its address allow
// list. Only whole-address allow rules can open a range. A narrower deny
// (one naming a port, protocol or direction) closes the whole range it
// overlaps: an address allow list cannot express "this address except port
// 443", and it errs closed.
func Compile(ep Endpoint, rules []Rule, now time.Time) Policy {
	var applicable []Rule
	var policy Policy
	for _, r := range rules {
		if !r.Active(now) || !r.AppliesTo(ep) {
			continue
		}
		if r.Action == Allow && (r.Port != 0 || r.Proto != ProtoAny || r.Direction != DirBoth) {
			policy.Withheld = append(policy.Withheld, Withheld{RuleID: r.ID, Reason: "port, protocol or direction scoped: not expressible as an address"})
			continue
		}
		// Narrow denies count as whole-address denies here.
		r.Port, r.Proto, r.Direction = 0, ProtoAny, DirBoth
		applicable = append(applicable, r)
	}
	var walk func(p netip.Prefix)
	walk = func(p netip.Prefix) {
		// A rule strictly inside p makes p non-uniform: split it.
		for _, r := range applicable {
			q := r.Prefix()
			if q.Addr().Is4() == p.Addr().Is4() && q.Bits() > p.Bits() && p.Contains(q.Addr()) {
				lo, hi := halves(p)
				walk(lo)
				walk(hi)
				return
			}
		}
		d := Decide(ep, applicable, Target{Addr: p.Addr()}, now)
		if d.Basis == BasisDefault {
			return
		}
		policy.Entries = append(policy.Entries, Entry{Prefix: p, Decision: d})
		if d.Action == Allow {
			policy.Allow = append(policy.Allow, p)
		}
	}
	seen := map[netip.Prefix]bool{}
	for _, r := range applicable {
		if r.Action != Allow || seen[r.Prefix()] {
			continue
		}
		seen[r.Prefix()] = true
		walk(r.Prefix())
	}
	policy.Allow = mergePrefixes(policy.Allow)
	policy.Addresses = []netip.Addr{}
	named := map[netip.Addr]bool{}
	for _, r := range applicable {
		if p := r.Prefix(); r.Action == Allow && p.IsSingleIP() && !named[p.Addr()] {
			named[p.Addr()] = true
			for _, a := range policy.Allow {
				if a.Contains(p.Addr()) {
					policy.Addresses = append(policy.Addresses, p.Addr())
					break
				}
			}
		}
	}
	sort.Slice(policy.Addresses, func(i, j int) bool { return policy.Addresses[i].Less(policy.Addresses[j]) })
	sort.Slice(policy.Entries, func(i, j int) bool { return lessPrefix(policy.Entries[i].Prefix, policy.Entries[j].Prefix) })
	policy.Entries = dedupeEntries(policy.Entries)
	return policy
}

// halves splits a prefix into its two children.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	idx := p.Bits() / 8
	b[idx] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(hiAddr, bits)
}

func lessPrefix(a, b netip.Prefix) bool {
	if a.Addr() != b.Addr() {
		return a.Addr().Less(b.Addr())
	}
	return a.Bits() < b.Bits()
}

func dedupeEntries(in []Entry) []Entry {
	out := in[:0]
	for i, e := range in {
		if i > 0 && e.Prefix == in[i-1].Prefix {
			continue
		}
		out = append(out, e)
	}
	return out
}

// mergePrefixes removes covered prefixes and joins sibling pairs.
func mergePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	set := append([]netip.Prefix(nil), in...)
	for changed := true; changed; {
		changed = false
		sort.Slice(set, func(i, j int) bool { return lessPrefix(set[i], set[j]) })
		var out []netip.Prefix
		for _, p := range set {
			if n := len(out); n > 0 {
				last := out[n-1]
				if last.Addr().Is4() == p.Addr().Is4() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
					changed = changed || last != p
					continue
				}
				if last.Bits() == p.Bits() && last.Bits() > 0 && last.Addr().Is4() == p.Addr().Is4() {
					if parent, _ := last.Addr().Prefix(last.Bits() - 1); parent.Contains(p.Addr()) && parent.Addr() == last.Addr() {
						out[n-1] = parent
						changed = true
						continue
					}
				}
			}
			out = append(out, p)
		}
		set = out
	}
	return set
}
