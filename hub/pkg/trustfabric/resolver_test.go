package trustfabric

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// pos04 is the worked example's endpoint: a point-of-sale terminal at a
// store of a client of the provider.
var pos04 = Endpoint{ID: "pos-04", TenantID: "acme", LocationID: "store-12", Role: "pos",
	HubAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}

func rule(t *testing.T, id, scope, scopeID, kind, value, action string, mods ...func(*Rule)) Rule {
	t.Helper()
	r := Rule{ID: id, ScopeType: scope, ScopeID: scopeID, Kind: kind, Value: value, Action: action}
	for _, m := range mods {
		m(&r)
	}
	n, err := Normalize(r)
	if err != nil {
		t.Fatalf("rule %s: %v", id, err)
	}
	return n
}

func locked(r *Rule) { r.Locked = true }

func addr(s string) Target { return Target{Addr: netip.MustParseAddr(s)} }

func TestDecidePrecedence(t *testing.T) {
	expired := now.Add(-time.Minute)
	later := now.Add(time.Hour)
	cases := []struct {
		name   string
		rules  []Rule
		target Target
		want   Decision
	}{
		{
			// The worked example: the provider denies a payment gateway
			// address, the store's endpoint allows it. Unlocked, the most
			// specific rule wins and pos-04 may reach it.
			name: "worked example, provider rule not locked",
			rules: []Rule{
				rule(t, "prov-deny", ScopeProvider, "", "ip", "198.51.100.25", Deny),
				rule(t, "ep-allow", ScopeEndpoint, "pos-04", "ip", "198.51.100.25", Allow),
			},
			target: addr("198.51.100.25"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "ep-allow", Scope: ScopeEndpoint},
		},
		{
			// The same, with the provider's rule locked: nothing below it
			// can override it.
			name: "worked example, provider rule locked",
			rules: []Rule{
				rule(t, "prov-deny", ScopeProvider, "", "ip", "198.51.100.25", Deny, locked),
				rule(t, "ep-allow", ScopeEndpoint, "pos-04", "ip", "198.51.100.25", Allow),
			},
			target: addr("198.51.100.25"),
			want:   Decision{Action: Deny, Basis: BasisLocked, RuleID: "prov-deny", Scope: ScopeProvider},
		},
		{
			name: "a provider lock beats a lower lock",
			rules: []Rule{
				rule(t, "prov-allow", ScopeProvider, "", "cidr", "198.51.100.0/24", Allow, locked),
				rule(t, "site-deny", ScopeSite, "store-12", "ip", "198.51.100.25", Deny, locked),
			},
			target: addr("198.51.100.25"),
			want:   Decision{Action: Allow, Basis: BasisLocked, RuleID: "prov-allow", Scope: ScopeProvider},
		},
		{
			name: "deny beats allow at equal specificity",
			rules: []Rule{
				rule(t, "grp-allow", ScopeGroup, "pos", "ip", "203.0.113.7", Allow),
				rule(t, "grp-deny", ScopeGroup, "pos", "ip", "203.0.113.7", Deny),
			},
			target: addr("203.0.113.7"),
			want:   Decision{Action: Deny, Basis: BasisSpecific, RuleID: "grp-deny", Scope: ScopeGroup},
		},
		{
			name: "a longer prefix wins at the same scope",
			rules: []Rule{
				rule(t, "client-deny", ScopeClient, "acme", "cidr", "203.0.113.0/24", Deny),
				rule(t, "client-allow", ScopeClient, "acme", "ip", "203.0.113.7", Allow),
			},
			target: addr("203.0.113.7"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "client-allow", Scope: ScopeClient},
		},
		{
			name: "scope outranks prefix length",
			rules: []Rule{
				rule(t, "client-allow", ScopeClient, "acme", "ip", "203.0.113.7", Allow),
				rule(t, "site-deny", ScopeSite, "store-12", "cidr", "203.0.113.0/24", Deny),
			},
			target: addr("203.0.113.7"),
			want:   Decision{Action: Deny, Basis: BasisSpecific, RuleID: "site-deny", Scope: ScopeSite},
		},
		{
			name: "allows add up across scopes",
			rules: []Rule{
				rule(t, "client-allow", ScopeClient, "acme", "ip", "192.0.2.10", Allow),
				rule(t, "site-allow", ScopeSite, "store-12", "ip", "192.0.2.11", Allow),
			},
			target: addr("192.0.2.10"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "client-allow", Scope: ScopeClient},
		},
		{
			name:   "rules for another endpoint, site or client do not apply",
			rules:  []Rule{rule(t, "other", ScopeEndpoint, "pos-05", "ip", "192.0.2.10", Allow), rule(t, "other-site", ScopeSite, "store-13", "ip", "192.0.2.10", Allow), rule(t, "other-client", ScopeClient, "globex", "ip", "192.0.2.10", Allow)},
			target: addr("192.0.2.10"),
			want:   Decision{Action: Deny, Basis: BasisDefault},
		},
		{
			name:   "an expired rule is gone",
			rules:  []Rule{rule(t, "old", ScopeEndpoint, "pos-04", "ip", "192.0.2.10", Allow, func(r *Rule) { r.ExpiresAt = &expired })},
			target: addr("192.0.2.10"),
			want:   Decision{Action: Deny, Basis: BasisDefault},
		},
		{
			name:   "a rule not yet expired holds",
			rules:  []Rule{rule(t, "temp", ScopeEndpoint, "pos-04", "ip", "192.0.2.10", Allow, func(r *Rule) { r.ExpiresAt = &later })},
			target: addr("192.0.2.10"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "temp", Scope: ScopeEndpoint},
		},
		{
			name:   "the hub is floor, a locked provider deny cannot touch it",
			rules:  []Rule{rule(t, "deny-all", ScopeProvider, "", "cidr", "0.0.0.0/0", Deny, locked)},
			target: addr("10.0.0.2"),
			want:   Decision{Action: Allow, Basis: BasisFloor},
		},
		{
			name:   "loopback is floor",
			rules:  []Rule{rule(t, "deny-lo", ScopeEndpoint, "pos-04", "cidr", "127.0.0.0/8", Deny, locked)},
			target: addr("127.0.0.1"),
			want:   Decision{Action: Allow, Basis: BasisFloor},
		},
		{
			name:   "DHCP is floor",
			rules:  []Rule{rule(t, "deny-all", ScopeProvider, "", "cidr", "0.0.0.0/0", Deny, locked)},
			target: Target{Addr: netip.MustParseAddr("10.0.0.1"), Port: 67, Proto: ProtoUDP},
			want:   Decision{Action: Allow, Basis: BasisFloor},
		},
		{
			name: "a port rule answers a port question and outranks the address rule",
			rules: []Rule{
				rule(t, "addr-allow", ScopeEndpoint, "pos-04", "ip", "192.0.2.20", Allow),
				rule(t, "port-deny", ScopeEndpoint, "pos-04", "ip", "192.0.2.20", Deny, func(r *Rule) { r.Port, r.Proto = 22, ProtoTCP }),
			},
			target: Target{Addr: netip.MustParseAddr("192.0.2.20"), Port: 22, Proto: ProtoTCP},
			want:   Decision{Action: Deny, Basis: BasisSpecific, RuleID: "port-deny", Scope: ScopeEndpoint},
		},
		{
			name:   "a port rule does not answer for the whole address",
			rules:  []Rule{rule(t, "port-allow", ScopeEndpoint, "pos-04", "ip", "192.0.2.20", Allow, func(r *Rule) { r.Port, r.Proto = 443, ProtoTCP })},
			target: addr("192.0.2.20"),
			want:   Decision{Action: Deny, Basis: BasisDefault},
		},
		{
			name:   "IPv4-mapped targets match IPv4 rules",
			rules:  []Rule{rule(t, "v4", ScopeEndpoint, "pos-04", "ip", "192.0.2.30", Allow)},
			target: addr("::ffff:192.0.2.30"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "v4", Scope: ScopeEndpoint},
		},
		{
			name:   "IPv6 prefixes",
			rules:  []Rule{rule(t, "v6", ScopeSite, "store-12", "cidr", "2001:db8:12::/48", Allow)},
			target: addr("2001:db8:12::5"),
			want:   Decision{Action: Allow, Basis: BasisSpecific, RuleID: "v6", Scope: ScopeSite},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(pos04, c.rules, c.target, now); got != c.want {
				t.Errorf("Decide = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestCompileAllowList(t *testing.T) {
	cases := []struct {
		name     string
		rules    []Rule
		allow    []string
		withheld int
	}{
		{
			name: "worked example unlocked compiles the endpoint's allow",
			rules: []Rule{
				rule(t, "prov-deny", ScopeProvider, "", "ip", "198.51.100.25", Deny),
				rule(t, "ep-allow", ScopeEndpoint, "pos-04", "ip", "198.51.100.25", Allow),
			},
			allow: []string{"198.51.100.25/32"},
		},
		{
			name: "worked example locked compiles nothing",
			rules: []Rule{
				rule(t, "prov-deny", ScopeProvider, "", "ip", "198.51.100.25", Deny, locked),
				rule(t, "ep-allow", ScopeEndpoint, "pos-04", "ip", "198.51.100.25", Allow),
			},
			allow: nil,
		},
		{
			// A /30 allowed with one address denied more specifically
			// leaves the other three.
			name: "a deny carves a hole in an allowed range",
			rules: []Rule{
				rule(t, "client-allow", ScopeClient, "acme", "cidr", "192.0.2.0/30", Allow),
				rule(t, "ep-deny", ScopeEndpoint, "pos-04", "ip", "192.0.2.1", Deny),
			},
			allow: []string{"192.0.2.0/32", "192.0.2.2/31"},
		},
		{
			name: "a narrow deny closes the whole address",
			rules: []Rule{
				rule(t, "allow", ScopeEndpoint, "pos-04", "ip", "192.0.2.40", Allow),
				rule(t, "deny-ssh", ScopeSite, "store-12", "ip", "192.0.2.40", Deny, func(r *Rule) { r.Port, r.Proto = 22, ProtoTCP }),
			},
			allow: []string{"192.0.2.40/32"}, // endpoint scope still outranks the site
		},
		{
			name: "a narrow deny at the same scope closes the address",
			rules: []Rule{
				rule(t, "allow", ScopeEndpoint, "pos-04", "ip", "192.0.2.40", Allow),
				rule(t, "deny-ssh", ScopeEndpoint, "pos-04", "ip", "192.0.2.40", Deny, func(r *Rule) { r.Port, r.Proto = 22, ProtoTCP }),
			},
			allow: nil,
		},
		{
			name:     "port-scoped allows are withheld",
			rules:    []Rule{rule(t, "https", ScopeEndpoint, "pos-04", "ip", "192.0.2.50", Allow, func(r *Rule) { r.Port, r.Proto = 443, ProtoTCP })},
			allow:    nil,
			withheld: 1,
		},
		{
			name: "allows from several scopes merge",
			rules: []Rule{
				rule(t, "a", ScopeClient, "acme", "ip", "192.0.2.0", Allow),
				rule(t, "b", ScopeSite, "store-12", "ip", "192.0.2.1", Allow),
				rule(t, "c", ScopeProvider, "", "cidr", "192.0.2.2/31", Allow),
				rule(t, "v6", ScopeEndpoint, "pos-04", "ip", "2001:db8::1", Allow),
			},
			allow: []string{"192.0.2.0/30", "2001:db8::1/128"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Compile(pos04, c.rules, now)
			var got []string
			for _, a := range p.Allow {
				got = append(got, a.String())
			}
			if !reflect.DeepEqual(got, c.allow) {
				t.Errorf("allow = %v, want %v (entries %+v)", got, c.allow, p.Entries)
			}
			if len(p.Withheld) != c.withheld {
				t.Errorf("withheld = %+v, want %d", p.Withheld, c.withheld)
			}
		})
	}
}

func TestNormalizeRefusals(t *testing.T) {
	for _, r := range []Rule{
		{ScopeType: "planet", ScopeID: "x", Kind: "ip", Value: "192.0.2.1", Action: Allow},
		{ScopeType: ScopeSite, Kind: "ip", Value: "192.0.2.1", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "ip", Value: "not-an-ip", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "ip", Value: "192.0.2.0/24", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "ip", Value: "fe80::1%eth0", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "0.0.0.0/0", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "192.0.2.0/24", Action: "maybe"},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "192.0.2.0/24", Action: Allow, Port: 80},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "192.0.2.0/24", Action: Allow, Port: 70000, Proto: ProtoTCP},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "192.0.2.0/24", Action: Allow, Direction: "sideways"},
		{ScopeType: ScopeProvider, Kind: "fqdn", Value: "example.com", Action: Allow},
		{ScopeType: ScopeProvider, Kind: "cidr", Value: "::ffff:0.0.0.0/80", Action: Deny},
	} {
		if _, err := Normalize(r); err == nil {
			t.Errorf("Normalize accepted %+v", r)
		}
	}
	n, err := Normalize(Rule{ScopeType: "Provider", ScopeID: "ignored", Kind: "cidr", Value: "192.0.2.77/24", Action: "DENY"})
	if err != nil || n.Value != "192.0.2.0/24" || n.ScopeID != "" || n.Direction != DirBoth || n.Proto != ProtoAny || n.Action != Deny {
		t.Errorf("Normalize = %+v, %v", n, err)
	}
	// A whole-family deny is allowed (an explicit default deny).
	if _, err := Normalize(Rule{ScopeType: ScopeProvider, Kind: "cidr", Value: "::/0", Action: Deny}); err != nil {
		t.Errorf("whole-family deny refused: %v", err)
	}
}

// Agents take literal addresses, so the enforceable part of a policy is the
// addresses rules name, not whatever single addresses a split or merge leaves.
func TestCompileNamedAddresses(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		want  []string
	}{
		{
			name: "adjacent named addresses stay enforceable after merging",
			rules: []Rule{
				rule(t, "a", ScopeProvider, "", "ip", "10.0.0.4", Allow),
				rule(t, "b", ScopeProvider, "", "ip", "10.0.0.5", Allow),
			},
			want: []string{"10.0.0.4", "10.0.0.5"},
		},
		{
			name: "a named address inside an allowed range is kept",
			rules: []Rule{
				rule(t, "range", ScopeClient, "acme", "cidr", "10.0.0.0/24", Allow),
				rule(t, "one", ScopeEndpoint, "pos-04", "ip", "10.0.0.9", Allow),
			},
			want: []string{"10.0.0.9"},
		},
		{
			name: "a deny in a range opens no neighbour",
			rules: []Rule{
				rule(t, "range", ScopeClient, "acme", "cidr", "10.0.0.0/24", Allow),
				rule(t, "deny", ScopeEndpoint, "pos-04", "ip", "10.0.0.5", Deny),
			},
			want: []string{},
		},
		{
			name: "a named address that is denied is left out",
			rules: []Rule{
				rule(t, "one", ScopeSite, "store-12", "ip", "10.0.0.9", Allow),
				rule(t, "deny", ScopeEndpoint, "pos-04", "cidr", "10.0.0.8/30", Deny),
			},
			want: []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := []string{}
			for _, a := range Compile(pos04, c.rules, now).Addresses {
				got = append(got, a.String())
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("addresses = %v, want %v", got, c.want)
			}
		})
	}
}
