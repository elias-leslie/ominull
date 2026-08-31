package storage

import (
	"fmt"
	"path/filepath"
	"testing"
)

// What these tests are about: a baseline rule becomes a permit in a kernel
// firewall on a host that is otherwise cut off. A rule that is too wide is a
// hole in every isolation its scope covers; a rule that is too narrow strands a
// host. Both failures are quiet.

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// TestABaselineRuleCannotNameEveryHost. "0.0.0.0" and "::" are the exact hole
// this policy exists to close: a DNS rule pointed at the unspecified address is
// the old compiled-in permit written back in by hand, and it would read in the
// console as an ordinary entry.
func TestABaselineRuleCannotNameEveryHost(t *testing.T) {
	for _, dest := range []string{"0.0.0.0", "::"} {
		r := BaselineRule{Service: "dns", Destination: dest}
		if err := ValidateBaselineRule(&r); err == nil {
			t.Errorf("a rule destined for %q was accepted; that permits every host", dest)
		}
	}
}

func TestABaselineRuleMustNameAnAddress(t *testing.T) {
	for _, dest := range []string{"", "dns.example.com", "10.0.0.0/24", "10.0.0.1 "} {
		r := BaselineRule{Service: "dns", Destination: dest}
		err := ValidateBaselineRule(&r)
		if dest == "10.0.0.1 " {
			// Surrounding space is trimmed, not rejected: an address pasted out
			// of a spreadsheet is still an address.
			if err != nil {
				t.Errorf("a padded address was rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("destination %q was accepted; only addresses reach a firewall rule", dest)
		}
	}
}

// TestANamedServiceCannotBeGivenDifferentWireDetails. If a rule could override
// the port for "dns", the console would say DNS and the kernel would hold
// something else.
func TestANamedServiceCannotBeGivenDifferentWireDetails(t *testing.T) {
	r := BaselineRule{Service: "dns", Destination: "10.0.0.1", Protocol: "tcp", Port: 8080}
	if err := ValidateBaselineRule(&r); err != nil {
		t.Fatalf("a valid DNS rule was rejected: %v", err)
	}
	if r.Protocol != "udp" || r.Port != 0 {
		t.Errorf("a DNS rule kept caller-supplied wire details: protocol=%q port=%d", r.Protocol, r.Port)
	}
}

func TestACustomRuleMustNameItsProtocolAndPort(t *testing.T) {
	for _, r := range []BaselineRule{
		{Service: "custom", Destination: "10.0.0.1", Port: 88},
		{Service: "custom", Destination: "10.0.0.1", Protocol: "icmp", Port: 88},
		{Service: "custom", Destination: "10.0.0.1", Protocol: "tcp"},
		{Service: "custom", Destination: "10.0.0.1", Protocol: "tcp", Port: 70000},
	} {
		rule := r
		if err := ValidateBaselineRule(&rule); err == nil {
			t.Errorf("an underspecified custom rule was accepted: %+v", r)
		}
	}
	ok := BaselineRule{Service: "custom", Destination: "10.0.0.1", Protocol: "TCP", Port: 88}
	if err := ValidateBaselineRule(&ok); err != nil {
		t.Fatalf("a complete custom rule was rejected: %v", err)
	}
	if ok.Protocol != "tcp" {
		t.Errorf("protocol was not normalised: %q", ok.Protocol)
	}
}

// TestDHCPExpandsToTheServerPortForItsOwnFamily. A v4 permit on 547, or a v6
// permit on 67, is a rule that can never match - and it would look correct in
// every list that showed it.
func TestDHCPExpandsToTheServerPortForItsOwnFamily(t *testing.T) {
	wire := BaselineWireRules([]BaselineRule{
		{Service: "dhcp", Destination: "10.0.0.1", Protocol: "udp"},
		{Service: "dhcp", Destination: "fe80::1", Protocol: "udp"},
	})

	got := map[string]int{}
	for _, w := range wire {
		got[w.Destination] = w.Port
	}
	if got["10.0.0.1"] != 67 {
		t.Errorf("the v4 DHCP server got port %d, want 67", got["10.0.0.1"])
	}
	if got["fe80::1"] != 547 {
		t.Errorf("the v6 DHCP server got port %d, want 547", got["fe80::1"])
	}
}

// TestDHCPCarriesItsBroadcastFallback. A renewal is unicast to the server, but a
// REBIND or a DISCOVER after a failed renewal is a broadcast. A baseline naming
// only the server address holds the lease right up to the moment the host needs
// the fallback, and then loses the address the hub reaches it on.
func TestDHCPCarriesItsBroadcastFallback(t *testing.T) {
	wire := BaselineWireRules([]BaselineRule{{Service: "dhcp", Destination: "10.0.0.1", Protocol: "udp"}})

	var haveV4Broadcast, haveV6Multicast bool
	for _, w := range wire {
		if w.Destination == "255.255.255.255" && w.Port == 67 {
			haveV4Broadcast = true
		}
		if w.Destination == "ff02::1:2" && w.Port == 547 {
			haveV6Multicast = true
		}
	}
	if !haveV4Broadcast || !haveV6Multicast {
		t.Errorf("DHCP did not carry its broadcast fallback: %+v", wire)
	}

	// And only when DHCP was permitted at all. A baseline that names no DHCP
	// server must not quietly open the broadcast address anyway.
	dnsOnly := BaselineWireRules([]BaselineRule{{Service: "dns", Destination: "10.0.0.1", Protocol: "udp"}})
	for _, w := range dnsOnly {
		if w.Destination == "255.255.255.255" {
			t.Errorf("a DNS-only baseline opened the DHCP broadcast address")
		}
	}
}

// TestAnEmptyBaselineExpandsToNothing. Hub and loopback only. It has to be legal
// and it has to mean what it says - the readiness gate is what stops it being
// applied to a host that needs more.
func TestAnEmptyBaselineExpandsToNothing(t *testing.T) {
	if wire := BaselineWireRules(nil); len(wire) != 0 {
		t.Errorf("an empty baseline expanded to %d rule(s): %+v", len(wire), wire)
	}
}

// TestScopesUnionRatherThanOverride. If a narrow policy replaced a broad one,
// writing an endpoint policy would silently drop the site's DNS rule, and the
// person who wrote it would find out when the site went quiet.
func TestScopesUnionRatherThanOverride(t *testing.T) {
	store := newTestStore(t)

	if err := store.CreateTenant(Tenant{ID: "t-01", Name: "T", APIKey: "k"}); err != nil {
		t.Fatalf("creating a tenant: %v", err)
	}
	if err := store.UpsertEndpoint(Endpoint{
		ID: "ep-1", TenantID: "t-01", Hostname: "ep-1", OS: "Linux",
		IP: "10.0.0.50", DriverVersion: "1.7.11", Status: "online",
	}); err != nil {
		t.Fatalf("creating an endpoint: %v", err)
	}

	if err := store.SaveBaselinePolicy(&BaselinePolicy{
		Name: "Global DNS", Scope: "global", Enabled: true,
		Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.1"}},
	}); err != nil {
		t.Fatalf("saving the global policy: %v", err)
	}
	if err := store.SaveBaselinePolicy(&BaselinePolicy{
		Name: "Host NTP", Scope: "endpoint", ScopeValue: "ep-1", Enabled: true,
		Rules: []BaselineRule{{Service: "ntp", Destination: "10.0.0.2"}},
	}); err != nil {
		t.Fatalf("saving the endpoint policy: %v", err)
	}
	// A policy for somebody else must not leak in.
	if err := store.SaveBaselinePolicy(&BaselinePolicy{
		Name: "Other host", Scope: "endpoint", ScopeValue: "ep-2", Enabled: true,
		Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.99"}},
	}); err != nil {
		t.Fatalf("saving the unrelated policy: %v", err)
	}

	res, err := store.ResolveBaseline("ep-1")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range res.Rules {
		seen[r.Service+"/"+r.Destination] = true
	}
	if !seen["dns/10.0.0.1"] {
		t.Errorf("the global DNS rule was lost when an endpoint policy existed: %+v", res.Rules)
	}
	if !seen["ntp/10.0.0.2"] {
		t.Errorf("the endpoint's own rule is missing: %+v", res.Rules)
	}
	if seen["dns/10.0.0.99"] {
		t.Errorf("another endpoint's rule was applied to this one: %+v", res.Rules)
	}
}

// TestADisabledPolicyContributesNothing.
func TestADisabledPolicyContributesNothing(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateTenant(Tenant{ID: "t-01", Name: "T", APIKey: "k"}); err != nil {
		t.Fatalf("creating a tenant: %v", err)
	}
	if err := store.UpsertEndpoint(Endpoint{
		ID: "ep-1", TenantID: "t-01", Hostname: "ep-1", OS: "Linux",
		IP: "10.0.0.50", DriverVersion: "1.7.11", Status: "online",
	}); err != nil {
		t.Fatalf("creating an endpoint: %v", err)
	}
	if err := store.SaveBaselinePolicy(&BaselinePolicy{
		Name: "Off", Scope: "global", Enabled: false,
		Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.1"}},
	}); err != nil {
		t.Fatalf("saving: %v", err)
	}
	res, err := store.ResolveBaseline("ep-1")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if len(res.Rules) != 0 {
		t.Errorf("a disabled policy contributed %d rule(s)", len(res.Rules))
	}
}

// TestAnEndpointCannotAuthorItsOwnPolicy. Observations are reported by an agent
// running on a host that may be the compromised one. They are stored so a person
// can look at them; anything that is not an address is dropped rather than kept
// as something that will never match a rule.
func TestAnEndpointCannotAuthorItsOwnPolicy(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateTenant(Tenant{ID: "t-01", Name: "T", APIKey: "k"}); err != nil {
		t.Fatalf("creating a tenant: %v", err)
	}
	if err := store.UpsertEndpoint(Endpoint{
		ID: "ep-1", TenantID: "t-01", Hostname: "ep-1", OS: "Linux",
		IP: "10.0.0.50", DriverVersion: "1.7.11", Status: "online",
	}); err != nil {
		t.Fatalf("creating an endpoint: %v", err)
	}
	if err := store.SetEndpointObservations("ep-1", []ObservedService{
		{Service: "dns", Destination: "10.0.0.1"},
		{Service: "dns", Destination: "not-an-address"},
		{Service: "dns", Destination: "10.0.0.1"},
	}, Readiness{EnforcementEngine: "ok", HubLiteral: "10.0.0.57"}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	res, err := store.ResolveBaseline("ep-1")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if len(res.Observed) != 1 {
		t.Fatalf("observations were not cleaned and de-duplicated: %+v", res.Observed)
	}
	// Observing something does not permit it.
	if len(res.Rules) != 0 {
		t.Errorf("an endpoint's own report became %d enforced rule(s)", len(res.Rules))
	}
	if len(res.Uncovered) != 1 {
		t.Errorf("the observed-but-unpermitted service was not reported as uncovered: %+v", res.Uncovered)
	}
}

// TestProposingRulesDoesNotApplyThem. The agent knows what the host talks to;
// only a person knows whether it should.
func TestProposingRulesDoesNotApplyThem(t *testing.T) {
	proposed := ProposeBaselineRules([]ObservedService{
		{Service: "dns", Destination: "10.0.0.1"},
		{Service: "ntp", Destination: "10.0.0.2"},
		{Service: "nonsense", Destination: "10.0.0.3"},
	})
	if len(proposed) != 2 {
		t.Fatalf("proposed %d rule(s), want 2 (the unknown service dropped): %+v", len(proposed), proposed)
	}
	for _, r := range proposed {
		if r.ID != "" || r.PolicyID != "" {
			t.Errorf("a proposal carries storage identity, so it looks saved: %+v", r)
		}
	}
}

// TestALoopbackResolverIsNotAGap. systemd-resolved puts the resolver on
// 127.0.0.53. Loopback is compiled into every agent and cannot be removed from
// the console, so that flow survives an isolation whatever the baseline says -
// and calling it a gap would leave most Linux hosts permanently "not ready" over
// something that was never going to be cut. A gate that cries wolf is a gate
// people learn to click past.
func TestALoopbackResolverIsNotAGap(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateTenant(Tenant{ID: "t-01", Name: "T", APIKey: "k"}); err != nil {
		t.Fatalf("creating a tenant: %v", err)
	}
	if err := store.UpsertEndpoint(Endpoint{
		ID: "ep-1", TenantID: "t-01", Hostname: "ep-1", OS: "Linux",
		IP: "10.0.0.50", DriverVersion: "1.7.11", Status: "online",
	}); err != nil {
		t.Fatalf("creating an endpoint: %v", err)
	}
	if err := store.SetEndpointObservations("ep-1", []ObservedService{
		{Service: "dns", Destination: "127.0.0.53", Source: "resolv.conf"},
		{Service: "dns", Destination: "::1", Source: "resolv.conf"},
		{Service: "dhcp", Destination: "10.0.0.1", Source: "dhcp lease"},
	}, Readiness{EnforcementEngine: "ok", HubLiteral: "10.0.0.57"}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	res, err := store.ResolveBaseline("ep-1")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if len(res.Observed) != 3 {
		t.Fatalf("the loopback resolvers were dropped from what the host reported: %+v", res.Observed)
	}
	if len(res.Uncovered) != 1 || res.Uncovered[0].Destination != "10.0.0.1" {
		t.Fatalf("uncovered should be the DHCP server alone, got %+v", res.Uncovered)
	}

	// And proposing from the same observations must not offer a rule that
	// permits something already permitted.
	proposed := ProposeBaselineRules(res.Observed)
	if len(proposed) != 1 || proposed[0].Destination != "10.0.0.1" {
		t.Fatalf("a loopback destination was proposed as a rule: %+v", proposed)
	}
}

// TestAnOverLargeBaselineIsTrimmedDeterministically. An agent holds a fixed
// number of rules. Past it the hub must trim rather than let the agent's own
// truncation decide, because "the first 64 of a sorted list" is reproducible and
// "whatever fitted in a 16KB buffer this time" is not.
func TestAnOverLargeBaselineIsTrimmedDeterministically(t *testing.T) {
	wire := make([]BaselineWireRule, 0, BaselineWireLimit+10)
	for i := 0; i < BaselineWireLimit+10; i++ {
		wire = append(wire, BaselineWireRule{
			Service: "dns", Destination: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
			Protocol: "udp", Port: 53,
		})
	}
	capped, over := CapBaselineWireRules(wire)
	if !over {
		t.Fatalf("a %d-rule expansion was not reported as over the %d-rule limit", len(wire), BaselineWireLimit)
	}
	if len(capped) != BaselineWireLimit {
		t.Fatalf("trimmed to %d rules, want %d", len(capped), BaselineWireLimit)
	}
	again, _ := CapBaselineWireRules(wire)
	for i := range capped {
		if capped[i] != again[i] {
			t.Fatalf("the same input trimmed to a different rule at %d: %+v vs %+v", i, capped[i], again[i])
		}
	}

	short := wire[:BaselineWireLimit]
	if _, over := CapBaselineWireRules(short); over {
		t.Errorf("an expansion exactly at the limit was reported as over it")
	}
}
