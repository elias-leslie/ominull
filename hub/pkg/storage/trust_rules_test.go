package storage

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/trustfabric"
)

func TestTrustRulesRoundTrip(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "trust.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "site", Kind: "ip", Value: "198.51.100.25", Action: "allow"}); err == nil {
		t.Fatal("a site rule without a scope id was stored")
	}
	exp := time.Now().Add(4 * time.Hour)
	created, err := store.CreateTrustRule(trustfabric.Rule{
		ScopeType: "endpoint", ScopeID: "pos-04", Kind: "cidr", Value: "198.51.100.77/24",
		Action: "allow", Proto: "tcp", Port: 443, ExpiresAt: &exp, Justification: "payments", CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Value != "198.51.100.0/24" || created.Direction != "both" {
		t.Fatalf("created = %+v", created)
	}
	locked, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "provider", Kind: "ip", Value: "198.51.100.25", Action: "deny", Locked: true})
	if err != nil {
		t.Fatal(err)
	}

	rules, err := store.TrustRules()
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	got := rules[0]
	if got.ID != created.ID {
		got = rules[1]
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*created.ExpiresAt) || got.Port != 443 || got.Justification != "payments" {
		t.Fatalf("round trip = %+v, want %+v", got, created)
	}

	ep := trustfabric.Endpoint{ID: "pos-04"}
	d := trustfabric.Decide(ep, rules, trustfabric.Target{Addr: netip.MustParseAddr("198.51.100.25"), Port: 443, Proto: "tcp", Direction: "out"}, time.Now())
	if d.Action != "deny" || d.RuleID != locked.ID {
		t.Fatalf("decision = %+v", d)
	}

	if _, err := store.DeleteTrustRule(locked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteTrustRule(locked.ID); !errors.Is(err, ErrTrustRuleNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestIsolationRecords(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "iso.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{"ep-1", "ep-2"} {
		if err := store.UpsertEndpoint(Endpoint{ID: id, TenantID: "default", Hostname: id, OS: "Linux", Status: "online"}); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(id string) IsolationRecord {
		t.Helper()
		all, err := store.IsolatedEndpoints()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range all {
			if r.EndpointID == id {
				return r
			}
		}
		return IsolationRecord{}
	}

	if err := store.SetEndpointIsolation("ep-1", true, []string{"10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	first := rec("ep-1")
	if first.ID == "" || first.Mode != "explicit" {
		t.Fatalf("first %+v", first)
	}
	if err := store.SetIsolationMode("ep-1", "selective"); err != nil {
		t.Fatal(err)
	}
	// The detector isolating again keeps the incident but drops the list:
	// the label follows the list, not the earlier choice.
	if err := store.SetEndpointIsolation("ep-1", true, nil); err != nil {
		t.Fatal(err)
	}
	if again := rec("ep-1"); again.ID != first.ID || again.Mode != "full" || len(again.AllowIPs) != 0 {
		t.Fatalf("again %+v (first %s)", again, first.ID)
	}
	if _, err := store.SetBulkIsolation("", "all", "", true, []string{"10.0.0.7"}); err != nil {
		t.Fatal(err)
	}
	if b := rec("ep-2"); b.ID == "" || b.ID == first.ID || b.Mode != "explicit" {
		t.Fatalf("bulk %+v", b)
	}
	if _, err := store.SetBulkIsolation("", "all", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointIsolation("ep-1", true, nil); err != nil {
		t.Fatal(err)
	}
	if next := rec("ep-1"); next.ID == "" || next.ID == first.ID {
		t.Fatalf("a new isolation reused id %s", next.ID)
	}
}
