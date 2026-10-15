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
