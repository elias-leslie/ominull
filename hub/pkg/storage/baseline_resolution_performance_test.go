package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBaselineResolutionKeepsPolicyAndRuleProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertEndpoint(Endpoint{ID: "resolve-host", TenantID: "default", LocationID: "site", Hostname: "host", IP: "10.0.0.8"}); err != nil {
		t.Fatal(err)
	}
	policies := []BaselinePolicy{
		{ID: "global-first", Name: "Same name", Scope: "global", Enabled: true, Rules: []BaselineRule{
			{ID: "dns-first", Service: "dns", Destination: "10.0.0.1", Note: "First author"},
			{ID: "dns-same-policy", Service: "dns", Destination: "10.0.0.1", Note: "Later author"},
		}},
		{ID: "global-second", Name: "Same name", Scope: "global", Enabled: true, Rules: []BaselineRule{{ID: "dns-second", Service: "dns", Destination: "10.0.0.1"}}},
		{ID: "tenant", Name: "Tenant", Scope: "tenant", ScopeValue: "default", Enabled: true, Rules: []BaselineRule{{ID: "ntp", Service: "ntp", Destination: "10.0.0.2"}}},
		{ID: "site", Name: "Site", Scope: "location", ScopeValue: "site", Enabled: true, Rules: []BaselineRule{{ID: "site-dns", Service: "dns", Destination: "10.0.0.5"}}},
		{ID: "host", Name: "Host", Scope: "endpoint", ScopeValue: "resolve-host", Enabled: true, Rules: []BaselineRule{{ID: "host-dns", Service: "dns", Destination: "10.0.0.6"}}},
		{ID: "disabled", Name: "Disabled", Scope: "global", Enabled: false, Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.3"}}},
		{ID: "other", Name: "Other", Scope: "endpoint", ScopeValue: "other-host", Enabled: true, Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.4"}}},
	}
	for i := range policies {
		if err := s.SaveBaselinePolicy(&policies[i]); err != nil {
			t.Fatal(err)
		}
	}
	// Persisted enabled values are interpreted as nonzero, not only as one.
	if _, err := s.db.Exec("UPDATE baseline_policies SET enabled = -1 WHERE id = 'host'"); err != nil {
		t.Fatal(err)
	}
	observed := []ObservedService{{Service: "dns", Destination: "10.0.0.1"}, {Service: "dns", Destination: "10.0.0.9"}, {Service: "dns", Destination: "127.0.0.53"}}
	if err := s.SetEndpointObservations("resolve-host", observed, Readiness{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ResolveBaseline("resolve-host")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Policies, []string{"Same name", "Same name", "Tenant", "Site", "Host"}) {
		t.Fatalf("policy order: %v", got.Policies)
	}
	if len(got.Rules) != 4 || got.Rules[0].ID != "dns-first" || got.Rules[0].Note != "First author" || got.Rules[1].ID != "site-dns" || got.Rules[2].ID != "host-dns" || got.Rules[3].ID != "ntp" {
		t.Fatalf("deduplicated rule provenance: %+v", got.Rules)
	}
	if !got.ReadinessReported || !reflect.DeepEqual(got.Uncovered, []ObservedService{{Service: "dns", Destination: "10.0.0.9"}}) {
		t.Fatalf("readiness/coverage: %+v", got)
	}
	all, err := s.ListBaselinePolicies()
	if err != nil || len(all) != len(policies) {
		t.Fatalf("administrative listing must retain all policies: %d, %v", len(all), err)
	}
	var listedRules int
	for _, policy := range all {
		listedRules += len(policy.Rules)
	}
	if listedRules != 8 {
		t.Fatalf("administrative listing lost rules: %d", listedRules)
	}
	if _, err := s.ResolveBaseline("missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing endpoint error: %v", err)
	}
}

func TestBaselineResolutionReflectsPolicyChanges(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertEndpoint(Endpoint{ID: "current-host", TenantID: "default", Hostname: "host", IP: "10.0.0.8"}); err != nil {
		t.Fatal(err)
	}
	p := BaselinePolicy{ID: "current-policy", Name: "Current", Scope: "global", Enabled: true,
		Rules: []BaselineRule{{Service: "dns", Destination: "10.0.0.1"}}}
	for _, enabled := range []bool{true, false, true} {
		p.Enabled = enabled
		if err := s.SaveBaselinePolicy(&p); err != nil {
			t.Fatal(err)
		}
		got, err := s.ResolveBaseline("current-host")
		if err != nil {
			t.Fatal(err)
		}
		if (len(got.Rules) == 1) != enabled || (len(got.Policies) == 1) != enabled {
			t.Fatalf("policy change is stale: enabled=%v, resolution=%+v", enabled, got)
		}
	}
	if err := s.DeleteBaselinePolicy(p.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.ResolveBaseline("current-host")
	if err != nil || len(got.Rules) != 0 || len(got.Policies) != 0 {
		t.Fatalf("deleted policy remains: %+v, %v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveBaseline("current-host"); err == nil {
		t.Fatal("closed store returned a resolution")
	}
}

func BenchmarkBaselineResolution(b *testing.B) {
	for _, unrelated := range []int{0, 1000} {
		b.Run(fmt.Sprintf("unrelated_%d", unrelated), func(b *testing.B) {
			s, err := New(filepath.Join(b.TempDir(), "baseline.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			if err := s.UpsertEndpoint(Endpoint{ID: "bench-host", TenantID: "default", Hostname: "bench", IP: "10.0.0.8"}); err != nil {
				b.Fatal(err)
			}
			for i := 0; i <= unrelated; i++ {
				p := BaselinePolicy{ID: fmt.Sprintf("policy-%d", i), Name: fmt.Sprintf("Policy %04d", i), Scope: "endpoint", ScopeValue: fmt.Sprintf("other-%d", i), Enabled: true}
				if i == 0 {
					p.ScopeValue = "bench-host"
				}
				for j := 1; j <= 4; j++ {
					p.Rules = append(p.Rules, BaselineRule{Service: "dns", Destination: fmt.Sprintf("10.0.0.%d", j)})
				}
				if err := s.SaveBaselinePolicy(&p); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.ResolveBaseline("bench-host")
				if err != nil || len(res.Rules) != 4 || len(res.Policies) != 1 {
					b.Fatalf("resolution: %+v, %v", res, err)
				}
			}
		})
	}
}
