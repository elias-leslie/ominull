package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFleetConsensusGroupingAndThreshold(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "consensus.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer st.Close()

	tenant := "test-tenant"
	_, _ = st.db.Exec("INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)", tenant, "Test Tenant", time.Now().UTC())

	// Insert 10 endpoints: 7 Linux workstations, 3 Windows servers
	for i := 1; i <= 7; i++ {
		id := "linux-workstation-" + string(rune('0'+i))
		obs := `[{"service":"dns","destination":"192.168.86.1"},{"service":"ntp","destination":"time.cloudflare.com"}]`
		if i == 7 {
			// One machine also has custom service
			obs = `[{"service":"dns","destination":"192.168.86.1"},{"service":"custom","destination":"10.0.0.99"}]`
		}
		_, err := st.db.Exec(
			"INSERT INTO endpoints (id, tenant_id, hostname, ip, mac, os, role_tag, status, driver_version, observed_services, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, tenant, id, "192.168.86."+string(rune('0'+i)), "00:11:22:33:44:0"+string(rune('0'+i)), "Linux Ubuntu 22.04", "workstation", "active", "1.8.0", obs, time.Now().UTC(), time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert endpoint: %v", err)
		}
	}

	for i := 1; i <= 3; i++ {
		id := "windows-server-" + string(rune('0'+i))
		obs := `[{"service":"dns","destination":"192.168.86.1"},{"service":"ntp","destination":"time.windows.com"}]`
		_, err := st.db.Exec(
			"INSERT INTO endpoints (id, tenant_id, hostname, ip, mac, os, role_tag, status, driver_version, observed_services, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, tenant, id, "192.168.86.10"+string(rune('0'+i)), "00:11:22:33:44:1"+string(rune('0'+i)), "Windows Server 2022", "server", "active", "1.8.0", obs, time.Now().UTC(), time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert endpoint: %v", err)
		}
	}

	// Compute consensus at 70% threshold
	candidates, err := st.ComputeFleetConsensus(tenant, 0.70)
	if err != nil {
		t.Fatalf("ComputeFleetConsensus: %v", err)
	}

	// In Linux workstation cohort (7 total):
	// DNS to 192.168.86.1 is observed by 7/7 (100% >= 70%) -> MUST MATCH
	// NTP to time.cloudflare.com is observed by 6/7 (85.7% >= 70%) -> MUST MATCH
	// Custom to 10.0.0.99 is observed by 1/7 (14.2% < 70%) -> MUST BE EXCLUDED

	foundDNS := false
	foundNTP := false
	foundCustom := false

	for _, c := range candidates {
		if c.CohortKey == "linux:workstation" {
			if c.Service == "dns" && c.Destination == "192.168.86.1" {
				foundDNS = true
				if c.EndpointsCount != 7 || c.TotalInCohort != 7 {
					t.Errorf("expected 7/7 DNS, got %d/%d", c.EndpointsCount, c.TotalInCohort)
				}
			}
			if c.Service == "ntp" && c.Destination == "time.cloudflare.com" {
				foundNTP = true
				if c.EndpointsCount != 6 || c.TotalInCohort != 7 {
					t.Errorf("expected 6/7 NTP, got %d/%d", c.EndpointsCount, c.TotalInCohort)
				}
			}
			if c.Service == "custom" && c.Destination == "10.0.0.99" {
				foundCustom = true
			}
		}
	}

	if !foundDNS {
		t.Errorf("expected to find DNS consensus candidate for linux:workstation")
	}
	if !foundNTP {
		t.Errorf("expected to find NTP consensus candidate for linux:workstation")
	}
	if foundCustom {
		t.Errorf("custom destination observed on 1/7 hosts should not achieve 70%% consensus")
	}

	// Propose rules
	rules, err := st.ProposeFleetConsensusRules(tenant, 0.70)
	if err != nil {
		t.Fatalf("ProposeFleetConsensusRules: %v", err)
	}
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules proposed from fleet consensus, got %d", len(rules))
	}
}
