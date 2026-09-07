package detector

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestPolicyBlockDoesNotInventThreatIntelOrIsolate(t *testing.T) {
	s, err := storage.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	isolations := 0
	e := New(s, nil, func(string, string) error { isolations++; return nil })
	e.Evaluate(storage.Event{TenantID: "default", EndpointID: "test-host", Action: "BLOCK", SrcIP: "10.0.4.2", DstIP: "fd12::9", Protocol: 6, Timestamp: time.Now().UTC()})
	alerts, err := s.ListAnomalyAlerts("default", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.AnomalyType == "THREAT_INTEL_MATCH" {
			t.Errorf("policy block became intelligence match: %s", a.Title)
		}
	}
	if isolations != 0 {
		t.Errorf("policy block triggered %d isolations", isolations)
	}
}

func TestLoopbackAddressesDoNotBecomeLateralTargets(t *testing.T) {
	s, err := storage.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := New(s, nil, nil)
	for i := 2; i < 30; i++ {
		e.Evaluate(storage.Event{TenantID: "default", EndpointID: "test-host", Action: "PERMIT", Direction: "OUTBOUND", SrcIP: "10.0.4.2", DstIP: fmt.Sprintf("127.0.0.%d", i), DstPort: 8080, ProcessPath: "/usr/bin/custom-client", Timestamp: time.Now().UTC()})
	}
	alerts, err := s.ListAnomalyAlerts("default", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.AnomalyType == "LATERAL_PORT_SWEEP" {
			t.Errorf("loopback became lateral movement: %s", a.Title)
		}
	}
}

func TestContainerExemptionsRequireConfiguredNetworks(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, configuration string
		wantSweep                   bool
	}{
		{"ordinary private segment", "172.31.0.", `{}`, true},
		{"configured IPv6 container segment", "fd12:3456::", `{"container_cidrs":["fd12:3456::/64"]}`, false},
		{"other IPv6 segment remains visible", "fd12:3457::", `{"container_cidrs":["fd12:3456::/64"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := storage.New(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			cfg := storage.DefaultDetectionTuning()
			if err := json.Unmarshal([]byte(tc.configuration), &cfg); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SaveDetectionTuning(cfg, "test"); err != nil {
				t.Fatal(err)
			}
			e := New(s, nil, nil)
			for i := 2; i < 30; i++ {
				e.Evaluate(storage.Event{TenantID: "default", EndpointID: "test-host", Action: "PERMIT", Direction: "OUTBOUND", SrcIP: "10.0.4.2", DstIP: tc.prefix + fmt.Sprint(i), DstPort: 8080, Protocol: 6, ProcessPath: "/usr/bin/custom-client", Timestamp: time.Now().UTC()})
			}
			alerts, err := s.ListAnomalyAlerts("default", 100)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, a := range alerts {
				if a.AnomalyType == "LATERAL_PORT_SWEEP" {
					found = true
				}
			}
			if found != tc.wantSweep {
				t.Errorf("sweep=%v want %v", found, tc.wantSweep)
			}
		})
	}
}

func TestMulticastGroupsAreNotLateralHosts(t *testing.T) {
	s, err := storage.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := New(s, nil, nil)
	for i := 2; i < 30; i++ {
		e.Evaluate(storage.Event{TenantID: "default", EndpointID: "test-host", Action: "PERMIT", Direction: "OUTBOUND", SrcIP: "fd12::1", DstIP: fmt.Sprintf("ff02::%x", i), DstPort: 8080, Protocol: 17, ProcessPath: "/usr/bin/custom-client", Timestamp: time.Now().UTC()})
	}
	alerts, err := s.ListAnomalyAlerts("default", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.AnomalyType == "LATERAL_PORT_SWEEP" {
			t.Errorf("multicast groups became lateral hosts: %s", a.Title)
		}
	}
}
