package storage

import (
	"testing"
	"time"
)

func TestCommunicationProfilesKeepProtocolsAndUnknownAttributionSeparate(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "batch"}[batch], func(t *testing.T) {
			s := newTestStore(t)
			defer s.Close()
			events := []Event{}
			for _, protocol := range []uint8{6, 17, 58, 253} {
				events = append(events, Event{TenantID: "default", EndpointID: "proto-host", Timestamp: time.Now().UTC(), Protocol: protocol, DstIP: "10.0.4.21", DstPort: 443, BytesOut: 5})
			}
			if batch {
				if err := s.RecordNetworkCommsBatch(events, "proto-host", ""); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, ev := range events {
					if err := s.RecordNetworkComms(ev, "proto-host", ""); err != nil {
						t.Fatal(err)
					}
				}
			}
			rows, err := s.ListCommProfiles("endpoint", "proto-host", 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 4 {
				t.Fatalf("protocols merged into %d rows: %+v", len(rows), rows)
			}
			names := map[string]bool{}
			for _, row := range rows {
				names[row.Protocol] = true
				if row.ProcessName != "unknown" || row.TotalBytesOut != 5 {
					t.Errorf("invented attribution or mixed volume: %+v", row)
				}
			}
			for _, name := range []string{"TCP", "UDP", "ICMPv6", "IP/253"} {
				if !names[name] {
					t.Errorf("missing %s: %v", name, names)
				}
			}
		})
	}
}
