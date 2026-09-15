package storage

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var destinationProbeCalls atomic.Int64

func init() {
	// Count rows actually visited by the production lookup, without a timing
	// threshold or a second implementation of the lookup in the test.
	sqlite.MustRegisterScalarFunction("test_destination_probe", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		destinationProbeCalls.Add(1)
		return args[0], nil
	})
}

func TestFirstSeenDestinationPreservesHistoryDecisions(t *testing.T) {
	s := newTestStore(t)
	const dst = "203.0.113.8"
	event := Event{TenantID: "tenant-a", EndpointID: "endpoint-a", DstIP: dst, DstPort: 443, Protocol: 6, ProcessPath: "/usr/bin/client", Timestamp: time.Now().UTC()}
	if !s.IsFirstSeenDestination("tenant-a", dst) {
		t.Fatal("absent destination should be first seen")
	}
	for i := 0; i < 3; i++ {
		if err := s.RecordNetworkCommsBatch([]Event{event}, "host", "location"); err != nil {
			t.Fatal(err)
		}
	}
	if !s.IsFirstSeenDestination("tenant-a", dst) {
		t.Fatal("one profile remains first seen regardless of its event count")
	}
	other := event
	other.TenantID, other.EndpointID = "tenant-b", "endpoint-b"
	for _, port := range []uint16{80, 443, 8443} {
		other.DstPort = port
		if err := s.RecordNetworkCommsBatch([]Event{other}, "host", "location"); err != nil {
			t.Fatal(err)
		}
	}
	if !s.IsFirstSeenDestination("tenant-a", dst) {
		t.Fatal("other tenants must not contribute to destination history")
	}
	event.DstPort = 8443
	if err := s.RecordNetworkCommsBatch([]Event{event}, "host", "location"); err != nil {
		t.Fatal(err)
	}
	if s.IsFirstSeenDestination("tenant-a", dst) || s.IsFirstSeenDestination("tenant-b", dst) {
		t.Fatal("two or more profiles must not be first seen")
	}
	if !s.IsFirstSeenDestination("tenant-a", "2001:db8::8") {
		t.Fatal("another destination must remain first seen")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.IsFirstSeenDestination("tenant-a", "203.0.113.9") {
		t.Fatal("database errors must not fabricate a first-seen result")
	}
}

func TestFirstSeenDestinationStopsAfterTwoMatches(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE VIEW comm_profiles AS
		WITH RECURSIVE history(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM history WHERE n < 128)
		SELECT 'tenant-a' AS tenant_id, test_destination_probe('203.0.113.8') AS dst_ip FROM history`)
	if err != nil {
		t.Fatal(err)
	}
	destinationProbeCalls.Store(0)
	s := &Store{db: db}
	if s.IsFirstSeenDestination("tenant-a", "203.0.113.8") {
		t.Fatal("repeated destination should not be first seen")
	}
	if visited := destinationProbeCalls.Load(); visited != 2 {
		t.Fatalf("visited %d matching profiles; only two are needed for the decision", visited)
	}
}

func TestFirstSeenDestinationIndexUpgradesExistingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	s := openStore(t, path)
	event := Event{TenantID: "default", EndpointID: "endpoint", DstIP: "203.0.113.8", DstPort: 443, Protocol: 6, ProcessPath: "/usr/bin/client", Timestamp: time.Now().UTC()}
	if err := s.RecordNetworkCommsBatch([]Event{event}, "host", "location"); err != nil {
		t.Fatal(err)
	}
	// Model an existing installation with data and the old tenant-only index.
	if _, err := s.db.Exec("DROP INDEX IF EXISTS idx_comm_tenant_destination"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for i := 0; i < 2; i++ {
		s = openStore(t, path)
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM comm_profiles").Scan(&count); err != nil || count != 1 {
			t.Fatalf("upgrade changed existing profiles: count=%d err=%v", count, err)
		}
		rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT 1 FROM comm_profiles WHERE tenant_id = ? AND dst_ip = ? LIMIT 2", "default", event.DstIP)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		s.Close()
		if text := strings.Join(plan, "\n"); !strings.Contains(text, "COVERING INDEX") || !strings.Contains(text, "tenant_id=? AND dst_ip=?") {
			t.Fatalf("destination lookup must seek both keys without reading profile rows: %s", text)
		}
	}
}

func BenchmarkFirstSeenDestination(b *testing.B) {
	for _, profiles := range []int{1000, 100000} {
		b.Run(fmt.Sprintf("profiles_%d", profiles), func(b *testing.B) {
			s, err := New(filepath.Join(b.TempDir(), "history.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			_, err = s.db.Exec(`WITH RECURSIVE history(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM history WHERE n < ?)
				INSERT INTO comm_profiles(id,tenant_id,endpoint_id,process_name,dst_ip,dst_port,first_seen,last_seen)
				SELECT 'profile-'||n,'default','endpoint','client',CASE WHEN n = ? THEN '203.0.113.9' ELSE '203.0.113.8' END,443,'2026-01-01','2026-01-01' FROM history`, profiles, profiles)
			if err != nil {
				b.Fatal(err)
			}
			for _, tc := range []struct {
				name, destination string
				firstSeen         bool
			}{{"common", "203.0.113.8", false}, {"single", "203.0.113.9", true}, {"absent", "203.0.113.10", true}} {
				b.Run(tc.name, func(b *testing.B) {
					for b.Loop() {
						if s.IsFirstSeenDestination("default", tc.destination) != tc.firstSeen {
							b.Fatal("wrong destination-history decision")
						}
					}
				})
			}
		})
	}
}
