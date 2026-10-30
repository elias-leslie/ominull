package storage

import (
	"strings"
	"testing"
	"time"
)

// Two Windows ESTATS samples of 8.4e18 bytes each were enough to overflow every
// SUM over a day of flows: the cold segment export stopped there for a week and
// the traffic overview answered 500. The stored ones are cleared once.
func TestByteCountsThatAreNotMeasurementsAreClearedOnce(t *testing.T) {
	store := newTestStore(t)
	day := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour)
	for i, b := range []int64{8389899496073898413, 8389756699818722813, 1200} {
		if _, err := store.db.Exec(`INSERT INTO events
			(tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
			 src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, process_path, process_id)
			VALUES ('default','e1',?,'windows-estats','PERMIT','OUTBOUND',6,'10.0.0.1','10.0.0.2',?,443,?,64,'/bin/x',1)`,
			day.Add(time.Duration(i)*time.Minute), 50000+i, b); err != nil {
			t.Fatalf("seed flow: %v", err)
		}
	}
	// An overflowed profile total is a REAL in SQLite.
	if _, err := store.db.Exec(`INSERT INTO comm_profiles
		(id, tenant_id, endpoint_id, process_name, dst_ip, dst_port, first_seen, last_seen, total_bytes_in, total_bytes_out)
		VALUES ('p1', 'default', 'e1', 'x', '10.0.0.2', 443, ?, ?, 3.3559018550844e19, 10), ('p2', 'default', 'e1', 'y', '10.0.0.3', 443, ?, ?, 500, 10)`,
		day, day, day, day); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	// An overflowed loopback rollup is a REAL too.
	if _, err := store.db.Exec(`INSERT INTO flow_local_hourly
		(endpoint_ref, hour, process_ref, shape_ref, protocol, service_port, samples, obs_count, bytes_in, bytes_out, first_at, last_at)
		SELECT endpoint_ref, ?, process_ref, shape_ref, 6, 8080, 1, 1, 1.6779646779477647e19, 10, COALESCE(first_at, 0), COALESCE(last_at, 0) FROM flows LIMIT 1`,
		day.Unix()/flowHour); err != nil {
		t.Fatalf("seed loopback: %v", err)
	}
	if err := store.exportColdDay(t.TempDir(), day); err == nil || !strings.Contains(err.Error(), "overflow") && !strings.Contains(err.Error(), "float64") {
		t.Fatalf("export before repair: %v, want the overflowed SUM refused; the fixture does not reproduce the failure", err)
	}

	if err := store.SetSetting(byteCountRepairSetting, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.repairByteCounts(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	var in, out, measured int64
	if err := store.db.QueryRow(`SELECT SUM(bytes_in), SUM(bytes_out), SUM(measured) FROM flows`).Scan(&in, &out, &measured); err != nil {
		t.Fatalf("sum after repair: %v", err)
	}
	if in != 1200 || out != 64 || measured != 1 {
		t.Errorf("after repair: in %d out %d measured %d, want only the real sample (1200, 64, 1)", in, out, measured)
	}
	var loopback int64
	if err := store.db.QueryRow(`SELECT bytes_in FROM flow_local_hourly`).Scan(&loopback); err != nil || loopback != 0 {
		t.Errorf("loopback rollup after repair: %d, %v, want 0", loopback, err)
	}
	var buckets int64
	if err := store.db.QueryRow(`SELECT COALESCE(SUM(bytes_in), 0) FROM bandwidth_buckets`).Scan(&buckets); err != nil {
		t.Fatalf("bandwidth buckets after repair: %v", err)
	}
	if buckets > MaxByteCount {
		t.Errorf("bandwidth buckets still hold %d bytes in", buckets)
	}
	var p1, p2 int64
	if err := store.db.QueryRow(`SELECT (SELECT total_bytes_in FROM comm_profiles WHERE id = 'p1'), (SELECT total_bytes_in FROM comm_profiles WHERE id = 'p2')`).Scan(&p1, &p2); err != nil {
		t.Fatalf("profiles after repair: %v", err)
	}
	if p1 != 0 || p2 != 500 {
		t.Errorf("profiles: overflowed %d (want 0), intact %d (want 500)", p1, p2)
	}
	if err := store.exportColdDay(t.TempDir(), day); err != nil {
		t.Errorf("export after repair: %v", err)
	}

	// Once: a later count is the ingest guard's job, not a sweep's.
	if _, err := store.db.Exec(`UPDATE comm_profiles SET total_bytes_in = -1 WHERE id = 'p2'`); err != nil {
		t.Fatal(err)
	}
	if err := store.repairByteCounts(); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT total_bytes_in FROM comm_profiles WHERE id = 'p2'`).Scan(&p2); err != nil || p2 != -1 {
		t.Errorf("second repair ran again: %d, %v", p2, err)
	}
}

func TestByteCountValid(t *testing.T) {
	for n, want := range map[int64]bool{0: true, 1200: true, MaxByteCount: true, MaxByteCount + 1: false, -1: false, 1 << 40: true} {
		if got := ByteCountValid(n); got != want {
			t.Errorf("ByteCountValid(%d) = %v, want %v", n, got, want)
		}
	}
}
