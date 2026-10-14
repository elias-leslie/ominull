package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// Flow storage keeps the evidence of the old row-per-sample table at a
// fraction of its size. These tests pin what must survive the compaction:
// exact flows within a minute, process attribution, loopback counts, and the
// legacy rows of an upgraded hub.

func flowCount(t *testing.T, s *Store, q string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func sampleFlow(at time.Time, srcPort uint16) Event {
	first := at.Add(-time.Second)
	return Event{
		TenantID: "default", EndpointID: "e1", Timestamp: at, Layer: "linux-socket-v1", Action: "PERMIT",
		Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.5", DstIP: "203.0.113.9", SrcPort: srcPort, DstPort: 443,
		BytesIn: 100, BytesOut: 40, ProcessPath: "/usr/bin/curl", ProcessID: 77, ProcessInstanceID: "boot:77:1234",
		ParentPID: 1, ParentProcessInstanceID: "boot:1:1", CommandLine: "curl https://example.test",
		UserIdentity: "uid:1000", ExecutableSHA256: "ab12", Domain: "example.test", AttributionStatus: "attributed",
		Observation: FlowObservation{Source: "linux-sock-diag", Timing: "counter_sample", Count: 2, FirstAt: &first, LastAt: &at},
	}
}

func TestRepeatSamplesInAMinuteAreOneFlow(t *testing.T) {
	s := newTestStore(t)
	at := time.Date(2026, 10, 14, 12, 0, 5, 250_000_000, time.UTC)
	batch := []Event{sampleFlow(at, 40001), sampleFlow(at.Add(10*time.Second), 40002), sampleFlow(at.Add(20*time.Second), 40003)}
	if err := s.InsertTelemetryBatch(batch, "host", "loc"); err != nil {
		t.Fatal(err)
	}
	// The next minute is a new row.
	if err := s.InsertTelemetryBatch([]Event{sampleFlow(at.Add(time.Minute), 40004)}, "host", "loc"); err != nil {
		t.Fatal(err)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flows"); n != 2 {
		t.Fatalf("flows rows = %d, want 2 (one per minute)", n)
	}
	var samples, bytesIn, obsCount int64
	var srcPort int
	var ts, cmd, inst, user, sha, domain string
	err := s.db.QueryRow(`SELECT samples, bytes_in, src_port, timestamp, command_line, process_instance_id, user_identity,
		executable_sha256, domain, json_extract(observation_json, '$.count') FROM events ORDER BY id LIMIT 1`).
		Scan(&samples, &bytesIn, &srcPort, &ts, &cmd, &inst, &user, &sha, &domain, &obsCount)
	if err != nil {
		t.Fatal(err)
	}
	if samples != 3 || bytesIn != 300 || obsCount != 6 {
		t.Errorf("aggregate samples=%d bytes_in=%d count=%d, want 3/300/6", samples, bytesIn, obsCount)
	}
	if srcPort != 40001 {
		t.Errorf("src_port = %d, want the first sample's 40001", srcPort)
	}
	if !strings.HasPrefix(ts, "2026-10-14T12:00:05") && !strings.HasPrefix(ts, "2026-10-14 12:00:05") {
		t.Errorf("timestamp = %q, want the first sample's second", ts)
	}
	if cmd != "curl https://example.test" || inst != "boot:77:1234" || user != "uid:1000" || sha != "ab12" || domain != "example.test" {
		t.Errorf("attribution lost: cmd=%q inst=%q user=%q sha=%q domain=%q", cmd, inst, user, sha, domain)
	}
	// Nanosecond observation times survive in the JSON the old readers parse.
	var firstAt string
	if err := s.db.QueryRow("SELECT json_extract(observation_json, '$.first_at') FROM events ORDER BY id LIMIT 1").Scan(&firstAt); err != nil {
		t.Fatal(err)
	}
	if firstAt != "2026-10-14T12:00:04.250000000Z" {
		t.Errorf("first_at = %q", firstAt)
	}
	// One process row for the repeated instance; reading through the view
	// gives back a time.Time.
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flow_processes"); n != 1 {
		t.Errorf("flow_processes = %d, want 1", n)
	}
	evs, err := s.QueryEvents("default", "e1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Timestamp.IsZero() || evs[0].CommandLine == "" {
		t.Fatalf("QueryEvents = %+v", evs)
	}
}

func TestADifferentCommandLineIsADifferentProcess(t *testing.T) {
	s := newTestStore(t)
	at := time.Now().UTC().Truncate(time.Minute)
	a, b := sampleFlow(at, 1), sampleFlow(at, 2)
	b.CommandLine = "curl https://other.test"
	if err := s.InsertEventsBatch([]Event{a, b}); err != nil {
		t.Fatal(err)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flow_processes"); n != 2 {
		t.Errorf("flow_processes = %d, want 2", n)
	}
	if n := flowCount(t, s, "SELECT COUNT(DISTINCT command_line) FROM events"); n != 2 {
		t.Errorf("distinct command lines through the view = %d, want 2", n)
	}
}

func TestLoopbackBecomesHourlyCounters(t *testing.T) {
	s := newTestStore(t)
	at := time.Now().UTC().Truncate(time.Hour).Add(5 * time.Minute)
	var evs []Event
	for i := 0; i < 5; i++ {
		ev := sampleFlow(at.Add(time.Duration(i)*time.Minute), uint16(50000+i))
		ev.SrcIP, ev.DstIP, ev.DstPort = "127.0.0.1", "127.0.0.1", 5432
		evs = append(evs, ev)
	}
	if err := s.InsertEventsBatch(evs); err != nil {
		t.Fatal(err)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flows"); n != 0 {
		t.Errorf("loopback wrote %d minute rows, want none", n)
	}
	var rows, samples, bytesIn, port int64
	if err := s.db.QueryRow("SELECT COUNT(*), SUM(samples), SUM(bytes_in), MAX(service_port) FROM flow_local_hourly").Scan(&rows, &samples, &bytesIn, &port); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || samples != 5 || bytesIn != 500 || port != 5432 {
		t.Errorf("local counters rows=%d samples=%d bytes_in=%d port=%d, want 1/5/500/5432", rows, samples, bytesIn, port)
	}
	// The bandwidth rollup still counts them.
	if n := flowCount(t, s, "SELECT COALESCE(SUM(flow_count), 0) FROM bandwidth_buckets"); n != 5 {
		t.Errorf("bandwidth flow_count = %d, want 5", n)
	}
}

func TestPlainInsertsIntoTheEventsViewStillWork(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 2; i++ {
		if _, err := s.db.Exec(`INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
			src_ip, dst_ip, src_port, dst_port, process_path, process_id, command_line)
			VALUES ('default', 'e1', ?, 'linux-socket-v1', 'PERMIT', 'OUTBOUND', 6, '10.0.0.1', '10.0.0.2', 1, 2, '/bin/x', 1, 'x -v')`,
			time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM events WHERE command_line = 'x -v'"); n != 2 {
		t.Errorf("rows through the view = %d, want 2", n)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flow_processes"); n != 1 {
		t.Errorf("flow_processes = %d, want 1", n)
	}
}

// An upgraded hub starts with the old events table. Its rows move into flows
// (here synchronously: the table is small), the legacy table goes, and the
// view answers for both.
func TestLegacyEventsAreMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, timestamp DATETIME NOT NULL,
		layer TEXT NOT NULL, action TEXT NOT NULL, direction TEXT NOT NULL, protocol INTEGER NOT NULL,
		src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,
		process_path TEXT NOT NULL, process_id INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	for i := 0; i < 4; i++ {
		if _, err := db.Exec(`INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, process_path, process_id)
			VALUES ('default', 'e1', ?, 'linux-socket-v1', 'PERMIT', 'OUTBOUND', 6, '10.0.0.1', '198.51.100.7', ?, 443, '/usr/bin/wget', 9)`,
			now.Add(time.Duration(i)*time.Second).String(), 40000+i); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.legacyEventsPresent() {
		t.Fatal("legacy table still present after a small migration")
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM flows"); n != 1 {
		t.Errorf("flows = %d, want the 4 samples in one minute row", n)
	}
	if n := flowCount(t, s, "SELECT SUM(samples) FROM events WHERE process_path = '/usr/bin/wget'"); n != 4 {
		t.Errorf("samples through the view = %d, want 4", n)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'flows'"); n != 3 {
		t.Errorf("flow indexes = %d, want 3", n)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestDNSQueriesAreCountedPerMinute(t *testing.T) {
	s := newTestStore(t)
	at := time.Now().UTC().Truncate(time.Minute).Add(7 * time.Second)
	for i := 0; i < 3; i++ {
		if err := s.RecordDNSEvent(DNSEvent{Timestamp: at.Add(time.Duration(i) * time.Second), ClientIP: "10.0.0.8", Domain: "example.test",
			QType: "A", Action: "PERMIT", Status: "HIT", Transport: "udp"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, total, err := s.ListDNSEvents("default", DNSEventFilter{From: at.Add(-time.Minute), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(evs) != 1 || evs[0].Count != 3 {
		t.Fatalf("dns events total=%d rows=%+v, want one row counting 3", total, evs)
	}
	if !evs[0].Timestamp.Equal(at) {
		t.Errorf("timestamp = %s, want the first query's second %s", evs[0].Timestamp, at)
	}
}

func TestPrunedAnomaliesLeaveCounts(t *testing.T) {
	s := newTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	for i, id := range []string{"a1", "a2"} {
		if _, err := s.db.Exec(`INSERT INTO anomaly_alerts (id, tenant_id, endpoint_id, anomaly_type, severity, title, description, timestamp)
			VALUES (?, 'default', 'e1', 'beacon', 'HIGH', 't', 'd', ?)`, id, old.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PruneOldData(DefaultRetention()); err != nil {
		t.Fatal(err)
	}
	if n := flowCount(t, s, "SELECT COUNT(*) FROM anomaly_alerts"); n != 0 {
		t.Errorf("anomalies older than 90 days kept: %d", n)
	}
	counts, err := s.AnomalySignatureCounts("2000-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 1 || counts[0].Count != 2 || counts[0].AnomalyType != "beacon" {
		t.Errorf("signature counts = %+v, want one beacon row counting 2", counts)
	}
}

func TestDataReportMeasuresFlows(t *testing.T) {
	s := newTestStore(t)
	day := time.Now().UTC().Truncate(24 * time.Hour).Add(-24*time.Hour + time.Hour)
	var evs []Event
	for i := 0; i < 50; i++ {
		ev := sampleFlow(day.Add(time.Duration(i)*time.Minute), uint16(30000+i))
		evs = append(evs, ev)
	}
	if err := s.InsertEventsBatch(evs); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshDataReport(DefaultRetention()); err != nil {
		t.Fatal(err)
	}
	r := s.DataReport()
	if r == nil {
		t.Fatal("no report")
	}
	if r.FlowIndexes != 3 {
		t.Errorf("flow_indexes = %d, want 3", r.FlowIndexes)
	}
	if len(r.Endpoints) != 1 || r.Endpoints[0].EndpointID != "e1" || r.Endpoints[0].RowsPerDay != 50 {
		t.Errorf("endpoint rates = %+v, want e1 at 50 rows/day", r.Endpoints)
	}
	if r.HotBusyMBPerDay <= 0 || r.DBBytes <= 0 {
		t.Errorf("report sizes not measured: busy=%v db=%v", r.HotBusyMBPerDay, r.DBBytes)
	}
}

func TestOverBudgetNamesWhatIsOver(t *testing.T) {
	r := &DataReport{Budgets: DefaultDataBudgets(), HotBusyMBPerDay: 14.9, RouterMBPerClient: 0.305, DBBytes: 10 * mb}
	got := overBudget(r)
	if len(got) != 1 || got[0] != "router 0.305 MB per client-day (budget 0.3)" {
		t.Errorf("overBudget = %q", got)
	}
	r.RouterMBPerClient = 0.2
	if got := overBudget(r); len(got) != 0 {
		t.Errorf("within budget reported %q", got)
	}
}
