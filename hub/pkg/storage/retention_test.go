package storage

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Nothing in this package ever deleted a telemetry row. The file grew for the
// life of the deployment and stopped only when the disk did - at which point
// every write fails, including the ones recording that something is wrong.
func TestOldTelemetryIsPruned(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	// Two rows either side of every boundary, plus enough old telemetry to make
	// the batching loop go round more than once.
	seed := func(table, column string, ts time.Time, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("%s-%d-%d", table, ts.UnixNano(), i)
			var err error
			switch table {
			case "events":
				// id is an AUTOINCREMENT integer here, so it is left to sqlite.
				_, err = store.db.Exec(`INSERT INTO events
					(tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
					 src_ip, dst_ip, src_port, dst_port, process_path, process_id)
					VALUES ('default','e1',?,'eBPF_TC','PERMIT','out',6,'10.0.0.1','10.0.0.2',1,2,'/bin/x',1)`, ts)
			case "anomaly_alerts":
				_, err = store.db.Exec(`INSERT INTO anomaly_alerts
					(id, tenant_id, endpoint_id, anomaly_type, title, description, timestamp)
					VALUES (?, 'default','e1','beacon','t','d',?)`, id, ts)
			case "alerts":
				_, err = store.db.Exec(`INSERT INTO alerts
					(id, tenant_id, endpoint_id, timestamp, title, description, severity)
					VALUES (?, 'default','e1',?,'t','d','HIGH')`, id, ts)
			case "audit_logs":
				_, err = store.db.Exec(`INSERT INTO audit_logs
					(id, tenant_id, user_id, username, action, resource, details, ip_address, timestamp)
					VALUES (?, 'default','u','admin','ISOLATE_HOST','e1','','10.0.0.9',?)`, id, ts)
			}
			if err != nil {
				t.Fatalf("seed %s: %v", table, err)
			}
		}
	}

	count := func(table string) int {
		var n int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	seed("events", "timestamp", now.Add(-30*24*time.Hour), pruneBatch+7)
	seed("events", "timestamp", now.Add(-1*time.Hour), 3)
	seed("anomaly_alerts", "timestamp", now.Add(-90*24*time.Hour), 4)
	seed("anomaly_alerts", "timestamp", now.Add(-1*time.Hour), 2)
	seed("alerts", "timestamp", now.Add(-90*24*time.Hour), 5)
	seed("audit_logs", "timestamp", now.Add(-400*24*time.Hour), 6)
	seed("audit_logs", "timestamp", now.Add(-10*24*time.Hour), 1)

	removed, err := store.PruneOldData(DefaultRetention())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}

	if got := count("events"); got != 3 {
		t.Errorf("events: kept %d rows, want the 3 inside retention (removed %d)", got, removed["events"])
	}
	if got := count("anomaly_alerts"); got != 2 {
		t.Errorf("anomaly_alerts: kept %d rows, want 2", got)
	}
	if got := count("alerts"); got != 0 {
		t.Errorf("alerts: kept %d rows, want 0", got)
	}
	// Audit is the record of who did what and outlives everything else.
	if got := count("audit_logs"); got != 1 {
		t.Errorf("audit_logs: kept %d rows, want the 1 inside a year", got)
	}

	// A zero duration is "keep everything", not "delete everything" - an
	// operator who disables pruning must not thereby erase the table.
	seed("events", "timestamp", now.Add(-365*24*time.Hour), 4)
	if _, err := store.PruneOldData(RetentionPolicy{}); err != nil {
		t.Fatalf("prune with an empty policy: %v", err)
	}
	if got := count("events"); got != 7 {
		t.Errorf("an empty retention policy removed rows: %d left, want 7", got)
	}
}

// The live half of the diurnal profile ran strftime('%H', timestamp) against a
// column holding Go's time.String() form, which SQLite answers with NULL. Every
// hour came back empty and had done for as long as the field existed, while the
// baseline beside it was a hardcoded business-hours curve scaled by the row
// count - a chart drawn entirely from numbers no traffic produced.
func TestDiurnalProfileIsMeasured(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "diurnal.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	insert := func(ts time.Time, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := store.db.Exec(`INSERT INTO events
				(tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
				 src_ip, dst_ip, src_port, dst_port, process_path, process_id)
				VALUES ('default','e1',?,'eBPF_TC','PERMIT','out',6,'10.0.0.1','10.0.0.2',1,2,'/bin/x',1)`,
				ts.UTC()); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}

	now := time.Now().UTC()
	// Something inside the live window, at a known hour.
	liveAt := now.Add(-3 * time.Hour)
	insert(liveAt, 5)
	// The same hour on each of the seven baseline days.
	// Each of the seven days that make up the baseline window, which ends where
	// the live window begins.
	for d := 1; d <= 7; d++ {
		insert(liveAt.AddDate(0, 0, -d), 7)
	}

	baseline, live, err := store.GetDiurnalProfiles("default")
	if err != nil {
		t.Fatalf("diurnal: %v", err)
	}
	hr := liveAt.Hour()

	if live[hr] != 5 {
		t.Errorf("live hour %02d: got %d, want the 5 events actually recorded there", hr, live[hr])
	}
	total := int64(0)
	for _, n := range live {
		total += n
	}
	if total != 5 {
		t.Errorf("live series totals %d across the day, want 5", total)
	}
	// 7 days x 7 events in that hour, averaged back down to one day.
	if baseline[hr] != 7 {
		t.Errorf("baseline hour %02d: got %d, want 7", hr, baseline[hr])
	}
	// Every other hour saw nothing, and must say so rather than draw a curve.
	for h := 0; h < 24; h++ {
		if h == hr {
			continue
		}
		if baseline[h] != 0 || live[h] != 0 {
			t.Errorf("hour %02d reports baseline=%d live=%d with no events recorded there",
				h, baseline[h], live[h])
		}
	}
}

// The totals, the countries card and the geo card were three separate full
// scans of events asking the same question three ways. They are one grouped
// scan now, so the thing worth pinning is that the three answers still agree
// with each other and with the rows.
func TestAnalyticsTotalsAgreeWithTheCountryBreakdown(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	insert := func(country, action string, in, out int64, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := store.db.Exec(`INSERT INTO events
				(tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
				 src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id)
				VALUES ('default','e1',?,'eBPF_TC',?,'out',6,'10.0.0.1','10.0.0.2',1,2,?,?,?,'/bin/x',1)`,
				time.Now().UTC(), action, in, out, country); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}

	insert("US", "PERMIT", 10, 20, 5)  //  5 flows,  150 bytes
	insert("DE", "BLOCK", 100, 200, 2) //  2 flows,  600 bytes
	insert("SE", "PERMIT", 1, 1, 9)    //  9 flows,   18 bytes

	summary, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}

	if summary.TotalEvents != 16 {
		t.Errorf("TotalEvents = %d, want 16", summary.TotalEvents)
	}
	if summary.TotalBytesIn != 5*10+2*100+9*1 {
		t.Errorf("TotalBytesIn = %d, want %d", summary.TotalBytesIn, 5*10+2*100+9*1)
	}
	if summary.TotalBytesOut != 5*20+2*200+9*1 {
		t.Errorf("TotalBytesOut = %d, want %d", summary.TotalBytesOut, 5*20+2*200+9*1)
	}
	if summary.TotalBlocks != 2 || summary.TotalPermits != 14 {
		t.Errorf("blocks/permits = %d/%d, want 2/14", summary.TotalBlocks, summary.TotalPermits)
	}

	// The countries card counts flows.
	if summary.Countries["SE"] != 9 || summary.Countries["US"] != 5 || summary.Countries["DE"] != 2 {
		t.Errorf("Countries = %v, want SE 9, US 5, DE 2", summary.Countries)
	}

	// The geo card ranks by bytes, so DE (600) leads despite having the fewest
	// flows, and its threat count is the blocked flows in it.
	if len(summary.GeoStats) != 3 {
		t.Fatalf("GeoStats has %d entries, want 3", len(summary.GeoStats))
	}
	if summary.GeoStats[0].Country != "DE" {
		t.Errorf("geo is ordered %v..., want DE first (most bytes)", summary.GeoStats[0].Country)
	}
	if summary.GeoStats[0].TotalBytes != 600 || summary.GeoStats[0].ThreatCount != 2 {
		t.Errorf("DE: %d bytes / %d threats, want 600 / 2",
			summary.GeoStats[0].TotalBytes, summary.GeoStats[0].ThreatCount)
	}
	if summary.GeoStats[0].CountryName != "Germany" {
		t.Errorf("DE renders as %q, want Germany", summary.GeoStats[0].CountryName)
	}

	// Column sums of the breakdown are the totals; that is the invariant the
	// single scan rests on.
	var flows, bytes int64
	for _, g := range summary.GeoStats {
		flows += g.FlowCount
		bytes += g.TotalBytes
	}
	if flows != summary.TotalEvents {
		t.Errorf("geo flows sum to %d, totals say %d", flows, summary.TotalEvents)
	}
	if bytes != summary.TotalBytesIn+summary.TotalBytesOut {
		t.Errorf("geo bytes sum to %d, totals say %d", bytes, summary.TotalBytesIn+summary.TotalBytesOut)
	}
}

// The summary costs two full passes over events - about 860ms on a 340k-row
// database - and it is what the console polls. Repeating that under the store's
// read lock for every watcher is the shape of the outage this package already
// had, so the result is held briefly. What has to hold: the cache is per
// tenant, it hands out copies rather than the maps it kept, and it expires.
func TestAnalyticsSummaryIsCachedPerTenant(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	insert := func(country string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := store.db.Exec(`INSERT INTO events
				(tenant_id, endpoint_id, timestamp, layer, action, direction, protocol,
				 src_ip, dst_ip, src_port, dst_port, country, process_path, process_id)
				VALUES ('default','e1',?,'eBPF_TC','PERMIT','out',6,'10.0.0.1','10.0.0.2',1,2,?,'/bin/x',1)`,
				time.Now().UTC(), country); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}

	insert("US", 3)
	first, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if first.TotalEvents != 3 {
		t.Fatalf("TotalEvents = %d, want 3", first.TotalEvents)
	}

	// Rows added inside the window are not expected to appear: that is the
	// trade the cache makes, and stating it here is what stops someone reading
	// a stale total as a bug later.
	insert("US", 4)
	second, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if second.TotalEvents != 3 {
		t.Errorf("second call recomputed inside the TTL: got %d, want the cached 3", second.TotalEvents)
	}

	// A copy, not the same maps: two callers must not be able to see each
	// other's writes, and the cached entry must survive a caller mutating what
	// it was handed.
	second.Countries["US"] = 999
	third, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if third.Countries["US"] == 999 {
		t.Error("the cache handed out its own map; a caller's write reached the next reader")
	}

	// Another tenant is a different question and must not be answered from
	// this one's entry.
	other, err := store.GetAnalyticsSummary("someone-else")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if other.TotalEvents != 0 {
		t.Errorf("a second tenant was served the first tenant's summary: %d events", other.TotalEvents)
	}

	// And it expires.
	store.analytics.mu.Lock()
	entry := store.analytics.entries["default"]
	entry.computed = entry.computed.Add(-analyticsCacheTTL - time.Second)
	store.analytics.entries["default"] = entry
	store.analytics.mu.Unlock()

	fresh, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if fresh.TotalEvents != 7 {
		t.Errorf("after the TTL the summary was still stale: got %d, want 7", fresh.TotalEvents)
	}
}
