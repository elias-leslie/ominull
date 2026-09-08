package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := New(path)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	return store
}

func seedAnomaly(t *testing.T, s *Store, id, severity string, acknowledged bool) {
	t.Helper()
	if err := s.CreateAnomalyAlert(AnomalyAlert{
		ID:           id,
		TenantID:     "default",
		EndpointID:   "ep-1",
		AnomalyType:  "C2_BEACONING",
		Technique:    "T1071.001",
		Severity:     severity,
		Title:        "finding " + id,
		Description:  "a finding",
		Timestamp:    time.Now().UTC(),
		Acknowledged: acknowledged,
	}); err != nil {
		t.Fatalf("seeding %s: %v", id, err)
	}
}

// The dashboard and the alerts page were reading two different tables, and
// nothing kept them in step: the strip reported 3,593 CRITICAL over a page
// showing two, because acknowledging a finding cleared one copy and not the
// other. They now count the same rows, and only the open ones.
func TestTheSeverityChartCountsTheFindingsTheAlertPageShows(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "counts.db"))
	seedAnomaly(t, store, "a-1", "CRITICAL", false)
	seedAnomaly(t, store, "a-2", "HIGH", false)
	seedAnomaly(t, store, "a-3", "HIGH", false)
	seedAnomaly(t, store, "a-4", "HIGH", true) // dealt with

	summary, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("analytics: %v", err)
	}
	if summary.SeverityCounts["CRITICAL"] != 1 {
		t.Errorf("CRITICAL is %d, want 1", summary.SeverityCounts["CRITICAL"])
	}
	if summary.SeverityCounts["HIGH"] != 2 {
		t.Errorf("HIGH is %d, want 2 - an acknowledged finding is still being charted", summary.SeverityCounts["HIGH"])
	}

	open, err := store.CountAnomalyAlerts("default", true)
	if err != nil {
		t.Fatalf("counting open findings: %v", err)
	}
	var charted int64
	for _, n := range summary.SeverityCounts {
		charted += n
	}
	if charted != open {
		t.Fatalf("the chart totals %d and the alert page totals %d", charted, open)
	}
}

// The legacy endpoint keeps its shape for callers outside the console, but the
// rows behind it are the findings, not a second copy of them.
func TestTheLegacyAlertEndpointServesTheFindings(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "legacy.db"))
	seedAnomaly(t, store, "b-1", "HIGH", false)
	seedAnomaly(t, store, "b-2", "LOW", true)

	list, err := store.ListAlerts("default", 100)
	if err != nil {
		t.Fatalf("listing alerts: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d alerts, want the 2 findings", len(list))
	}
	byID := map[string]Alert{}
	for _, a := range list {
		byID[a.ID] = a
	}
	if byID["b-1"].Severity != "HIGH" || byID["b-1"].Mitigated {
		t.Errorf("open finding came back as %+v", byID["b-1"])
	}
	if !byID["b-2"].Mitigated {
		t.Error("an acknowledged finding is not reported as handled")
	}
}

// Every detector used to write a row into `alerts` as well, and nothing ever
// read, acknowledged or cleared it - 48,046 of them had accumulated in
// production. Retire the empty copy, preserving unexpected data on older upgrades.
func TestRetireEmptyLegacyAlertsWithoutLosingFindings(t *testing.T) {
	for _, rows := range []int{0, 1} {
		t.Run(fmt.Sprint(rows), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "legacy.db")
			store := openStore(t, dbPath)
			seedAnomaly(t, store, "retained", "HIGH", false)
			store.Close()
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, tenant_id TEXT, endpoint_id TEXT, timestamp DATETIME, title TEXT, description TEXT, severity TEXT)"); err != nil {
				t.Fatal(err)
			}
			if rows > 0 {
				if _, err := db.Exec("INSERT INTO alerts (id, tenant_id, endpoint_id, timestamp, title, description, severity) VALUES ('legacy', 'default', 'ep-1', CURRENT_TIMESTAMP, 'old', 'old', 'HIGH')"); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			store = openStore(t, dbPath)
			defer store.Close()
			var exists int
			if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alerts'").Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists != rows {
				t.Fatalf("legacy table exists=%d; want %d (only empty tables may retire)", exists, rows)
			}
			if rows > 0 {
				var n int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&n); err != nil || n != rows {
					t.Fatalf("legacy data lost: rows=%d err=%v", n, err)
				}
			}
			if n, err := store.CountAnomalyAlerts("default", true); err != nil || n != 1 {
				t.Fatalf("current finding lost: count=%d err=%v", n, err)
			}
		})
	}
}

func TestRetentionAfterLegacyAlertsRetirement(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "retired-retention.db"))
	defer store.Close()
	seedAnomaly(t, store, "current", "HIGH", false)
	if _, err := store.PruneOldData(DefaultRetention()); err != nil {
		t.Fatalf("retention still depends on retired table: %v", err)
	}
	if n, err := store.CountAnomalyAlerts("default", true); err != nil || n != 1 {
		t.Fatalf("current findings changed: %d %v", n, err)
	}
}
