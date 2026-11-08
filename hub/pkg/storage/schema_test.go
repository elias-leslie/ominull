package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// A fresh hub must not recreate retired feature storage. Existing databases
// may still carry those tables and settings, but no current code reads them.
func TestFreshSchemaOmitsRetiredFeatureStorage(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "schema.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	for _, name := range []string{"rules", "policy_groups"} {
		var count int
		if err := store.db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name,
		).Scan(&count); err != nil {
			t.Fatalf("checking %s: %v", name, err)
		}
		if count != 0 {
			t.Errorf("fresh schema recreated retired table %q", name)
		}
	}
	if value, err := store.GetSetting("copilot.config"); err != nil || value != "" {
		t.Errorf("fresh schema has retired copilot setting: value=%q err=%v", value, err)
	}
}

func TestUpgradedSchemaLeavesLegacyRowsInert(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening legacy database: %v", err)
	}
	for _, statement := range []string{
		`CREATE TABLE rules (id TEXT PRIMARY KEY, tenant_id TEXT, active INTEGER)`,
		`CREATE TABLE policy_groups (id TEXT PRIMARY KEY, tenant_id TEXT, active INTEGER)`,
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO rules (id, tenant_id, active) VALUES ('old-rule', 'default', 1)`,
		`INSERT INTO policy_groups (id, tenant_id, active) VALUES ('old-group', 'default', 1)`,
		`INSERT INTO settings (key, value) VALUES ('copilot.config', '{"enabled":true}')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("seeding legacy database: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("upgrading legacy database: %v", err)
	}
	defer store.Close()

	for _, table := range []string{"rules", "policy_groups"} {
		var rows int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&rows); err != nil {
			t.Fatalf("checking preserved %s rows: %v", table, err)
		}
		if rows != 1 {
			t.Fatalf("upgrade changed preserved %s rows: %d", table, rows)
		}
	}
	if value, err := store.GetSetting("copilot.config"); err != nil || value != "" {
		t.Fatalf("upgrade kept the retired copilot setting: value=%q err=%v", value, err)
	}
	// No current schema initializer or retained API recreates, migrates, or
	// evaluates these rows. Their continued presence is historical data only.
}

// Retired tables go at startup while empty and stay while they hold rows.
func TestRetiredTablesDroppedOnlyWhenEmpty(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retired.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE rules (id TEXT PRIMARY KEY)`,
		`CREATE TABLE dns_rules (id TEXT PRIMARY KEY)`,
		`INSERT INTO rules (id) VALUES ('kept')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	db.Close()
	store, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	has := func(table string) bool {
		var n int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !has("rules") {
		t.Error("rules held a row and was dropped")
	}
	if has("dns_rules") {
		t.Error("empty dns_rules was not dropped")
	}
	if err := store.dropRetiredTables(); err != nil { // again: nothing to do
		t.Fatal(err)
	}
}

// Settings keys nothing reads any more are gone after a start.
func TestRetiredSettingsAreDropped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ominull.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range append([]string{"setup.complete"}, retiredSettings...) {
		if err := store.SetSetting(k, "x"); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	store, err = New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, k := range retiredSettings {
		if v, _ := store.GetSetting(k); v != "" {
			t.Errorf("%s still set", k)
		}
	}
	if v, _ := store.GetSetting("aico_relay_key_sha256"); v != "x" {
		t.Errorf("the relay key was not kept under its Aico name: %q", v)
	}
	if v, _ := store.GetSetting("setup.complete"); v != "x" {
		t.Errorf("a live setting was dropped: setup.complete = %q", v)
	}
}

// A queued update for a Linux agent goes at startup; a Windows one stays.
func TestQueuedLinuxUpdatesAreDropped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ominull.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for id, capability := range map[string]string{"lin": "deb", "win": "msi"} {
		if err := store.UpsertEndpoint(Endpoint{ID: id, TenantID: "default", UpdateCapability: capability}); err != nil {
			t.Fatal(err)
		}
		if err := store.RequestAgentUpdate(id, "9.9.9"); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	store, err = New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if job, _ := store.GetAgentUpdateJob("lin"); job != nil {
		t.Errorf("Linux job kept: %+v", job)
	}
	if job, _ := store.GetAgentUpdateJob("win"); job == nil {
		t.Error("Windows job dropped")
	}
}
