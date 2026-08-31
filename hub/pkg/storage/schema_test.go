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
	value, err := store.GetSetting("copilot.config")
	if err != nil || value != `{"enabled":true}` {
		t.Fatalf("upgrade changed legacy setting: value=%q err=%v", value, err)
	}
	// No current schema initializer or retained API recreates, migrates, or
	// evaluates these rows. Their continued presence is historical data only.
}
