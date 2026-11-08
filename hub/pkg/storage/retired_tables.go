package storage

import (
	"fmt"
	"log"
)

// retiredTables are tables the hub no longer reads or writes (the third
// trim). Each is dropped at startup only while it is empty: a table that still
// holds rows is history nobody has looked at yet, so it is left in place and
// named in the log rather than deleted.
var retiredTables = []string{
	"rules",          // legacy firewall rules; no code since the feature reduction
	"dns_rules",      // legacy DNS allow/block list; no code since the DNS incident
	"topology_views", // saved topology layouts; the feature was cut in 2026-10-31
}

// retiredSettings are settings keys nothing reads any more: the retired
// copilot and Nightshift, the shared-key agent login (closed on every hub),
// and the markers of one-time repairs that ran everywhere and whose code is
// gone.
var retiredSettings = []string{
	"nightshift_approval_relay_key_sha256", // copied to aico_relay_key_sha256 first
	"nightshift_feed_key_sha256",
	"nightshift_device_salt",
	"copilot.config",
	"legacy_agent_auth",
	"byte_count_repair_v1",
	"byte_rate_repair_v1",
	"anomaly_hunt_tier_backfill_v1",
}

// dropRetiredTables drops each retired table that exists and holds no rows,
// and the retired settings keys.
func (s *Store) dropRetiredTables() error {
	// A database from before 2026-11-06 still holds the relay key under its
	// Nightshift name; keep it under the Aico one (a key already issued there
	// wins) before the old name goes.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings (key, value)
		SELECT 'aico_relay_key_sha256', value FROM settings WHERE key = 'nightshift_approval_relay_key_sha256'`); err != nil {
		return fmt.Errorf("keeping the relay key: %w", err)
	}
	for _, key := range retiredSettings {
		if _, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key); err != nil {
			return fmt.Errorf("dropping retired setting %s: %w", key, err)
		}
	}
	for _, table := range retiredTables {
		var exists int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		var rows int
		// The name comes from retiredTables above, never from input.
		if err := s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %q`, table)).Scan(&rows); err != nil {
			return err
		}
		if rows > 0 {
			log.Printf("[*] Retired table %s still holds %d row(s); kept. Nothing reads it.", table, rows)
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(`DROP TABLE %q`, table)); err != nil {
			return fmt.Errorf("dropping retired table %s: %w", table, err)
		}
		log.Printf("[*] Dropped retired table %s (empty).", table)
	}
	return nil
}
