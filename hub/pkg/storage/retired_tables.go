package storage

import (
	"fmt"
	"log"
)

// retiredTables are tables the hub no longer reads or writes (the third trim,
// docs/DESIGN_HISTORY.md). Each is dropped at startup only while it is empty:
// a table that still holds rows is history nobody has looked at yet, so it is
// left in place and named in the log rather than deleted.
var retiredTables = []string{
	"rules",          // legacy firewall rules; no code since the feature reduction
	"dns_rules",      // legacy DNS allow/block list; no code since the DNS incident
	"topology_views", // saved topology layouts; the feature was cut in 2026-10-31
}

// dropRetiredTables drops each retired table that exists and holds no rows.
func (s *Store) dropRetiredTables() error {
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
