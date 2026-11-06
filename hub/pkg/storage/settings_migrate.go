package storage

import "log"

// Settings the retired Nightshift product left behind. The relay key moved to
// its Aico name (the stored hash is the key Aico already holds); the other two
// have no reader any more. Runs at startup and does nothing once done.
const (
	oldRelayKeySetting = "nightshift_approval_relay_key_sha256"
	newRelayKeySetting = "aico_relay_key_sha256"
)

var deadNightshiftSettings = []string{"nightshift_feed_key_sha256", "nightshift_device_salt"}

func (s *Store) migrateNightshiftSettings() error {
	var old string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, oldRelayKeySetting).Scan(&old)
	if err == nil {
		// A key already issued under the new name wins.
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, newRelayKeySetting, old); err != nil {
			return err
		}
		if _, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, oldRelayKeySetting); err != nil {
			return err
		}
		log.Printf("[*] Settings: relay key moved to %s.", newRelayKeySetting)
	}
	for _, k := range deadNightshiftSettings {
		if _, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, k); err != nil {
			return err
		}
	}
	return nil
}
