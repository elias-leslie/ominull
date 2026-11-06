package storage

import "time"

// The notices already pushed to Aico, one row per token (an incident, an
// incident's escalation, or an alert id), so a restart or a repeat never asks
// the owner twice.

func (s *Store) initAicoPushSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS aico_push_sent (
		token TEXT PRIMARY KEY,
		sent_at TIMESTAMP NOT NULL
	)`)
	return err
}

// AicoPushSent returns which of the tokens were already sent.
func (s *Store) AicoPushSent(tokens []string) (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]bool{}
	for _, t := range tokens {
		var one int
		err := s.db.QueryRow(`SELECT 1 FROM aico_push_sent WHERE token = ?`, t).Scan(&one)
		if err == nil {
			out[t] = true
		}
	}
	return out, nil
}

// MarkAicoPushSent records the tokens as sent at the given time.
func (s *Store) MarkAicoPushSent(tokens []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tokens {
		if _, err := s.db.Exec(`INSERT INTO aico_push_sent (token, sent_at) VALUES (?, ?)
			ON CONFLICT(token) DO UPDATE SET sent_at = excluded.sent_at`, t, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// PruneAicoPushSent forgets tokens sent before the given time.
func (s *Store) PruneAicoPushSent(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM aico_push_sent WHERE sent_at < ?`, before.UTC())
	return err
}
