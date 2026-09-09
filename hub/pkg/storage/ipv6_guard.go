package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"ominull/hub/pkg/ipv6guard"
	"time"
)

func (s *Store) initIPv6GuardSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ipv6_observations (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, payload TEXT NOT NULL,
 first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, count INTEGER NOT NULL,
 last_alert DATETIME
 ); CREATE INDEX IF NOT EXISTS idx_ipv6_observation_time ON ipv6_observations(tenant_id,last_seen);`)
	return err
}
func (s *Store) IPv6GuardConfig() (ipv6guard.Config, error) {
	var c ipv6guard.Config
	raw, err := s.GetSetting("ipv6.guard")
	if err != nil {
		return c, err
	}
	if raw != "" {
		if err = json.Unmarshal([]byte(raw), &c); err != nil {
			return c, err
		}
	}
	return c, c.Validate()
}
func (s *Store) SetIPv6GuardConfig(c ipv6guard.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.SetSetting("ipv6.guard", string(raw))
}

type IPv6Finding struct {
	ID          string
	Observation ipv6guard.Observation
	Reasons     []string
}

// A flood cannot grow history without bound. Counters retain repeated observed
// packets; only 2,048 recent distinct observations per tenant are retained.
func (s *Store) RecordIPv6Observations(batch []ipv6guard.Observation, c ipv6guard.Config) ([]IPv6Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var findings []IPv6Finding
	for _, o := range batch {
		key := o
		key.FirstSeen = time.Time{}
		key.LastSeen = time.Time{}
		key.Count = 0
		raw, _ := json.Marshal(key)
		id := fmt.Sprintf("%x", sha256.Sum256(append([]byte(c.TenantID+"\n"), raw...)))
		payload, err := json.Marshal(o)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO ipv6_observations(id,tenant_id,payload,first_seen,last_seen,count) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,last_seen=excluded.last_seen,count=count+excluded.count`, id, c.TenantID, string(payload), o.FirstSeen, o.LastSeen, o.Count)
		if err != nil {
			return nil, err
		}
		reasons := ipv6guard.Violations(o, c)
		if len(reasons) == 0 {
			continue
		}
		var last sql.NullTime
		if err = tx.QueryRow(`SELECT last_alert FROM ipv6_observations WHERE id=?`, id).Scan(&last); err != nil {
			return nil, err
		}
		if last.Valid && o.LastSeen.Sub(last.Time) < time.Hour {
			continue
		}
		findings = append(findings, IPv6Finding{id, o, reasons})
	}
	if _, err = tx.Exec(`DELETE FROM ipv6_observations WHERE tenant_id=? AND id NOT IN (SELECT id FROM ipv6_observations WHERE tenant_id=? ORDER BY last_seen DESC LIMIT 2048)`, c.TenantID, c.TenantID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return findings, nil
}
func (s *Store) IPv6Observations(tenant string) ([]ipv6guard.Observation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT payload,first_seen,last_seen,count FROM ipv6_observations WHERE tenant_id=? ORDER BY last_seen DESC LIMIT 100`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ipv6guard.Observation{}
	for rows.Next() {
		var raw string
		var first, last time.Time
		var count int64
		if err := rows.Scan(&raw, &first, &last, &count); err != nil {
			return nil, err
		}
		var o ipv6guard.Observation
		if err := json.Unmarshal([]byte(raw), &o); err != nil {
			return nil, err
		}
		o.FirstSeen = first
		o.LastSeen = last
		o.Count = count
		out = append(out, o)
	}
	return out, rows.Err()
}

// Mark only after the alert write succeeds; transient persistence failures must
// not suppress the next attempt for an hour.
func (s *Store) MarkIPv6Alert(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE ipv6_observations SET last_alert=? WHERE id=?`, at, id)
	return err
}
