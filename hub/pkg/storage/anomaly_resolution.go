package storage

import (
	"errors"
	"strings"
	"time"
)

// A resolution is why an operator closed a finding. Acknowledging alone says
// only that somebody looked; a backlog closed in bulk without a reason is one
// nobody can audit later, and the reason is usually the tuning that now keeps
// the same conversation from being raised again.
func (s *Store) initAnomalyResolutionSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS anomaly_resolutions (
		anomaly_id TEXT PRIMARY KEY,
		reason TEXT NOT NULL,
		resolved_by TEXT NOT NULL DEFAULT '',
		resolved_at DATETIME NOT NULL
	);`)
	return err
}

// MaxReplayAlerts bounds how many findings one replay or bulk resolution reads.
const MaxReplayAlerts = 200000

// ListAnomalyAlertsBetween returns every finding raised in [from, to), held or
// not, oldest first. openOnly leaves out acknowledged ones.
func (s *Store) ListAnomalyAlertsBetween(tenantID string, from, to time.Time, openOnly bool) ([]AnomalyAlert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	where := " WHERE timestamp >= ? AND timestamp < ?"
	args := []any{from.UTC(), to.UTC()}
	if tenantID != "" {
		where += " AND tenant_id = ?"
		args = append(args, tenantID)
	}
	if openOnly {
		where += " AND acknowledged = 0"
	}
	args = append(args, MaxReplayAlerts)
	rows, err := s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, anomaly_type, severity, title, description, details, COALESCE(evidence, ''), COALESCE(technique, ''), COALESCE(held_reason, ''), process_path, dst_ip, dst_port, timestamp, acknowledged FROM anomaly_alerts"+where+" ORDER BY timestamp ASC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AnomalyAlert, 0)
	for rows.Next() {
		var a AnomalyAlert
		var ack int
		if err := rows.Scan(&a.ID, &a.TenantID, &a.LocationID, &a.EndpointID, &a.Hostname,
			&a.AnomalyType, &a.Severity, &a.Title, &a.Description, &a.Details, &a.Evidence,
			&a.Technique, &a.HeldReason, &a.ProcessPath, &a.DstIP, &a.DstPort, &a.Timestamp, &ack); err != nil {
			return nil, err
		}
		a.Acknowledged = ack != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// ResolveAnomalies acknowledges findings and records why, in one transaction.
// Only findings of tenantID are touched when it is set. It returns how many
// findings were open and are now resolved.
func (s *Store) ResolveAnomalies(tenantID string, ids []string, reason, by string) (int, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return 0, errors.New("a resolution needs a reason")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	n := 0
	for _, id := range ids {
		q, args := "UPDATE anomaly_alerts SET acknowledged = 1 WHERE id = ? AND acknowledged = 0", []any{id}
		if tenantID != "" {
			q += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
		r, err := tx.Exec(q, args...)
		if err != nil {
			return 0, err
		}
		if c, _ := r.RowsAffected(); c == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO anomaly_resolutions (anomaly_id, reason, resolved_by, resolved_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(anomaly_id) DO UPDATE SET reason = excluded.reason, resolved_by = excluded.resolved_by, resolved_at = excluded.resolved_at`,
			id, reason, by, now); err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

// AnomalyResolution returns the recorded reason a finding was closed, if any.
func (s *Store) AnomalyResolution(id string) (reason, by string, at time.Time, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	err := s.db.QueryRow(`SELECT reason, resolved_by, resolved_at FROM anomaly_resolutions WHERE anomaly_id = ?`, id).Scan(&reason, &by, &at)
	return reason, by, at, err == nil
}
