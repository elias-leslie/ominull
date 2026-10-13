package storage

import (
	"errors"
	"fmt"
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
	if err != nil {
		return err
	}
	// The reason is prose for people. What a learner may train on is the
	// structured part: the verdict an operator gave (benign, malicious or
	// none) and how the finding was closed (by a tuning rule or by hand).
	for _, col := range []string{"verdict TEXT NOT NULL DEFAULT ''", "method TEXT NOT NULL DEFAULT ''"} {
		if _, err := s.db.Exec(`ALTER TABLE anomaly_resolutions ADD COLUMN ` + col); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	// Before the columns existed only the tuning path wrote this prefix.
	_, err = s.db.Exec(`UPDATE anomaly_resolutions SET verdict = ?, method = ? WHERE method = '' AND reason LIKE 'covered by tuning:%'`,
		VerdictBenign, MethodTuning)
	return err
}

// Resolution verdicts and methods.
const (
	VerdictBenign    = "benign"
	VerdictMalicious = "malicious"
	MethodTuning     = "tuning"   // closed because a saved tuning rule no longer raises it
	MethodOperator   = "operator" // closed by an administrator naming it
)

// Resolution is why and how a finding was closed. Verdict is "" when the
// operator gave none: the finding is closed, but nothing is confirmed.
type Resolution struct {
	Reason  string
	By      string
	Verdict string
	Method  string
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

// resolveChunk bounds one resolution transaction, so a bulk close never holds
// the store's lock long enough to stall ingest.
const resolveChunk = 500

// ResolveAnomalies acknowledges findings and records why, a few hundred per
// transaction. Only findings of tenantID are touched when it is set. It
// returns how many findings were open and are now resolved; on an error the
// chunks before it stay resolved and are counted.
func (s *Store) ResolveAnomalies(tenantID string, ids []string, res Resolution) (int, error) {
	res.Reason = strings.TrimSpace(res.Reason)
	if res.Reason == "" {
		return 0, errors.New("a resolution needs a reason")
	}
	switch res.Verdict {
	case "", VerdictBenign, VerdictMalicious:
	default:
		return 0, fmt.Errorf("verdict %q is not benign or malicious", res.Verdict)
	}
	total := 0
	for len(ids) > 0 {
		chunk := ids[:min(resolveChunk, len(ids))]
		ids = ids[len(chunk):]
		n, err := s.resolveAnomalyChunk(tenantID, chunk, res)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *Store) resolveAnomalyChunk(tenantID string, ids []string, res Resolution) (int, error) {
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
			// A finding acknowledged earlier can still be given an operator's
			// verdict: one acked unread and later found malicious must be
			// labelled malicious. Tuning never overwrites a closed finding.
			if res.Verdict == "" || res.Method != MethodOperator {
				continue
			}
			q, args := "SELECT 1 FROM anomaly_alerts WHERE id = ? AND acknowledged = 1", []any{id}
			if tenantID != "" {
				q += " AND tenant_id = ?"
				args = append(args, tenantID)
			}
			var one int
			if err := tx.QueryRow(q, args...).Scan(&one); err != nil {
				continue
			}
		}
		if _, err := tx.Exec(`INSERT INTO anomaly_resolutions (anomaly_id, reason, resolved_by, resolved_at, verdict, method) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(anomaly_id) DO UPDATE SET reason = excluded.reason, resolved_by = excluded.resolved_by, resolved_at = excluded.resolved_at,
			verdict = excluded.verdict, method = excluded.method`,
			id, res.Reason, res.By, now, res.Verdict, res.Method); err != nil {
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

// ResolutionRecord is a recorded resolution as the console shows it.
type ResolutionRecord struct {
	Reason     string    `json:"reason"`
	By         string    `json:"by"`
	Verdict    string    `json:"verdict"`
	Method     string    `json:"method"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// AttachResolutions fills Resolution on each finding that has one, in one
// read: a page of alerts is at most a few hundred ids.
func (s *Store) AttachResolutions(alerts []AnomalyAlert) error {
	if len(alerts) == 0 {
		return nil
	}
	ids := make([]any, len(alerts))
	for i, a := range alerts {
		ids[i] = a.ID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT anomaly_id, reason, resolved_by, verdict, method, resolved_at FROM anomaly_resolutions WHERE anomaly_id IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := map[string]*ResolutionRecord{}
	for rows.Next() {
		var id string
		var r ResolutionRecord
		if err := rows.Scan(&id, &r.Reason, &r.By, &r.Verdict, &r.Method, &r.ResolvedAt); err != nil {
			return err
		}
		byID[id] = &r
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range alerts {
		alerts[i].Resolution = byID[alerts[i].ID]
	}
	return nil
}
