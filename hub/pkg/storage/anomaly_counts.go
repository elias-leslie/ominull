package storage

import (
	"fmt"
	"time"
)

// Anomalies are kept in full for the anomaly window (90 days on the home
// tier). What goes after that is folded into per-signature daily counts that
// stay a year, so "how often has this fired" outlives the findings.

func (s *Store) initAnomalyCountsSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS anomaly_signature_daily (
		day TEXT NOT NULL,
		anomaly_type TEXT NOT NULL,
		severity TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		count INTEGER NOT NULL,
		PRIMARY KEY (day, anomaly_type, severity, endpoint_id)
	) WITHOUT ROWID;`)
	return err
}

// AnomalySignatureCount is one day's count of pruned findings of one kind.
type AnomalySignatureCount struct {
	Day         string `json:"day"`
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
	EndpointID  string `json:"endpoint_id"`
	Count       int64  `json:"count"`
}

// rollUpAndPruneAnomalies counts and deletes findings older than cutoff, one
// batch per transaction so a count is never added without its rows going.
func (s *Store) rollUpAndPruneAnomalies(cutoff time.Time) (int64, error) {
	var total int64
	for {
		n, err := s.rollUpAnomalyBatch(cutoff)
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneBatch {
			return total, nil
		}
	}
}

func (s *Store) rollUpAnomalyBatch(cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DROP TABLE IF EXISTS temp.anomaly_prune"); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(fmt.Sprintf("CREATE TEMP TABLE anomaly_prune AS SELECT rowid AS rid FROM anomaly_alerts WHERE timestamp < ? LIMIT %d", pruneBatch), cutoff); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`
		INSERT INTO anomaly_signature_daily (day, anomaly_type, severity, endpoint_id, count)
		SELECT substr(timestamp, 1, 10), anomaly_type, severity, endpoint_id, COUNT(*)
		FROM anomaly_alerts WHERE rowid IN (SELECT rid FROM temp.anomaly_prune)
		GROUP BY 1, 2, 3, 4
		ON CONFLICT (day, anomaly_type, severity, endpoint_id) DO UPDATE SET count = count + excluded.count`); err != nil {
		return 0, err
	}
	res, err := tx.Exec("DELETE FROM anomaly_alerts WHERE rowid IN (SELECT rid FROM temp.anomaly_prune)")
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec("DROP TABLE temp.anomaly_prune"); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// AnomalySignatureCounts lists the counted (pruned) findings since a day.
func (s *Store) AnomalySignatureCounts(sinceDay string) ([]AnomalySignatureCount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT day, anomaly_type, severity, endpoint_id, count FROM anomaly_signature_daily WHERE day >= ? ORDER BY day, anomaly_type", sinceDay)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnomalySignatureCount
	for rows.Next() {
		var c AnomalySignatureCount
		if err := rows.Scan(&c.Day, &c.AnomalyType, &c.Severity, &c.EndpointID, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
