package storage

import (
	"fmt"
	"log"
	"time"
)

// Retention.
//
// Nothing ever deleted a row. Telemetry, anomaly alerts and alerts accumulated
// for the life of the deployment, and the only thing that ever stopped the file
// growing was the disk filling - at which point sqlite fails every write and the
// hub stops being able to record that anything is wrong, which is the worst
// moment for it to happen. A four-endpoint fleet was writing about 57 MB a day.
//
// The policy is per-table because the tables are not worth the same. Telemetry
// is the bulk and the least valuable once the anomaly detector has read it;
// audit logs are tiny and are the record of who did what, so they are kept far
// longer than anything else.
type RetentionPolicy struct {
	Events         time.Duration
	AnomalyAlerts  time.Duration
	Alerts         time.Duration
	AuditLogs      time.Duration
	QuarantineLift time.Duration
}

// DefaultRetention is what a hub uses unless an operator says otherwise.
func DefaultRetention() RetentionPolicy {
	return RetentionPolicy{
		Events:        14 * 24 * time.Hour,
		AnomalyAlerts: 30 * 24 * time.Hour,
		Alerts:        30 * 24 * time.Hour,
		AuditLogs:     365 * 24 * time.Hour,
	}
}

// pruneBatch bounds one DELETE. A single unbounded DELETE over a table with
// millions of rows holds the write lock for as long as it takes and blocks every
// reader behind it, so the first prune on a hub that has never pruned would look
// exactly like the deadlock this package already had once. Deleting in batches
// gives the lock up between them.
const pruneBatch = 5000

// PruneOldData deletes rows past their retention and returns how many went, by
// table. It takes the write lock itself and calls nothing else in this package:
// the mutex is not reentrant and a method that reaches another locking method
// deadlocks the whole hub.
func (s *Store) PruneOldData(policy RetentionPolicy) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	removed := make(map[string]int64)

	for _, target := range []struct {
		table  string
		column string
		keep   time.Duration
	}{
		{"events", "timestamp", policy.Events},
		{"anomaly_alerts", "timestamp", policy.AnomalyAlerts},
		{"alerts", "timestamp", policy.Alerts},
		{"audit_logs", "timestamp", policy.AuditLogs},
	} {
		if target.keep <= 0 {
			continue // 0 disables pruning for this table
		}
		cutoff := now.Add(-target.keep)

		// rowid, because these tables do not all have an indexed primary key to
		// sub-select on and rowid is always there and always unique.
		stmt := fmt.Sprintf(
			"DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s < ? LIMIT %d)",
			target.table, target.table, target.column, pruneBatch)

		for {
			res, err := s.db.Exec(stmt, cutoff)
			if err != nil {
				return removed, fmt.Errorf("pruning %s: %w", target.table, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return removed, fmt.Errorf("pruning %s: %w", target.table, err)
			}
			removed[target.table] += n
			if n < pruneBatch {
				break
			}
		}
	}

	return removed, nil
}

// StartRetention prunes once at startup and then on a ticker, and returns a
// function that stops it. Startup matters: a hub that has been running without
// retention has the whole backlog to clear, and waiting an hour to begin is an
// hour of a disk that may not have one.
func (s *Store) StartRetention(policy RetentionPolicy, every time.Duration) func() {
	if every <= 0 {
		every = time.Hour
	}
	stop := make(chan struct{})

	run := func() {
		start := time.Now()
		removed, err := s.PruneOldData(policy)
		if err != nil {
			log.Printf("[!] Retention sweep failed: %v", err)
			return
		}
		total := int64(0)
		for _, n := range removed {
			total += n
		}
		if total > 0 {
			log.Printf("[*] Retention: removed %d rows in %s (events %d, anomalies %d, alerts %d, audit %d)",
				total, time.Since(start).Round(time.Millisecond),
				removed["events"], removed["anomaly_alerts"], removed["alerts"], removed["audit_logs"])
		}
	}

	go func() {
		run()
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-stop:
				return
			}
		}
	}()

	return func() { close(stop) }
}
