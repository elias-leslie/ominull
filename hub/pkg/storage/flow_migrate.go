package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// Legacy events migration.
//
// A hub upgraded from the row-per-sample schema starts with its old table
// renamed to events_legacy (initFlowSchema) and writes new telemetry to flows
// at once. This worker then moves the raw window of legacy rows into flows an
// hour at a time, oldest first, through the same writer (so they are minute
// aggregated and loopback becomes hourly counters), and records its cursor so
// a restart resumes. Rollups are not recounted: the old trigger already
// counted those rows into bandwidth_buckets.
//
// When every hour is copied the legacy indexes and table are dropped, and the
// file is compacted into incremental auto-vacuum mode. Each step takes the
// store lock briefly; ingest keeps running throughout.

const (
	settingFlowMigrationCursor = "storage.flow_migration_cursor"
	settingFlowMigrationDone   = "storage.flow_migration_done"
	// migrationStep is how many legacy rows are copied per transaction.
	migrationStep = 20000
)

func (s *Store) legacyEventsPresent() bool {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'events_legacy'").Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// FlowMigrationStatus reports progress for the data report.
type FlowMigrationStatus struct {
	Pending  bool   `json:"pending"`
	Cursor   string `json:"cursor,omitempty"`
	Finished string `json:"finished,omitempty"`
}

func (s *Store) flowMigrationStatus() FlowMigrationStatus {
	st := FlowMigrationStatus{Pending: s.legacyEventsPresent()}
	st.Cursor, _ = s.GetSetting(settingFlowMigrationCursor)
	st.Finished, _ = s.GetSetting(settingFlowMigrationDone)
	return st
}

// migrateLegacyEvents runs to completion (or until stop closes).
func (s *Store) migrateLegacyEvents(policy RetentionPolicy, stop <-chan struct{}) {
	if !s.legacyEventsPresent() {
		return
	}
	start := time.Now()
	copied, err := s.copyLegacyEvents(policy, stop)
	if err != nil {
		log.Printf("[!] Flow migration stopped after %d legacy rows: %v (resumes on restart)", copied, err)
		return
	}
	select {
	case <-stop:
		return
	default:
	}
	log.Printf("[*] Flow migration: %d legacy rows copied in %s; dropping the legacy table", copied, time.Since(start).Round(time.Second))
	if err := s.dropLegacyEvents(); err != nil {
		log.Printf("[!] Flow migration: dropping legacy table: %v", err)
		return
	}
	if err := s.compactAfterMigration(); err != nil {
		log.Printf("[!] Flow migration: compaction: %v", err)
	}
	log.Printf("[+] Flow migration finished in %s", time.Since(start).Round(time.Second))
}

// copyLegacyEvents walks the legacy table by rowid (insert order, a primary
// key range scan) from the first row inside the raw window.
func (s *Store) copyLegacyEvents(policy RetentionPolicy, stop <-chan struct{}) (int64, error) {
	var last sql.NullInt64
	if err := s.db.QueryRow("SELECT MAX(rowid) FROM events_legacy").Scan(&last); err != nil {
		return 0, err
	}
	if !last.Valid {
		return 0, nil
	}
	var cursor int64 = -1
	if v, err := s.GetSetting(settingFlowMigrationCursor); err == nil && v != "" {
		if _, err := fmt.Sscan(v, &cursor); err != nil {
			cursor = -1
		}
	}
	if cursor < 0 {
		var first sql.NullInt64
		q, args := "SELECT MIN(rowid) FROM events_legacy", []interface{}{}
		if policy.Events > 0 {
			q += " WHERE timestamp >= ?"
			args = append(args, time.Now().UTC().Add(-policy.Events))
		}
		if err := s.db.QueryRow(q, args...).Scan(&first); err != nil {
			return 0, err
		}
		if !first.Valid {
			return 0, nil
		}
		cursor = first.Int64 - 1
	}
	var copied int64
	for cursor < last.Int64 {
		if stop != nil {
			select {
			case <-stop:
				return copied, nil
			default:
			}
		}
		next := cursor + migrationStep
		n, err := s.copyLegacySpan(cursor, next)
		if err != nil {
			return copied, fmt.Errorf("rows after %d: %w", cursor, err)
		}
		copied += n
		cursor = next
		if err := s.SetSetting(settingFlowMigrationCursor, fmt.Sprint(cursor)); err != nil {
			return copied, err
		}
	}
	return copied, nil
}

const legacyColumns = `tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port,
	bytes_in, bytes_out, country, process_path, process_id, COALESCE(domain, ''), COALESCE(sni, ''),
	COALESCE(process_instance_id, ''), COALESCE(parent_pid, 0), COALESCE(parent_process_instance_id, ''),
	COALESCE(command_line, ''), COALESCE(user_identity, ''), COALESCE(executable_sha256, ''),
	COALESCE(attribution_status, ''), observed_at, COALESCE(observation_json, '{}')`

// copyLegacySpan reads rows (after, upto] outside the write lock, then writes
// them in one transaction.
func (s *Store) copyLegacySpan(after, upto int64) (int64, error) {
	rows, err := s.db.Query("SELECT "+legacyColumns+" FROM events_legacy WHERE rowid > ? AND rowid <= ? ORDER BY rowid", after, upto)
	if err != nil {
		return 0, err
	}
	var events []Event
	for rows.Next() {
		var ev Event
		var observed sql.NullTime
		if err := rows.Scan(&ev.TenantID, &ev.EndpointID, &ev.Timestamp, &ev.Layer, &ev.Action, &ev.Direction, &ev.Protocol,
			&ev.SrcIP, &ev.DstIP, &ev.SrcPort, &ev.DstPort, &ev.BytesIn, &ev.BytesOut, &ev.Country, &ev.ProcessPath, &ev.ProcessID,
			&ev.Domain, &ev.SNI, &ev.ProcessInstanceID, &ev.ParentPID, &ev.ParentProcessInstanceID, &ev.CommandLine,
			&ev.UserIdentity, &ev.ExecutableSHA256, &ev.AttributionStatus, &observed, &ev.Observation); err != nil {
			rows.Close()
			return 0, err
		}
		if observed.Valid {
			t := observed.Time.UTC()
			ev.ObservedAt = &t
		}
		events = append(events, ev)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	b, err := s.writeFlows(tx, events, false)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	b.commit()
	return int64(len(events)), nil
}

// dropLegacyEvents drops the legacy indexes one at a time, then the table, so
// no single step holds the lock for the whole file.
func (s *Store) dropLegacyEvents() error {
	rows, err := s.db.Query("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events_legacy' AND sql IS NOT NULL")
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		started := time.Now()
		if err := s.execExclusive(`DROP INDEX IF EXISTS "` + n + `"`); err != nil {
			return fmt.Errorf("drop %s: %w", n, err)
		}
		log.Printf("[*] Flow migration: dropped %s in %s", n, time.Since(started).Round(time.Millisecond))
	}
	started := time.Now()
	if err := s.execExclusive("DROP TABLE IF EXISTS events_legacy"); err != nil {
		return err
	}
	log.Printf("[*] Flow migration: dropped events_legacy in %s", time.Since(started).Round(time.Millisecond))
	return s.SetSetting(settingFlowMigrationDone, time.Now().UTC().Format(time.RFC3339))
}

func (s *Store) execExclusive(stmt string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(stmt)
	return err
}

// compactAfterMigration switches the file to incremental auto-vacuum and
// rebuilds it, returning the legacy table's pages to the filesystem. The
// rebuild holds the write lock; its length scales with the remaining data,
// not the dropped table.
func (s *Store) compactAfterMigration() error {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// The auto_vacuum setting only takes effect through a VACUUM on the same
	// connection.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, stmt := range []string{"PRAGMA auto_vacuum = INCREMENTAL", "VACUUM", "PRAGMA wal_checkpoint(TRUNCATE)"} {
		if _, err := conn.ExecContext(context.Background(), stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	log.Printf("[*] Flow migration: VACUUM in %s", time.Since(started).Round(time.Millisecond))
	return nil
}
