package storage

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// Retention.
//
// The policy is per-table because the tables are not worth the same. Raw flows
// are the bulk: they are kept at minute resolution for the raw window (14 days
// covers the median attacker dwell time), then live on as hourly per-process
// per-destination rollups in daily gzip cold segments (cold.go). Audit logs are
// tiny and are the record of who did what, so they are kept far longer than
// anything else. Flows near a bundle under legal hold stay until the hold is
// released.
type RetentionPolicy struct {
	// Events is the raw flow window (minute rows and loopback hourly counters).
	Events time.Duration
	// FlowRollups is how long the daily cold segments (hourly rollups) stay.
	FlowRollups   time.Duration
	CommProfiles  time.Duration
	AnomalyAlerts time.Duration
	// AnomalyCounts keeps per-signature daily counts of pruned anomalies.
	AnomalyCounts  time.Duration
	AuditLogs      time.Duration
	QuarantineLift time.Duration
	RouterFlows    time.Duration
	// A name-to-address binding goes stale quickly on a CDN, so the mapping is
	// kept for less time than the flows it exists to explain.
	DNSResolutions time.Duration
	// RouterDaily covers the per-device daily traffic and DNS aggregates that
	// baselines are built from, so it outlives the raw rows by months.
	RouterDaily time.Duration
	// ColdDir overrides where cold segments are written (default: "cold"
	// beside the database file; none for an in-memory database).
	ColdDir string
}

// DefaultRetention is what a hub uses unless an operator says otherwise: the
// home tier (raw 14 d; hourly rollups 90 d; anomalies 90 d, counts 1 y).
func DefaultRetention() RetentionPolicy {
	return RetentionPolicy{
		Events:         14 * 24 * time.Hour,
		FlowRollups:    90 * 24 * time.Hour,
		CommProfiles:   14 * 24 * time.Hour,
		AnomalyAlerts:  90 * 24 * time.Hour,
		AnomalyCounts:  365 * 24 * time.Hour,
		AuditLogs:      365 * 24 * time.Hour,
		RouterFlows:    14 * 24 * time.Hour,
		DNSResolutions: 14 * 24 * time.Hour,
		RouterDaily:    RouterDailyRetention,
	}
}

// pruneBatch bounds one DELETE. A single unbounded DELETE over a table with
// millions of rows holds the write lock for as long as it takes and blocks every
// reader behind it. Deleting in batches gives the lock up between them.
const pruneBatch = 5000

// legalHoldMargin is how much flow history either side of a held evidence
// bundle stays with it.
const legalHoldMargin = 24 * time.Hour

// PruneOldData deletes rows past their retention and returns how many went, by
// table. Sweeps remain serialized, while each deletion batch gives ordinary
// readers and writers another turn at the store lock.
func (s *Store) PruneOldData(policy RetentionPolicy) (map[string]int64, error) {
	s.retention.Lock()
	defer s.retention.Unlock()

	now := time.Now().UTC()
	removed := make(map[string]int64)

	if policy.Events > 0 {
		// Rollups are cut from the raw rows before those go.
		if err := s.exportColdSegments(policy, now); err != nil {
			log.Printf("[!] Cold segment export failed: %v", err)
		}
		n, err := s.pruneFlows(now.Add(-policy.Events))
		if err != nil {
			return removed, fmt.Errorf("pruning flows: %w", err)
		}
		for k, v := range n {
			removed[k] = v
		}
	}
	if policy.FlowRollups > 0 {
		n, err := s.pruneColdSegments(now.Add(-policy.FlowRollups))
		if err != nil {
			return removed, fmt.Errorf("pruning cold segments: %w", err)
		}
		removed["cold_segments"] = n
	}
	if policy.AnomalyAlerts > 0 {
		n, err := s.rollUpAndPruneAnomalies(now.Add(-policy.AnomalyAlerts))
		if err != nil {
			return removed, fmt.Errorf("pruning anomaly_alerts: %w", err)
		}
		removed["anomaly_alerts"] = n
	}

	for _, target := range []struct {
		table  string
		column string
		keep   time.Duration
	}{
		{"bandwidth_buckets", "hour_bucket", policy.Events},
		{"dns_events", "timestamp", policy.Events},
		{"comm_profiles", "last_seen", policy.CommProfiles},
		// A resolution is never older than its finding, so pruning both on
		// the same period never leaves a finding without its reason.
		{"anomaly_resolutions", "resolved_at", policy.AnomalyAlerts},
		{"anomaly_signature_daily", "day", policy.AnomalyCounts},
		{"audit_logs", "timestamp", policy.AuditLogs},
		// A destination a runtime has not reached for the profile period is
		// forgotten with its profile, and reaching it again is news again.
		{"agent_egress_destinations", "last_seen", policy.CommProfiles},
	} {
		if target.keep <= 0 {
			continue // 0 disables pruning for this table
		}
		var cutoff interface{} = now.Add(-target.keep)
		if target.column == "day" {
			cutoff = now.Add(-target.keep).Format("2006-01-02")
		}

		// rowid, because these tables do not all have an indexed primary key to
		// sub-select on and rowid is always there and always unique.
		stmt := fmt.Sprintf(
			"DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s < ? LIMIT %d)",
			target.table, target.table, target.column, pruneBatch)
		if target.table == "anomaly_signature_daily" {
			stmt = fmt.Sprintf("DELETE FROM %s WHERE %s < ?", target.table, target.column)
		}

		for {
			n, err := s.pruneBatch(stmt, cutoff)
			if err != nil {
				return removed, fmt.Errorf("pruning %s: %w", target.table, err)
			}
			removed[target.table] += n
			if n < pruneBatch {
				break
			}
		}
	}

	// router_flows keys its bucket as epoch seconds rather than a timestamp, so
	// it cannot ride the loop above and is pruned on its own terms.
	if policy.RouterFlows > 0 {
		n, err := s.PruneOldRouterFlows(policy.RouterFlows)
		if err != nil {
			return removed, fmt.Errorf("pruning router_flows: %w", err)
		}
		removed["router_flows"] = n
	}

	if policy.DNSResolutions > 0 {
		n, err := s.PruneOldDNSResolutions(policy.DNSResolutions)
		if err != nil {
			return removed, fmt.Errorf("pruning dns_resolutions: %w", err)
		}
		removed["dns_resolutions"] = n
	}

	// agent_egress_hourly keys its row as an epoch hour; the baseline reads
	// two weeks of it, and it goes with the profiles it summarises.
	if policy.CommProfiles > 0 {
		n, err := s.PruneAgentUploads(policy.CommProfiles)
		if err != nil {
			return removed, fmt.Errorf("pruning agent_egress_hourly: %w", err)
		}
		removed["agent_egress_hourly"] = n
	}

	if policy.RouterDaily > 0 {
		n, err := s.PruneRouterDaily(policy.RouterDaily)
		if err != nil {
			return removed, err
		}
		removed["router_daily"] = n
	}

	if policy.Events > 0 {
		if err := s.collectFlowDictionaries(now.Add(-policy.Events), now); err != nil {
			return removed, fmt.Errorf("flow dictionaries: %w", err)
		}
	}
	s.releaseFreePages()
	return removed, nil
}

func (s *Store) pruneBatch(statement string, args ...interface{}) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(statement, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type heldWindow struct {
	endpointID string
	from, to   time.Time
}

// legalHoldWindows lists the flow ranges that evidence under legal hold keeps.
func (s *Store) legalHoldWindows() ([]heldWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'evidence_bundles'").Scan(&exists); err != nil || exists == 0 {
		return nil, err
	}
	rows, err := s.db.Query("SELECT endpoint_id, created_at FROM evidence_bundles WHERE legal_hold = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []heldWindow
	for rows.Next() {
		var endpoint string
		var created interface{}
		if err := rows.Scan(&endpoint, &created); err != nil {
			return nil, err
		}
		at := scanTime(created)
		if at.IsZero() {
			continue
		}
		out = append(out, heldWindow{endpoint, at.Add(-legalHoldMargin), at.Add(legalHoldMargin)})
	}
	return out, rows.Err()
}

// pruneFlows removes minute rows and loopback counters older than cutoff,
// except those inside a legal-hold window.
func (s *Store) pruneFlows(cutoff time.Time) (map[string]int64, error) {
	removed := map[string]int64{}
	held, err := s.legalHoldWindows()
	if err != nil {
		return removed, err
	}
	var keepFlows, keepLocal []string
	var flowArgs, localArgs []interface{}
	for _, h := range held {
		keepFlows = append(keepFlows, "(endpoint_ref IN (SELECT id FROM flow_endpoints WHERE endpoint_id = ?) AND timestamp >= ? AND timestamp <= ?)")
		flowArgs = append(flowArgs, h.endpointID, flowTime(h.from), flowTime(h.to))
		keepLocal = append(keepLocal, "(endpoint_ref IN (SELECT id FROM flow_endpoints WHERE endpoint_id = ?) AND hour >= ? AND hour <= ?)")
		localArgs = append(localArgs, h.endpointID, h.from.Unix()/flowHour, h.to.Unix()/flowHour)
	}
	flowWhere, localWhere := "timestamp < ?", "hour < ?"
	if len(keepFlows) > 0 {
		flowWhere += " AND NOT (" + strings.Join(keepFlows, " OR ") + ")"
		localWhere += " AND NOT (" + strings.Join(keepLocal, " OR ") + ")"
	}
	flowStmt := "DELETE FROM flows WHERE id IN (SELECT id FROM flows WHERE " + flowWhere + fmt.Sprintf(" LIMIT %d)", pruneBatch)
	flowArgs = append([]interface{}{flowTime(cutoff)}, flowArgs...)
	for {
		n, err := s.pruneBatch(flowStmt, flowArgs...)
		if err != nil {
			return removed, fmt.Errorf("flows: %w", err)
		}
		removed["flows"] += n
		if n < pruneBatch {
			break
		}
	}
	// Hourly counters are a few thousand rows a day: one statement.
	n, err := s.pruneBatch("DELETE FROM flow_local_hourly WHERE "+localWhere, append([]interface{}{cutoff.Unix() / flowHour}, localArgs...)...)
	if err != nil {
		return removed, fmt.Errorf("flow_local_hourly: %w", err)
	}
	removed["flow_local_hourly"] = n
	// The legacy name stays in the log line and API.
	removed["events"] = removed["flows"]
	return removed, nil
}

// collectFlowDictionaries drops dictionary rows nothing references any more,
// once a day. Processes keep their row while seen within the raw window.
func (s *Store) collectFlowDictionaries(cutoff, now time.Time) error {
	if s.legacyEventsPresent() {
		return nil // the migration still adds references
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.flowWriter; w == nil || now.Sub(w.lastGC) < 23*time.Hour {
		return nil
	}
	for _, q := range []struct {
		stmt string
		args []interface{}
	}{
		{"DELETE FROM flow_processes WHERE last_seen < ? AND id NOT IN (SELECT process_ref FROM flows UNION SELECT process_ref FROM flow_local_hourly)", []interface{}{flowTime(cutoff)}},
		{"DELETE FROM flow_images WHERE id NOT IN (SELECT image_ref FROM flow_processes)", nil},
		{"DELETE FROM flow_commands WHERE id != 0 AND id NOT IN (SELECT command_ref FROM flow_processes)", nil},
		{"DELETE FROM flow_names WHERE id != 0 AND id NOT IN (SELECT domain_ref FROM flows UNION SELECT sni_ref FROM flows)", nil},
		{"DELETE FROM flow_endpoints WHERE id NOT IN (SELECT endpoint_ref FROM flow_processes)", nil},
	} {
		if _, err := s.db.Exec(q.stmt, q.args...); err != nil {
			return err
		}
	}
	s.resetFlowCaches()
	s.flowWriter.lastGC = now
	return nil
}

// releaseFreePages returns pruned pages to the filesystem when the database
// is in incremental auto-vacuum mode (set by the flow migration's VACUUM).
func (s *Store) releaseFreePages() {
	var mode int
	if err := s.db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil || mode != 2 {
		return
	}
	for i := 0; i < 1000; i++ {
		var free int64
		if err := s.db.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil || free == 0 {
			return
		}
		s.mu.Lock()
		_, err := s.db.Exec("PRAGMA incremental_vacuum(2000)")
		s.mu.Unlock()
		if err != nil {
			log.Printf("[!] Incremental vacuum: %v", err)
			return
		}
	}
}

// StartRetention prunes once at startup and then on a ticker, and returns a
// function that stops it. Startup matters: a hub that has been running without
// retention has the whole backlog to clear. It also starts the background
// migration of a legacy events table, if there is one.
func (s *Store) StartRetention(policy RetentionPolicy, every time.Duration) func() {
	if every <= 0 {
		every = time.Hour
	}
	stop := make(chan struct{})
	s.coldDir = policy.ColdDir

	run := func() {
		start := time.Now()
		removed, err := s.PruneOldData(policy)
		if err != nil {
			log.Printf("[!] Retention sweep failed: %v", err)
			return
		}
		total := int64(0)
		for k, n := range removed {
			if k != "events" {
				total += n
			}
		}
		if total > 0 {
			log.Printf("[*] Retention: removed %d rows in %s (flows %d, local counters %d, comm_profiles %d, anomalies %d, audit %d)",
				total, time.Since(start).Round(time.Millisecond),
				removed["flows"], removed["flow_local_hourly"], removed["comm_profiles"], removed["anomaly_alerts"], removed["audit_logs"])
		}
		if err := s.RefreshDataReport(policy); err != nil {
			log.Printf("[!] Data size report failed: %v", err)
		}
	}

	go func() {
		s.migrateLegacyEvents(policy, stop)
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
