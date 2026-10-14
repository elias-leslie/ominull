package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DNSEvent represents a telemetry log record for a resolved or sinkholed query.
type DNSEvent struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	Domain       string    `json:"domain"`
	QType        string    `json:"qtype"`
	Action       string    `json:"action"`        // "PERMIT", "BLOCK", "ALLOWLIST"
	Status       string    `json:"status"`        // "HIT", "MISS", "BLOCKED", "ERROR"
	ResponseCode string    `json:"response_code"` // "NOERROR", "NXDOMAIN", "SERVFAIL", etc.
	LatencyUs    int64     `json:"latency_us"`
	Upstream     string    `json:"upstream"`
	Transport    string    `json:"transport"` // "udp" or "tcp"
	BlockReason  string    `json:"block_reason"`
	// Count is how many identical queries this row stands for: repeats of
	// the same query (client, name, type, outcome) within a minute are one row.
	Count int64 `json:"count,omitempty"`
}

// DNSEventFilter contains criteria for querying DNS telemetry events.
type DNSEventFilter struct {
	ClientIP string
	Domain   string
	Action   string
	Status   string
	From     time.Time
	To       time.Time
	Limit    int
	Offset   int
}

// dnsEventsSchema: an integer key, minute aggregation (count), and two
// indexes (time, client and time). The old text uuid key, its autoindex and a
// domain index no query could use (the filter is a substring match) were
// 40% of each row.
const dnsEventsSchema = `
	CREATE TABLE IF NOT EXISTS dns_events (
		id INTEGER PRIMARY KEY,
		tenant_id TEXT NOT NULL DEFAULT 'default',
		timestamp DATETIME NOT NULL,
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		qtype TEXT NOT NULL,
		action TEXT NOT NULL,
		status TEXT NOT NULL,
		response_code TEXT NOT NULL,
		latency_us INTEGER NOT NULL,
		upstream TEXT NOT NULL DEFAULT '',
		transport TEXT NOT NULL DEFAULT 'udp',
		block_reason TEXT NOT NULL DEFAULT '',
		count INTEGER NOT NULL DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_dns_events_time ON dns_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dns_events_client_time ON dns_events(client_ip, timestamp);
`

func (s *Store) initDNSSchema() error {
	var hasCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('dns_events') WHERE name = 'count'").Scan(&hasCount); err != nil {
		return err
	}
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'dns_events'").Scan(&exists); err != nil {
		return err
	}
	if exists > 0 && hasCount == 0 {
		return s.rebuildDNSEvents()
	}
	_, err := s.db.Exec(dnsEventsSchema)
	return err
}

// rebuildDNSEvents moves the old row-per-query table into the new shape,
// folding repeats within a minute (a few hundred thousand rows: seconds).
func (s *Store) rebuildDNSEvents() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		"ALTER TABLE dns_events RENAME TO dns_events_old",
		"DROP INDEX IF EXISTS idx_dns_events_tenant_time",
		"DROP INDEX IF EXISTS idx_dns_events_domain",
		"DROP INDEX IF EXISTS idx_dns_events_client",
		dnsEventsSchema,
		`INSERT INTO dns_events (tenant_id, timestamp, client_ip, domain, qtype, action, status, response_code, latency_us, upstream, transport, block_reason, count)
		 SELECT tenant_id, substr(MIN(timestamp), 1, 19), client_ip, domain, qtype, action, status, response_code, MAX(latency_us),
			COALESCE(upstream, ''), transport, COALESCE(block_reason, ''), COUNT(*)
		 FROM dns_events_old
		 GROUP BY tenant_id, substr(timestamp, 1, 16), client_ip, domain, qtype, action, status, response_code,
			COALESCE(upstream, ''), transport, COALESCE(block_reason, '')
		 ORDER BY MIN(timestamp)`,
		"DROP TABLE dns_events_old",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("rebuild dns_events: %w", err)
		}
	}
	return tx.Commit()
}

type dnsKey struct {
	minute                                                      int64
	tenant, client, domain, qtype, action, status, rc, upstream string
	transport, blockReason                                      string
}

func (s *Store) RecordDNSEvent(ev DNSEvent) error {
	if ev.TenantID == "" {
		ev.TenantID = "default"
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Timestamp = ev.Timestamp.UTC()
	ev.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ev.Domain), "."))

	s.mu.Lock()
	defer s.mu.Unlock()

	key := dnsKey{ev.Timestamp.Unix() / 60, ev.TenantID, ev.ClientIP, ev.Domain, ev.QType, ev.Action, ev.Status,
		ev.ResponseCode, ev.Upstream, ev.Transport, ev.BlockReason}
	w := s.flowWriter
	if id, ok := w.dns[key]; ok {
		res, err := s.db.Exec("UPDATE dns_events SET count = count + 1, latency_us = MAX(latency_us, ?) WHERE id = ?", ev.LatencyUs, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
	}
	res, err := s.db.Exec(`INSERT INTO dns_events (tenant_id, timestamp, client_ip, domain, qtype, action, status, response_code, latency_us, upstream, transport, block_reason)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TenantID, flowTime(ev.Timestamp), ev.ClientIP, ev.Domain, ev.QType, ev.Action, ev.Status, ev.ResponseCode, ev.LatencyUs, ev.Upstream, ev.Transport, ev.BlockReason)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if key.minute > w.dnsMinute {
		w.dnsMinute = key.minute
		for k := range w.dns {
			if k.minute < w.dnsMinute-flowOpenWindow {
				delete(w.dns, k)
			}
		}
	}
	w.dns[key] = id
	return nil
}

func (s *Store) ListDNSEvents(tenantID string, filter DNSEventFilter) ([]DNSEvent, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var where []string
	var args []interface{}

	if tenantID != "" {
		where = append(where, "tenant_id = ?")
		args = append(args, tenantID)
	}
	if filter.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, filter.ClientIP)
	}
	if filter.Domain != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(filter.Domain)+"%")
	}
	if filter.Action != "" {
		where = append(where, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if !filter.From.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, flowTime(filter.From))
	}
	if !filter.To.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, flowTime(filter.To))
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM dns_events" + whereClause
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := "SELECT id, tenant_id, timestamp, client_ip, domain, qtype, action, status, response_code, latency_us, upstream, transport, block_reason, count FROM dns_events" +
		whereClause + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	dataArgs := append(args, limit, offset)

	rows, err := s.db.Query(dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []DNSEvent
	for rows.Next() {
		var ev DNSEvent
		var upstream, blockReason sql.NullString
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.Timestamp, &ev.ClientIP, &ev.Domain, &ev.QType, &ev.Action, &ev.Status, &ev.ResponseCode, &ev.LatencyUs, &upstream, &ev.Transport, &blockReason, &ev.Count); err != nil {
			return nil, 0, err
		}
		ev.Upstream = upstream.String
		ev.BlockReason = blockReason.String
		events = append(events, ev)
	}
	return events, total, rows.Err()
}

func (s *Store) PruneOldDNSEvents(olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM dns_events WHERE timestamp < ?", flowTime(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
