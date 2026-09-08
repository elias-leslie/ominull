package storage

import (
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
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

func (s *Store) initDNSSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dns_events (
		id TEXT PRIMARY KEY,
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
		block_reason TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_dns_events_tenant_time ON dns_events(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_dns_events_domain ON dns_events(domain);
	CREATE INDEX IF NOT EXISTS idx_dns_events_client ON dns_events(client_ip);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) RecordDNSEvent(ev DNSEvent) error {
	if ev.ID == "" {
		ev.ID = uuid.New().String()
	}
	if ev.TenantID == "" {
		ev.TenantID = "default"
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ev.Domain), "."))

	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	INSERT INTO dns_events (id, tenant_id, timestamp, client_ip, domain, qtype, action, status, response_code, latency_us, upstream, transport, block_reason)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, ev.ID, ev.TenantID, ev.Timestamp, ev.ClientIP, ev.Domain, ev.QType, ev.Action, ev.Status, ev.ResponseCode, ev.LatencyUs, ev.Upstream, ev.Transport, ev.BlockReason)
	return err
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
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, filter.To)
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

	dataQuery := "SELECT id, tenant_id, timestamp, client_ip, domain, qtype, action, status, response_code, latency_us, upstream, transport, block_reason FROM dns_events" +
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
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.Timestamp, &ev.ClientIP, &ev.Domain, &ev.QType, &ev.Action, &ev.Status, &ev.ResponseCode, &ev.LatencyUs, &upstream, &ev.Transport, &blockReason); err != nil {
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

	res, err := s.db.Exec("DELETE FROM dns_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
