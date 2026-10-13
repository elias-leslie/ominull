package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Daily router aggregates.
//
// Raw DNS events and hourly flow rollups are kept for days; baselines need
// months. These tables hold one row per device per day, small enough to keep
// for RouterDailyRetention without the raw history:
//
//   - router_client_daily: per-client received and sent bytes, from the
//     gateway's own per-client counters (gl-clients on GL.iNet firmware).
//   - dns_domain_daily: how many times each client asked for each domain.
//
// Clients are keyed by MAC for byte counters, because the gateway reports it,
// and by client IP for DNS, because that is all the resolver log carries.

// RouterDailyRetention is how long daily aggregates are kept.
const RouterDailyRetention = 90 * 24 * time.Hour

// MaxRouterClientsPerPoll bounds one poll's client list.
const MaxRouterClientsPerPoll = 2000

// RouterClient is one entry of the gateway's per-client counters. Totals are
// cumulative and may reset when the gateway reboots or forgets a client.
type RouterClient struct {
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Online  bool   `json:"online"`
	RxTotal int64  `json:"total_rx"`
	TxTotal int64  `json:"total_tx"`
}

// RouterClientDay is one device's traffic on one UTC day.
type RouterClientDay struct {
	RouterID string `json:"router_id"`
	MAC      string `json:"mac"`
	Day      string `json:"day"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	RxBytes  int64  `json:"rx_bytes"`
	TxBytes  int64  `json:"tx_bytes"`
}

// DNSDomainCount is one client's query count for one domain on one UTC day.
type DNSDomainCount struct {
	ClientIP string
	Domain   string
	Queries  int
}

func (s *Store) initRouterDailySchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS router_client_counters (
		router_id TEXT NOT NULL,
		mac TEXT NOT NULL,
		rx_total INTEGER NOT NULL,
		tx_total INTEGER NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		PRIMARY KEY (router_id, mac)
	);
	CREATE TABLE IF NOT EXISTS router_client_daily (
		router_id TEXT NOT NULL,
		mac TEXT NOT NULL,
		day TEXT NOT NULL,
		ip TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL DEFAULT '',
		rx_bytes INTEGER NOT NULL DEFAULT 0,
		tx_bytes INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (router_id, mac, day)
	);
	CREATE INDEX IF NOT EXISTS idx_router_client_daily_day ON router_client_daily(day);
	CREATE TABLE IF NOT EXISTS dns_domain_daily (
		day TEXT NOT NULL,
		router_id TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		queries INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, router_id, client_ip, domain)
	);
	CREATE INDEX IF NOT EXISTS idx_dns_domain_daily_client ON dns_domain_daily(client_ip, day);
	CREATE TABLE IF NOT EXISTS router_identities (
		router_id TEXT PRIMARY KEY,
		cert_sha256 TEXT NOT NULL,
		issued_at TIMESTAMP NOT NULL
	);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("router daily schema: %w", err)
	}
	return nil
}

func utcDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

// RecordRouterClients folds the gateway's cumulative per-client counters into
// daily deltas. The first sighting of a client only records its counters: its
// lifetime total is not today's traffic. A total that went backwards means the
// counter reset, so the new total is the traffic since the reset.
func (s *Store) RecordRouterClients(routerID string, clients []RouterClient, now time.Time) (int, int, error) {
	accepted, rejected := 0, 0
	if len(clients) > MaxRouterClientsPerPoll {
		rejected += len(clients) - MaxRouterClientsPerPoll
		clients = clients[:MaxRouterClientsPerPoll]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	day := utcDay(now)
	for _, c := range clients {
		mac, ok := normaliseMAC(c.MAC)
		if !ok || c.RxTotal < 0 || c.TxTotal < 0 {
			rejected++
			continue
		}
		ip := ""
		if v, ok := normaliseIP(c.IP); ok {
			ip = v
		}
		var prevRx, prevTx int64
		err := tx.QueryRow(`SELECT rx_total, tx_total FROM router_client_counters WHERE router_id=? AND mac=?`, routerID, mac).Scan(&prevRx, &prevTx)
		first := err == sql.ErrNoRows
		if err != nil && !first {
			return accepted, rejected, err
		}
		var dRx, dTx int64
		if !first {
			dRx, dTx = counterDelta(prevRx, c.RxTotal), counterDelta(prevTx, c.TxTotal)
		}
		if _, err := tx.Exec(`INSERT INTO router_client_counters (router_id, mac, rx_total, tx_total, updated_at) VALUES (?,?,?,?,?)
			ON CONFLICT(router_id, mac) DO UPDATE SET rx_total=excluded.rx_total, tx_total=excluded.tx_total, updated_at=excluded.updated_at`,
			routerID, mac, c.RxTotal, c.TxTotal, now.UTC()); err != nil {
			return accepted, rejected, err
		}
		if _, err := tx.Exec(`INSERT INTO router_client_daily (router_id, mac, day, ip, name, rx_bytes, tx_bytes) VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(router_id, mac, day) DO UPDATE SET
				ip=CASE WHEN excluded.ip='' THEN ip ELSE excluded.ip END,
				name=CASE WHEN excluded.name='' THEN name ELSE excluded.name END,
				rx_bytes=rx_bytes+excluded.rx_bytes, tx_bytes=tx_bytes+excluded.tx_bytes`,
			routerID, mac, day, ip, clampField(c.Name), dRx, dTx); err != nil {
			return accepted, rejected, err
		}
		accepted++
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return accepted, rejected, nil
}

func counterDelta(prev, cur int64) int64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// RecordDNSDomainCounts adds query counts to the per-client daily aggregate.
func (s *Store) RecordDNSDomainCounts(routerID string, day time.Time, counts []DNSDomainCount) error {
	if len(counts) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	d := utcDay(day)
	for _, c := range counts {
		if c.Queries <= 0 || c.Domain == "" || c.ClientIP == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO dns_domain_daily (day, router_id, client_ip, domain, queries) VALUES (?,?,?,?,?)
			ON CONFLICT(day, router_id, client_ip, domain) DO UPDATE SET queries=queries+excluded.queries`,
			d, routerID, c.ClientIP, c.Domain, c.Queries); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListRouterClientDays returns daily per-client traffic since a day, busiest
// first. An empty mac returns every client.
func (s *Store) ListRouterClientDays(since time.Time, mac string, limit int) ([]RouterClientDay, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	q := `SELECT router_id, mac, day, ip, name, rx_bytes, tx_bytes FROM router_client_daily WHERE day >= ?`
	args := []interface{}{utcDay(since)}
	if m := strings.TrimSpace(mac); m != "" {
		norm, ok := normaliseMAC(m)
		if !ok {
			return nil, fmt.Errorf("invalid mac")
		}
		q += ` AND mac = ?`
		args = append(args, norm)
	}
	q += ` ORDER BY day DESC, (rx_bytes + tx_bytes) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RouterClientDay{}
	for rows.Next() {
		var r RouterClientDay
		if err := rows.Scan(&r.RouterID, &r.MAC, &r.Day, &r.IP, &r.Name, &r.RxBytes, &r.TxBytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DNSDomainQueries returns one client's query count for a domain on a day.
func (s *Store) DNSDomainQueries(day time.Time, routerID, clientIP, domain string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT queries FROM dns_domain_daily WHERE day=? AND router_id=? AND client_ip=? AND domain=?`,
		utcDay(day), routerID, clientIP, domain).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// PruneRouterDaily drops daily aggregates older than the retention window.
func (s *Store) PruneRouterDaily(olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := utcDay(time.Now().Add(-olderThan))
	var total int64
	for _, table := range []string{"router_client_daily", "dns_domain_daily"} {
		res, err := s.db.Exec(`DELETE FROM `+table+` WHERE day < ?`, cutoff)
		if err != nil {
			return total, fmt.Errorf("pruning %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// SetRouterIdentity records the client certificate a gateway authenticates
// with, replacing any earlier one so a reissue revokes the old certificate.
func (s *Store) SetRouterIdentity(routerID, certSHA256 string, issuedAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO router_identities (router_id, cert_sha256, issued_at) VALUES (?,?,?)
		ON CONFLICT(router_id) DO UPDATE SET cert_sha256=excluded.cert_sha256, issued_at=excluded.issued_at`,
		routerID, strings.ToLower(certSHA256), issuedAt.UTC())
	return err
}

// RouterIdentity returns the certificate fingerprint registered for a gateway.
func (s *Store) RouterIdentity(routerID string) (string, bool) {
	var fp string
	if err := s.db.QueryRow(`SELECT cert_sha256 FROM router_identities WHERE router_id=?`, routerID).Scan(&fp); err != nil {
		return "", false
	}
	return fp, true
}
