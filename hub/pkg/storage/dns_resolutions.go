package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Destination naming.
//
// An alert that reads "104.18.32.7" tells an analyst nothing. The gateway's
// resolver already answered the question of what name that address was looked
// up under, and dnsmasq writes it plainly: "reply <name> is <address>". Keeping
// those answers is what lets a finding say "the thermostat reached
// firmware.nest.com" instead of quoting an edge address that will be a
// different one tomorrow.
//
// The mapping is deliberately many-to-many. One CDN address serves thousands of
// names and one name resolves to dozens of addresses, so a row is a (name,
// address) pair that was actually observed, with a hit count and the window it
// was seen in. Naming a destination is a best answer, not a fact, and callers
// are expected to treat it that way.
//
// Like everything else arriving from the gateway this is untrusted input: names
// are attacker-chosen (anyone on the estate can look up whatever they like), so
// they are bounded and stripped before they are stored.

// MaxRouterResolutionsPerPoll bounds one poll's answer set. Reply lines
// outnumber queries - a single lookup answers with several addresses - so this
// sits above the query cap.
const MaxRouterResolutionsPerPoll = 40000

// maxDomainLen is the longest legal DNS name; anything past it is a lie.
const maxDomainLen = 253

// DNSResolution is one observed answer: a name and an address it resolved to.
type DNSResolution struct {
	Domain string    `json:"domain"`
	IP     string    `json:"ip"`
	At     time.Time `json:"at"`
}

// ResolvedName is what the store can say about an address.
type ResolvedName struct {
	Domain     string    `json:"domain"`
	Hits       int64     `json:"hits"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

func (s *Store) initDNSResolutionSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS dns_resolutions (
		ip            TEXT NOT NULL,
		domain        TEXT NOT NULL,
		hits          INTEGER NOT NULL DEFAULT 0,
		first_seen_at TIMESTAMP NOT NULL,
		last_seen_at  TIMESTAMP NOT NULL,
		PRIMARY KEY (ip, domain)
	);
	CREATE INDEX IF NOT EXISTS idx_dns_resolutions_ip ON dns_resolutions(ip, last_seen_at DESC);
	CREATE INDEX IF NOT EXISTS idx_dns_resolutions_seen ON dns_resolutions(last_seen_at);
	`)
	return err
}

// normaliseDomain bounds an attacker-chosen name. A trailing dot is the same
// name, and case is not significant, so both are folded to keep one row per
// name rather than one per spelling.
func normaliseDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > maxDomainLen {
		return "", false
	}
	// A name with a control character or a space is not a name.
	for _, r := range d {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return "", false
		}
	}
	// dnsmasq writes these in the value position for answers that carry no
	// address. They are outcomes, not names, and must never become rows.
	switch d {
	case "nxdomain", "nodata", "nodata-ipv4", "nodata-ipv6", "servfail", "refused", "<cname>":
		return "", false
	}
	if !strings.Contains(d, ".") {
		return "", false
	}
	return d, true
}

// RecordDNSResolutions folds a poll's observed answers into the mapping.
func (s *Store) RecordDNSResolutions(res []DNSResolution, now time.Time) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	accepted, rejected := 0, 0
	if len(res) > MaxRouterResolutionsPerPoll {
		rejected += len(res) - MaxRouterResolutionsPerPoll
		res = res[:MaxRouterResolutionsPerPoll]
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, rejected, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO dns_resolutions (ip, domain, hits, first_seen_at, last_seen_at)
		VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(ip, domain) DO UPDATE SET
			hits = hits + 1,
			last_seen_at = excluded.last_seen_at`)
	if err != nil {
		return 0, rejected, err
	}
	defer stmt.Close()

	for _, r := range res {
		ip, ok := normaliseIP(r.IP)
		if !ok {
			rejected++
			continue
		}
		domain, ok := normaliseDomain(r.Domain)
		if !ok {
			rejected++
			continue
		}
		at := r.At
		if at.IsZero() {
			at = now
		}
		if _, err := stmt.Exec(ip, domain, at.UTC(), at.UTC()); err != nil {
			rejected++
			continue
		}
		accepted++
	}

	if err := tx.Commit(); err != nil {
		return 0, rejected, err
	}
	return accepted, rejected, nil
}

// LookupNamesForIP returns what this address has been seen resolving from, the
// most recently observed first.
func (s *Store) LookupNamesForIP(ip string, limit int) ([]ResolvedName, error) {
	clean, ok := normaliseIP(ip)
	if !ok {
		return nil, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 5
	}
	rows, err := s.db.Query(`
		SELECT domain, hits, last_seen_at FROM dns_resolutions
		WHERE ip = ? ORDER BY last_seen_at DESC, hits DESC LIMIT ?`, clean, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ResolvedName
	for rows.Next() {
		var r ResolvedName
		if err := rows.Scan(&r.Domain, &r.Hits, &r.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NameForIP is the single best name for an address, or "" when nothing is known.
//
// "Best" is the most recently observed. A CDN address serves many names and the
// most recent lookup is the one most likely to explain the connection being
// judged right now.
func (s *Store) NameForIP(ip string) string {
	names, err := s.LookupNamesForIP(ip, 1)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0].Domain
}

// NamesForIPs answers for a batch in one query, because naming a page of alerts
// one address at a time is a query per row.
func (s *Store) NamesForIPs(ips []string) (map[string]string, error) {
	out := map[string]string{}
	clean := make([]string, 0, len(ips))
	seen := map[string]bool{}
	for _, ip := range ips {
		c, ok := normaliseIP(ip)
		if !ok || seen[c] {
			continue
		}
		seen[c] = true
		clean = append(clean, c)
	}
	if len(clean) == 0 {
		return out, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(clean)), ",")
	args := make([]interface{}, len(clean))
	for i, c := range clean {
		args[i] = c
	}
	// One row per address: the most recently observed name for it.
	query := fmt.Sprintf(`
		SELECT r.ip, r.domain FROM dns_resolutions r
		JOIN (SELECT ip, MAX(last_seen_at) AS ls FROM dns_resolutions
		      WHERE ip IN (%s) GROUP BY ip) m
		  ON r.ip = m.ip AND r.last_seen_at = m.ls`, placeholders)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, domain string
		if err := rows.Scan(&ip, &domain); err != nil {
			return out, err
		}
		if _, ok := out[ip]; !ok {
			out[ip] = domain
		}
	}
	return out, rows.Err()
}

// PruneOldDNSResolutions drops mappings nothing has confirmed lately. A name to
// address binding goes stale quickly on a CDN, and a table nobody prunes is a
// disk-full incident waiting for a busy week.
func (s *Store) PruneOldDNSResolutions(olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneDNSResolutionsLocked(olderThan)
}

// pruneDNSResolutionsLocked is the body, for callers that already hold the lock.
// PruneOldData does, and calling the exported form from there would deadlock.
func (s *Store) pruneDNSResolutionsLocked(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	res, err := s.db.Exec(`DELETE FROM dns_resolutions WHERE last_seen_at < ?`, cutoff)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return res.RowsAffected()
}
