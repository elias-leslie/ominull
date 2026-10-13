package storage

import (
	"time"
)

// AnomalyWindow counts open anomaly findings raised since a point in time:
// not acknowledged and not held by a learning window.
type AnomalyWindow struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
	ByHost     map[string]int `json:"by_host"`
	// Backlog is every open finding regardless of age.
	Backlog int `json:"backlog"`
}

// SummariseOpenAnomalies returns the counts the Nightshift feed reports.
func (s *Store) SummariseOpenAnomalies(since time.Time) (AnomalyWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := AnomalyWindow{BySeverity: map[string]int{}, ByType: map[string]int{}, ByHost: map[string]int{}}
	rows, err := s.db.Query(`SELECT severity, anomaly_type, hostname, COUNT(*) FROM anomaly_alerts
		WHERE acknowledged = 0 AND held_reason = '' AND timestamp >= ?
		GROUP BY severity, anomaly_type, hostname`, since.UTC())
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev, typ, host string
		var n int
		if err := rows.Scan(&sev, &typ, &host, &n); err != nil {
			return out, err
		}
		out.Total += n
		out.BySeverity[sev] += n
		out.ByType[typ] += n
		out.ByHost[host] += n
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM anomaly_alerts WHERE acknowledged = 0 AND held_reason = ''`).Scan(&out.Backlog)
	return out, err
}

// RouterSource is one gateway that has reported telemetry.
type RouterSource struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	LastSeenAt time.Time `json:"last_seen_at"`
	LastResult string    `json:"last_result"`
	// IdentityIssuedAt is when its current client certificate was issued;
	// zero when it has none.
	IdentityIssuedAt time.Time `json:"identity_issued_at"`
}

// ListRouterSources returns every gateway that has reported, with its client
// certificate issue time when it has one.
func (s *Store) ListRouterSources() ([]RouterSource, error) {
	rows, err := s.db.Query(`SELECT r.id, r.label, r.last_seen_at, r.last_result, i.issued_at
		FROM router_sources r LEFT JOIN router_identities i ON i.router_id = r.id ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouterSource
	for rows.Next() {
		var rs RouterSource
		var seen, issued *time.Time
		if err := rows.Scan(&rs.ID, &rs.Label, &seen, &rs.LastResult, &issued); err != nil {
			return nil, err
		}
		if seen != nil {
			rs.LastSeenAt = *seen
		}
		if issued != nil {
			rs.IdentityIssuedAt = *issued
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}
