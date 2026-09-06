package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// The last good network attribution snapshot.
//
// Attribution is fetched from published vendor feeds, and a hub is not always
// able to reach them: no internet on a customer site, a mirror down, a proxy in
// the way. Detection must not degrade because of that, so the snapshot that was
// in force is kept here and reloaded at startup. The feeds refresh it; they are
// never a prerequisite for it.
//
// The swap is one transaction. A half-written table would leave part of the
// estate unattributed, which reads to an operator exactly like a fleet-wide
// change in behaviour.

// How a range is tenanted, which decides what may ever be vouched for on it.
// The resolver in pkg/threatintel aliases these; they live here because the
// tuning rules have to reason about tenancy too, and storage cannot import the
// resolver that depends on it.
const (
	// TenancyVendor: the range runs the owner's own services - Apple's 17/8,
	// Microsoft 365, Google's own front ends.
	TenancyVendor = "vendor"

	// TenancySharedCDN: edge infrastructure fronting other people's sites.
	// Ordinary browser traffic goes here constantly, and so does a
	// domain-fronted implant; the process is what separates them.
	TenancySharedCDN = "shared-cdn"

	// TenancyHosting: rented compute, which belongs to whoever paid for it this
	// morning. Never vouched for, however familiar the owner's name looks.
	TenancyHosting = "hosting"
)

// NetworkPrefixRow is one attributed range. It mirrors the resolver's own type
// without importing it — threatintel depends on storage, not the reverse.
type NetworkPrefixRow struct {
	Prefix      string
	Country     string
	CountryName string
	ASN         string
	Org         string
	Tenancy     string
	Source      string
}

func (s *Store) initNetworkAttributionSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS network_attribution (
		prefix TEXT PRIMARY KEY,
		country TEXT NOT NULL DEFAULT '',
		country_name TEXT NOT NULL DEFAULT '',
		asn TEXT NOT NULL DEFAULT '',
		org TEXT NOT NULL DEFAULT '',
		tenancy TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS network_attribution_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		refreshed_at DATETIME NOT NULL,
		source TEXT NOT NULL DEFAULT '',
		entry_count INTEGER NOT NULL DEFAULT 0
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// ReplaceNetworkAttribution swaps in a whole snapshot, or changes nothing.
//
// A caller that arrives with an implausibly small set is refused rather than
// obeyed: emptying this table silently turns every named destination in the
// console back into a bare address.
func (s *Store) ReplaceNetworkAttribution(entries []NetworkPrefixRow, source string, minimum int) error {
	if len(entries) < minimum {
		return fmt.Errorf("refusing to store %d attribution prefixes, fewer than the %d minimum", len(entries), minimum)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM network_attribution`); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO network_attribution
		(prefix, country, country_name, asn, org, tenancy, source) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		if e.Prefix == "" {
			continue
		}
		if _, err := stmt.Exec(e.Prefix, e.Country, e.CountryName, e.ASN, e.Org, e.Tenancy, e.Source); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`INSERT INTO network_attribution_state (id, refreshed_at, source, entry_count)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET refreshed_at = excluded.refreshed_at, source = excluded.source, entry_count = excluded.entry_count`,
		time.Now().UTC(), source, len(entries)); err != nil {
		return err
	}

	return tx.Commit()
}

// ListNetworkAttribution returns the stored snapshot. An empty result is the
// ordinary state of a hub that has never synced, not an error.
func (s *Store) ListNetworkAttribution() ([]NetworkPrefixRow, error) {
	rows, err := s.db.Query(`SELECT prefix, country, country_name, asn, org, tenancy, source
		FROM network_attribution`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []NetworkPrefixRow
	for rows.Next() {
		var r NetworkPrefixRow
		if err := rows.Scan(&r.Prefix, &r.Country, &r.CountryName, &r.ASN, &r.Org, &r.Tenancy, &r.Source); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NetworkAttributionState reports when the snapshot was last refreshed and from
// where, for the diagnostics page.
func (s *Store) NetworkAttributionState() (refreshedAt time.Time, source string, count int, err error) {
	row := s.db.QueryRow(`SELECT refreshed_at, source, entry_count FROM network_attribution_state WHERE id = 1`)
	err = row.Scan(&refreshedAt, &source, &count)
	if err == sql.ErrNoRows {
		return time.Time{}, "", 0, nil
	}
	return refreshedAt, source, count, err
}

// HasOpenAnomaly reports whether an unacknowledged finding of this type already
// stands for an endpoint.
//
// The silence detector holds its armed state in memory, which a hub restart
// loses. Without this, restarting the service would re-raise a finding for
// every host that was already known to be dark - the operator would be told
// again about something they are already looking at, and the restart would look
// like an event.
func (s *Store) HasOpenAnomaly(endpointID, anomalyType string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM anomaly_alerts
		WHERE endpoint_id = ? AND anomaly_type = ? AND acknowledged = 0`,
		endpointID, anomalyType).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
