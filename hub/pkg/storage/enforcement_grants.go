package storage

import (
	"database/sql"
	"strings"
	"time"
)

// Enforcement grants are the response authority's signed statements that
// move an endpoint's enforcement state (isolate, release, mesh quarantine) or
// authorize an agent update. The hub only carries them: agents verify each
// one themselves. They are kept until they expire so an endpoint that was
// offline when the owner approved still receives its grant when it returns.

// StoredGrant is one grant as the hub keeps it. Target is the endpoint ID, or
// "mesh:<address>" for a fleet-wide mesh quarantine change.
type StoredGrant struct {
	GrantID   string
	TenantID  string
	Target    string
	Kind      string
	GrantJSON string
	Payload   []byte
	IssuedAt  int64
	ExpiresAt int64
	// Pending grants are kept but not delivered until MarkGrantsDeliverable:
	// an owner-approved action's grants are stored before its handler runs
	// and released to agents only once the handler succeeded.
	Pending bool
}

func (s *Store) initEnforcementGrantSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS enforcement_grants (
		grant_id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		target TEXT NOT NULL,
		kind TEXT NOT NULL,
		grant_json TEXT NOT NULL,
		payload BLOB NOT NULL,
		issued_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		deliverable INTEGER NOT NULL DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_enforcement_grants_target ON enforcement_grants(target, kind, issued_at);
	CREATE INDEX IF NOT EXISTS idx_enforcement_grants_kind ON enforcement_grants(kind, issued_at);`)
	if err != nil {
		return err
	}
	// Tables from before the deliverable flag.
	if _, err := s.db.Exec(`ALTER TABLE enforcement_grants ADD COLUMN deliverable INTEGER NOT NULL DEFAULT 1`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// PendingGrants returns grants still waiting for their action's outcome,
// issued at or before the given time.
func (s *Store) PendingGrants(issuedBefore int64) ([]StoredGrant, error) {
	rows, err := s.db.Query(`SELECT `+grantColumns+` FROM enforcement_grants WHERE deliverable = 0 AND issued_at <= ?`, issuedBefore)
	if err != nil {
		return nil, err
	}
	list, err := scanGrants(rows)
	for i := range list {
		list[i].Pending = true
	}
	return list, err
}

// MarkGrantsDeliverable releases pending grants to agents.
func (s *Store) MarkGrantsDeliverable(ids []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`UPDATE enforcement_grants SET deliverable = 1 WHERE grant_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteEnforcementGrants removes grants by ID (an approved action whose
// handler then failed must not reach agents).
func (s *Store) DeleteEnforcementGrants(ids []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM enforcement_grants WHERE grant_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveEnforcementGrants records grants and drops expired ones.
func (s *Store) SaveEnforcementGrants(list []StoredGrant) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, g := range list {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO enforcement_grants
			(grant_id, tenant_id, target, kind, grant_json, payload, issued_at, expires_at, deliverable) VALUES (?,?,?,?,?,?,?,?,?)`,
			g.GrantID, g.TenantID, g.Target, g.Kind, g.GrantJSON, g.Payload, g.IssuedAt, g.ExpiresAt, !g.Pending); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM enforcement_grants WHERE expires_at < ?`, time.Now().Add(-time.Hour).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func scanGrants(rows *sql.Rows) ([]StoredGrant, error) {
	defer rows.Close()
	var out []StoredGrant
	for rows.Next() {
		var g StoredGrant
		if err := rows.Scan(&g.GrantID, &g.TenantID, &g.Target, &g.Kind, &g.GrantJSON, &g.Payload, &g.IssuedAt, &g.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

const grantColumns = `grant_id, tenant_id, target, kind, grant_json, payload, issued_at, expires_at`

// LatestIsolationGrant returns the newest unexpired isolation grant (owner or
// detector) for an endpoint issued after the given time, if any.
func (s *Store) LatestIsolationGrant(endpointID string, after, now int64) (*StoredGrant, error) {
	rows, err := s.db.Query(`SELECT `+grantColumns+` FROM enforcement_grants
		WHERE target = ? AND kind IN ('isolation_change','auto_isolate') AND issued_at > ? AND expires_at > ? AND deliverable = 1
		ORDER BY issued_at DESC LIMIT 1`, endpointID, after, now)
	if err != nil {
		return nil, err
	}
	list, err := scanGrants(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

// MeshGrantsAfter returns unexpired mesh grants issued after the given time,
// oldest first, at most limit.
func (s *Store) MeshGrantsAfter(after, now int64, limit int) ([]StoredGrant, error) {
	rows, err := s.db.Query(`SELECT `+grantColumns+` FROM enforcement_grants
		WHERE kind = 'mesh_quarantine' AND issued_at > ? AND expires_at > ? AND deliverable = 1
		ORDER BY issued_at ASC LIMIT ?`, after, now, limit)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}

// UpdateGrants returns unexpired agent-update grants for an endpoint, newest first.
func (s *Store) UpdateGrants(endpointID string, now int64) ([]StoredGrant, error) {
	rows, err := s.db.Query(`SELECT `+grantColumns+` FROM enforcement_grants
		WHERE target = ? AND kind = 'agent_update' AND expires_at > ? AND deliverable = 1
		ORDER BY issued_at DESC LIMIT 4`, endpointID, now)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}
