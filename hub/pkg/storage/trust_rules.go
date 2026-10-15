package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"ominull/hub/pkg/trustfabric"
)

// Trust rules: the destinations an isolated endpoint may still reach, written
// at provider, client, site, group or endpoint scope. The rules are kept here
// and decided by trustfabric; scopes name the existing tenant, location, role
// and endpoint ids, so there is no table of scopes. Expired rules stay until
// deleted so the audit trail of what was trusted when keeps its subject.

// ErrTrustRuleNotFound is returned when a rule id names no rule.
var ErrTrustRuleNotFound = errors.New("trust rule not found")

func (s *Store) initTrustRuleSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS trust_rules (
		id TEXT PRIMARY KEY,
		scope_type TEXT NOT NULL,
		scope_id TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL,
		value TEXT NOT NULL,
		action TEXT NOT NULL,
		direction TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0,
		proto TEXT NOT NULL,
		locked INTEGER NOT NULL DEFAULT 0,
		expires_at INTEGER,
		justification TEXT NOT NULL DEFAULT '',
		created_by TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_trust_rules_scope ON trust_rules(scope_type, scope_id);`)
	return err
}

// CreateTrustRule validates r, gives it an id and creation time and stores it.
func (s *Store) CreateTrustRule(r trustfabric.Rule) (trustfabric.Rule, error) {
	r, err := trustfabric.Normalize(r)
	if err != nil {
		return trustfabric.Rule{}, err
	}
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return trustfabric.Rule{}, err
	}
	r.ID = "tr_" + hex.EncodeToString(raw[:])
	r.CreatedAt = time.Now().UTC().Truncate(time.Second)
	var expires any
	if r.ExpiresAt != nil {
		t := r.ExpiresAt.UTC().Truncate(time.Second)
		r.ExpiresAt = &t
		expires = t.Unix()
	}
	_, err = s.db.Exec(`INSERT INTO trust_rules (id, scope_type, scope_id, kind, value, action, direction, port, proto, locked, expires_at, justification, created_by, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ScopeType, r.ScopeID, r.Kind, r.Value, r.Action, r.Direction, r.Port, r.Proto, r.Locked,
		expires, r.Justification, r.CreatedBy, r.Source, r.CreatedAt.Unix())
	if err != nil {
		return trustfabric.Rule{}, err
	}
	return r, nil
}

// TrustRules lists every stored rule, expired ones included, oldest first.
func (s *Store) TrustRules() ([]trustfabric.Rule, error) {
	rows, err := s.db.Query(`SELECT id, scope_type, scope_id, kind, value, action, direction, port, proto, locked, expires_at, justification, created_by, source, created_at
		FROM trust_rules ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []trustfabric.Rule
	for rows.Next() {
		r, err := scanTrustRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TrustRule returns one rule by id.
func (s *Store) TrustRule(id string) (trustfabric.Rule, error) {
	r, err := scanTrustRule(s.db.QueryRow(`SELECT id, scope_type, scope_id, kind, value, action, direction, port, proto, locked, expires_at, justification, created_by, source, created_at
		FROM trust_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return trustfabric.Rule{}, ErrTrustRuleNotFound
	}
	return r, err
}

// DeleteTrustRule removes a rule and returns it as it was.
func (s *Store) DeleteTrustRule(id string) (trustfabric.Rule, error) {
	r, err := s.TrustRule(id)
	if err != nil {
		return trustfabric.Rule{}, err
	}
	res, err := s.db.Exec(`DELETE FROM trust_rules WHERE id = ?`, id)
	if err != nil {
		return trustfabric.Rule{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return trustfabric.Rule{}, ErrTrustRuleNotFound
	}
	return r, nil
}

func scanTrustRule(row interface{ Scan(...any) error }) (trustfabric.Rule, error) {
	var r trustfabric.Rule
	var expires sql.NullInt64
	var created int64
	if err := row.Scan(&r.ID, &r.ScopeType, &r.ScopeID, &r.Kind, &r.Value, &r.Action, &r.Direction, &r.Port, &r.Proto,
		&r.Locked, &expires, &r.Justification, &r.CreatedBy, &r.Source, &created); err != nil {
		return trustfabric.Rule{}, err
	}
	if expires.Valid {
		t := time.Unix(expires.Int64, 0).UTC()
		r.ExpiresAt = &t
	}
	r.CreatedAt = time.Unix(created, 0).UTC()
	return r, nil
}
