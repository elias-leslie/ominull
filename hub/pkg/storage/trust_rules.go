package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
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
	CREATE INDEX IF NOT EXISTS idx_trust_rules_scope ON trust_rules(scope_type, scope_id);
	CREATE TABLE IF NOT EXISTS trust_name_answers (
		name TEXT PRIMARY KEY,
		addrs TEXT NOT NULL DEFAULT '[]',
		resolved_at INTEGER NOT NULL DEFAULT 0,
		error TEXT NOT NULL DEFAULT ''
	);`)
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

// TrustNameAddr is one address a name resolved to and when the hub last saw it.
type TrustNameAddr struct {
	Addr string `json:"addr"`
	Seen int64  `json:"seen"`
}

// TrustNameAnswer is what the hub knows about one name: the addresses it has
// resolved to, newest first, and the last lookup's outcome.
type TrustNameAnswer struct {
	Name       string          `json:"name"`
	Addrs      []TrustNameAddr `json:"addrs"`
	ResolvedAt time.Time       `json:"resolved_at"`
	Error      string          `json:"error,omitempty"`
}

// SaveTrustNameAnswer records a lookup. A success refreshes the addresses it
// returned and drops those not seen within retain, so a name behind a rotating
// pool keeps the addresses an endpoint may still hold from an earlier lookup. A
// failure changes no address: a resolver outage must not close an allowed name.
// At most maxAddrs are kept, the most recently seen.
func (s *Store) SaveTrustNameAnswer(name string, addrs []netip.Addr, lookupErr string, now time.Time, retain time.Duration, maxAddrs int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	var resolvedAt int64
	switch err := s.db.QueryRow(`SELECT addrs, resolved_at FROM trust_name_answers WHERE name = ?`, name).Scan(&raw, &resolvedAt); {
	case errors.Is(err, sql.ErrNoRows):
		raw = "[]"
	case err != nil:
		return err
	}
	var kept []TrustNameAddr
	if err := json.Unmarshal([]byte(raw), &kept); err != nil {
		kept = nil
	}
	if lookupErr == "" {
		seen := map[string]int64{}
		for _, a := range kept {
			if time.Unix(a.Seen, 0).Add(retain).After(now) {
				seen[a.Addr] = a.Seen
			}
		}
		for _, a := range addrs {
			seen[a.Unmap().String()] = now.Unix()
		}
		kept = kept[:0]
		for a, at := range seen {
			kept = append(kept, TrustNameAddr{Addr: a, Seen: at})
		}
		sort.Slice(kept, func(i, j int) bool {
			if kept[i].Seen != kept[j].Seen {
				return kept[i].Seen > kept[j].Seen
			}
			return kept[i].Addr < kept[j].Addr
		})
		if len(kept) > maxAddrs {
			kept = kept[:maxAddrs]
		}
		resolvedAt = now.Unix()
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO trust_name_answers (name, addrs, resolved_at, error) VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET addrs = excluded.addrs, resolved_at = excluded.resolved_at, error = excluded.error`,
		name, string(out), resolvedAt, lookupErr)
	return err
}

// TrustNameAnswers returns every stored answer by name.
func (s *Store) TrustNameAnswers() (map[string]TrustNameAnswer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT name, addrs, resolved_at, error FROM trust_name_answers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]TrustNameAnswer{}
	for rows.Next() {
		var a TrustNameAnswer
		var raw string
		var at int64
		if err := rows.Scan(&a.Name, &raw, &at, &a.Error); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &a.Addrs); err != nil {
			return nil, err
		}
		a.ResolvedAt = time.Unix(at, 0).UTC()
		out[a.Name] = a
	}
	return out, rows.Err()
}

// ForgetTrustNameAnswers deletes the answers for names nothing uses any more.
func (s *Store) ForgetTrustNameAnswers(keep map[string]bool) error {
	answers, err := s.TrustNameAnswers()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range answers {
		if !keep[name] {
			if _, err := s.db.Exec(`DELETE FROM trust_name_answers WHERE name = ?`, name); err != nil {
				return err
			}
		}
	}
	return nil
}
