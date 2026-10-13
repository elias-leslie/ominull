package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Data inventory: what each agent's read-only data scan last reported.
//
// The agent sends metadata only (paths, sizes, times, counts, rule names; no
// file contents and no matched text). The hub keeps the latest picture per
// endpoint - one row per store and per flagged item - and an append-only run
// log that is the audit trail of every scan it accepted. Scope and cadence
// are hub configuration: a policy layered default -> role tag -> endpoint,
// changed only through an audited administrator call.

// DataPolicy is one layer of scan configuration. A nil field is "inherit".
type DataPolicy struct {
	Enabled            *bool    `json:"enabled,omitempty"`
	Roots              []string `json:"roots,omitempty"`
	Excludes           []string `json:"excludes,omitempty"`
	StoreDepth         *int     `json:"store_depth,omitempty"`
	MaxFiles           *int     `json:"max_files,omitempty"`
	MaxSeconds         *int     `json:"max_seconds,omitempty"`
	ContentMaxBytes    *int64   `json:"content_max_bytes,omitempty"`
	ContentBudgetBytes *int64   `json:"content_budget_bytes,omitempty"`
	IntervalHours      *int     `json:"interval_hours,omitempty"`
	ResumeMinutes      *int     `json:"resume_minutes,omitempty"`
	FullEveryDays      *int     `json:"full_every_days,omitempty"`
	OneFilesystem      *bool    `json:"one_filesystem,omitempty"`
	MaxStores          *int     `json:"max_stores,omitempty"`
	MaxItems           *int     `json:"max_items,omitempty"`
}

// DataPolicyLayer is a stored layer and the scope it applies to: "default",
// "role:<tag>" or "endpoint:<id>".
type DataPolicyLayer struct {
	Scope     string     `json:"scope"`
	Policy    DataPolicy `json:"policy"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy string     `json:"updated_by"`
}

// DataCanaries is the canary path list the hub holds for one endpoint. Synced
// is what matters: the hub never enables a scan on an endpoint whose canary
// list was not explicitly synced, even when the list is empty.
type DataCanaries struct {
	EndpointID string    `json:"endpoint_id"`
	Paths      []string  `json:"paths"`
	SyncedAt   time.Time `json:"synced_at"`
	Source     string    `json:"source"`
}

// DataRun is one accepted scan run.
type DataRun struct {
	EndpointID    string          `json:"endpoint_id"`
	CycleID       string          `json:"cycle_id"`
	Mode          string          `json:"mode"`
	StartedAt     int64           `json:"started_at"`
	FinishedAt    int64           `json:"finished_at"`
	CycleStarted  int64           `json:"cycle_started_at"`
	CycleComplete bool            `json:"cycle_complete"`
	BudgetHit     string          `json:"budget_hit"`
	PolicyVersion int64           `json:"policy_version"`
	RulesVersion  int64           `json:"rules_version"`
	Sandboxed     bool            `json:"sandboxed"`
	Summary       json.RawMessage `json:"summary"`
	ReceivedAt    time.Time       `json:"received_at"`
}

// DataStore and DataItem are the latest rows; Doc is the agent's own JSON
// object for the row, already validated by the server.
type DataStore struct {
	Path    string          `json:"path"`
	CycleID string          `json:"cycle_id"`
	SeenAt  time.Time       `json:"seen_at"`
	Doc     json.RawMessage `json:"doc"`
}

type DataItem struct {
	Path    string          `json:"path"`
	Store   string          `json:"store"`
	Kind    string          `json:"kind"`
	CycleID string          `json:"cycle_id"`
	SeenAt  time.Time       `json:"seen_at"`
	Doc     json.RawMessage `json:"doc"`
}

// DataSnapshot is the latest picture of one endpoint.
type DataSnapshot struct {
	EndpointID      string          `json:"endpoint_id"`
	Host            json.RawMessage `json:"host,omitempty"`
	LastRun         *DataRun        `json:"last_run,omitempty"`
	LastCompleteAt  int64           `json:"last_complete_at"`
	Stores          []DataStore     `json:"stores"`
	Items           []DataItem      `json:"items"`
	StoresTruncated bool            `json:"stores_truncated"`
	ItemsTruncated  bool            `json:"items_truncated"`
}

// DataRunUpload is what the server hands the store for one accepted run.
type DataRunUpload struct {
	Run       DataRun
	Host      json.RawMessage
	Stores    []DataStore // in walk order; partial ones flagged
	Partial   map[string]bool
	Items     []DataItem
	Complete  bool
	Truncated bool // the agent dropped items (max_items)
}

// ErrDataStaleRun is returned for a run older than one already accepted.
var ErrDataStaleRun = errors.New("an older run than the latest accepted one")

const dataRunsKept = 200

func (s *Store) initDataInventorySchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS data_policies (
		scope TEXT PRIMARY KEY,
		policy TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		updated_by TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS data_canaries (
		endpoint_id TEXT PRIMARY KEY,
		paths TEXT NOT NULL,
		synced_at DATETIME NOT NULL,
		source TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS data_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		endpoint_id TEXT NOT NULL,
		cycle_id TEXT NOT NULL,
		mode TEXT NOT NULL,
		started_at INTEGER NOT NULL,
		finished_at INTEGER NOT NULL,
		cycle_started_at INTEGER NOT NULL,
		cycle_complete INTEGER NOT NULL,
		budget_hit TEXT NOT NULL,
		policy_version INTEGER NOT NULL,
		rules_version INTEGER NOT NULL,
		sandboxed INTEGER NOT NULL,
		summary TEXT NOT NULL,
		received_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_data_runs_endpoint ON data_runs(endpoint_id, id);
	CREATE TABLE IF NOT EXISTS data_host (
		endpoint_id TEXT PRIMARY KEY,
		doc TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS data_stores (
		endpoint_id TEXT NOT NULL,
		path TEXT NOT NULL,
		cycle_id TEXT NOT NULL,
		seen_at DATETIME NOT NULL,
		doc TEXT NOT NULL,
		PRIMARY KEY (endpoint_id, path)
	);
	CREATE TABLE IF NOT EXISTS data_items (
		endpoint_id TEXT NOT NULL,
		path TEXT NOT NULL,
		store TEXT NOT NULL,
		kind TEXT NOT NULL,
		cycle_id TEXT NOT NULL,
		seen_at DATETIME NOT NULL,
		doc TEXT NOT NULL,
		PRIMARY KEY (endpoint_id, path)
	);
	CREATE INDEX IF NOT EXISTS idx_data_items_store ON data_items(endpoint_id, store);
	`)
	return err
}

// ValidDataPolicyScope reports a scope a layer may be stored under.
func ValidDataPolicyScope(scope string) bool {
	switch {
	case scope == "default":
		return true
	case strings.HasPrefix(scope, "role:"), strings.HasPrefix(scope, "endpoint:"):
		rest := scope[strings.Index(scope, ":")+1:]
		return rest != "" && len(rest) <= 128 && !strings.ContainsAny(rest, "\n\r\x00")
	}
	return false
}

// SetDataPolicy stores (or with nil, removes) one layer.
func (s *Store) SetDataPolicy(scope string, p *DataPolicy, by string) error {
	if !ValidDataPolicyScope(scope) {
		return fmt.Errorf("scope is default, role:<tag> or endpoint:<id>")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		_, err := s.db.Exec("DELETE FROM data_policies WHERE scope = ?", scope)
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO data_policies (scope, policy, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT(scope) DO UPDATE SET policy = excluded.policy, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		scope, string(raw), time.Now().UTC(), by)
	return err
}

// ListDataPolicies returns every stored layer.
func (s *Store) ListDataPolicies() ([]DataPolicyLayer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT scope, policy, updated_at, updated_by FROM data_policies ORDER BY scope")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DataPolicyLayer{}
	for rows.Next() {
		var l DataPolicyLayer
		var raw string
		if err := rows.Scan(&l.Scope, &raw, &l.UpdatedAt, &l.UpdatedBy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &l.Policy); err != nil {
			return nil, fmt.Errorf("data policy %s unreadable: %w", l.Scope, err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// DataPolicyLayers returns the default, role and endpoint layers that apply
// to one endpoint, in that order (absent layers are omitted).
func (s *Store) DataPolicyLayers(endpointID, roleTag string) ([]DataPolicyLayer, error) {
	all, err := s.ListDataPolicies()
	if err != nil {
		return nil, err
	}
	var out []DataPolicyLayer
	for _, want := range []string{"default", "role:" + roleTag, "endpoint:" + endpointID} {
		for _, l := range all {
			if l.Scope == want {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

// SetDataCanaries replaces the canary list of one endpoint.
func (s *Store) SetDataCanaries(c DataCanaries) error {
	if c.Paths == nil {
		c.Paths = []string{}
	}
	raw, err := json.Marshal(c.Paths)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO data_canaries (endpoint_id, paths, synced_at, source) VALUES (?, ?, ?, ?)
		ON CONFLICT(endpoint_id) DO UPDATE SET paths = excluded.paths, synced_at = excluded.synced_at, source = excluded.source`,
		c.EndpointID, string(raw), c.SyncedAt.UTC(), c.Source)
	return err
}

// GetDataCanaries returns the endpoint's canary list; ok is false when none
// was ever synced.
func (s *Store) GetDataCanaries(endpointID string) (DataCanaries, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := DataCanaries{EndpointID: endpointID}
	var raw string
	err := s.db.QueryRow("SELECT paths, synced_at, source FROM data_canaries WHERE endpoint_id = ?", endpointID).
		Scan(&raw, &c.SyncedAt, &c.Source)
	if errors.Is(err, sql.ErrNoRows) {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	if err := json.Unmarshal([]byte(raw), &c.Paths); err != nil {
		return c, false, fmt.Errorf("canary list of %s unreadable: %w", endpointID, err)
	}
	return c, true, nil
}

// RecordDataRun applies one accepted run: the run log, the host facts, the
// stores and items it reported, and - when it completed a cycle - removal of
// every store and item the cycle no longer saw.
func (s *Store) RecordDataRun(u DataRunUpload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last sql.NullInt64
	if err := tx.QueryRow("SELECT MAX(started_at) FROM data_runs WHERE endpoint_id = ?", u.Run.EndpointID).Scan(&last); err != nil {
		return err
	}
	if last.Valid && u.Run.StartedAt < last.Int64 {
		return ErrDataStaleRun
	}
	now := u.Run.ReceivedAt.UTC()
	r := u.Run
	if _, err := tx.Exec(`INSERT INTO data_runs (endpoint_id, cycle_id, mode, started_at, finished_at, cycle_started_at,
		cycle_complete, budget_hit, policy_version, rules_version, sandboxed, summary, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.EndpointID, r.CycleID, r.Mode, r.StartedAt, r.FinishedAt, r.CycleStarted, boolInt(r.CycleComplete), r.BudgetHit,
		r.PolicyVersion, r.RulesVersion, boolInt(r.Sandboxed), string(r.Summary), now); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM data_runs WHERE endpoint_id = ? AND id NOT IN
		(SELECT id FROM data_runs WHERE endpoint_id = ? ORDER BY id DESC LIMIT ?)`, r.EndpointID, r.EndpointID, dataRunsKept); err != nil {
		return err
	}
	if len(u.Host) > 0 {
		if _, err := tx.Exec(`INSERT INTO data_host (endpoint_id, doc, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(endpoint_id) DO UPDATE SET doc = excluded.doc, updated_at = excluded.updated_at`,
			r.EndpointID, string(u.Host), now); err != nil {
			return err
		}
	}
	for _, st := range u.Stores {
		if _, err := tx.Exec(`INSERT INTO data_stores (endpoint_id, path, cycle_id, seen_at, doc) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(endpoint_id, path) DO UPDATE SET cycle_id = excluded.cycle_id, seen_at = excluded.seen_at, doc = excluded.doc`,
			r.EndpointID, st.Path, r.CycleID, now, string(st.Doc)); err != nil {
			return err
		}
		// A store walked to the end replaces its items; a partial one (cut
		// by the budget) only adds, so items it did not reach are kept.
		// When the agent dropped items for max_items the old rows are kept
		// too: a missing row then means "not reported", never "gone".
		if !u.Partial[st.Path] && !u.Truncated {
			if _, err := tx.Exec("DELETE FROM data_items WHERE endpoint_id = ? AND store = ?", r.EndpointID, st.Path); err != nil {
				return err
			}
		}
	}
	for _, it := range u.Items {
		if _, err := tx.Exec(`INSERT INTO data_items (endpoint_id, path, store, kind, cycle_id, seen_at, doc) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(endpoint_id, path) DO UPDATE SET store = excluded.store, kind = excluded.kind, cycle_id = excluded.cycle_id,
			seen_at = excluded.seen_at, doc = excluded.doc`,
			r.EndpointID, it.Path, it.Store, it.Kind, r.CycleID, now, string(it.Doc)); err != nil {
			return err
		}
	}
	if u.Complete && !u.Truncated {
		// The cycle walked every root: what it did not see is gone.
		if _, err := tx.Exec("DELETE FROM data_stores WHERE endpoint_id = ? AND cycle_id != ?", r.EndpointID, r.CycleID); err != nil {
			return err
		}
		// Items of a store the budget cut short were not all reached; they
		// stay until a cycle walks that store to the end.
		if _, err := tx.Exec(`DELETE FROM data_items WHERE endpoint_id = ? AND cycle_id != ? AND store NOT IN
			(SELECT path FROM data_stores WHERE endpoint_id = ? AND json_extract(doc, '$.partial') = 1)`,
			r.EndpointID, r.CycleID, r.EndpointID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DataSnapshotFor reads the latest picture of one endpoint, at most
// maxStores stores (largest first) and maxItems items.
func (s *Store) DataSnapshotFor(endpointID string, maxStores, maxItems int) (DataSnapshot, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := DataSnapshot{EndpointID: endpointID, Stores: []DataStore{}, Items: []DataItem{}}
	var host string
	err := s.db.QueryRow("SELECT doc FROM data_host WHERE endpoint_id = ?", endpointID).Scan(&host)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return snap, false, err
	}
	if host != "" {
		snap.Host = json.RawMessage(host)
	}
	var run DataRun
	var complete, sandboxed int
	var summary string
	err = s.db.QueryRow(`SELECT cycle_id, mode, started_at, finished_at, cycle_started_at, cycle_complete, budget_hit,
		policy_version, rules_version, sandboxed, summary, received_at FROM data_runs WHERE endpoint_id = ? ORDER BY id DESC LIMIT 1`,
		endpointID).Scan(&run.CycleID, &run.Mode, &run.StartedAt, &run.FinishedAt, &run.CycleStarted, &complete, &run.BudgetHit,
		&run.PolicyVersion, &run.RulesVersion, &sandboxed, &summary, &run.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return snap, false, nil
	}
	if err != nil {
		return snap, false, err
	}
	run.EndpointID = endpointID
	run.CycleComplete = complete == 1
	run.Sandboxed = sandboxed == 1
	run.Summary = json.RawMessage(summary)
	snap.LastRun = &run
	var lastComplete sql.NullInt64
	if err := s.db.QueryRow("SELECT MAX(finished_at) FROM data_runs WHERE endpoint_id = ? AND cycle_complete = 1", endpointID).
		Scan(&lastComplete); err != nil {
		return snap, false, err
	}
	snap.LastCompleteAt = lastComplete.Int64

	rows, err := s.db.Query(`SELECT path, cycle_id, seen_at, doc FROM data_stores WHERE endpoint_id = ?
		ORDER BY CAST(json_extract(doc, '$.items') AS INTEGER) DESC, CAST(json_extract(doc, '$.bytes') AS INTEGER) DESC, path
		LIMIT ?`, endpointID, maxStores+1)
	if err != nil {
		return snap, false, err
	}
	for rows.Next() {
		var st DataStore
		var doc string
		if err := rows.Scan(&st.Path, &st.CycleID, &st.SeenAt, &doc); err != nil {
			rows.Close()
			return snap, false, err
		}
		st.Doc = json.RawMessage(doc)
		snap.Stores = append(snap.Stores, st)
	}
	rows.Close()
	if len(snap.Stores) > maxStores {
		snap.Stores = snap.Stores[:maxStores]
		snap.StoresTruncated = true
	}
	// Secrets first: they are what a reader acts on.
	rows, err = s.db.Query(`SELECT path, store, kind, cycle_id, seen_at, doc FROM data_items WHERE endpoint_id = ?
		ORDER BY CASE kind WHEN 'private_key' THEN 0 WHEN 'secret_candidate' THEN 1 WHEN 'encrypted_container' THEN 2 ELSE 3 END, path
		LIMIT ?`, endpointID, maxItems+1)
	if err != nil {
		return snap, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var it DataItem
		var doc string
		if err := rows.Scan(&it.Path, &it.Store, &it.Kind, &it.CycleID, &it.SeenAt, &doc); err != nil {
			return snap, false, err
		}
		it.Doc = json.RawMessage(doc)
		snap.Items = append(snap.Items, it)
	}
	if len(snap.Items) > maxItems {
		snap.Items = snap.Items[:maxItems]
		snap.ItemsTruncated = true
	}
	return snap, true, rows.Err()
}

// DataInventoryEndpoints lists the endpoints with at least one accepted run.
func (s *Store) DataInventoryEndpoints() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT DISTINCT endpoint_id FROM data_runs ORDER BY endpoint_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
