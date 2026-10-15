package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

// Staged agent rollouts: one owner approval covers a release, which installs
// on the canary endpoints first. The other approved endpoints are held here,
// with no update job, until the canaries run the version with a clean
// provenance check; then they are queued. A canary that fails or does not
// report in time halts the rollout and the held endpoints are never queued.
// The held endpoints' update grants stay pending (undelivered) with the
// rollout: released with it, deleted when it halts or is superseded.

// AgentRollout is one staged rollout.
type AgentRollout struct {
	ID       string   `json:"id"`
	Version  string   `json:"version"`
	AllFleet bool     `json:"all"`
	Canary   []string `json:"canary"`
	Held     []string `json:"held"`
	// HeldGrants are the pending update grants of the held endpoints.
	HeldGrants []string  `json:"-"`
	State      string    `json:"state"` // canary, released, halted, superseded
	Detail     string    `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
	Deadline   time.Time `json:"deadline"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Rollout states.
const (
	RolloutCanary     = "canary"
	RolloutReleased   = "released"
	RolloutHalted     = "halted"
	RolloutSuperseded = "superseded"
)

func (s *Store) initAgentRolloutSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS agent_rollouts (
		id TEXT PRIMARY KEY,
		version TEXT NOT NULL,
		all_fleet INTEGER NOT NULL DEFAULT 0,
		canary TEXT NOT NULL,
		held TEXT NOT NULL,
		held_grants TEXT NOT NULL DEFAULT '',
		state TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		deadline INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_agent_rollouts_state ON agent_rollouts(state, created_at);`)
	return err
}

// CreateAgentRollout records a staged rollout in the canary state. Any rollout
// still waiting on its canaries is superseded (the newer approval decides) and
// returned, so the caller withdraws its held grants.
func (s *Store) CreateAgentRollout(r AgentRollout) (AgentRollout, []AgentRollout, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return AgentRollout{}, nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	r.ID = "ro_" + hex.EncodeToString(raw[:])
	r.State = RolloutCanary
	r.CreatedAt, r.UpdatedAt = now, now
	r.Deadline = r.Deadline.UTC().Truncate(time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return AgentRollout{}, nil, err
	}
	defer tx.Rollback()
	superseded, err := supersedeRollouts(tx, "superseded by rollout "+r.ID, now)
	if err != nil {
		return AgentRollout{}, nil, err
	}
	if _, err := tx.Exec(`INSERT INTO agent_rollouts (id, version, all_fleet, canary, held, held_grants, state, detail, created_at, deadline, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Version, r.AllFleet, strings.Join(r.Canary, ","), strings.Join(r.Held, ","), strings.Join(r.HeldGrants, ","), r.State, r.Detail,
		now.Unix(), r.Deadline.Unix(), now.Unix()); err != nil {
		return AgentRollout{}, nil, err
	}
	return r, superseded, tx.Commit()
}

// SupersedeAgentRollouts ends every rollout waiting on its canaries (a newer
// update decides) and returns them.
func (s *Store) SupersedeAgentRollouts(reason string) ([]AgentRollout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := supersedeRollouts(tx, reason, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func supersedeRollouts(tx *sql.Tx, reason string, now time.Time) ([]AgentRollout, error) {
	rows, err := tx.Query(`SELECT `+rolloutColumns+` FROM agent_rollouts WHERE state = ?`, RolloutCanary)
	if err != nil {
		return nil, err
	}
	out, err := scanRollouts(rows)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE agent_rollouts SET state = ?, detail = ?, updated_at = ? WHERE state = ?`,
		RolloutSuperseded, reason, now.Unix(), RolloutCanary); err != nil {
		return nil, err
	}
	return out, nil
}

// FinishAgentRollout moves a rollout out of the canary state. It reports
// false when the rollout had already left it (another caller decided).
func (s *Store) FinishAgentRollout(id, state, detail string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE agent_rollouts SET state = ?, detail = ?, updated_at = ? WHERE id = ? AND state = ?`,
		state, detail, time.Now().UTC().Unix(), id, RolloutCanary)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// AgentRollouts lists rollouts, newest first; only those waiting on their
// canaries when active is set.
func (s *Store) AgentRollouts(active bool, limit int) ([]AgentRollout, error) {
	q := `SELECT ` + rolloutColumns + ` FROM agent_rollouts`
	var args []any
	if active {
		q += ` WHERE state = ?`
		args = append(args, RolloutCanary)
	}
	q += ` ORDER BY created_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanRollouts(rows)
}

// HeldRolloutGrants is the set of update grants rollouts waiting on their
// canaries keep pending.
func (s *Store) HeldRolloutGrants() (map[string]bool, error) {
	active, err := s.AgentRollouts(true, 100)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range active {
		for _, g := range r.HeldGrants {
			out[g] = true
		}
	}
	return out, nil
}

const rolloutColumns = `id, version, all_fleet, canary, held, held_grants, state, detail, created_at, deadline, updated_at`

func scanRollouts(rows *sql.Rows) ([]AgentRollout, error) {
	defer rows.Close()
	out := []AgentRollout{}
	for rows.Next() {
		var r AgentRollout
		var canary, held, grants string
		var created, deadline, updated int64
		if err := rows.Scan(&r.ID, &r.Version, &r.AllFleet, &canary, &held, &grants, &r.State, &r.Detail, &created, &deadline, &updated); err != nil {
			return nil, err
		}
		r.Canary, r.Held, r.HeldGrants = splitIDs(canary), splitIDs(held), splitIDs(grants)
		r.CreatedAt, r.Deadline, r.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(deadline, 0).UTC(), time.Unix(updated, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

func splitIDs(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
