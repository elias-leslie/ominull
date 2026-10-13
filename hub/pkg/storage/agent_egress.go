package storage

import (
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// Agent egress baselines: which destinations each AI agent runtime on each
// endpoint talks to, and how much it uploads per hour.
//
// An agent runtime (Claude Code, Codex, Ollama) holds a small, stable set of
// conversations - its model API, its telemetry, its updater - and it reads
// whatever it is shown, which is how a prompt injection steers it. What that
// steering looks like on the wire is the runtime reaching somewhere it never
// has, or sending far more than it ever does. Both questions need a memory per
// runtime, which the per-flow detectors do not have.

// AgentDestination is one destination a runtime has been seen reaching.
type AgentDestination struct {
	TenantID    string    `json:"tenant_id"`
	EndpointID  string    `json:"endpoint_id"`
	Runtime     string    `json:"runtime"`
	Destination string    `json:"destination"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Events      int64     `json:"events"`
	BytesOut    int64     `json:"bytes_out"`
}

func (s *Store) initAgentEgressSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS agent_egress_destinations (
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		runtime TEXT NOT NULL,
		destination TEXT NOT NULL,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		events INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (tenant_id, endpoint_id, runtime, destination)
	);
	CREATE TABLE IF NOT EXISTS agent_egress_hourly (
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		runtime TEXT NOT NULL,
		hour INTEGER NOT NULL,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		alerted INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (tenant_id, endpoint_id, runtime, hour)
	);
	-- When each runtime's baseline began on each endpoint. Retention never
	-- prunes it: a runtime idle past the retention period must not get a
	-- second silent learning week when it wakes.
	CREATE TABLE IF NOT EXISTS agent_egress_runtimes (
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		runtime TEXT NOT NULL,
		baseline_start DATETIME NOT NULL,
		PRIMARY KEY (tenant_id, endpoint_id, runtime)
	);
	CREATE TABLE IF NOT EXISTS agent_egress_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`)
	if err != nil {
		return err
	}
	// Development builds created agent_egress_hourly before it had the column.
	if _, err := s.db.Exec(`ALTER TABLE agent_egress_hourly ADD COLUMN alerted INTEGER NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	return nil
}

// ObserveAgentDestination records that runtime reached destination and says
// whether it had before, and when this runtime was first seen on this
// endpoint at all (the start of its baseline).
func (s *Store) ObserveAgentDestination(tenantID, endpointID, runtime, destination string, bytesOut int64, at time.Time) (known bool, since time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at = at.UTC()
	since, err = s.agentBaselineStart(tenantID, endpointID, runtime, at)
	if err != nil {
		return false, at, err
	}
	res, err := s.db.Exec(`UPDATE agent_egress_destinations SET last_seen = ?, events = events + 1, bytes_out = bytes_out + ?
		WHERE tenant_id = ? AND endpoint_id = ? AND runtime = ? AND destination = ?`,
		at, max(bytesOut, 0), tenantID, endpointID, runtime, destination)
	if err != nil {
		return false, since, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, since, nil
	}
	_, err = s.db.Exec(`INSERT INTO agent_egress_destinations (tenant_id, endpoint_id, runtime, destination, first_seen, last_seen, events, bytes_out)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?) ON CONFLICT DO NOTHING`,
		tenantID, endpointID, runtime, destination, at, at, max(bytesOut, 0))
	return false, since, err
}

// agentBaselineStart returns when the runtime's baseline began on the
// endpoint, starting it at `at` the first time. Callers hold s.mu.
func (s *Store) agentBaselineStart(tenantID, endpointID, runtime string, at time.Time) (time.Time, error) {
	if _, err := s.db.Exec(`INSERT INTO agent_egress_runtimes (tenant_id, endpoint_id, runtime, baseline_start) VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING`, tenantID, endpointID, runtime, at.UTC()); err != nil {
		return at, err
	}
	var start time.Time
	err := s.db.QueryRow(`SELECT baseline_start FROM agent_egress_runtimes WHERE tenant_id = ? AND endpoint_id = ? AND runtime = ?`,
		tenantID, endpointID, runtime).Scan(&start)
	return start, err
}

// MarkAgentUploadAlerted claims the right to report the runtime's hour and
// reports whether this call got it, so an hour is reported once however the
// threshold moves while it runs.
func (s *Store) MarkAgentUploadAlerted(tenantID, endpointID, runtime string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.db.Exec(`UPDATE agent_egress_hourly SET alerted = 1 WHERE tenant_id = ? AND endpoint_id = ? AND runtime = ? AND hour = ? AND alerted = 0`,
		tenantID, endpointID, runtime, at.UTC().Unix()/3600)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n == 1, nil
}

// AddAgentUpload adds bytes to the runtime's upload for the hour containing at
// and returns that hour's total so far.
func (s *Store) AddAgentUpload(tenantID, endpointID, runtime string, bytesOut int64, at time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hour := at.UTC().Unix() / 3600
	var total int64
	err := s.db.QueryRow(`INSERT INTO agent_egress_hourly (tenant_id, endpoint_id, runtime, hour, bytes_out) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, endpoint_id, runtime, hour) DO UPDATE SET bytes_out = bytes_out + excluded.bytes_out
		RETURNING bytes_out`, tenantID, endpointID, runtime, hour, max(bytesOut, 0)).Scan(&total)
	return total, err
}

// PruneAgentUploads deletes hourly upload totals older than keep.
func (s *Store) PruneAgentUploads(keep time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.db.Exec(`DELETE FROM agent_egress_hourly WHERE hour < ?`, time.Now().UTC().Add(-keep).Unix()/3600)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// AgentUploadBaseline returns the 95th-percentile hourly upload of the runtime
// over the `days` before the hour containing at, counting only hours in which
// it uploaded anything, and how many such hours there were.
func (s *Store) AgentUploadBaseline(tenantID, endpointID, runtime string, at time.Time, days int) (p95 int64, hours int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hour := at.UTC().Unix() / 3600
	rows, err := s.db.Query(`SELECT bytes_out FROM agent_egress_hourly WHERE tenant_id = ? AND endpoint_id = ? AND runtime = ?
		AND hour >= ? AND hour < ? AND bytes_out > 0`, tenantID, endpointID, runtime, hour-int64(days)*24, hour)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var v []int64
	for rows.Next() {
		var b int64
		if err := rows.Scan(&b); err != nil {
			return 0, 0, err
		}
		v = append(v, b)
	}
	if len(v) == 0 {
		return 0, 0, rows.Err()
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[(len(v)*95)/100], len(v), rows.Err()
}

// ListAgentDestinations returns the learned destinations, most recent first.
func (s *Store) ListAgentDestinations(tenantID string, limit int) ([]AgentDestination, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT tenant_id, endpoint_id, runtime, destination, first_seen, last_seen, events, bytes_out FROM agent_egress_destinations`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentDestination{}
	for rows.Next() {
		var d AgentDestination
		if err := rows.Scan(&d.TenantID, &d.EndpointID, &d.Runtime, &d.Destination, &d.FirstSeen, &d.LastSeen, &d.Events, &d.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SeedAgentDestinations fills the baseline from the communication profiles
// already held, once, so a hub that has watched its agents for weeks does not
// start learning them from nothing. classify returns the runtime and
// destination for a profile row, or "" to skip it. A marker, not the table
// being empty, says it has run, so a runtime event that lands first cannot
// cancel it. The profiles are read without holding the write lock.
func (s *Store) SeedAgentDestinations(classify func(processPath, processName, domain, dstIP string) (runtime, destination string)) (int, error) {
	var done string
	s.mu.RLock()
	err := s.db.QueryRow(`SELECT value FROM agent_egress_meta WHERE key = 'seeded'`).Scan(&done)
	s.mu.RUnlock()
	switch {
	case err == nil:
		return 0, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, err
	}
	s.mu.RLock()
	acc, err := s.readAgentSeed(classify)
	s.mu.RUnlock()
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	type rk struct{ t, e, r string }
	starts := map[rk]time.Time{}
	for _, a := range acc {
		if _, err := tx.Exec(`INSERT INTO agent_egress_destinations (tenant_id, endpoint_id, runtime, destination, first_seen, last_seen, events, bytes_out)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, a.TenantID, a.EndpointID, a.Runtime, a.Destination, a.FirstSeen.UTC(), a.LastSeen.UTC(), a.Events, a.BytesOut); err != nil {
			return 0, err
		}
		k := rk{a.TenantID, a.EndpointID, a.Runtime}
		if st, ok := starts[k]; !ok || a.FirstSeen.Before(st) {
			starts[k] = a.FirstSeen
		}
	}
	// The baseline began when the profiles first saw the runtime, also where
	// a live event already started it later.
	for k, st := range starts {
		if _, err := tx.Exec(`INSERT INTO agent_egress_runtimes (tenant_id, endpoint_id, runtime, baseline_start) VALUES (?, ?, ?, ?)
			ON CONFLICT(tenant_id, endpoint_id, runtime) DO UPDATE SET baseline_start = MIN(baseline_start, excluded.baseline_start)`,
			k.t, k.e, k.r, st.UTC()); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO agent_egress_meta (key, value) VALUES ('seeded', ?) ON CONFLICT DO NOTHING`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return 0, err
	}
	return len(acc), tx.Commit()
}

func (s *Store) readAgentSeed(classify func(processPath, processName, domain, dstIP string) (runtime, destination string)) (map[agentSeedKey]*AgentDestination, error) {
	rows, err := s.db.Query(`SELECT tenant_id, endpoint_id, process_path, process_name, COALESCE(domain, ''), dst_ip, first_seen, last_seen, event_count, total_bytes_out
		FROM comm_profiles WHERE direction = 'OUTBOUND'`)
	if err != nil {
		return nil, err
	}
	acc := map[agentSeedKey]*AgentDestination{}
	for rows.Next() {
		var t, e, path, name, domain, ip string
		var first, last time.Time
		var events, bytes int64
		if err := rows.Scan(&t, &e, &path, &name, &domain, &ip, &first, &last, &events, &bytes); err != nil {
			rows.Close()
			return nil, err
		}
		r, d := classify(path, name, domain, ip)
		if r == "" || d == "" {
			continue
		}
		k := agentSeedKey{t, e, r, d}
		a := acc[k]
		if a == nil {
			a = &AgentDestination{TenantID: t, EndpointID: e, Runtime: r, Destination: d, FirstSeen: first, LastSeen: last}
			acc[k] = a
		}
		if first.Before(a.FirstSeen) {
			a.FirstSeen = first
		}
		if last.After(a.LastSeen) {
			a.LastSeen = last
		}
		a.Events += events
		a.BytesOut += bytes
	}
	rows.Close()
	return acc, rows.Err()
}

type agentSeedKey struct{ t, e, r, d string }

// AgentRuntime names one AI agent runtime by the executable it runs as. Path is
// matched against the executable's full path when it contains a "/", and
// against its base name otherwise; "*" spans one path segment.
type AgentRuntime struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func defaultAgentRuntimes() []AgentRuntime {
	return []AgentRuntime{
		// Claude Code's native build runs as its version number.
		{Name: "claude", Path: "/home/*/.local/share/claude/versions/*"},
		{Name: "claude", Path: "claude"},
		{Name: "codex", Path: "codex"},
		{Name: "ollama", Path: "ollama"},
		{Name: "antigravity", Path: "agy"},
	}
}

// AgentRuntimeOf returns the runtime an executable belongs to, or "".
func (t DetectionTuning) AgentRuntimeOf(processPath string) string {
	p := strings.TrimSuffix(strings.ReplaceAll(processPath, "\\", "/"), " (deleted)")
	base := strings.ToLower(p[strings.LastIndex(p, "/")+1:])
	base = strings.TrimSuffix(base, ".exe")
	for _, r := range t.AgentRuntimes {
		if strings.Contains(r.Path, "/") {
			if matchWorkload(r.Path, p) {
				return r.Name
			}
		} else if strings.EqualFold(r.Path, base) {
			return r.Name
		}
	}
	return ""
}

func tidyAgentRuntimes(in []AgentRuntime) []AgentRuntime {
	seen := map[string]bool{}
	out := make([]AgentRuntime, 0, len(in))
	for _, r := range in {
		r.Name = strings.ToLower(strings.TrimSpace(r.Name))
		r.Path = strings.TrimSpace(r.Path)
		if r.Name == "" || strings.Trim(r.Path, "*/ ") == "" || seen[r.Name+"\x00"+r.Path] {
			continue
		}
		seen[r.Name+"\x00"+r.Path] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	return out
}
