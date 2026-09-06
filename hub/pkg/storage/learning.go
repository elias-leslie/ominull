package storage

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Learning mode: a bounded period during which an estate is described rather
// than judged.
//
// Tuning a detector by hand means reading findings and deciding, one at a time,
// which of them describe the place rather than a problem. That is the work this
// replaces. Inside a learning window the detectors still run and still write
// their findings - they are recorded as *held*, kept out of the open count and
// off the default alert list, and readable under their own filter - while a
// second, much cheaper record accumulates: which programs talked to which
// networks, on which ports, at which hours.
//
// When the window closes that record becomes proposals: "this program talks to
// this network here, on five machines, four thousand times - should it be
// expected?" Nothing applies itself. A proposal carries what it would silence,
// how much evidence stands behind it, and how many other systems corroborate
// it, because a pair seen on five workstations is platform traffic and the same
// pair seen on exactly one host is the thing you were looking for.
//
// Two of the five candidate kinds the plan named turned out to need no
// machinery at all, and building them would have been theatre:
//
//   - first-seen history. `IsFirstSeenDestination` reads the stored event
//     table, so a destination reached during the window is already not new
//     afterwards. Recording it a second time would change nothing.
//   - bandwidth baselines. The detector's per-process ring holds real transfer
//     sizes and the engine runs throughout the window, so the ring warms itself
//     on the traffic that actually happened. Seeding it from a mean and a
//     variance would be inventing samples nobody measured.
//
// What is left is what genuinely needs a human to agree to it: a quiet pair, a
// quiet client, and the hours this estate is actually awake.

// Learning window scopes. An endpoint is learning if it, its location, or its
// tenant has an active window - the same hierarchy the console navigates.
const (
	LearningScopeTenant   = "tenant"
	LearningScopeLocation = "location"
	LearningScopeEndpoint = "endpoint"
)

// Learning window states.
const (
	LearningActive    = "active"
	LearningCompleted = "completed"
	LearningCancelled = "cancelled"
)

// HeldLearning is the reason stamped on a finding raised inside a window.
const HeldLearning = "learning"

// Observation kinds.
const (
	LearnPair    = "pair"    // key: "procbase@owner"
	LearnProcess = "process" // key: process base name
	LearnOwner   = "owner"   // key: destination network owner
	LearnPort    = "port"    // key: destination port
	LearnHour    = "hour"    // key: hour of the day, in the tuned zone
)

// LearningWindow is one bounded period of description over one scope.
type LearningWindow struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	ScopeType  string     `json:"scope_type"`
	ScopeID    string     `json:"scope_id"`
	ScopeLabel string     `json:"scope_label"`
	StartedAt  time.Time  `json:"started_at"`
	EndsAt     time.Time  `json:"ends_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	StartedBy  string     `json:"started_by"`
	Note       string     `json:"note"`
	Status     string     `json:"status"`
}

// Open reports whether this window is still describing rather than judging.
// A window whose end time has passed is over even if nothing has written
// "completed" to it yet, so that a hub which was down at the end of a window
// does not resume holding findings when it comes back.
func (w LearningWindow) Open(now time.Time) bool {
	return w.Status == LearningActive && now.Before(w.EndsAt)
}

// Covers reports whether this window is the one an endpoint is learning under.
func (w LearningWindow) Covers(ep Endpoint) bool {
	switch w.ScopeType {
	case LearningScopeEndpoint:
		return w.ScopeID == ep.ID
	case LearningScopeLocation:
		return w.ScopeID != "" && w.ScopeID == ep.LocationID
	case LearningScopeTenant:
		return w.ScopeID == "" || w.ScopeID == ep.TenantID
	}
	return false
}

// LearningObservation is one accumulated fact about an endpoint in a window.
type LearningObservation struct {
	WindowID   string    `json:"window_id"`
	EndpointID string    `json:"endpoint_id"`
	Kind       string    `json:"kind"`
	Key        string    `json:"key"`
	Count      int64     `json:"count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// LearningProposal is a candidate tuning change, with the argument for it.
//
// It is computed from the observations every time it is asked for rather than
// stored, so a proposal can never describe a window as it was three days ago,
// and applying one is validated against the same computation that produced it.
type LearningProposal struct {
	ID       string `json:"id"`
	WindowID string `json:"window_id"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	// Silences is what changes if this is applied, in words.
	Silences string `json:"silences"`
	// Technique is the ATT&CK technique this proposal would blunt, so the cost
	// of accepting it is stated in the same terms as the findings it silences.
	Technique string `json:"technique"`
	Evidence  int64  `json:"evidence"`
	Endpoints int    `json:"endpoints"`
	// Roles is how the corroborating endpoints break down by role tag. Five
	// workstations agreeing is ordinary; a workstation and a server agreeing is
	// a weaker argument than the raw count suggests.
	Roles         map[string]int `json:"roles,omitempty"`
	Corroboration float64        `json:"corroboration"`
	FirstSeen     time.Time      `json:"first_seen"`
	LastSeen      time.Time      `json:"last_seen"`
	// Applied is true when the tuning already contains this proposal, so the
	// list can be read twice without applying anything twice.
	Applied bool `json:"applied"`
}

// Proposal kinds.
const (
	ProposeQuietPair    = "quiet_pair"
	ProposeQuietProcess = "quiet_process"
	ProposeOffHours     = "off_hours"
)

type learningCache struct {
	mu      sync.RWMutex
	windows []LearningWindow
	at      time.Time
}

// CreateLearningWindow opens a window. Duration is clamped to something a human
// could plausibly have meant: an hour at the shortest, ninety days at the
// longest.
func (s *Store) CreateLearningWindow(w LearningWindow) (LearningWindow, error) {
	switch w.ScopeType {
	case LearningScopeTenant, LearningScopeLocation, LearningScopeEndpoint:
	default:
		return LearningWindow{}, fmt.Errorf("a learning window is scoped to a tenant, a location or an endpoint, not %q", w.ScopeType)
	}
	if w.ScopeType != LearningScopeTenant && strings.TrimSpace(w.ScopeID) == "" {
		return LearningWindow{}, fmt.Errorf("a %s window has to name which one", w.ScopeType)
	}

	now := time.Now().UTC()
	w.ID = uuid.New().String()
	w.StartedAt = now
	w.Status = LearningActive
	if w.EndsAt.IsZero() {
		w.EndsAt = now.Add(7 * 24 * time.Hour)
	}
	if d := w.EndsAt.Sub(now); d < time.Hour {
		w.EndsAt = now.Add(time.Hour)
	} else if d > 90*24*time.Hour {
		w.EndsAt = now.Add(90 * 24 * time.Hour)
	}

	if _, err := s.db.Exec(
		`INSERT INTO learning_windows (id, tenant_id, scope_type, scope_id, scope_label, started_at, ends_at, started_by, note, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.TenantID, w.ScopeType, w.ScopeID, w.ScopeLabel, w.StartedAt, w.EndsAt, w.StartedBy, w.Note, w.Status); err != nil {
		return LearningWindow{}, err
	}
	s.learning.invalidate()
	return w, nil
}

// CloseLearningWindow ends a window early or records that it ran its course.
func (s *Store) CloseLearningWindow(id, status string) error {
	if status != LearningCompleted && status != LearningCancelled {
		return fmt.Errorf("a window closes as completed or cancelled, not %q", status)
	}
	res, err := s.db.Exec(
		`UPDATE learning_windows SET status = ?, closed_at = ? WHERE id = ? AND status = ?`,
		status, time.Now().UTC(), id, LearningActive)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no open learning window with id %s", id)
	}
	s.learning.invalidate()
	return nil
}

// CloseExpiredLearningWindows marks windows whose end has passed as completed.
//
// Holding already stops the moment the end time passes - Open() decides that,
// not the status column - so this is bookkeeping rather than enforcement. It
// exists so the console does not show a window as "active" for a week after it
// finished, and so the proposals it produced are read against a window that
// says it is over.
func (s *Store) CloseExpiredLearningWindows() (int64, error) {
	res, err := s.db.Exec(
		`UPDATE learning_windows SET status = ?, closed_at = ? WHERE status = ? AND ends_at <= ?`,
		LearningCompleted, time.Now().UTC(), LearningActive, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.learning.invalidate()
	}
	return n, nil
}

// GetLearningWindow returns one window.
func (s *Store) GetLearningWindow(id string) (LearningWindow, error) {
	rows, err := s.queryLearningWindows(`WHERE id = ?`, id)
	if err != nil {
		return LearningWindow{}, err
	}
	if len(rows) == 0 {
		return LearningWindow{}, sql.ErrNoRows
	}
	return rows[0], nil
}

// ListLearningWindows returns windows newest first. A tenant sees its own.
func (s *Store) ListLearningWindows(tenantID string, openOnly bool) ([]LearningWindow, error) {
	clauses := []string{}
	args := []interface{}{}
	if tenantID != "" {
		clauses = append(clauses, "tenant_id = ?")
		args = append(args, tenantID)
	}
	if openOnly {
		clauses = append(clauses, "status = ?")
		args = append(args, LearningActive)
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	return s.queryLearningWindows(where+" ORDER BY started_at DESC", args...)
}

func (s *Store) queryLearningWindows(tail string, args ...interface{}) ([]LearningWindow, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, scope_type, scope_id, COALESCE(scope_label, ''),
		started_at, ends_at, closed_at, COALESCE(started_by, ''), COALESCE(note, ''), status
		FROM learning_windows `+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LearningWindow{}
	for rows.Next() {
		var w LearningWindow
		var closed sql.NullTime
		if err := rows.Scan(&w.ID, &w.TenantID, &w.ScopeType, &w.ScopeID, &w.ScopeLabel,
			&w.StartedAt, &w.EndsAt, &closed, &w.StartedBy, &w.Note, &w.Status); err != nil {
			return nil, err
		}
		if closed.Valid {
			t := closed.Time.UTC()
			w.ClosedAt = &t
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (c *learningCache) invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// LearningWindowFor returns the window an endpoint is currently learning under.
//
// The detector asks this for every event, so the open windows are cached for a
// few seconds. A window opened in the console is therefore live within that,
// which is the same bargain the detection tuning cache makes.
func (s *Store) LearningWindowFor(ep Endpoint) (LearningWindow, bool) {
	now := time.Now().UTC()

	s.learning.mu.RLock()
	fresh := now.Sub(s.learning.at) < 10*time.Second
	windows := s.learning.windows
	s.learning.mu.RUnlock()

	if !fresh {
		loaded, err := s.ListLearningWindows("", true)
		if err != nil {
			// A database that cannot answer is not grounds for holding
			// findings: judge the traffic.
			return LearningWindow{}, false
		}
		s.learning.mu.Lock()
		s.learning.windows = loaded
		s.learning.at = now
		s.learning.mu.Unlock()
		windows = loaded
	}

	// The narrowest scope wins, so an endpoint window opened during an
	// estate-wide one is the one its observations land in.
	best := LearningWindow{}
	rank := map[string]int{LearningScopeEndpoint: 3, LearningScopeLocation: 2, LearningScopeTenant: 1}
	found := 0
	for _, w := range windows {
		if !w.Open(now) || !w.Covers(ep) {
			continue
		}
		if rank[w.ScopeType] > found {
			best, found = w, rank[w.ScopeType]
		}
	}
	return best, found > 0
}

// RecordLearningObservations folds a batch of counted facts into a window.
//
// The detector aggregates in memory and flushes on a timer, because one row
// written per flow would make learning mode the most expensive thing the hub
// does.
func (s *Store) RecordLearningObservations(obs []LearningObservation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO learning_observations
		(window_id, endpoint_id, kind, key, count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(window_id, endpoint_id, kind, key) DO UPDATE SET
			count = count + excluded.count,
			last_seen = MAX(last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, o := range obs {
		if o.WindowID == "" || o.Kind == "" || o.Key == "" {
			continue
		}
		if _, err := stmt.Exec(o.WindowID, o.EndpointID, o.Kind, o.Key, o.Count, o.FirstSeen, o.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListLearningObservations returns what a window has recorded, largest first.
func (s *Store) ListLearningObservations(windowID, kind string) ([]LearningObservation, error) {
	args := []interface{}{windowID}
	where := "WHERE window_id = ?"
	if kind != "" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	rows, err := s.db.Query(`SELECT window_id, endpoint_id, kind, key, count, first_seen, last_seen
		FROM learning_observations `+where+` ORDER BY count DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LearningObservation{}
	for rows.Next() {
		var o LearningObservation
		if err := rows.Scan(&o.WindowID, &o.EndpointID, &o.Kind, &o.Key, &o.Count, &o.FirstSeen, &o.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) initLearningSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS learning_windows (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL DEFAULT '',
		scope_type TEXT NOT NULL,
		scope_id TEXT NOT NULL DEFAULT '',
		scope_label TEXT NOT NULL DEFAULT '',
		started_at DATETIME NOT NULL,
		ends_at DATETIME NOT NULL,
		closed_at DATETIME,
		started_by TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active'
	);
	CREATE INDEX IF NOT EXISTS idx_learning_windows_status ON learning_windows(status, ends_at);

	CREATE TABLE IF NOT EXISTS learning_observations (
		window_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL,
		key TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 0,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		PRIMARY KEY (window_id, endpoint_id, kind, key)
	);
	CREATE INDEX IF NOT EXISTS idx_learning_obs_window ON learning_observations(window_id, kind);
	`)
	return err
}

// sortProposals puts the best-argued first: corroboration, then evidence.
func sortProposals(p []LearningProposal) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Corroboration != p[j].Corroboration {
			return p[i].Corroboration > p[j].Corroboration
		}
		if p[i].Evidence != p[j].Evidence {
			return p[i].Evidence > p[j].Evidence
		}
		return p[i].Subject < p[j].Subject
	})
}

// learningAgg is one proposal candidate's accumulated evidence across the
// endpoints a window covers.
type learningAgg struct {
	count     int64
	endpoints map[string]bool
	roles     map[string]int
	first     time.Time
	last      time.Time
}

func (a *learningAgg) add(o LearningObservation, role string) {
	a.count += o.Count
	if !a.endpoints[o.EndpointID] {
		a.endpoints[o.EndpointID] = true
		a.roles[role]++
	}
	if a.first.IsZero() || o.FirstSeen.Before(a.first) {
		a.first = o.FirstSeen
	}
	if o.LastSeen.After(a.last) {
		a.last = o.LastSeen
	}
}

func newLearningAgg() *learningAgg {
	return &learningAgg{endpoints: map[string]bool{}, roles: map[string]int{}}
}

// endpointsInScope is the set of endpoints a window covers. It is what a
// corroboration count is measured against: "four of the five machines this
// window watches" is an argument; "four machines" on its own is not.
func (s *Store) endpointsInScope(w LearningWindow) ([]Endpoint, error) {
	all, err := s.ListEndpoints(w.TenantID)
	if err != nil {
		return nil, err
	}
	out := []Endpoint{}
	for _, ep := range all {
		if ep.Status == "retired" {
			continue
		}
		if w.Covers(ep) {
			out = append(out, ep)
		}
	}
	return out, nil
}

// corroboration scores how many independent systems agree, on a 0-1 scale.
//
// One host doing something is not evidence that it is ordinary - it is the
// shape of every finding worth having. Five hosts doing it is platform
// behaviour. The curve is steep at the bottom for that reason: a
// single-endpoint proposal scores 0.2 and has to be argued for, and the list is
// sorted so those are read last.
func corroboration(endpoints, inScope int) float64 {
	if endpoints <= 0 {
		return 0
	}
	score := 0.2 + 0.2*float64(endpoints-1)
	if inScope > 0 {
		// A window watching two machines cannot produce five-machine evidence,
		// so the score is capped by how much agreement was available to find.
		share := float64(endpoints) / float64(inScope)
		if capped := 0.2 + 0.8*share; capped < score {
			score = capped
		}
	}
	if score > 1 {
		return 1
	}
	return score
}

// ComputeLearningProposals turns a window's observations into candidate tuning
// changes. It reads; it never writes.
func (s *Store) ComputeLearningProposals(windowID string) ([]LearningProposal, error) {
	w, err := s.GetLearningWindow(windowID)
	if err != nil {
		return nil, err
	}
	obs, err := s.ListLearningObservations(windowID, "")
	if err != nil {
		return nil, err
	}
	scope, err := s.endpointsInScope(w)
	if err != nil {
		return nil, err
	}
	roleOf := map[string]string{}
	for _, ep := range scope {
		role := strings.TrimSpace(ep.RoleTag)
		if role == "" {
			role = "untagged"
		}
		roleOf[ep.ID] = role
	}
	tuning := s.GetDetectionTuning()

	byKind := map[string]map[string]*learningAgg{}
	for _, o := range obs {
		kind, ok := byKind[o.Kind]
		if !ok {
			kind = map[string]*learningAgg{}
			byKind[o.Kind] = kind
		}
		a, ok := kind[o.Key]
		if !ok {
			a = newLearningAgg()
			kind[o.Key] = a
		}
		role := roleOf[o.EndpointID]
		if role == "" {
			role = "untagged"
		}
		a.add(o, role)
	}

	out := []LearningProposal{}

	// A pair the window saw repeatedly is the proposal the console's Expected
	// button makes by hand, with the evidence attached.
	for key, a := range byKind[LearnPair] {
		proc, owner, ok := splitPair(key)
		if !ok {
			continue
		}
		if tuning.IsVouchedPair(proc, owner, "") {
			continue // already expected; nothing to propose
		}
		out = append(out, LearningProposal{
			ID:            proposalID(windowID, ProposeQuietPair, key),
			WindowID:      windowID,
			Kind:          ProposeQuietPair,
			Subject:       key,
			Silences:      fmt.Sprintf("beaconing and volume findings for %s talking to %s", proc, owner),
			Technique:     "T1071.001",
			Evidence:      a.count,
			Endpoints:     len(a.endpoints),
			Roles:         a.roles,
			Corroboration: corroboration(len(a.endpoints), len(scope)),
			FirstSeen:     a.first,
			LastSeen:      a.last,
		})
	}

	// A process whose whole observed footprint stayed inside already-vouched
	// networks is a candidate quiet client. The test is over what was seen, not
	// over a list of familiar names: a program that reached one unnamed address
	// during the window does not qualify, whatever it is called.
	for proc, a := range byKind[LearnProcess] {
		if tuning.IsQuietClient(proc) {
			continue
		}
		pairs := 0
		allVouched := true
		for key := range byKind[LearnPair] {
			p, owner, ok := splitPair(key)
			if !ok || p != proc {
				continue
			}
			pairs++
			if !tuning.IsQuietOrg(owner) {
				allVouched = false
				break
			}
		}
		if pairs == 0 || !allVouched {
			continue
		}
		out = append(out, LearningProposal{
			ID:            proposalID(windowID, ProposeQuietProcess, proc),
			WindowID:      windowID,
			Kind:          ProposeQuietProcess,
			Subject:       proc,
			Silences:      fmt.Sprintf("%s talking to any already-vouched network, on every endpoint", proc),
			Technique:     "T1071",
			Evidence:      a.count,
			Endpoints:     len(a.endpoints),
			Roles:         a.roles,
			Corroboration: corroboration(len(a.endpoints), len(scope)),
			FirstSeen:     a.first,
			LastSeen:      a.last,
		})
	}

	// When the estate was actually asleep. Off-hours is one fleet-wide setting,
	// so this proposal says so in its own words rather than pretending to be
	// scoped to what it watched.
	if start, end, a, ok := quietHours(byKind[LearnHour]); ok &&
		(start != tuning.OffHoursStart || end != tuning.OffHoursEnd) {
		out = append(out, LearningProposal{
			ID:            proposalID(windowID, ProposeOffHours, fmt.Sprintf("%02d-%02d", start, end)),
			WindowID:      windowID,
			Kind:          ProposeOffHours,
			Subject:       fmt.Sprintf("%02d:00-%02d:00", start, end),
			Silences:      fmt.Sprintf("marks %02d:00-%02d:00 as off-hours, so activity in that range is scored as out-of-hours - a fleet-wide setting, wider than this window's scope", start, end),
			Technique:     "T1029",
			Evidence:      a.count,
			Endpoints:     len(a.endpoints),
			Roles:         a.roles,
			Corroboration: corroboration(len(a.endpoints), len(scope)),
			FirstSeen:     a.first,
			LastSeen:      a.last,
		})
	}

	sortProposals(out)
	return out, nil
}

// quietHours reads the observed activity histogram and returns the longest run
// of hours in which nothing was seen at all - the honest reading of "when is
// this estate asleep". An estate that was busy in all twenty-four hours has no
// quiet window to propose, and this says so rather than inventing one.
func quietHours(hours map[string]*learningAgg) (int, int, *learningAgg, bool) {
	if len(hours) == 0 {
		return 0, 0, nil, false
	}
	busy := [24]bool{}
	total := newLearningAgg()
	for key, a := range hours {
		h, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || h < 0 || h > 23 {
			continue
		}
		busy[h] = true
		total.count += a.count
		for ep := range a.endpoints {
			if !total.endpoints[ep] {
				total.endpoints[ep] = true
			}
		}
		for role, n := range a.roles {
			total.roles[role] += n
		}
		if total.first.IsZero() || (!a.first.IsZero() && a.first.Before(total.first)) {
			total.first = a.first
		}
		if a.last.After(total.last) {
			total.last = a.last
		}
	}

	bestStart, bestLen := -1, 0
	for start := 0; start < 24; start++ {
		if busy[start] {
			continue
		}
		length := 0
		for length < 24 && !busy[(start+length)%24] {
			length++
		}
		if length > bestLen {
			bestStart, bestLen = start, length
		}
	}
	// Fewer than two quiet hours is noise, not a working pattern, and
	// twenty-four is a window that saw nothing at all. More than twenty-one
	// means the window caught activity in fewer than three hours of the day,
	// which is a window that barely watched rather than an estate that slept:
	// a one-hour window must not be allowed to declare the other twenty-three
	// off-hours.
	if bestStart < 0 || bestLen < 2 || bestLen > 21 {
		return 0, 0, nil, false
	}
	return bestStart, (bestStart + bestLen) % 24, total, true
}

func proposalID(windowID, kind, subject string) string {
	return fmt.Sprintf("%s:%s:%s", windowID, kind, strings.ToLower(strings.TrimSpace(subject)))
}
